import './fixes';
import { jest } from '@jest/globals'

import { RequestCookieStore } from '@worker-tools/request-cookie-store';
import { SignedCookieStore } from '../index.js'

test('exists', () => {
  expect(SignedCookieStore).toBeDefined
})

const emptyStore = new RequestCookieStore(new Request('/', {
  headers: {
    'Cookie': 'foo=bar; user=bert; no=mad',
  },
}));

const secret = 'password123'
const keyPromise = SignedCookieStore.deriveCryptoKey({ secret });

const baseStore = new RequestCookieStore(new Request('/', {
  headers: {
    'Cookie': 'foo=bar; foo.sig=Sd_7Nz01uxBspv_y6Lqs8gLXXYEe8iFEN8fNouVNLzI; bar=ignored',
  },
}))

test('unsigned cookies to be ignored', async () => {
  const cookieStore = new SignedCookieStore(emptyStore, await keyPromise)
  expect(cookieStore.getAll()).resolves.toStrictEqual([])
  expect(cookieStore.get('foo')).resolves.toBeNull
})

test('get signed cookie', async () => {
  const cookieStore = new SignedCookieStore(baseStore, await keyPromise)
  expect(cookieStore.get('foo')).resolves.toStrictEqual({ name: 'foo', value: 'bar' })
  expect(cookieStore.get('bar')).resolves.toBeNull
})

const forgedStore = new RequestCookieStore(new Request('/', {
  headers: {
    'Cookie': 'foo=bar; foo.sig=Sd_7Nz01uxBspv_y6Lqs8gLXXYEe8iFEN8fAAAAAAAA',
  },
}))
test('throws on forged signature', async () => {
  const cookieStore = new SignedCookieStore(forgedStore, await keyPromise)
  expect(cookieStore.get('foo')).rejects.toBeInstanceOf(Error)
})

const newKeyPromise = SignedCookieStore.deriveCryptoKey({ secret: 'new-key' });

test('verifying signatures form previous keys', async () => {
  const cookieStore = new SignedCookieStore(baseStore, await newKeyPromise, { keyring: [await keyPromise] })
  expect(cookieStore.get('foo')).resolves.toStrictEqual({ name: 'foo', value: 'bar' })
})

test('not verifying forged signatures with previous keys', async () => {
  const cookieStore = new SignedCookieStore(forgedStore, await newKeyPromise, { keyring: [await keyPromise] })
  expect(cookieStore.get('foo')).rejects.toBeInstanceOf(Error)
})

test('signing signatures with new key', async () => {
  const cookieStore = new SignedCookieStore(emptyStore, await newKeyPromise, { keyring: [await keyPromise] })
  await cookieStore.set('foo', 'bar')
  expect([...emptyStore.headers].map(x => x[1])).not.toContain('foo.sig=Sd_7Nz01uxBspv_y6Lqs8gLXXYEe8iFEN8fNouVNLzI')
  expect([...emptyStore.headers].map(x => x[1])).toContain('foo.sig=-VaHv2_MfLKX42ys3uhI9fa9XhpMVmi5l7PdPAGGA9c')
})
