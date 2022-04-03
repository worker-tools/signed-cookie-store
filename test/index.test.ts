import 'https://gist.githubusercontent.com/qwtel/b14f0f81e3a96189f7771f83ee113f64/raw/TestRequest.ts'
import {
  assert,
  assertExists,
  assertEquals,
  assertStrictEquals,
  assertStringIncludes,
  assertThrows,
  assertRejects,
  assertArrayIncludes,
} from 'https://deno.land/std@0.133.0/testing/asserts.ts'
const { test } = Deno;

import { RequestCookieStore } from '../../request-cookie-store/index.ts';
import { SignedCookieStore } from '../index.ts'

test('exists', () => {
  assertExists(SignedCookieStore)
})

const emptyStore = new RequestCookieStore(new Request('/', {
  headers: {
    'Cookie': 'foo=bar; user=bert; no=mad',
  },
}));

const secret = 'password123'
const keyPromise = SignedCookieStore.deriveCryptoKey({ secret });

test('unsigned cookies to be ignored', async () => {
  const cookieStore = new SignedCookieStore(emptyStore, await keyPromise)
  assertEquals(await cookieStore.getAll(), [])
  assertEquals(await cookieStore.get('foo'), null)
})

const baseStore = new RequestCookieStore(new Request('/', {
  headers: {
    'Cookie': 'foo=bar; foo.sig=Sd_7Nz01uxBspv_y6Lqs8gLXXYEe8iFEN8fNouVNLzI; bar=ignored',
  },
}))

test('get signed cookie', async () => {
  const cookieStore = new SignedCookieStore(baseStore, await keyPromise)
  assertEquals(await cookieStore.get('foo'), { name: 'foo', value: 'bar' })
  assertEquals(await cookieStore.get('bar'), null)
})

const forgedStore = new RequestCookieStore(new Request('/', {
  headers: {
    'Cookie': 'foo=bar; foo.sig=Sd_7Nz01uxBspv_y6Lqs8gLXXYEe8iFEN8fAAAAAAAA',
  },
}))

test('throws on forged signature', async () => {
  const cookieStore = new SignedCookieStore(forgedStore, await keyPromise)
  assertRejects(() => cookieStore.get('foo'), Error)
})

const newKeyPromise = SignedCookieStore.deriveCryptoKey({ secret: 'new-key' });

test('verifying signatures form previous keys', async () => {
  const cookieStore = new SignedCookieStore(baseStore, await newKeyPromise, { keyring: [await keyPromise] })
  assertEquals(await cookieStore.get('foo'), { name: 'foo', value: 'bar' })
})

test('not verifying forged signatures with previous keys', async () => {
  const cookieStore = new SignedCookieStore(forgedStore, await newKeyPromise, { keyring: [await keyPromise] })
  assertRejects(() => cookieStore.get('foo'), Error)
})

test('signing signatures with new key', async () => {
  const cookieStore = new SignedCookieStore(emptyStore, await newKeyPromise, { keyring: [await keyPromise] })
  await cookieStore.set('foo', 'bar')
  assert(!emptyStore.headers.map(x => x[1]).includes('foo.sig=Sd_7Nz01uxBspv_y6Lqs8gLXXYEe8iFEN8fNouVNLzI'))
  assert(emptyStore.headers.map(x => x[1]).includes('foo.sig=-VaHv2_MfLKX42ys3uhI9fa9XhpMVmi5l7PdPAGGA9c'))
})
