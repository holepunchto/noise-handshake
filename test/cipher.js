/* eslint-disable camelcase */
const {
  randombytes_buf,
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_aead_chacha20poly1305_ietf_ABYTES
} = require('sodium-universal')
const Cipher = require('../cipher')
const { test } = require('brittle')

test('constants', function (assert) {
  assert.ok(Cipher.KEYBYTES === 32, 'KEYBYTES conforms to Noise Protocol')
  assert.ok(Cipher.NONCEBYTES === 8, 'NONCEBYTES conforms to Noise Protocol')
  assert.ok(Cipher.MACBYTES === 16, 'MACBYTES conforms to Noise Protocol')

  assert.ok(Cipher.KEYBYTES === crypto_aead_chacha20poly1305_ietf_KEYBYTES, 'KEYBYTES')
  assert.ok(Cipher.NONCEBYTES + 4 === crypto_aead_chacha20poly1305_ietf_NPUBBYTES, 'NONCEBYTES')
  assert.ok(Cipher.MACBYTES === crypto_aead_chacha20poly1305_ietf_ABYTES, 'MACBYTES')

  assert.end()
})

test('identity', function (assert) {
  const key = Buffer.alloc(Cipher.KEYBYTES)
  randombytes_buf(key)

  const key2 = Buffer.alloc(Cipher.KEYBYTES)
  randombytes_buf(key2)

  const plaintext = Buffer.from('Hello world')

  const cipher = new Cipher(key)
  const ciphertext = cipher.encrypt(plaintext)

  assert.exception(_ => cipher.decrypt(ciphertext, Buffer.alloc(1)))
  for (let i = 0; i < ciphertext.length; i++) {
    ciphertext[i] ^= i + 1
    assert.exception(_ => cipher.decrypt(ciphertext))
    ciphertext[i] ^= i + 1
  }

  cipher.initialiseKey(key)
  const decrypted = cipher.decrypt(ciphertext)

  assert.alike(decrypted, plaintext)
  assert.end()
})

test('identity with ad', function (assert) {
  const key = Buffer.alloc(Cipher.KEYBYTES)
  randombytes_buf(key)

  const cipher = new Cipher(key)

  const ad = Buffer.from('version 0')

  const key2 = Buffer.alloc(Cipher.KEYBYTES)
  randombytes_buf(key2)

  const cipher2 = new Cipher(key2)

  const plaintext = Buffer.from('Hello world')
  const ciphertext = cipher.encrypt(plaintext, ad)

  assert.exception(_ => cipher.decrypt(ciphertext, Buffer.alloc(1)), 'should not have ad')
  assert.exception(_ => cipher2.decrypt(ciphertext, ad), 'wrong key')

  cipher2.key = key
  cipher2.nonce = 2
  assert.exception(_ => cipher2.decrypt(ciphertext, ad), 'wrong nonce')

  for (let i = 0; i < ciphertext.length; i++) {
    ciphertext[i] ^= 255
    assert.exception(_ => cipher.decrypt(ciphertext, ad))
    ciphertext[i] ^= 255
  }

  cipher.initialiseKey(key)
  const decrypted = cipher.decrypt(ciphertext, ad)

  assert.alike(decrypted, plaintext)
  assert.end()
})

test('max encrypt length', function (assert) {
  assert.plan(2)

  const key = Buffer.alloc(Cipher.KEYBYTES)
  randombytes_buf(key)
  const cipher = new Cipher(key)

  const plaintext = Buffer.alloc(90_000).fill(0x08)

  try {
    cipher.encrypt(plaintext)
  } catch (err) {
    assert.ok(err instanceof Error)
    assert.alike(err.message, 'ciphertext length of 90016 exceeds maximum Noise message length of 65535')
  }
})

test('max decrypt length', function (assert) {
  assert.plan(2)

  const key = Buffer.alloc(Cipher.KEYBYTES)
  randombytes_buf(key)
  const cipher = new Cipher(key)

  const ciphertext = Buffer.alloc(100_000).fill(0xBABECAFE)
  try {
    cipher.decrypt(ciphertext)
  } catch (err) {
    assert.ok(err instanceof Error)
    assert.alike(err.message, 'ciphertext length of 100000 exceeds maximum Noise message length of 65535')
  }
})

// test.skip('rekey', function (assert) {
//   const key = Buffer.alloc(Cipher.KEYBYTES)
//   const nonce = Buffer.alloc(Cipher.NONCEBYTES)
//   randombytes_buf(key)
//   randombytes_buf(nonce)

//   const keyCopy = Buffer.from(key)
//   cipher.rekey(key, key)
//   assert.absent(Buffer.equals(key, keyCopy))

//   const plaintext = Buffer.from('Hello world')
//   const ciphertext = Buffer.alloc(plaintext.byteLength + Cipher.MACBYTES)
//   const decrypted = Buffer.alloc(plaintext.byteLength)

//   cipher.encrypt(ciphertext, key, nonce, null, plaintext)

//   assert.exception(_ => cipher.decrypt(ciphertext, null), 'wrong key')

//   cipher.rekey(keyCopy, keyCopy)
//   cipher.decrypt(decrypted, keyCopy, nonce, null, ciphertext)

//   assert.ok(Buffer.equals(decrypted, plaintext))
//   assert.end()
// })
