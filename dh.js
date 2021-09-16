/* eslint-disable camelcase */
const { crypto_kx_SEEDBYTES, crypto_kx_keypair, crypto_kx_seed_keypair } = require('sodium-universal/crypto_kx')
const { crypto_scalarmult_BYTES, crypto_scalarmult_SCALARBYTES, crypto_scalarmult, crypto_scalarmult_base } = require('sodium-universal/crypto_scalarmult')

const assert = require('nanoassert')

const DHLEN = crypto_scalarmult_BYTES
const PKLEN = crypto_scalarmult_BYTES
const SKLEN = crypto_scalarmult_SCALARBYTES
const SEEDLEN = crypto_kx_SEEDBYTES
const ALG = '25519'

module.exports = {
  DHLEN,
  PKLEN,
  SKLEN,
  SEEDLEN,
  ALG,
  generateKeyPair,
  generateSeedKeyPair,
  dh
}

function generateKeyPair (privKey) {
  const keyPair = {}

  keyPair.secretKey = privKey || new Uint8Array(SKLEN)
  keyPair.publicKey = new Uint8Array(PKLEN)

  if (privKey) {
    crypto_scalarmult_base(keyPair.publicKey, keyPair.secretKey)
  } else {
    crypto_kx_keypair(keyPair.publicKey, keyPair.secretKey)
  }

  return keyPair
}

function generateSeedKeyPair (seed) {
  assert(seed.byteLength === SKLEN)

  const keyPair = {}
  keyPair.secretKey = new Uint8Array(SKLEN)
  keyPair.publicKey = new Uint8Array(PKLEN)

  crypto_kx_seed_keypair(keyPair.publicKey, keyPair.secretKey, seed)
  return keyPair
}

function dh (pk, lsk) {
  assert(lsk.byteLength === SKLEN)
  assert(pk.byteLength === PKLEN)

  const output = new Uint8Array(DHLEN)

  crypto_scalarmult(
    output,
    lsk,
    pk
  )

  return output
}
