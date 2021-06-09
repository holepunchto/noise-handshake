const sodium = require('sodium-native')
const CipherState = require('./cipher')
const curve = require('./dh')
const hkdf = require('./hkdf')

module.exports = class SymmetricState extends CipherState {
  constructor () {
    super()

    this.digest = Buffer.alloc(64)
    this.chainingKey = null
    this.offset = 0
  }

  mixHash (data) {
    accumulateDigest(this.digest, data)
  }

  mixKey (pubkey, seckey) {
    const dh = curve.dh(pubkey, seckey)
    const hkdfResult = hkdf(this.chainingKey, dh)
    this.chainingKey = hkdfResult[0]
    this.initialiseKey(hkdfResult[1].subarray(0, 32))
  }

  encryptAndHash (plaintext) {
    const ciphertext = this.encrypt(plaintext, this.digest)
    accumulateDigest(this.digest, ciphertext)
    return ciphertext
  }

  decryptAndHash (ciphertext) {
    const plaintext = this.decrypt(ciphertext, this.digest)
    accumulateDigest(this.digest, ciphertext)
    return plaintext
  }

  split () {
    const [k1, k2] = hkdf(this.chainingKey, Buffer.alloc(0))

    return {
      cipher1: new CipherState(k1.subarray(0, 32)),
      cipher2: new CipherState(k2.subarray(0, 32))
    }
  }

  static get alg () {
    return CipherState.alg + '_BLAKE2b'
  }
}

function accumulateDigest (digest, input) {
  const toHash = Buffer.concat([digest, input])
  sodium.crypto_generichash(digest, toHash)
}
