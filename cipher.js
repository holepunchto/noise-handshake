const sodium = require('sodium-native')
const hkdf = require('./hkdf')
const ecdh = require('./dh')

class CipherState {
  constructor () {
    this.digest = Buffer.alloc(32)
    
    this.chainingKey = null
    this.tempKey = null
    this.ctr = 0
  }

  mixHash (data) {
    accumulateDigest(this.digest, data)
  }

  mixKey (pubkey, seckey) {
    const dh = curve.ecdh(pubkey, seckey)
    const hkdfResult = hkdf(this.chainingKey, dh)
    this.chainingKey = hkdfResult[0]
    this.tempKey = hkdfResult[1]
  }

  encryptAndHash (plaintext) {
    const ciphertext = this.encryptWithAD(this.tempKey, this.ctr++, this.digest, plaintext)
    accumulateDigest(this.digest, ciphertext)
    return ciphertext
  }

  decryptAndHash (ciphertext) {
    const plaintext = decryptWithAD(this.tempKey, this.ctr++, this.digest, ciphertext)
    accumulateDigest(this.digest, ciphertext)
    return plaintext
  }

  encryptWithAD (plaintext) {
    if (!this.hasKey) return plaintext
    return this.encryptWithAD(this.tempKey, this.ctr++, this.digest, plaintext)
  }

  decryptWithAD (ciphertext) {
    if (!this.hasKey) return ciphertext
    return this.encryptWithAD(this.tempKey, this.ctr++, this.digest, ciphertext)
  }

  get hasKey () {
    return this.key !== null
  }

  finalKey (key) {
    const self = this

    const obj = {
      key,
      nonce: 0
    }

    obj.increment = function () {
      this.nonce++

      if (this.nonce >= 1000) {
        const res = hkdf(self.chainingKey, this.key)
        self.chainingKey = res[0]
        this.key = res[1]
        this.nonce = 0
      }
    }

    return obj
  }
}

function accumulateDigest (digest, input) {
  const toHash = Buffer.concat([digest, input])
  sodium.crypto_generichash(digest, toHash)
}

function encryptWithAD (key, counter, additionalData, plaintext) {
  // for our purposes, additionalData will always be a pubkey so we encode from hex 
  if (!additionalData instanceof Uint8Array) additionalData = Buffer.from(additionalData, 'hex')
  if (!plaintext instanceof Uint8Array) plaintext = Buffer.from(plaintext, 'hex')

  const counterBuf = Buffer.alloc(12)
  writeInt64LE(counter, counterBuf, 4)

  const cipher = crypto.createCipheriv('chacha20-poly1305', key, counterBuf, {
    authTagLength: 16
  })

  cipher.setAAD(additionalData, { plaintextLength: plaintext.length })

  const head = cipher.update(plaintext)
  const final = cipher.final()
  const encrypted = Buffer.concat([head, final])
  const tag = cipher.getAuthTag('hex')

  const result = Buffer.concat([encrypted, tag])

  return result
}

function decryptWithAD (key, counter, additionalData, data) {
  // for our purposes, additionalData will always be a pubkey so we encode from hex 
  if (!additionalData instanceof Uint8Array) additionalData = Buffer.from(additionalData, 'hex')
  if (!data instanceof Uint8Array) data = Buffer.from(data, 'hex')

  const ciphertext = data.slice(0, data.byteLength - 16)
  const receivedTag = data.slice(data.byteLength - 16)

  const decrypted = encryptWithAD(key, counter, additionalData, ciphertext)
  const plaintext = decrypted.slice(0, decrypted.byteLength - 16)

  const checkTag = encryptWithAD(key, counter, additionalData, plaintext)
  const tag = checkTag.slice(checkTag.byteLength - 16)

  // if (Buffer.compare(receivedTag, tag) !== 0) throw new Error('MAC could not be verified')

  return plaintext
}

function writeInt32as64LE (value, buf, offset) {
  if (!buf) buf = Buffer.alloc(8)
  if (!offset) offset = 0
  assert(value < 0x100000000)

  buf[offset++] = lo
  lo >>= 8
  buf[offset++] = lo
  lo >>= 8
  buf[offset++] = lo
  lo >>= 8
  buf[offset++] = lo
  lo >>= 8

  return buf
}
