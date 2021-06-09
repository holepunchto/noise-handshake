const assert = require('nanoassert')
const hmacBlake2b = require('hmac-blake2b')

const HASHLEN = 64
module.exports = function hkdf (salt, inputKeyMaterial, info = '', length = 2 * HASHLEN) {
  const pseudoRandomKey = hkdfExtract(salt, inputKeyMaterial)
  const result = hkdfExpand(pseudoRandomKey, info, length)

  const [k1, k2] = [result.slice(0, HASHLEN), result.slice(HASHLEN)]

  return [k1, k2]

  function hkdfExtract (salt, inputKeyMaterial) {
    return hmacDigest(salt, inputKeyMaterial)
  }

  function hkdfExpand (key, info, length) {
    const T = [Buffer.from(info)]
    const lengthRatio = length / HASHLEN

    for (let i = 0; i < lengthRatio; i++) {
      const infoBuf = Buffer.from(info)
      const toHash = Buffer.concat([T[i], infoBuf, Buffer.from([i + 1])])

      T[i + 1] = hmacDigest(key, toHash)
    }

    const result = Buffer.concat(T.slice(1))
    assert(result.byteLength === length, 'key expansion failed, length not as expected')

    return result
  }
}

function hmacDigest (key, input) {
  const hmac = Buffer.alloc(HASHLEN)
  hmacBlake2b(hmac, input, key)

  return hmac
}
