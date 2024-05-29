const hmacBlake2b = require('./hmac')
const assert = require('nanoassert')
const b4a = require('b4a')

const HASHLEN = 64

module.exports = {
  hkdf,
  HASHLEN
}

// HMAC-based Extract-and-Expand KDF
// https://www.ietf.org/rfc/rfc5869.txt

function hkdf (salt, inputKeyMaterial, info = '', length = 2 * HASHLEN) {
  const pseudoRandomKey = hkdfExtract(salt, inputKeyMaterial)
  const result = hkdfExpand(pseudoRandomKey, info, length)

  const results = []
  let offset = 0
  while (offset < result.length) {
    results.push(result.subarray(offset, offset + HASHLEN))
    offset += HASHLEN
  }
  return results

  function hkdfExtract (salt, inputKeyMaterial) {
    return hmacDigest(salt, inputKeyMaterial)
  }

  function hkdfExpand (key, info, length) {
    let prevHash = b4a.from(info)
    const lengthRatio = length / HASHLEN
    const hashByteLength = 64

    // Put in dedicated slab to avoid keeping shared slab from being gc'ed
    const result = b4a.allocUnsafeSlow(lengthRatio * hashByteLength)

    for (let i = 0; i < lengthRatio; i++) {
      const infoBuf = b4a.from(info)
      const toHash = b4a.concat([prevHash, infoBuf, b4a.from([i + 1])])

      prevHash = hmacDigest(key, toHash)
      b4a.copy(prevHash, result, hashByteLength * i)
    }

    assert(result.byteLength === length, 'key expansion failed, length not as expected')

    return result
  }
}

function hmacDigest (key, input) {
  const hmac = b4a.alloc(HASHLEN)
  hmacBlake2b(hmac, input, key)

  return hmac
}
