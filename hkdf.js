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
    const hmac = b4a.alloc(HASHLEN)
    return hmacDigest(hmac, salt, inputKeyMaterial)
  }

  function hkdfExpand (key, info, length) {
    // Put in dedicated slab to avoid keeping shared slab from being gc'ed
    const result = b4a.allocUnsafeSlow(length)

    const infoBuf = b4a.from(info)
    let prev = infoBuf

    for (let i = 0; i < length; i += HASHLEN) {
      const out = result.subarray(i, i + HASHLEN)
      const pos = b4a.from([(i / HASHLEN) + 1])

      prev = hmacDigest(out, key, [prev, infoBuf, pos])
    }

    assert(result.byteLength === length, 'key expansion failed, length not as expected')

    return result
  }
}

function hmacDigest (out, key, input) {
  hmacBlake2b(out, input, key)
  return out
}
