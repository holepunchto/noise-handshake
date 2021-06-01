const crypto = require('crypto')

module.exports = function hkdf (salt, inputKeyMaterial, info = '', length = 64) {
  const pseudoRandomKey = hkdfExtract(salt, inputKeyMaterial)
  const result = hkdfExpand(pseudoRandomKey, info, length)

  const [ k1, k2 ] = [ result.slice(0, 32), result.slice(32)]
  
  return [ k1, k2 ]
  
  function hkdfExtract (salt, inputKeyMaterial) {
    return hmacDigest(salt, inputKeyMaterial)
  }

  function hkdfExpand(key, info = '', length = 64) {
    const T = [Buffer.from('')]
    const lengthRatio = length / SHA256_BYTES

    for (let i = 0; i < lengthRatio; i++) {
      const toHash = new Uint8Array(T[i].byteLength + info.length + 1)
      
      toHash.set(T[i])
      let offset = T[i].byteLength

      if (info.length) {
        const infoBuf = Buffer.from(info)
        toHash.set(infoBuf, offset)
        offset += infoBuf.byteLength
      }

      toHash[offset] = i + 1

      T[i + 1] = hmacDigest(key, toHash)
    }

    const result = Buffer.concat(T.slice(1))
    assert(result.byteLength === length, 'key expansion failed, length not as expected')

    return result
  }
}

function hmacDigest (key, input) {
  const hmac = crypto.createHmac('sha256', key)
  hmac.update(input)

  return hmac.digest()
}
