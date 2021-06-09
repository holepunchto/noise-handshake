const test = require('tape')
const dh = require('../dh')
const hkdf = require('../hkdf')
const ref = require('../node_modules/noise-protocol/hash')

test('hkdf', t => {
  const salt = Buffer.from('25c1185cb4e9cd7182f2323451741216357943b9a4a1ce5b73885597b5998a5001f013b9787fa2596e89a7ab568edf69182bb20eab1b92593a655c8c8f050eaf', 'hex')
  const input = Buffer.from('6d289c8c4024c4b8c84b192b31bc54bdf636594cecd2724a005daa9413c9025a', 'hex')
  const info = ''
  const length = 128

  const exp = [
    Buffer.from('e4da80fb5a2f66a0f8c3866c4f9d0d4930ac3b207d251e5f16bdc2dd102832cb992fdcf80d34362861403e7eeb9c3167f56631a7ebfc26e1d1433e8c55962629', 'hex'),
    Buffer.from('b9ab0dc14aaa19df2e1697bcd4bad9869ee267388a59db654c968d68bcd17dc940d7b998987dd4357bf39a01fafe8e9c4ef62dfbd16a5eb49cb460e1b8a9e2bf', 'hex')
  ]
  const result = hkdf(salt, input, info, length)

  t.deepEqual(exp, result)
  t.end()
})

test('ref', t => {
  const salt = Buffer.from('25c1185cb4e9cd7182f2323451741216357943b9a4a1ce5b73885597b5998a5001f013b9787fa2596e89a7ab568edf69182bb20eab1b92593a655c8c8f050eaf', 'hex')
  const input = Buffer.from('6d289c8c4024c4b8c84b192b31bc54bdf636594cecd2724a005daa9413c9025a', 'hex')
  const info = ''
  const length = 128

  const exp = [
    Buffer.from('e4da80fb5a2f66a0f8c3866c4f9d0d4930ac3b207d251e5f16bdc2dd102832cb992fdcf80d34362861403e7eeb9c3167f56631a7ebfc26e1d1433e8c55962629', 'hex'),
    Buffer.from('b9ab0dc14aaa19df2e1697bcd4bad9869ee267388a59db654c968d68bcd17dc940d7b998987dd4357bf39a01fafe8e9c4ef62dfbd16a5eb49cb460e1b8a9e2bf', 'hex')
  ]

  const result = [
    Buffer.alloc(64),
    Buffer.alloc(64)
  ]

  ref.hkdf(result[0], result[1], null, salt, input)

  t.deepEqual(exp, result)
  t.end()
})
