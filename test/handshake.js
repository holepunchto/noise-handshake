const { test } = require('brittle')
const NoiseState = require('../noise.js')
const sodium = require('sodium-universal')
// const curve = require('noise-curve-secp')

test('IK', t => {
  const initiator = new NoiseState('IK', true, null)
  const responder = new NoiseState('IK', false, null)

  initiator.initialise(Buffer.alloc(0), responder.s.publicKey)
  responder.initialise(Buffer.alloc(0))

  const message = initiator.send()
  responder.recv(message)

  const reply = responder.send()
  initiator.recv(reply)

  t.alike(initiator.key, null)
  t.alike(initiator.nonce, null)
  t.alike(initiator.curve, null)
  t.alike(initiator.digest, null)
  t.alike(initiator.chainingKey, null)
  t.alike(initiator.offset, null)
  t.alike(initiator.e, null)
  t.alike(initiator.re, null)

  t.alike(initiator.rs, responder.s.publicKey)

  t.alike(initiator.rx, responder.tx)
  t.alike(initiator.tx, responder.rx)
  t.end()
})

test('IK does not use shared-slab memory', t => {
  // Keys generated as with default curve, but using allocUnsafe mem
  const initiatorKeyPair = {
    publicKey: Buffer.allocUnsafe(sodium.crypto_scalarmult_BYTES),
    secretKey: Buffer.allocUnsafe(sodium.crypto_scalarmult_SCALARBYTES)
  }
  const responderKeyPair = {
    publicKey: Buffer.allocUnsafe(sodium.crypto_scalarmult_BYTES),
    secretKey: Buffer.allocUnsafe(sodium.crypto_scalarmult_SCALARBYTES)
  }

  sodium.crypto_kx_keypair(initiatorKeyPair.publicKey, initiatorKeyPair.secretKey)
  sodium.crypto_kx_keypair(responderKeyPair.publicKey, responderKeyPair.secretKey)

  t.is(initiatorKeyPair.publicKey.buffer.byteLength > 500, true, 'sanity check: uses shared slab')
  t.is(responderKeyPair.publicKey.buffer.byteLength > 500, true, 'sanity check: uses shared slab')

  const initiator = new NoiseState('IK', true, initiatorKeyPair)
  const responder = new NoiseState('IK', false, responderKeyPair)

  initiator.initialise(Buffer.alloc(0), responder.s.publicKey)
  responder.initialise(Buffer.alloc(0), initiator.s.publicKey)

  const message = initiator.send()
  responder.recv(message)

  const reply = responder.send()
  initiator.recv(reply)

  t.is(initiator.rs.buffer.byteLength, 32, 'remote public key does not use default slab')
  t.is(initiator.rx.buffer.byteLength < 500, true, 'rx does not use default slab')
  t.is(initiator.tx.buffer.byteLength < 500, true, 'tx does not use default slab')
  t.is(initiator.rx.buffer, initiator.tx.buffer, 'rx and tx share same slab')

  t.is(responder.rs.buffer.byteLength, 32, 'remote public key does not use default slab')
  t.is(responder.rx.buffer.byteLength < 500, true, 'rx does not use default slab')
  t.is(responder.tx.buffer.byteLength < 500, true, 'tx does not use default slab')
  t.is(responder.rx.buffer, responder.tx.buffer, 'rx and tx share same slab')

  t.end()
})

test('XX', t => {
  const initiator = new NoiseState('XX', true, null)
  const responder = new NoiseState('XX', false, null)

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  const message = initiator.send()
  responder.recv(message)

  const reply = responder.send()
  initiator.recv(reply)

  const initiatorReply = initiator.send()
  responder.recv(initiatorReply)

  t.alike(initiator.complete, true)
  t.alike(responder.complete, true)

  t.unlike(initiator.rx, null)
  t.unlike(initiator.tx, null)

  t.alike(initiator.rx, responder.tx)
  t.alike(initiator.tx, responder.rx)
  t.end()
})

test('NN', t => {
  const initiator = new NoiseState('NN', true, null)
  const responder = new NoiseState('NN', false, null)

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  const message = initiator.send()
  responder.recv(message)

  const reply = responder.send()
  initiator.recv(reply)

  t.alike(initiator.rx, responder.tx)
  t.alike(initiator.tx, responder.rx)
  t.end()
})

test('NNpsk0: bad', t => {
  t.plan(1)

  const psk1 = Buffer.from(
    '324eee92611cd877841c4de9fd5253e9dba6033329a837ee5f01beb005dffb2f', 'hex')
  const psk2 = Buffer.from(
    'ebdb9f8cd9c704844ca47b88fe7526a3c9f865be998486ca16ae3431e019d0cc', 'hex')
  const initiator = new NoiseState('NNpsk0', true, null, { psk: psk1 })
  const responder = new NoiseState('NNpsk0', false, null, { psk: psk2 })

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  const message = initiator.send()
  try {
    responder.recv(message)
    t.fail('should have failed to verify!')
  } catch (err) {
    t.alike(err.toString(), 'Error: could not verify data')
  }
})

test('NNpsk0: good', t => {
  const psk = Buffer.from(
    '324eee92611cd877841c4de9fd5253e9dba6033329a837ee5f01beb005dffb2f', 'hex')
  const initiator = new NoiseState('NNpsk0', true, null, { psk })
  const responder = new NoiseState('NNpsk0', false, null, { psk })

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  const message = initiator.send()
  responder.recv(message)

  const reply = responder.send()
  initiator.recv(reply)

  t.alike(initiator.rx, responder.tx)
  t.alike(initiator.tx, responder.rx)
  t.end()
})

test('XXpsk0: bad', t => {
  t.plan(1)

  const psk1 = Buffer.from(
    '324eee92611cd877841c4de9fd5253e9dba6033329a837ee5f01beb005dffb2f', 'hex')
  const psk2 = Buffer.from(
    'ebdb9f8cd9c704844ca47b88fe7526a3c9f865be998486ca16ae3431e019d0cc', 'hex')
  const initiator = new NoiseState('XXpsk0', true, null, { psk: psk1 })
  const responder = new NoiseState('XXpsk0', false, null, { psk: psk2 })

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  const message = initiator.send()
  try {
    responder.recv(message)
    t.fail('should have failed to verify!')
  } catch (err) {
    t.alike(err.toString(), 'Error: could not verify data')
  }
})

test('XXpsk0: good', t => {
  const psk = Buffer.from(
    '324eee92611cd877841c4de9fd5253e9dba6033329a837ee5f01beb005dffb2f', 'hex')
  const initiator = new NoiseState('XXpsk0', true, null, { psk })
  const responder = new NoiseState('XXpsk0', false, null, { psk })

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  const message = initiator.send()
  responder.recv(message)

  const reply = responder.send()
  initiator.recv(reply)

  t.alike(initiator.rx, responder.tx)
  t.alike(initiator.tx, responder.rx)
  t.end()
})
