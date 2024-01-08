const test = require('tape')
const NoiseState = require('../noise.js')
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

  t.equal(initiator.key, null)
  t.equal(initiator.nonce, null)
  t.equal(initiator.curve, null)
  t.equal(initiator.digest, null)
  t.equal(initiator.chainingKey, null)
  t.equal(initiator.offset, null)
  t.equal(initiator.e, null)
  t.equal(initiator.re, null)

  t.same(initiator.rs, responder.s.publicKey)

  t.deepEqual(initiator.rx, responder.tx)
  t.deepEqual(initiator.tx, responder.rx)
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

  t.deepEqual(initiator.rx, responder.tx)
  t.deepEqual(initiator.tx, responder.rx)
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

  t.deepEqual(initiator.rx, responder.tx)
  t.deepEqual(initiator.tx, responder.rx)
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
    t.equals(err.toString(), 'Error: could not verify data')
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

  t.deepEqual(initiator.rx, responder.tx)
  t.deepEqual(initiator.tx, responder.rx)
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
    t.equals(err.toString(), 'Error: could not verify data')
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

  t.deepEqual(initiator.rx, responder.tx)
  t.deepEqual(initiator.tx, responder.rx)
  t.end()
})
