const test = require('tape')
const NoiseState = require('../noise.js')

test('IK', t => {
  const initiator = new NoiseState('IK', true)
  const responder = new NoiseState('IK', false)

  const rpk = new Uint8Array(responder.s.publicKey)
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
  t.equal(initiator.rs, null)

  t.same(initiator.remotePublicKey, rpk)

  t.deepEqual(initiator.rx, responder.tx)
  t.deepEqual(initiator.tx, responder.rx)
  t.end()
})

test('XX', t => {
  const initiator = new NoiseState('XX', true)
  const responder = new NoiseState('XX', false)

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  while (!initiator.handshakeComplete) {
    const message = initiator.send()
    responder.recv(message)

    if (!responder.handshakeComplete) {
      const reply = responder.send()
      initiator.recv(reply)
    }
  }

  t.deepEqual(initiator.rx, responder.tx)
  t.deepEqual(initiator.tx, responder.rx)
  t.end()
})
