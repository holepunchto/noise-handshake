const test = require('tape')
const NoiseState = require('../noise.js')

test('IK', t => {
  const initiator = new NoiseState('IK', true)
  const responder = new NoiseState('IK', false)

  initiator.initialise(Buffer.alloc(0), responder.s.publicKey)
  responder.initialise(Buffer.alloc(0))

  while (!initiator.handshakeComplete) {
    const message = initiator.send()
    responder.recv(message)

    if (!responder.handshakeComplete) {
      const reply = responder.send()
      initiator.recv(reply)
    }
  }

  t.deepEqual(initiator.rx.key, responder.tx.key)
  t.deepEqual(initiator.tx.key, responder.rx.key)
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

  t.deepEqual(initiator.rx.key, responder.tx.key)
  t.deepEqual(initiator.tx.key, responder.rx.key)
  t.end()
})
