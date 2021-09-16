const Noise = require('../noise')
const test = require('tape')

test('IK with payload', t => {
  const initiator = new Noise('IK', true)
  const responder = new Noise('IK', false)

  initiator.initialise(new Uint8Array(0), responder.s.publicKey)
  responder.initialise(new Uint8Array(0))

  const payload1 = new Uint8Array(2).fill(1)
  const payload2 = new Uint8Array(3).fill(2)

  let message = initiator.send(payload1)
  t.deepEqual(responder.recv(message), payload1)

  message = responder.send(payload2)
  t.deepEqual(initiator.recv(message), payload2)

  t.deepEqual(initiator.rx, responder.tx)
  t.deepEqual(initiator.tx, responder.rx)
  t.end()
})

test('XX with payload', t => {
  const initiator = new Noise('XX', true)
  const responder = new Noise('XX', false)

  initiator.initialise(new Uint8Array(0))
  responder.initialise(new Uint8Array(0))

  const payload1 = new Uint8Array(2).fill(1)
  const payload2 = new Uint8Array(3).fill(2)
  const payload3 = new Uint8Array(4).fill(3)

  let message = initiator.send(payload1)
  t.deepEqual(responder.recv(message), payload1)

  message = responder.send(payload2)
  t.deepEqual(initiator.recv(message), payload2)

  message = initiator.send(payload3)
  t.deepEqual(responder.recv(message), payload3)

  t.deepEqual(initiator.rx, responder.tx)
  t.deepEqual(initiator.tx, responder.rx)
  t.end()
})
