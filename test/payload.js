const Noise = require('../noise')
const test = require('tape')

test('IK with payload', t => {
  const initiator = new Noise('IK', true)
  const responder = new Noise('IK', false)

  initiator.initialise(Buffer.alloc(0), responder.s.pub)
  responder.initialise(Buffer.alloc(0))

  const payload1 = Buffer.alloc(2, 1)
  const payload2 = Buffer.alloc(3, 2)
  const payload3 = Buffer.alloc(4, 3)

  let message = initiator.send(payload1)
  t.deepEqual(Buffer.from(responder.recv(message)), payload1)

  message = responder.send(payload2)
  t.deepEqual(initiator.recv(message), payload2)

  t.deepEqual(initiator.rx.key, responder.tx.key)
  t.deepEqual(initiator.tx.key, responder.rx.key)
  t.end()  
})

test('XX with payload', t => {
  const initiator = new Noise('XX', true)
  const responder = new Noise('XX', false)

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  const payload1 = Buffer.alloc(2, 1)
  const payload2 = Buffer.alloc(3, 2)
  const payload3 = Buffer.alloc(4, 3)

  let message = initiator.send(payload1)
  t.deepEqual(Buffer.from(responder.recv(message)), payload1)

  message = responder.send(payload2)
  t.deepEqual(initiator.recv(message), payload2)

  message = initiator.send(payload3)
  t.deepEqual(responder.recv(message), payload3)

  t.deepEqual(initiator.rx.key, responder.tx.key)
  t.deepEqual(initiator.tx.key, responder.rx.key)
  t.end()  
})
