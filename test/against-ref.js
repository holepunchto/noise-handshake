const test = require('tape')
const ref = require('noise-protocol')
const sodium = require('sodium-universal')
const { getHandshakeHash } = require('noise-protocol/symmetric-state')
const Noise = require('../noise')
const { generateKeyPair } = require('../dh')

test('XX handshake against reference impl', t => {
  const initiator = new Noise('XX', true)
  const responder = new Noise('XX', false)

  const handshakeHash = Buffer.alloc(64)
  const handshakeHashes = []
  const refHandshakeHashes = []

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  handshakeHashes.push(initiator.getHandshakeHash())
  handshakeHashes.push(responder.getHandshakeHash())

  let message = initiator.send()
  responder.recv(message)

  handshakeHashes.push(initiator.getHandshakeHash())
  handshakeHashes.push(responder.getHandshakeHash())

  message = responder.send()
  initiator.recv(message)

  handshakeHashes.push(initiator.getHandshakeHash())
  handshakeHashes.push(responder.getHandshakeHash())

  message = initiator.send()
  responder.recv(message)

  handshakeHashes.push(initiator.getHandshakeHash())
  handshakeHashes.push(responder.getHandshakeHash())

  const client = ref.initialize('XX', true, Buffer.alloc(0), initiator.s, initiator.e)
  const server = ref.initialize('XX', false, Buffer.alloc(0), responder.s, responder.e)

  storeHash(client, refHandshakeHashes)
  storeHash(server, refHandshakeHashes)

  const clientTx = Buffer.alloc(512)
  const serverRx = Buffer.alloc(512)

  const serverTx = Buffer.alloc(512)
  const clientRx = Buffer.alloc(512)

  // ->
  ref.writeMessage(client, Buffer.alloc(0), clientTx)
  ref.readMessage(server, clientTx.subarray(0, ref.writeMessage.bytes), serverRx)

  storeHash(client, refHandshakeHashes)
  storeHash(server, refHandshakeHashes)

  // <-
  ref.writeMessage(server, Buffer.alloc(0), serverTx)
  ref.readMessage(client, serverTx.subarray(0, ref.writeMessage.bytes), clientRx)

  storeHash(client, refHandshakeHashes)
  storeHash(server, refHandshakeHashes)

  // ->
  const splitClient = ref.writeMessage(client, Buffer.alloc(0), clientTx)
  const splitServer = ref.readMessage(server, clientTx.subarray(0, ref.writeMessage.bytes), serverRx)

  storeHash(client, refHandshakeHashes)
  storeHash(server, refHandshakeHashes)

  t.deepEqual(initiator.rx.key, splitClient.rx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitClient.tx.subarray(0, 32))
  t.deepEqual(initiator.rx.key, splitServer.tx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitServer.rx.subarray(0, 32))

  while (handshakeHashes.length && refHandshakeHashes.length) {
    t.same(handshakeHashes.shift(), refHandshakeHashes.shift())
  }

  t.end()

  function storeHash (state, arr) {
    getHandshakeHash(state.symmetricState, handshakeHash)
    arr.push(Buffer.from(handshakeHash))
  }
})

test('IK handshake against reference impl', t => {
  const initiator = new Noise('IK', true)
  const responder = new Noise('IK', false)

  const handshakeHash = Buffer.alloc(64)
  const handshakeHashes = []
  const refHandshakeHashes = []

  initiator.initialise(Buffer.alloc(0), responder.s.publicKey)
  responder.initialise(Buffer.alloc(0))

  handshakeHashes.push(initiator.getHandshakeHash())
  handshakeHashes.push(responder.getHandshakeHash())

  while (!initiator.handshakeComplete) {
    const message = initiator.send()
    responder.recv(message)

    handshakeHashes.push(initiator.getHandshakeHash())
    handshakeHashes.push(responder.getHandshakeHash())

    if (!responder.handshakeComplete) {
      const reply = responder.send()
      initiator.recv(reply)

      handshakeHashes.push(initiator.getHandshakeHash())
      handshakeHashes.push(responder.getHandshakeHash())
    }
  }

  const client = ref.initialize('IK', true, Buffer.alloc(0), initiator.s, initiator.e, responder.s.publicKey)
  const server = ref.initialize('IK', false, Buffer.alloc(0), responder.s, responder.e)

  const clientTx = Buffer.alloc(512)
  const serverRx = Buffer.alloc(512)

  const serverTx = Buffer.alloc(512)
  const clientRx = Buffer.alloc(512)

  storeHash(client, refHandshakeHashes)
  storeHash(server, refHandshakeHashes)

  // ->
  ref.writeMessage(client, Buffer.alloc(0), clientTx)
  ref.readMessage(server, clientTx.subarray(0, ref.writeMessage.bytes), serverRx)
  // <-

  storeHash(client, refHandshakeHashes)
  storeHash(server, refHandshakeHashes)

  // ->
  const splitClient = ref.writeMessage(server, Buffer.alloc(0), serverTx)
  const splitServer = ref.readMessage(client, serverTx.subarray(0, ref.writeMessage.bytes), clientRx)

  storeHash(client, refHandshakeHashes)
  storeHash(server, refHandshakeHashes)

  t.deepEqual(initiator.rx.key, splitClient.rx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitClient.tx.subarray(0, 32))
  t.deepEqual(initiator.rx.key, splitServer.tx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitServer.rx.subarray(0, 32))

  while (handshakeHashes.length && refHandshakeHashes.length) {
    t.same(handshakeHashes.shift(), refHandshakeHashes.shift())
  }

  t.end()

  function storeHash (state, arr) {
    getHandshakeHash(state.symmetricState, handshakeHash)
    arr.push(Buffer.from(handshakeHash))
  }
})

test('IK handshake with reference server', t => {
  const initiator = new Noise('IK', true)
  const keypair = generateKeyPair()

  initiator.initialise(Buffer.alloc(0), keypair.publicKey)

  const server = ref.initialize('IK', false, Buffer.alloc(0), keypair)
  const serverRx = Buffer.alloc(512)
  const serverTx = Buffer.alloc(512)

  let splitClient

  while (!initiator.handshakeComplete) {
    let payload = randomBytes(128)

    const message = initiator.send(payload)
    splitClient = ref.readMessage(server, message, serverRx)

    t.same(payload, serverRx.subarray(0, ref.readMessage.bytes))
    t.same(initiator.getHandshakeHash(), getHash(server))

    if (!splitClient) {
      payload = randomBytes(128)

      splitClient = ref.writeMessage(server, payload, serverTx)
      const check = initiator.recv(serverTx.subarray(0, ref.writeMessage.bytes))

      t.same(payload, check)
      t.same(initiator.getHandshakeHash(), getHash(server))
    }
  }

  t.deepEqual(initiator.rx.key, splitClient.rx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitClient.tx.subarray(0, 32))

  t.end()

  function getHash (state) {
    const ret = Buffer.alloc(64)
    getHandshakeHash(state.symmetricState, ret)
    return ret
  }
})

test('IK handshake with reference client', t => {
  const responder = new Noise('IK', false)
  const keypair = generateKeyPair()

  const client = ref.initialize('IK', true, Buffer.alloc(0), keypair, null, responder.s.publicKey)
  const clientRx = Buffer.alloc(512)
  const clientTx = Buffer.alloc(512)

  responder.initialise(Buffer.alloc(0))

  let splitServer

  while (!responder.handshakeComplete) {
    let payload = randomBytes(128)

    splitServer = ref.writeMessage(client, payload, clientTx)
    const check = responder.recv(clientTx.subarray(0, ref.writeMessage.bytes))

    t.same(payload, check)
    t.same(responder.getHandshakeHash(), getHash(client))

    if (!splitServer) {
      payload = randomBytes(128)

      const message = responder.send(payload)
      splitServer = ref.readMessage(client, message, clientRx)

      t.same(payload, clientRx.subarray(0, ref.readMessage.bytes))
      t.same(responder.getHandshakeHash(), getHash(client))
    }
  }

  t.deepEqual(responder.rx.key, splitServer.rx.subarray(0, 32))
  t.deepEqual(responder.tx.key, splitServer.tx.subarray(0, 32))

  t.end()

  function getHash (state) {
    const ret = Buffer.alloc(64)
    getHandshakeHash(state.symmetricState, ret)
    return ret
  }
})

test('XX handshake with reference server', t => {
  const initiator = new Noise('XX', true)
  const keypair = generateKeyPair()

  initiator.initialise(Buffer.alloc(0))

  const server = ref.initialize('XX', false, Buffer.alloc(0), keypair)
  const serverRx = Buffer.alloc(512)
  const serverTx = Buffer.alloc(512)

  let splitClient

  while (!initiator.handshakeComplete) {
    let payload = randomBytes(128)

    const message = initiator.send(payload)
    splitClient = ref.readMessage(server, message, serverRx)

    t.same(payload, serverRx.subarray(0, ref.readMessage.bytes))
    t.same(initiator.getHandshakeHash(), getHash(server))

    if (!splitClient) {
      payload = randomBytes(128)

      splitClient = ref.writeMessage(server, payload, serverTx)
      const check = initiator.recv(serverTx.subarray(0, ref.writeMessage.bytes))

      t.same(payload, check)
      t.same(initiator.getHandshakeHash(), getHash(server))
    }
  }

  t.deepEqual(initiator.rx.key, splitClient.tx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitClient.rx.subarray(0, 32))

  t.end()

  function getHash (state) {
    const ret = Buffer.alloc(64)
    getHandshakeHash(state.symmetricState, ret)
    return ret
  }
})

test('XX handshake with reference client', t => {
  const responder = new Noise('XX', false)
  const keypair = generateKeyPair()

  responder.initialise(Buffer.alloc(0))

  const client = ref.initialize('XX', true, Buffer.alloc(0), keypair)
  const clientTx = Buffer.alloc(512)
  const clientRx = Buffer.alloc(512)

  let splitServer

  while (!responder.handshakeComplete) {
    let payload = randomBytes(128)

    splitServer = ref.writeMessage(client, payload, clientTx)
    const check = responder.recv(clientTx.subarray(0, ref.writeMessage.bytes))

    t.same(payload, check)
    t.same(responder.getHandshakeHash(), getHash(client))

    if (!splitServer) {
      payload = randomBytes(128)

      const message = responder.send(payload)
      splitServer = ref.readMessage(client, message, clientRx)

      t.same(payload, clientRx.subarray(0, ref.readMessage.bytes))
      t.same(responder.getHandshakeHash(), getHash(client))
    }
  }

  t.deepEqual(responder.rx.key, splitServer.tx.subarray(0, 32))
  t.deepEqual(responder.tx.key, splitServer.rx.subarray(0, 32))

  t.end()

  function getHash (state) {
    const ret = Buffer.alloc(64)
    getHandshakeHash(state.symmetricState, ret)
    return ret
  }
})

test('Bugfix: prologue >64 bytes', t => {
  const responder = new Noise('XX', false)
  const keypair = generateKeyPair()

  const prologue = Buffer.alloc(65, 1)

  responder.initialise(prologue)

  const client = ref.initialize('XX', true, prologue, keypair)
  const clientTx = Buffer.alloc(512)
  const clientRx = Buffer.alloc(512)

  let splitServer

  let payload = randomBytes(128)

  splitServer = ref.writeMessage(client, payload, clientTx)
  let check = responder.recv(clientTx.subarray(0, ref.writeMessage.bytes))

  t.same(payload, check)
  t.same(responder.getHandshakeHash(), getHash(client))

  payload = randomBytes(128)

  const message = responder.send(payload)
  splitServer = ref.readMessage(client, message, clientRx)

  t.same(payload, clientRx.subarray(0, ref.readMessage.bytes))
  t.same(responder.getHandshakeHash(), getHash(client))

  payload = randomBytes(128)

  splitServer = ref.writeMessage(client, payload, clientTx)
  check = responder.recv(clientTx.subarray(0, ref.writeMessage.bytes))

  t.same(payload, check)
  t.same(responder.handshakeHash, getHash(client))

  t.deepEqual(responder.rx, splitServer.tx.subarray(0, 32))
  t.deepEqual(responder.tx, splitServer.rx.subarray(0, 32))

  t.end()

  function getHash (state) {
    const ret = Buffer.alloc(64)
    getHandshakeHash(state.symmetricState, ret)
    return ret
  }
})

function randomBytes (n) {
  const bytes = Buffer.alloc(Math.ceil(Math.random() * n))
  sodium.randombytes_buf(bytes)
  return bytes
}
