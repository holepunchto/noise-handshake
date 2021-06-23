const ref = require('noise-protocol')
const Noise = require('../noise')
const test = require('tape')

test('XX handshake with reference impl', t => {
  const initiator = new Noise('XX', true)
  const responder = new Noise('XX', false)

  // console.log(initiator)
  const sClient = {
    secretKey: initiator.s.priv,
    publicKey: initiator.s.pub
  }

  const sServer = {
    secretKey: responder.s.priv,
    publicKey: responder.s.pub
  }

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  let message = initiator.send()
  responder.recv(message)

  message = responder.send()
  initiator.recv(message)

  message = initiator.send()
  responder.recv(message)

  const eClient = {
    secretKey: initiator.e.priv,
    publicKey: initiator.e.pub
  }

  const eServer = {
    secretKey: responder.e.priv,
    publicKey: responder.e.pub
  }

  const client = ref.initialize('XX', true, Buffer.alloc(0), sClient, eClient)
  const server = ref.initialize('XX', false, Buffer.alloc(0), sServer, eServer)

  const clientTx = Buffer.alloc(512)
  const serverRx = Buffer.alloc(512)

  const serverTx = Buffer.alloc(512)
  const clientRx = Buffer.alloc(512)

  // ->
  // console.log('ref digest', responder.protocol.toString())
  // console.log('ref digest', server.symmetricState.subarray(64, 128).toString('hex'))
  ref.writeMessage(client, Buffer.alloc(0), clientTx)
  ref.readMessage(server, clientTx.subarray(0, ref.writeMessage.bytes), serverRx)
  // <-

  ref.writeMessage(server, Buffer.alloc(0), serverTx)
  // console.log(serverTx.subarray(0, ref.writeMessage.bytes))

  ref.readMessage(client, serverTx.subarray(0, ref.writeMessage.bytes), clientRx)

  // ->
  const splitClient = ref.writeMessage(client, Buffer.alloc(0), clientTx)
  const splitServer = ref.readMessage(server, clientTx.subarray(0, ref.writeMessage.bytes), serverRx)

  t.deepEqual(initiator.rx.key, splitClient.rx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitClient.tx.subarray(0, 32))
  t.deepEqual(initiator.rx.key, splitServer.tx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitServer.rx.subarray(0, 32))
  t.end()  
})

test('IK handshake with reference impl', t => {
  const initiator = new Noise('IK', true)
  const responder = new Noise('IK', false)

  initiator.initialise(Buffer.alloc(0), responder.s.pub)
  responder.initialise(Buffer.alloc(0))

  // console.log(initiator)
  const sClient = {
    secretKey: initiator.s.priv,
    publicKey: initiator.s.pub
  }

  const sServer = {
    secretKey: responder.s.priv,
    publicKey: responder.s.pub
  }

  let reply
  i = 0
  while (!initiator.handshakeComplete) {
    const message = initiator.send()
    responder.recv(message)

    if (!responder.handshakeComplete) {
      const reply = responder.send()
      initiator.recv(reply)
    }
  }

  const eClient = {
    secretKey: initiator.e.priv,
    publicKey: initiator.e.pub
  }

  const eServer = {
    secretKey: responder.e.priv,
    publicKey: responder.e.pub
  }

  const client = ref.initialize('IK', true, Buffer.alloc(0), sClient, eClient, sServer.publicKey)
  const server = ref.initialize('IK', false, Buffer.alloc(0), sServer, eServer)

  const clientTx = Buffer.alloc(512)
  const serverRx = Buffer.alloc(512)

  const serverTx = Buffer.alloc(512)
  const clientRx = Buffer.alloc(512)

  // ->
  // console.log('ref digest', responder.protocol.toString())
  // console.log('ref digest', server.symmetricState.subarray(64, 128).toString('hex'))
  ref.writeMessage(client, Buffer.alloc(0), clientTx)
  ref.readMessage(server, clientTx.subarray(0, ref.writeMessage.bytes), serverRx)
  // <-

  const splitClient = ref.writeMessage(server, Buffer.alloc(0), serverTx)
  // console.log(serverTx.subarray(0, ref.writeMessage.bytes))

  const splitServer = ref.readMessage(client, serverTx.subarray(0, ref.writeMessage.bytes), clientRx)

  // // ->
  // const splitClient = ref.writeMessage(client, Buffer.alloc(0), clientTx)
  // const splitServer = ref.readMessage(server, clientTx.subarray(0, ref.writeMessage.bytes), serverRx)

  t.deepEqual(initiator.rx.key, splitClient.rx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitClient.tx.subarray(0, 32))
  t.deepEqual(initiator.rx.key, splitServer.tx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitServer.rx.subarray(0, 32))
  t.end()  
})

test('handshake with reference impl', t => {
  const initiator = new Noise('IK', true)
  const responder = new Noise('IK', false)

  const sServer = {
    secretKey: responder.s.priv,
    publicKey: responder.s.pub
  }

  initiator.initialise(Buffer.alloc(0), responder.s.pub)

  const server = ref.initialize('IK', false, Buffer.alloc(0), sServer)
  const serverRx = Buffer.alloc(512)
  const serverTx = Buffer.alloc(512)

  let splitClient

  i = 0
  while (!initiator.handshakeComplete) {
    const message = initiator.send()
    ref.readMessage(server, message, serverRx)

    if (!splitClient) {
      splitClient = ref.writeMessage(server, Buffer.alloc(0), serverTx)
      initiator.recv(serverTx.subarray(0, ref.writeMessage.bytes))
    }
  }

  // ->
  // console.log('ref digest', responder.protocol.toString())
  // // ->
  // const splitClient = ref.writeMessage(client, Buffer.alloc(0), clientTx)
  // const splitServer = ref.readMessage(server, clientTx.subarray(0, ref.writeMessage.bytes), serverRx)

  t.deepEqual(initiator.rx.key, splitClient.rx.subarray(0, 32))
  t.deepEqual(initiator.tx.key, splitClient.tx.subarray(0, 32))
  t.end()  
})
