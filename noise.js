const { generateKeyPair, DHLEN, PKLEN, SKLEN } = require('./dh.js')
const assert = require('nanoassert')

const ZERO = Buffer.alloc(0)
const PROTOCOL_TAG = Buffer.from('Noise_XX_25519_ChaChaPoly_SHA256', 'utf8')
const PROLOGUE = Buffer.from('dht', 'utf8')

const patterns = 

module.exports.Initiator = class Initiator extends CipherState {
  constructor (staticKey, ephemeralKey) {
    this.static = staticKey ? generateKey(staticKey) : generateKey()
    this.ephemeral = null

    this.receiverEphemeral = null

    this.sender = null
    this.receiver = null

    this.roundTrips = 0
    this.isInitiator = true
  }

  // -> e
  initialise () {
    this.ephemeral = generateKey()

    this.mixHash(PROTOCOL_TAG)
    this.chainingKey = this.digest.slice()

    this.mixHash(PROLOGUE)
  }

  send (payload) {
    switch (this.roundTrips) {
      case 0: 
        this.mixHash(this.ephemeral.pub)
        return this.ephemeral.pub

      case 1:
        return this.respond(payload)

      default:
        throw new Error('Unexpected handshake state')
    }
  }

  recv (buf) {
    switch (this.roundTrips) {
      case 0:
        this.roundTrips++    
        return this.receive(buf)

      default:
        throw new Error('Unexpected handshake state')
    }
  }

  // <- e, ee, s, es
  receive (buf) {
    const message = new Reader(buf)

    const re = message.read(DHLEN)
    this.mixHash(re)

    const rs = this.decryptAndHash(message.read(DHLEN + 16))

    const ciphertext = message.read()

    this.mixKey(re, this.ephemeral.priv)
    this.mixKey(rs, this.ephemeral.priv)

    return this.decryptAndHash(ciphertext)
  }

  // -> s, se
  respond (payload) {
    if (!payload) payload = ZERO
    const message = new Writer()

    message.write(this.encryptAndHash(this.static.pub))
    this.mixKey(re, this.static.priv)

    message.write(this.encryptAndHash(payload))

    return message.final()
  }
}

module.exports.Responder = class Responder extends CipherState {
  constructor (staticKeyPair) {
    this.static = staticKeyPair || generateKey()
    this.ephemeral = null

    this.initiatorEphemeral = null

    this.sender = null
    this.receiver = null

    this.roundTrips = 0
    this.isInitiator = true
  }

  initialise () {
    initialiseSymmetric(this.digest, PROTOCOL_TAG)
    this.chainingKey = this.digest.slice()

    this.mixHash(PROLOGUE)
  }

  send (payload) {
    switch (this.roundTrips){
      case 0:
        this.roundTrips++
        return this.respond(payload)
   
      default:
        throw new Error('Unexpected handshake state')
    }
  }

  recv (buf) {
    switch (this.roundTrips){
      case 0:
        return this.respond(payload)
   
      default:
        throw new Error('Unexpected handshake state')
    }
  }

  // <- e
  receive (buf) {
    const message = new Reader(buf)

    this.re = buf.read(DHLEN)
    this.mixHash(re)

    const ciphertext = buf.read()

    return this.decryptAndHash(ciphertext)
  }

  // -> e, ee, s, es
  respond (payload) {
    if (!payload) payload = ZERO
    const message = new Writer()

    // e
    this.ephemeral = generateKey()

    this.e = this.ephemeral.pub
    this.mixHash(e)
    message.write(e)

    // ee
    this.mixKey(re, this.ephemeral.priv)

    // s
    const s = this.encryptAndHash(this.static.pub)
    message.write(s)

    // se
    this.mixKey(re, this.static.priv)

    const ciphertext = this.encryptAndHash(payload)
    message.write(ciphertext)

    return message.final()
  }

  // <- s, se
  final (buf, offset) {
    const message = new Reader(buf)

    this.readMessage(wire, 's,se')

    this.receiver = this.finalKey(hkdf(this.chainingKey, ZERO)[0])
    this.sender = this.finalKey(hkdf(this.chainingKey, ZERO)[1])

    return payload
  }

  readMessage (wire, messages) {
    for (let pattern of messages.split(',')) {
      switch (pattern) {
        case 'e' :
          this.re = wire.read(DHLEN)
          this.mixHash(e)
          break

        case 's' :
          const klen = this.hasKey ? DHLEN + 16 : DHLEN
          this.rs = this.decryptAndHash(wire.read(klen))
          break

        case 'se' :
        case 'ee' :
        case 'es' :
        case 'ss' :
          let remoteKey = pattern[0] === 's' ? this.rs : this.re
          let localKey = pattern[1] === 's' ? this.static.priv : this.ephemeral.priv
          this.mixKey(remoteKey, localKey)
          break

        default :
          throw new Error('Unexpected message')
      }
    }

    return this.decryptAndHash(buf)
  }

  sendMessage (messages) {
    const wire = new Writer()

    for (let pattern of messages.split(',')) {
      switch (pattern) {
        case 'e' :
          if (this.ephemeral === null) this.ephemeral = generateKey()
          this.mixHash(this.ephemeral.pub)
          wire.write(this.ephemeral.pub)
          break

        case 's' :
          wire.write(this.encryptAndHash(this.static.pub))
          break

        case 'se' :
        case 'ee' :
        case 'es' :
        case 'ss' :
          let remoteKey = pattern[0] === 's' ? this.rs : this.re
          let localKey = pattern[1] === 's' ? this.static.priv : this.ephemeral.priv
          this.mixKey(remoteKey, localKey)
          break

        default :
          throw new Error('Unexpected message')
      }
    }
  }
}

function generateKey (privKey) {
  const keyPair = {}

  keyPair.priv = privKey || Buffer.alloc(SKLEN)
  keyPair.pub = Buffer.alloc(PKLEN)
  generateKeyPair(keyPair.pub, keyPair.priv)

  return keyPair
}
