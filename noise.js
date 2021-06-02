const { Writer, Reader } = require('wire-encoder')
const assert = require('nanoassert')

const { generateKeypair, DHLEN, PKLEN, SKLEN, ALG } = require('./dh.js')
const SymmetricState = require('./state')

const HANDSHAKES = {
  XX: {
    messages: ['e', 'e,ee,s,es', 's,se']
  },
  IK: {
    responderPreshare: true,
    messages: ['e,es,s,ss', 'e,ee,se']
  }
}

module.exports = class NoiseState extends SymmetricState {
  constructor (pattern, initiator, staticKey) {
    super()

    this.static = staticKey ? generateKey(staticKey) : generateKey()
    this.ephemeral = null

    this.re = null
    this.rs = null

    this.pattern = pattern
    this.handshake = HANDSHAKES[this.pattern]
    this.messages = this.handshake.messages

    this.protocol = Buffer.from(['Noise', this.pattern, ALG, this.constructor.alg].join('_'))

    this.initiator = initiator
    this.handshakeStep = 0
    this.handshakeComplete = false

    this.rx = null
    this.tx = null
  }

  initialise (prologue, remoteStatic) {
    this.mixHash(this.protocol)
    this.chainingKey = this.digest.slice()

    this.mixHash(prologue)

    if (this.handshake.responderPreshare) {
      if (this.initiator) this.rs = remoteStatic

      const key = this.initiator ? this.rs : this.static.pub
      assert(key != null, 'Remote pubkey required')

      this.mixHash(this.initiator ? this.rs : this.static.pub)
    }

    if (this.handshake.initiatorPreshare) {
      if (!this.initiator) this.rs = remoteStatic

      const key = this.initiator ? this.static.pub : this.rs
      assert(key != null, 'Remote pubkey required')

      this.mixHash(this.initiator ? this.static.pub : this.rs)
    }
  }

  send (payload = Buffer.alloc(0)) {
    assert(!(this.handshakeStep % 2) === this.initiator, 'Unexpected handshake state')

    const pattern = this.messages[this.handshakeStep++]
    return this.sendMessage(payload, pattern)
  }

  recv (buf) {
    assert(!!(this.handshakeStep % 2) === this.initiator, 'Unexpected handshake state')

    const pattern = this.messages[this.handshakeStep++]
    return this.readMessage(buf, pattern)
  }

  final () {
    const { cipher1, cipher2 } = this.split()

    this.tx = this.initiator ? cipher1 : cipher2
    this.rx = this.initiator ? cipher2 : cipher1

    this.handshakeComplete = true
  }

  readMessage (buf, messages) {
    const wire = new Reader(buf)

    for (const pattern of messages.split(',')) {
      switch (pattern) {
        case 'e' :
          this.re = wire.read(DHLEN)
          this.mixHash(this.re)
          break

        case 's' :
          const klen = this.hasKey ? DHLEN + 16 : DHLEN
          this.rs = this.decryptAndHash(wire.read(klen))
          break

        case 'es' :
        case 'ee' :
        case 'se' :
        case 'ss' :
          const remoteKey = pattern[this.initiator ? 1 : 0] === 's' ? this.rs : this.re
          const localKey = pattern[this.initiator ? 0 : 1] === 's' ? this.static.priv : this.ephemeral.priv
          this.mixKey(remoteKey, localKey)
          break

        default :
          throw new Error('Unexpected message')
      }
    }

    const payload = this.decryptAndHash(wire.read())

    if (this.handshakeStep === this.messages.length) this.final()
    return payload
  }

  sendMessage (payload = Buffer.alloc(0), messages) {
    const wire = new Writer()

    for (const pattern of messages.split(',')) {
      switch (pattern) {
        case 'e' :
          if (this.ephemeral === null) this.ephemeral = generateKey()
          this.mixHash(this.ephemeral.pub)
          wire.write(this.ephemeral.pub)
          break

        case 's' :
          wire.write(this.encryptAndHash(this.static.pub))
          break

        case 'es' :
        case 'ee' :
        case 'se' :
        case 'ss' :
          const remoteKey = pattern[this.initiator ? 1 : 0] === 's' ? this.rs : this.re
          const localKey = pattern[this.initiator ? 0 : 1] === 's' ? this.static.priv : this.ephemeral.priv
          this.mixKey(remoteKey, localKey)
          break

        default :
          throw new Error('Unexpected message')
      }
    }

    wire.write(this.encryptAndHash(payload))

    if (this.handshakeStep === this.messages.length) this.final()
    return wire.final()
  }
}

function generateKey (privKey) {
  const keyPair = {}

  keyPair.priv = privKey || Buffer.alloc(SKLEN)
  keyPair.pub = Buffer.alloc(PKLEN)
  generateKeypair(keyPair.pub, keyPair.priv)

  return keyPair
}
