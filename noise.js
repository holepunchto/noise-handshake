const { Writer, Reader } = require('wire-encoder')
const assert = require('nanoassert')

const dh = require('./dh.js')
const { generateKeypair, DHLEN } = dh
const SymmetricState = require('./symmetric-state')

const INITIATOR = Symbol('initiator')
const RESPONDER = Symbol('responder')

const PRESHARE_IS = Symbol('initiator static key preshared')
const PRESHARE_RS = Symbol('responder static key preshared')

const TOK_S = Symbol('s')
const TOK_E = Symbol('e')

const TOK_ES = Symbol('es')
const TOK_SE = Symbol('se')
const TOK_EE = Symbol('ee')
const TOK_SS = Symbol('ss')

const HANDSHAKES = Object.freeze({
  XX: [
    [TOK_E],
    [TOK_E, TOK_EE, TOK_S, TOK_ES],
    [TOK_S, TOK_SE]
  ],
  IK: [
    PRESHARE_RS,
    [TOK_E, TOK_ES, TOK_S, TOK_SS],
    [TOK_E, TOK_EE, TOK_SE]
  ]
})

module.exports = class NoiseState extends SymmetricState {
  constructor (pattern, initiator, staticKeypair) {
    super()

    this.s = staticKeypair ? staticKeypair : generateKeypair()
    this.e = null

    this.re = null
    this.rs = null

    this.pattern = pattern
    this.handshake = HANDSHAKES[this.pattern].slice()

    this.protocol = Buffer.from([
      'Noise',
      this.pattern,
      dh.ALG,
      this.constructor.alg
    ].join('_'))

    this.initiator = initiator
    this.handshakeComplete = false

    this.rx = null
    this.tx = null
  }

  initialise (prologue, remoteStatic) {
    if (prologue.byteLength <= 64) this.digest.set(this.protocol)
    else this.mixHash(this.protocol)

    this.chainingKey = Buffer.from(this.digest)

    this.mixHash(prologue)

    while (!Array.isArray(this.handshake[0])) {
      const message = this.handshake.shift()

      // handshake steps should be as arrays, only
      // preshare tokens are provided otherwise
      assert(message === PRESHARE_RS || message === PRESHARE_IS,
        'Unexpected pattern')

      const takeRemoteKey = this.initiator
        ? message === PRESHARE_RS
        : message === PRESHARE_IS

      if (takeRemoteKey) this.rs = remoteStatic

      const key = takeRemoteKey ? this.rs : this.s.pub
      assert(key != null, 'Remote pubkey required')

      this.mixHash(key)
    }
  }

  final () {
    const { cipher1, cipher2 } = this.split()

    this.tx = this.initiator ? cipher1 : cipher2
    this.rx = this.initiator ? cipher2 : cipher1

    this.handshakeComplete = true
  }

  recv (buf) {
    const wire = new Reader(buf)

    for (const pattern of this.handshake.shift()) {
      switch (pattern) {
        case TOK_E :
          this.re = wire.read(DHLEN)
          this.mixHash(this.re)
          break

        case TOK_S :
          const klen = this.hasKey ? DHLEN + 16 : DHLEN
          this.rs = this.decryptAndHash(wire.read(klen))
          break

        case TOK_EE :
        case TOK_ES :
        case TOK_SE :
        case TOK_SS :
          const useStatic = keyPattern(pattern, this.initiator)

          const localKey = useStatic.local ? this.s.priv : this.e.priv
          const remoteKey = useStatic.remote ? this.rs : this.re

          this.mixKey(remoteKey, localKey)
          break

        default :
          throw new Error('Unexpected message')
      }
    }

    const payload = this.decryptAndHash(wire.read())

    if (!this.handshake.length) this.final()
    return payload
  }

  send (payload = Buffer.alloc(0)) {
    const wire = new Writer()

    for (const pattern of this.handshake.shift()) {
      switch (pattern) {
        case TOK_E :
          if (this.e === null) this.e = generateKeypair()
          this.mixHash(this.e.pub)
          wire.write(this.e.pub)
          break

        case TOK_S :
          wire.write(this.encryptAndHash(this.s.pub))
          break

        case TOK_ES :
        case TOK_SE :
        case TOK_EE :
        case TOK_SS :
          const useStatic = keyPattern(pattern, this.initiator)

          const localKey = useStatic.local ? this.s.priv : this.e.priv
          const remoteKey = useStatic.remote ? this.rs : this.re

          this.mixKey(remoteKey, localKey)
          break

        default :
          throw new Error('Unexpected message')
      }
    }

    wire.write(this.encryptAndHash(payload))

    if (!this.handshake.length) this.final()
    return wire.final()
  }
}

function keyPattern (pattern, initiator) {
  let ret = {
    local: false,
    remote: false
  }

  switch (pattern) {
    case TOK_EE:
      return ret

    case TOK_ES:
      ret.local ^= !initiator
      ret.remote ^= initiator
      return ret

    case TOK_SE:
      ret.local ^= initiator
      ret.remote ^= !initiator
      return ret

    case TOK_SS:
      ret.local ^= 1
      ret.remote ^= 1
      return ret
  }
}
