# simple-noise

## Usage
```js
const Noise = require('simple-noise')
const initiator = new Noise('IK ', true)
const responder = new Noise('IK', false)

const prologue = Buffer.alloc(0)

// preshared key
initiator.initialise(prologue, responder.s.pub)
responder.initialise(prologue)

// -> e, es, s, ss
const message = initiator.send()
responder.recv(message)

// <- e, ee, se
const reply = responder.send()
initiator.recv(reply)

console.log(initiator.handshakeComplete) // true

const msg = Buffer.from('hello, world')

const enc = initiator.rx.encrypt(msg)
console.log(responder.tx.decrypt(enc)) // hello, world
```

## API

### `const peer = new Noise(pattern, initiator, staticKeypair)`

Create a new handshake state for a given pattern. Initiator should be either `true` or `false` depending on the role. A preexisting keypair may be passed as `staticKeypair`

### `peer.initialise(prologue, remoteStatic)`

Initialise the handshake state with a prologue and any preshared keys.

### `const buf = send([payload])`

Send the next message in the handshake, add an optional payload buffer to be included in the message, payload is a zero length buffer by default.

### `const payload = peer.recv(buf)`

Receive a handshake message from the peer and return the encrypted payload.

### `peer.handshakeComplete`

`true` or `false`. Indicates whether `rx` and `tx` have been created yet.

### `const ciphertext = peer.rx.encrypt(plaintext, [ad])`

Encrypt a message to the remote peer with an optional authenticated data passed in as `ad`.

### `const plaintext = peer.tx.decrypt(ciphertext, [ad])`

Decrypt a ciphertext from the remote peer. Note `initiator.rx` is decrypted by `responder.tx` and vice versa. If the message was encrypted with authenticated data, this must be passed in as `ad` otherwise decryption shall fail
