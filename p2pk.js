let {
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let { lazyprop } = require('./lazy')

// input: {signature}
// output: {pubKey} OP_CHECKSIG
function p2pk (a) {
  if (
    !a.output &&
    !a.pubkey
  ) throw new TypeError('Not enough data')

  typef({
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.Buffer),

    pubkey: typef.maybe(bscript.isCanonicalPubKey),
    signature: typef.maybe(bscript.isCanonicalSignature),
    input: typef.maybe(typef.Buffer)
  }, a)

  let network = a.network || bnetworks.bitcoin
  let o = { network }
  lazyprop(o, 'output', function () {
    if (!a.pubkey) return
    return bscript.compile([
      a.pubkey,
      OPS.OP_CHECKSIG
    ])
  })
  lazyprop(o, 'pubkey', function () {
    if (!a.output) return
    return a.output.slice(0, -1)
  })
  lazyprop(o, 'signature', function () {
    if (!a.input) return
    return bscript.decompile(a.input)[0]
  })
  lazyprop(o, 'input', function () {
    if (!a.signature) return
    return bscript.compile([a.signature])
  })

  // validation
  if (a.input) {
    let chunks = bscript.decompile(a.input)

    if (
      chunks.length !== 1 || !bscript.isCanonicalSignature(chunks[0])
    ) throw new TypeError('Input is invalid')

    o.signature = chunks[0]
  }

  if (a.input && a.signature) {
    if (!a.input.equals(o.input)) throw new TypeError('Input mismatch')
  }

  if (a.output) {
    if (a.output[a.output.length - 1] !== OPS.OP_CHECKSIG) throw new TypeError('Output is invalid')
    if (!bscript.isCanonicalPubKey(o.pubkey)) throw new TypeError('Output pubkey is invalid')
  }

  if (a.pubkey && a.output) {
    if (!a.pubkey.equals(o.pubkey)) throw new TypeError('Pubkey mismatch')
  }

  return Object.assign(o, a)
}

module.exports = p2pk
