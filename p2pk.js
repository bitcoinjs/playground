let {
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let { lazyprop, lazyvalue } = require('./lazy')

// input: {signature}
// output: {pubKey} OP_CHECKSIG
function p2pk (a, opts) {
  if (
    !a.output &&
    !a.pubkey
  ) throw new TypeError('Not enough data')
  opts = opts || { validate: true }

  typef({
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.Buffer),

    pubkey: typef.maybe(bscript.isCanonicalPubKey),
    signature: typef.maybe(bscript.isCanonicalSignature),
    input: typef.maybe(typef.Buffer)
  }, a)

  let _chunks = lazyvalue(function () { return bscript.decompile(a.input) })

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
    return a.output.slice(1, -1)
  })
  lazyprop(o, 'signature', function () {
    if (!a.input) return
    return _chunks()[0]
  })
  lazyprop(o, 'input', function () {
    if (!a.signature) return
    return bscript.compile([a.signature])
  })
  lazyprop(o, 'witness', function () {
    if (!o.input) return
    return []
  })

  // extended validation
  if (opts.validate) {
    if (a.pubkey && a.output) {
      if (!a.pubkey.equals(o.pubkey)) throw new TypeError('Pubkey mismatch')
    }

    if (a.output) {
      if (a.output[a.output.length - 1] !== OPS.OP_CHECKSIG) throw new TypeError('Output is invalid')
      if (!bscript.isCanonicalPubKey(o.pubkey)) throw new TypeError('Output pubkey is invalid')
    }

    if (a.signature) {
      if (a.input && !a.input.equals(o.input)) throw new TypeError('Input mismatch')
    }

    if (a.input) {
      if (_chunks().length !== 1) throw new TypeError('Input is invalid')
      if (!bscript.isCanonicalSignature(_chunks()[0])) throw new TypeError('Input has invalid signature')
    }
  }

  return Object.assign(o, a)
}

module.exports = p2pk
