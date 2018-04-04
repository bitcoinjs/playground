let {
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let OP_INT_BASE = OPS.OP_RESERVED // OP_1 - 1
let { lazyprop } = require('./lazy')

function stacksEqual (a, b) {
  if (a.length !== b.length) return false

  return a.every(function (x, i) {
    return x.equals(b[i])
  })
}

// input: OP_0 [signatures ...]
// output: m [pubKeys ...] n OP_CHECKMULTISIG
function p2ms (a, opts) {
  if (
    !a.output &&
    !(a.pubkeys && a.m !== undefined)
  ) throw new TypeError('Not enough data')
  opts = opts || { validate: true }

  function isAcceptableSignature (x) {
    return bscript.isCanonicalSignature(x) || (a.allowIncomplete && x === OPS.OP_0)
  }

  typef({
    network: typef.maybe(typef.Object),
    m: typef.maybe(typef.Number),
    n: typef.maybe(typef.Number),
    output: typef.maybe(typef.Buffer),
    pubkeys: typef.maybe(typef.arrayOf(bscript.isCanonicalPubKey)),

    signatures: typef.maybe(typef.arrayOf(isAcceptableSignature)),
    input: typef.maybe(typef.Buffer),
    allowIncomplete: typef.maybe(typef.Boolean)
  }, a)

  let network = a.network || bnetworks.bitcoin
  let o = { network }

  let chunks
  let decoded = false
  function decode (output) {
    if (decoded) return
    decoded = true
    chunks = bscript.decompile(output)
    let om = chunks[0] - OP_INT_BASE
    let on = chunks[chunks.length - 2] - OP_INT_BASE
    o.m = om
    o.n = on
    o.pubkeys = chunks.slice(1, -2)
  }

  lazyprop(o, 'output', function () {
    if (!a.m) return
    if (!o.n) return
    if (!a.pubkeys) return
    return bscript.compile([].concat(
      OP_INT_BASE + a.m,
      a.pubkeys,
      OP_INT_BASE + o.n,
      OPS.OP_CHECKMULTISIG
    ))
  })
  lazyprop(o, 'm', function () {
    if (!o.output) return
    decode(o.output)
    return o.m
  })
  lazyprop(o, 'n', function () {
    if (!o.pubkeys) return
    return o.pubkeys.length
  })
  lazyprop(o, 'pubkeys', function () {
    if (!a.output) return
    decode(a.output)
    return o.pubkeys
  })
  lazyprop(o, 'signatures', function () {
    if (!a.input) return
    return bscript.decompile(a.input).slice(1)
  })
  lazyprop(o, 'input', function () {
    if (!a.signatures) return
    return bscript.compile([OPS.OP_0].concat(a.signatures))
  })

  // extended validation
  if (opts.validate) {
    if (a.input) {
      if (a.input[0] !== OPS.OP_0 ||
        o.signatures.length === 0 ||
        !o.signatures.every(isAcceptableSignature)) throw new TypeError('Input is invalid')

      if (a.signatures && !stacksEqual(a.signatures.equals(o.signatures))) throw new TypeError('Signature mismatch')
    }

    if (a.pubkeys) {
      if (a.n !== undefined && a.n !== a.pubkeys.length) throw new TypeError('n Pubkeys mismatch')
      o.n = a.pubkeys.length

      if (o.n < o.m) throw new TypeError('Not enough pubkeys provided')
    }

    if (a.signatures) {
      if (a.signatures.length < o.m) throw new TypeError('Not enough signatures provided')
    }

    if (a.output) {
      decode(a.output)
      if (chunks[chunks.length - 1] !== OPS.OP_CHECKMULTISIG) throw new TypeError('Output is invalid')
      if (!typef.Number(chunks[0])) throw new TypeError('Output is invalid')
      if (!typef.Number(chunks[chunks.length - 2])) throw new TypeError('Output is invalid')

      if (
        o.m <= 0 ||
        o.n > 16 ||
        o.m > o.n ||
        o.n !== chunks.length - 3) throw new TypeError('Output is invalid')
      if (!o.pubkeys.every(x => bscript.isCanonicalPubKey(x))) throw new TypeError('Output is invalid')

      if (a.m !== undefined && a.m !== o.m) throw new TypeError('m mismatch')
      if (a.n !== undefined && a.n !== o.n) throw new TypeError('n mismatch')
      if (a.pubkeys && !stacksEqual(a.pubkeys, o.pubkeys)) throw new TypeError('Pubkeys mismatch')
    }
  }

  return Object.assign(o, a)
}

module.exports = p2ms
