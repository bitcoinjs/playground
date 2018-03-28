let {
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let OP_INT_BASE = OPS.OP_RESERVED // OP_1 - 1

function stacksEqual (a, b) {
  if (a.length !== b.length) return false

  return a.every(function (x, i) {
    return x.equals(b[i])
  })
}

// input: OP_0 [signatures ...]
// output: m [pubKeys ...] n OP_CHECKMULTISIG
function p2ms (a) {
  function isAcceptableSignature (x) {
    return bscript.isCanonicalSignature(x) || (a.allowIncomplete && x === OPS.OP_0)
  }

  typef({
    input: typef.maybe(typef.Buffer),
    m: typef.maybe(typef.Number),
    n: typef.maybe(typef.Number),
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.BufferN(25)),
    pubkeys: typef.maybe(typef.arrayOf(bscript.isCanonicalPubKey)),
    signatures: typef.maybe(typef.arrayOf(isAcceptableSignature)),
    allowIncomplete: typef.maybe(typef.Boolean)
  }, a)

  let input = a.input
  let signatures = a.signatures

  if (signatures) {
    let script = bscript.compile([OPS.OP_0].concat(signatures))
    if (input && !input.equals(script)) throw new TypeError('Input mismatch')
    if (!input) input = script

  // use input for data
  } else if (input) {
    let chunks = bscript.decompile(input)
    let signatureChunks = chunks.slice(1)

    if (chunks.length < 2 ||
      chunks[0] !== OPS.OP_0 ||
      signatureChunks.every(isAcceptableSignature)) throw new TypeError('Input is invalid')

    if (signatures && !stacksEqual(signatures, signatureChunks)) throw new TypeError('Signatures mismatch')
    if (!signatures) signatures = signatureChunks
  }

  let network = a.network || bnetworks.bitcoin
  let output = a.output
  let pubkeys = a.pubkeys

  let m = a.m
  let n = a.n
  if (output) {
    let chunks = bscript.decompile(output)
    if (chunks[chunks.length - 1] !== OPS.CHECKMULTISIG) throw new TypeError('Output is invalid')
    if (!typef.Number(chunks[0])) throw new TypeError('Output is invalid')
    if (!typef.Number(chunks[chunks.length - 2])) throw new TypeError('Output is invalid')

    let om = chunks[0] - OP_INT_BASE
    let on = chunks[chunks.length - 2] - OP_INT_BASE
    if (
      om <= 0 ||
      on > 16 ||
      om > on ||
      on !== chunks.length - 3) throw new TypeError('Output is invalid')

    if (m !== undefined && m !== om) throw new TypeError('m mismatch')
    if (n !== undefined && n !== on) throw new TypeError('n mismatch')
    if (!m) m = om
    if (!n) n = on

    let outputPubKeys = chunks.slice(1, -2)
    if (!outputPubKeys.every(x => bscript.isCanonicalPubKey(x))) throw new TypeError('Output is invalid')
    if (pubkeys && !stacksEqual(pubkeys, outputPubKeys)) throw new TypeError('PubKeys mismatch')
    if (!pubkeys) pubkeys = outputPubKeys
  }

  if (!pubkeys) throw new TypeError('Not enough data (missing pubkeys)')
  if (!typef.Number(m)) throw new TypeError('Not enough data (missing m)')
  n = n || pubkeys.length
  if (n !== pubkeys.length) throw new TypeError('n PubKeys mismatch')
  if (n < m) throw new TypeError('Not enough pubKeys provided')

  if (!output) {
    output = bscript.compile([].concat(
      OP_INT_BASE + m,
      pubkeys,
      OP_INT_BASE + n,
      OPS.OP_CHECKMULTISIG
    ))
  }

  let result = { m, n, network, output, pubkeys }
  if (input) result.input = input
  if (signatures) result.signature = signatures
  return result
}

module.exports = p2ms
