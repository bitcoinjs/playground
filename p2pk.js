let {
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')

// input: {signature}
// output: {pubKey} OP_CHECKSIG
function p2pk (a) {
  typef({
    input: typef.maybe(typef.Buffer),
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.Buffer),
    pubkey: typef.maybe(bscript.isCanonicalPubKey),
    signature: typef.maybe(bscript.isCanonicalSignature)
  }, a)

  let input = a.input
  let signature = a.signature

  if (signature) {
    let script = bscript.compile([signature])
    if (input && !input.equals(script)) throw new TypeError('Input mismatch')
    if (!input) input = script

  // use input for data
  } else if (input) {
    let chunks = bscript.decompile(input)
    if (chunks.length !== 1 ||
      !bscript.isCanonicalSignature(chunks[0])) throw new TypeError('Input is invalid')

    if (signature && !signature.equals(chunks[0])) throw new TypeError('Signature mismatch')
    if (!signature) signature = chunks[0]
  }

  let network = a.network || bnetworks.bitcoin
  let output = a.output
  let pubkey = a.pubkey

  if (output) {
    if (output[output.length - 1] !== OPS.OP_CHECKSIG) throw new TypeError('Output is invalid')

    let outputPubKey = output.slice(0, -1)
    if (pubkey && !pubkey.equals(outputPubKey)) throw new TypeError('PubKey mismatch')
    if (!pubkey && !bscript.isCanonicalPubKey(outputPubKey)) throw new TypeError('Output pubkey is invalid')
    if (!pubkey) pubkey = outputPubKey
  }

  if (!pubkey) throw new TypeError('Not enough data')
  if (!output) {
    output = bscript.compile([
      pubkey,
      OPS.OP_CHECKSIG
    ])
  }

  let result = { network, output, pubkey }
  if (input) result.input = input
  if (signature) result.signature = signature
  return result
}

module.exports = p2pk
