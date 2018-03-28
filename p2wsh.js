let {
  address: baddress,
  crypto: bcrypto,
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
//  let { lazyprop } = require('./lazy')
let EMPTY_BUFFER = Buffer.alloc(0)

function stacksEqual (a, b) {
  if (a.length !== b.length) return false

  return a.every(function (x, i) {
    return x.equals(b[i])
  })
}

// input: <>
// witness: [redeemScriptSig ...] {redeemScript}
// output: OP_0 {sha256(redeemScript)}
function p2wsh (a) {
  typef({
    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(32)),
    input: typef.maybe(typef.BufferN(0)),
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.BufferN(34)),
    redeem: typef.maybe({
      input: typef.maybe(typef.Buffer),
      network: typef.Object,
      output: typef.Buffer,
      witness: typef.maybe(typef.arrayOf(typef.Buffer))
    }),
    witness: typef.maybe(typef.arrayOf(typef.Buffer))
  }, a)

  let input = a.input
  let redeem = a.redeem
  let witness = a.witness

  if (witness) {
    if (!bscript.isPushOnly(witness)) throw new TypeError('Non push-only witness')

    let redeemOutput = witness[witness.length - 1]
    let redeemWitness = witness.slice(0, -1)

    if (redeem && redeem.witness && !stacksEqual(redeem.witness, redeemWitness)) throw new TypeError('Witness and redeem.witness mismatch')
    if (redeem && redeem.output && redeem.output.equals(redeemOutput)) throw new TypeError('Witness and redeem.output mismatch')
    if (!redeem || !redeem.witness) redeem = Object.assign({ witness: redeemWitness }, redeem)
    if (!redeem.output) redeem = Object.assign({ output: redeemOutput }, redeem)
  }

  let hash = a.hash
  let network = a.network
  if (redeem) {
    if (network && network !== redeem.network) throw new TypeError('Network mismatch')
    if (!network) network = redeem.network

    let redeemOutputHash = bcrypto.sha256(redeem.output)
    if (hash && !hash.equals(redeemOutputHash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = redeemOutputHash

    // is redeemScript a valid script?
    if (bscript.decompile(redeem.output).length === 0) throw new TypeError('Redeem.output is invalid')

    if (
      redeem.input &&
      redeem.input.length > 0 &&
      redeem.witness) throw new TypeError('Ambiguous witness source')

    // attempt to transform redeem input to witness stack
    let redeemWitness = redeem.witness
    if (!redeemWitness && redeem.input && redeem.input.length > 0) {
      redeemWitness = bscript.decompile(redeem.input)
      if (!bscript.isPushOnly(redeemWitness)) throw new TypeError('Non push-only witness')

      redeemWitness = bscript.toStack(redeemWitness)
      redeem = Object.assign({ witness: redeemWitness }, redeem)
      delete redeem.input // delete the input, as the redeem in isolation isn't "valid" for encoding
    }

    if (redeemWitness) {
      let derivedWitness = [].concat(redeemWitness, redeem.output)
      if (witness && !stacksEqual(witness, derivedWitness)) throw new TypeError('Witness mismatch')
      if (!witness) witness = derivedWitness
    }

    if (!input) input = EMPTY_BUFFER
  }

  // default as late as possible
  network = network || bnetworks.bitcoin

  let address = a.address
  if (address) {
    let decode = baddress.fromBech32(address)
    if (network && network.bech32 !== decode.prefix) throw new TypeError('Network mismatch')
    if (decode.version !== 0x00) throw new TypeError('Invalid version')
    if (decode.data.length !== 32) throw new TypeError('Invalid data')

    if (hash && !hash.equals(decode.data)) throw new TypeError('Hash mismatch')
    if (!hash) hash = decode.data
  }

  let output = a.output
  if (output) {
    if (
      output.length !== 34 ||
      output[0] !== OPS.OP_0 ||
      output[1] !== 0x20) throw new TypeError('Output is invalid')

    let scriptHash = output.slice(2)
    if (hash && !hash.equals(scriptHash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = scriptHash
  }

  if (!hash) throw new TypeError('Not enough data')
  if (!address) {
    address = baddress.toBech32(hash, 0x00, network.bech32)
  }

  if (!output) {
    output = bscript.compile([
      OPS.OP_0,
      hash
    ])
  }

  let result = { address, hash, network, output }
  if (input) result.input = input
  if (redeem) result.redeem = redeem
  if (witness) result.witness = witness
  return result
}

module.exports = p2wsh
