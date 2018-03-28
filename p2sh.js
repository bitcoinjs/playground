let {
  address: baddress,
  crypto: bcrypto,
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')

function stacksEqual (a, b) {
  if (a.length !== b.length) return false

  return a.every(function (x, i) {
    return x.equals(b[i])
  })
}

// input: [redeemScriptSig ...] {redeemScript}
// witness: <?>
// output: OP_HASH160 {hash160(redeemScript)} OP_EQUAL
function p2sh (a) {
  typef({
    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(20)),
    input: typef.maybe(typef.Buffer),
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.BufferN(23)),
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

  if (input) {
    let chunks = bscript.decompile(input)
    if (chunks.length < 1) throw new TypeError('Input too short')

    let redeemOutput = chunks[chunks.length - 1]
    if (!Buffer.isBuffer(redeemOutput)) throw new TypeError('Input is invalid')

    let redeemInput = bscript.compile(chunks.slice(0, -1))
    if (redeem && redeem.input && !redeem.input.equals(redeemInput)) throw new TypeError('Input and redeem.input mismatch')
    if (redeem && !redeem.output.equals(redeemOutput)) throw new TypeError('Input and redeem.output mismatch')
    if (!redeem || !redeem.input) redeem = Object.assign({ input: redeemInput }, redeem)
    if (!redeem.output) redeem = Object.assign({ output: redeemOutput }, redeem)
  }

  if (witness) {
    if (redeem && redeem.witness && witness && !stacksEqual(redeem.witness, witness)) throw new TypeError('Witness and redeem.witness mismatch')
  }

  let hash = a.hash
  let network = a.network
  if (redeem) {
    if (network && network !== redeem.network) throw new TypeError('Network mismatch')
    if (!network) network = redeem.network

    // is redeemScript a valid script?
    if (bscript.decompile(redeem.output).length === 0) throw new TypeError('Redeem.output is invalid')

    let redeemOutputHash = bcrypto.hash160(redeem.output)
    if (hash && !hash.equals(redeemOutputHash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = redeemOutputHash

    if (redeem.input) {
      if (redeem.input.length === 0 && !redeem.witness) throw new TypeError('Redeem.input is invalid')
      if (redeem.input.length !== 0 && redeem.witness) throw new TypeError('Unexpected witness')

      if (!witness && redeem.witness) witness = redeem.witness

      let redeemInputChunks = bscript.decompile(redeem.input)
      if (!bscript.isPushOnly(redeemInputChunks)) throw new TypeError('Non push-only scriptSig')
      if (!input) input = bscript.compile([].concat(redeemInputChunks, redeem.output))
    }
  }

  // default as late as possible
  network = network || bnetworks.bitcoin

  let address = a.address
  if (address) {
    let decode = baddress.fromBase58Check(address)
    if (network && network.scriptHash !== decode.version) throw new TypeError('Network mismatch')

    if (hash && !hash.equals(decode.hash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = decode.hash
  }

  let output = a.output
  if (output) {
    if (
      output.length !== 23 ||
      output[0] !== OPS.OP_HASH160 ||
      output[1] !== 0x14 ||
      output[22] !== OPS.OP_EQUAL) throw new TypeError('Output is invalid')

    let scriptHash = output.slice(1, 21)
    if (hash && !hash.equals(scriptHash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = scriptHash
  }

  if (!hash) throw new TypeError('Not enough data')
  if (!address) {
    address = baddress.toBase58Check(hash, network.scriptHash)
  }

  if (!output) {
    output = bscript.compile([
      OPS.OP_HASH160,
      hash,
      OPS.OP_EQUAL
    ])
  }

  let result = { address, hash, network, output }
  if (input) result.input = input
  if (redeem) result.redeem = redeem
  if (witness) result.witness = witness
  return result
}

module.exports = p2sh
