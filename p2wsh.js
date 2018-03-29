let {
  address: baddress,
  crypto: bcrypto,
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let { lazyprop } = require('./lazy')
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
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.redeem &&
    !a.witness
  ) throw new TypeError('Not enough data')

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
}

// input: <>
// witness: [redeemScriptSig ...] {redeemScript}
// output: OP_0 {sha256(redeemScript)}
function _p2wsh (a) {
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.redeem &&
    !a.input &&
    !a.witness
  ) throw new TypeError('Not enough data')

  typef({
    network: typef.maybe(typef.Object),

    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(32)),
    output: typef.maybe(typef.BufferN(34)),

    redeem: typef.maybe({
      input: typef.maybe(typef.Buffer),
      network: typef.Object,
      output: typef.Buffer,
      witness: typef.maybe(typef.arrayOf(typef.Buffer))
    }),
    input: typef.maybe(typef.BufferN(0)),
    witness: typef.maybe(typef.arrayOf(typef.Buffer))
  }, a)

  let network = a.network || bnetworks.bitcoin
  let o = { network }
  lazyprop(o, 'address', function () {
    if (!o.hash) return
    return baddress.toBech32(o.hash, 0x00, network.bech32)
  })
  lazyprop(o, 'hash', function () {
    if (a.output) return a.output.slice(2)
    if (a.address) return baddress.fromBech32(a.address).hash
    if (!o.redeem) return
    if (o.redeem.output) return bcrypto.sha256(o.redeem.output)
  })
  lazyprop(o, 'output', function () {
    if (!o.hash) return
    return bscript.compile([
      OPS.OP_0,
      o.hash
    ])
  })

  lazyprop(o, 'redeem', function () {
    if (!a.input) return
    let chunks = bscript.decompile(a.input)
    return {
      network: o.network,
      output: chunks[chunks.length - 1],
      input: bscript.compile(chunks.slice(0, -1))
    }
  })
  lazyprop(o, 'input', function () {
    if (!a.redeem) return
    if (!a.redeem.input) return
    if (!a.redeem.output) return

    return bscript.compile([].concat(
      bscript.decompile(a.redeem.input),
      a.redeem.output
    ))
  })
  lazyprop(o, 'witness', function () {
    return o.redeem.witness
  })

  // validation
  if (a.address) {
    let decode = baddress.fromBech32(a.address, network.scriptHash)
    if (network.bech32 !== decode.prefix) throw new TypeError('Network mismatch')
    if (decode.version !== 0x00) throw new TypeError('Invalid version')
    if (decode.data.length !== 32) throw new TypeError('Invalid data')
    if (!a.hash.equals(decode.hash)) throw new TypeError('Hash mismatch')
    o.hash = decode.hash
  }

  if (a.output) {
    if (
      a.output.length !== 34 ||
      a.output[0] !== OPS.OP_0 ||
      a.output[1] !== 0x20) throw new TypeError('Output is invalid')

    if (a.hash && !a.hash.equals(o.hash)) throw new TypeError('Hash mismatch')
  }

  if (a.input) {
    let chunks = bscript.decompile(a.input)
    if (chunks.length < 1) throw new TypeError('Input too short')
    if (!Buffer.isBuffer(o.redeem.output)) throw new TypeError('Input is invalid')
    if (a.redeem &&
      a.redeem.input &&
      !a.redeem.input.equals(o.redeem.input)) throw new TypeError('Input and redeem.input mismatch')
    if (a.redeem &&
      !a.redeem.output.equals(o.redeem.output)) throw new TypeError('Input and redeem.output mismatch')
  }

  if (a.redeem) {
    if (network !== a.redeem.network) throw new TypeError('Network mismatch')

    // is redeemScript a valid script?
    if (bscript.decompile(a.redeem.output).length === 0) throw new TypeError('Redeem.output is invalid')

    // match hash against other sources
    if (a.output || a.address || a.hash) {
      let redeemOutputHash = bcrypto.hash160(a.redeem.output)
      if (o.hash.equals(redeemOutputHash)) throw new TypeError('Hash mismatch')
    }

    if (a.redeem.input) {
      if (a.redeem.input.length === 0 && !a.redeem.witness) throw new TypeError('Redeem.input is invalid')
      if (a.redeem.input.length !== 0 && a.redeem.witness) throw new TypeError('Unexpected witness')

      let redeemInputChunks = bscript.decompile(a.redeem.input)
      if (!bscript.isPushOnly(redeemInputChunks)) throw new TypeError('Non push-only scriptSig')
    }
  }

  if (a.witness) {
    if (a.redeem &&
      a.redeem.witness &&
      a.witness &&
      !stacksEqual(a.redeem.witness, a.witness)) throw new TypeError('Witness and redeem.witness mismatch')
  }

  return Object.assign(o, a)
}

module.exports = p2wsh
