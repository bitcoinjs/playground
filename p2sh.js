let {
  address: baddress,
  crypto: bcrypto,
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let { lazyprop } = require('./lazy')

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
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.redeem &&
    !a.input
  ) throw new TypeError('Not enough data')

  typef({
    network: typef.maybe(typef.Object),

    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(20)),
    output: typef.maybe(typef.BufferN(23)),

    redeem: typef.maybe({
      network: typef.Object,
      output: typef.Buffer,
      input: typef.maybe(typef.Buffer),
      witness: typef.maybe(typef.arrayOf(typef.Buffer))
    }),
    input: typef.maybe(typef.Buffer),
    witness: typef.maybe(typef.arrayOf(typef.Buffer))
  }, a)

  let network = a.network || bnetworks.bitcoin
  let o = { network }
  lazyprop(o, 'address', function () {
    if (!o.hash) return
    return baddress.toBase58Check(o.hash, network.scriptHash)
  })
  lazyprop(o, 'hash', function () {
    if (a.output) return a.output.slice(1, 21)
    if (a.address) return baddress.fromBase58Check(a.address, network.scriptHash).hash
    if (!o.redeem) return
    if (o.redeem.output) return bcrypto.hash160(o.redeem.output)
  })
  lazyprop(o, 'output', function () {
    if (!o.hash) return
    return bscript.compile([
      OPS.OP_HASH160,
      o.hash,
      OPS.OP_EQUAL
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
    let decode = baddress.fromBase58Check(a.address, network.scriptHash)
    if (network.scriptHash !== decode.version) throw new TypeError('Network mismatch')
    if (!a.hash.equals(decode.hash)) throw new TypeError('Hash mismatch')
    o.hash = decode.hash
  }

  if (a.output) {
    if (
      a.output.length !== 23 ||
      a.output[0] !== OPS.OP_HASH160 ||
      a.output[1] !== 0x14 ||
      a.output[22] !== OPS.OP_EQUAL) throw new TypeError('Output is invalid')

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

module.exports = p2sh
