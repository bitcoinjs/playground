let {
  address: baddress,
  crypto: bcrypto,
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let { lazyprop, lazyvalue } = require('./lazy')

function stacksEqual (a, b) {
  if (a.length !== b.length) return false

  return a.every(function (x, i) {
    return x.equals(b[i])
  })
}

// input: [redeemScriptSig ...] {redeemScript}
// witness: <?>
// output: OP_HASH160 {hash160(redeemScript)} OP_EQUAL
function p2sh (a, opts) {
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.redeem &&
    !a.input
  ) throw new TypeError('Not enough data')
  opts = opts || { validate: true }

  typef({
    network: typef.maybe(typef.Object),

    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(20)),
    output: typef.maybe(typef.BufferN(23)),

    redeem: typef.maybe({
      network: typef.maybe(typef.Object),
      output: typef.Buffer,
      input: typef.maybe(typef.Buffer),
      witness: typef.maybe(typef.arrayOf(typef.Buffer))
    }),
    input: typef.maybe(typef.Buffer),
    witness: typef.maybe(typef.arrayOf(typef.Buffer))
  }, a)

  let _address = lazyvalue(function () { return baddress.fromBase58Check(a.address) })
  let _chunks = lazyvalue(function () { return bscript.decompile(a.input) })

  let network = a.network || bnetworks.bitcoin
  let o = { network }

  // output dependents
  lazyprop(o, 'address', function () {
    if (!o.hash) return
    return baddress.toBase58Check(o.hash, network.scriptHash)
  })
  lazyprop(o, 'hash', function () {
    // in order of least effort
    if (a.output) return a.output.slice(2, 22)
    if (a.address) return _address().hash
    if (o.redeem && o.redeem.output) return bcrypto.hash160(o.redeem.output)
  })
  lazyprop(o, 'output', function () {
    if (!o.hash) return
    return bscript.compile([
      OPS.OP_HASH160,
      o.hash,
      OPS.OP_EQUAL
    ])
  })

  // input dependents
  lazyprop(o, 'redeem', function () {
    if (!a.input) return
    let chunks = _chunks()
    return {
      network: network,
      output: chunks[chunks.length - 1],
      input: bscript.compile(chunks.slice(0, -1)),
      witness: a.witness || []
    }
  })
  lazyprop(o, 'input', function () {
    if (!a.redeem || !a.redeem.input) return
    return bscript.compile([].concat(
      bscript.decompile(a.redeem.input),
      a.redeem.output
    ))
  })
  lazyprop(o, 'witness', function () {
    if (o.redeem && o.redeem.witness) return o.redeem.witness
    if (o.input) return []
  })

  if (opts.validate) {
    let hash
    if (a.address) {
      if (_address().version !== network.scriptHash) throw new TypeError('Network mismatch')
      if (_address().hash.length !== 20) throw new TypeError('Invalid address')
      else hash = _address().hash
    }

    if (a.hash) {
      if (hash && !hash.equals(a.hash)) throw new TypeError('Hash mismatch')
      else hash = a.hash
    }

    if (a.output) {
      if (
        a.output.length !== 23 ||
        a.output[0] !== OPS.OP_HASH160 ||
        a.output[1] !== 0x14 ||
        a.output[22] !== OPS.OP_EQUAL) throw new TypeError('Output is invalid')
      let hash2 = a.output.slice(2, 22)
      if (hash && !hash.equals(hash2)) throw new TypeError('Hash mismatch')
      else hash = hash2
    }

    if (a.input) {
      let chunks = _chunks()
      if (chunks.length < 1) throw new TypeError('Input too short')
      if (!Buffer.isBuffer(o.redeem.output)) throw new TypeError('Input is invalid')
    }

    if (a.redeem) {
      if (a.redeem.network && a.redeem.network !== network) throw new TypeError('Network mismatch')
      if (o.redeem) {
        if (a.redeem.output && !a.redeem.output.equals(o.redeem.output)) throw new TypeError('Redeem.output mismatch')
        if (a.redeem.input && !a.redeem.input.equals(o.redeem.input)) throw new TypeError('Redeem.input mismatch')
      }

      let hash2 = bcrypto.hash160(a.redeem.output)
      if (hash && !hash.equals(hash2)) throw new TypeError('Hash mismatch')
      else hash = hash2

      o.redeem = a.redeem
    }

    if (o.redeem) {
      // is the redeem output empty/invalid?
      if (bscript.decompile(o.redeem.output).length < 1) throw new TypeError('Redeem.output too short')

      // match hash against other sources
      let rOutputHash = bcrypto.hash160(o.redeem.output)
      if (o.hash && !o.hash.equals(rOutputHash)) throw new TypeError('Hash mismatch')

      if (o.redeem.input) {
        let hasInput = o.redeem.input.length > 0
        let hasWitness = o.witness && o.witness.length > 0
        if (!hasInput && !hasWitness) throw new TypeError('Empty input')
        if (hasInput && hasWitness) throw new TypeError('Input and witness provided')
        if (hasInput) {
          let rInputChunks = bscript.decompile(o.redeem.input)
          if (!bscript.isPushOnly(rInputChunks)) throw new TypeError('Non push-only scriptSig')
        }
      }
    }

    if (a.witness) {
      if (
        a.redeem &&
        a.redeem.witness &&
        !stacksEqual(a.redeem.witness, a.witness)) throw new TypeError('Witness and redeem.witness mismatch')
    }
  }

  return Object.assign(o, a)
}

module.exports = p2sh
