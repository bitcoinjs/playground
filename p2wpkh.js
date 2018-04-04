let {
  address: baddress,
  crypto: bcrypto,
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let EMPTY_BUFFER = Buffer.alloc(0)
let { lazyprop } = require('./lazy')

// witness: {signature} {pubKey}
// input: <>
// output: OP_0 {pubKeyHash}
function p2wpkh (a, opts) {
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.pubkey &&
    !a.witness
  ) throw new TypeError('Not enough data')
  opts = opts || { validate: true }

  typef({
    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(20)),
    input: typef.maybe(typef.BufferN(0)),
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.BufferN(22)),
    pubkey: typef.maybe(bscript.isCanonicalPubKey),
    signature: typef.maybe(bscript.isCanonicalSignature),
    witness: typef.maybe(typef.arrayOf(typef.Buffer))
  }, a)

  let network = a.network || bnetworks.bitcoin
  let o = { network }

  lazyprop(o, 'address', function () {
    if (!o.hash) return
    return baddress.toBech32(o.hash, 0x00, network.bech32)
  })
  lazyprop(o, 'hash', function () {
    if (a.output) return a.output.slice(2, 22)
    if (a.address) return baddress.fromBech32(a.address).data
    if (o.pubkey) return bcrypto.hash160(o.pubkey)
  })
  lazyprop(o, 'output', function () {
    if (!o.hash) return
    return bscript.compile([
      OPS.OP_0,
      o.hash
    ])
  })
  lazyprop(o, 'pubkey', function () {
    if (!a.witness) return
    return a.witness[1]
  })
  lazyprop(o, 'signature', function () {
    if (!a.witness) return
    return a.witness[0]
  })
  lazyprop(o, 'input', function () {
    if (!o.witness) return
    return EMPTY_BUFFER
  })
  lazyprop(o, 'witness', function () {
    if (!a.pubkey) return
    if (!a.signature) return
    return [a.signature, a.pubkey]
  })

  // extended validation
  if (opts.validate) {
    if (a.witness) {
      if (a.witness.length !== 2 ||
        !bscript.isCanonicalSignature(a.witness[0]) ||
        !bscript.isCanonicalPubKey(a.witness[1])) throw new TypeError('Input is invalid')

      if (a.signature && !a.signature.equals(a.witness[0])) throw new TypeError('Signature mismatch')
      if (!a.signature) o.signature = a.witness[0]

      if (a.pubkey && !a.pubkey.equals(a.witness[1])) throw new TypeError('Pubkey mismatch')
      if (!a.pubkey) o.pubkey = a.witness[1]
    }

    if (a.address) {
      let decode = baddress.fromBech32(a.address)
      if (network && network.bech32 !== decode.prefix) throw new TypeError('Network mismatch')
      if (decode.version !== 0x00) throw new TypeError('Invalid version')
      if (decode.data.length !== 20) throw new TypeError('Invalid data')

      o.hash = decode.data
    }

    if (a.pubkey && a.hash) {
      if (!a.hash.equals(o.hash)) throw new TypeError('Hash mismatch')
    }

    if (a.output) {
      if (
        a.output.length !== 22 ||
        a.output[0] !== OPS.OP_0 ||
        a.output[1] !== 0x14) throw new TypeError('Output is invalid')
    }
  }

  return Object.assign(o, a)
}

module.exports = p2wpkh
