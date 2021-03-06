let {
  address: baddress,
  crypto: bcrypto,
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let EMPTY_BUFFER = Buffer.alloc(0)
let { lazyprop, lazyvalue } = require('./lazy')

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

  let _address = lazyvalue(function () { return baddress.fromBech32(a.address) })

  let network = a.network || bnetworks.bitcoin
  let o = { network }

  lazyprop(o, 'address', function () {
    if (!o.hash) return
    return baddress.toBech32(o.hash, 0x00, network.bech32)
  })
  lazyprop(o, 'hash', function () {
    if (a.output) return a.output.slice(2, 22)
    if (a.address) return _address().data
    if (a.pubkey || o.pubkey) return bcrypto.hash160(a.pubkey || o.pubkey)
  })
  lazyprop(o, 'output', function () {
    if (!o.hash) return
    return bscript.compile([
      OPS.OP_0,
      o.hash
    ])
  })
  lazyprop(o, 'pubkey', function () {
    if (a.pubkey) return a.pubkey
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
    let hash
    if (a.address) {
      if (network && network.bech32 !== _address().prefix) throw new TypeError('Network mismatch')
      if (_address().version !== 0x00) throw new TypeError('Invalid version')
      if (_address().data.length !== 20) throw new TypeError('Invalid data')
      if (hash && !hash.equals(_address().data)) throw new TypeError('Hash mismatch')
      else hash = _address().data
    }

    if (a.pubkey) {
      let pkh = bcrypto.hash160(a.pubkey)
      if (hash && !hash.equals(pkh)) throw new TypeError('Hash mismatch')
      else hash = pkh
    }

    if (a.hash) {
      if (hash && !hash.equals(a.hash)) throw new TypeError('Hash mismatch')
      else hash = a.hash
    }

    if (a.output) {
      if (
        a.output.length !== 22 ||
        a.output[0] !== OPS.OP_0 ||
        a.output[1] !== 0x14) throw new TypeError('Output is invalid')
      if (hash && !hash.equals(a.output.slice(2))) throw new TypeError('Hash mismatch')
      else hash = a.output.slice(2)
    }

    if (a.witness) {
      if (a.witness.length !== 2) throw new TypeError('Input is invalid')
      if (!bscript.isCanonicalSignature(a.witness[0])) throw new TypeError('Input has invalid signature')
      if (!bscript.isCanonicalPubKey(a.witness[1])) throw new TypeError('Input has invalid pubkey')

      if (a.signature && !a.signature.equals(a.witness[0])) throw new TypeError('Signature mismatch')
      if (a.pubkey && !a.pubkey.equals(a.witness[1])) throw new TypeError('Pubkey mismatch')

      let pkh = bcrypto.hash160(a.witness[1])
      if (hash && !hash.equals(pkh)) throw new TypeError('Hash mismatch')
    }
  }

  return Object.assign(o, a)
}

module.exports = p2wpkh
