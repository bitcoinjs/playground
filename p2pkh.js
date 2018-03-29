let {
  address: baddress,
  crypto: bcrypto,
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let { lazyprop } = require('./lazy')

// input: {signature} {pubkey}
// output: OP_DUP OP_HASH160 {hash160(pubkey)} OP_EQUALVERIFY OP_CHECKSIG
function p2pkh (a) {
  typef({
    network: typef.maybe(typef.Object),
    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(20)),
    output: typef.maybe(typef.BufferN(25)),

    pubkey: typef.maybe(bscript.isCanonicalPubKey),
    signature: typef.maybe(bscript.isCanonicalSignature),
    input: typef.maybe(typef.Buffer)
  }, a)

  let network = a.network || bnetworks.bitcoin
  let o = { network }
  lazyprop(o, 'address', function () {
    if (!o.hash) return
    return baddress.toBase58Check(o.hash, network.pubKeyHash)
  })
  lazyprop(o, 'hash', function () {
    if (a.output) return a.output.slice(3, 23)
    if (a.address) return baddress.fromBase58Check(a.address, network.pubKeyHash).hash
    if (o.pubkey) return bcrypto.hash160(o.pubkey)
  })
  lazyprop(o, 'output', function () {
    if (!o.hash) return
    return bscript.compile([
      OPS.OP_DUP,
      OPS.OP_HASH160,
      o.hash,
      OPS.OP_EQUALVERIFY,
      OPS.OP_CHECKSIG
    ])
  })

  lazyprop(o, 'pubkey', function () {
    if (!a.input) return
    let chunks = bscript.decompile(a.input)
    if (!a.signature) o.signature = chunks[0]
    return chunks[1]
  })
  lazyprop(o, 'signature', function () {
    if (!a.input) return
    let chunks = bscript.decompile(a.input)
    if (!o.pubkey) o.pubkey = chunks[1]
    return chunks[0]
  })
  lazyprop(o, 'input', function () {
    if (!a.pubkey) return
    if (!a.signature) return
    return bscript.compile([a.signature, a.pubkey])
  })

  // validation
  if (a.input) {
    let chunks = bscript.decompile(a.input)
    if (chunks.length !== 2 ||
      !bscript.isCanonicalSignature(chunks[0]) ||
      !bscript.isCanonicalPubKey(chunks[1])) throw new TypeError('Input is invalid')

    if (a.signature && !a.signature.equals(chunks[0])) throw new TypeError('Signature mismatch')
    if (a.pubkey && !a.pubkey.equals(chunks[1])) throw new TypeError('Pubkey mismatch')

    o.signature = chunks[0]
    o.pubkey = chunks[1]
  }

  if (a.address) {
    let decode = baddress.fromBase58Check(a.address, network.pubKeyHash)
    if (network.pubKeyHash !== decode.version) throw new TypeError('Network mismatch')

    o.hash = decode.hash
  }

  if (a.pubkey && a.hash) {
    if (!a.hash.equals(o.hash)) throw new TypeError('Hash mismatch')
  }

  if (a.output) {
    if (
      a.output.length !== 25 ||
      a.output[0] !== OPS.OP_DUP ||
      a.output[1] !== OPS.OP_HASH160 ||
      a.output[2] !== 0x14 ||
      a.output[23] !== OPS.OP_EQUALVERIFY ||
      a.output[24] !== OPS.OP_CHECKSIG) throw new TypeError('Output is invalid')
  }

  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.pubkey &&
    !a.input
  ) throw new TypeError('Not enough data')

  return Object.assign(o, a)
}

module.exports = p2pkh
