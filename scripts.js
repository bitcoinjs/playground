let {
  address: baddress,
  crypto: bcrypto,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')

function p2pk () {

}

// {signature} {pubkey}
// OP_DUP OP_HASH160 {pubkeyhash} OP_EQUALVERIFY OP_CHECKSIG
function p2pkh (a) {
  typef({
    hash: typef.maybe(typef.BufferN(20)),
    input: typef.maybe(typef.Buffer),
    output: typef.maybe(typef.BufferN(25)),
    pubkey: typef.maybe(bscript.isCanonicalPubKey),
    signature: typef.maybe(bscript.isCanonicalSignature),
    address: typef.maybe(typef.String),
    network: typef.maybe(typef.Object)
  }, a)

  let hash = a.hash
  let pubkey = a.pubkey
  let input = a.input
  let signature = a.signature
  if (input) {
    let chunks = bscript.decompile(input)
    if (chunks.length !== 2 ||
      !bscript.isCanonicalSignature(chunks[0]) ||
      !bscript.isCanonicalPubKey(chunks[1])) throw new TypeError('Input is invalid')

    if (signature && !signature.equals(chunks[0])) throw new TypeError('Signature mismatch')
    if (!signature) signature = chunks[0]

    if (pubkey && !pubkey.equals(chunks[1])) throw new TypeError('Pubkey mismatch')
    if (!pubkey) pubkey = chunks[1]
  }

  if (signature && pubkey) {
    let script = bscript.compile([signature, pubkey])
    if (input && !input.equals(script)) throw new TypeError('Input mismatch')
    if (!input) input = script
  }

  let output = a.output
  if (output) {
    if (
      output.length !== 25 ||
      output[0] !== OPS.OP_DUP ||
      output[1] !== OPS.OP_HASH160 ||
      output[2] !== 0x14 ||
      output[23] !== OPS.OP_EQUALVERIFY ||
      output[24] !== OPS.OP_CHECKSIG) throw new TypeError('Output is invalid')

    let pubkeyhash = output.slice(3, 23)
    if (hash && !hash.equals(pubkeyhash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = pubkeyhash
  }

  let network = a.network
  let address = a.address
  if (address) {
    let decode = baddress.fromBase58Check(address)
    if (network && network.pubkeyhash !== decode.version) throw new TypeError('Network mismatch')

    if (hash && !hash.equals(decode.hash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = decode.hash
  }

  if (pubkey) {
    let pubkeyhash = bcrypto.hash160(pubkey)

    if (hash && !hash.equals(pubkeyhash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = pubkeyhash
  }

  if (hash) {
    output = bscript.compile([
      OPS.OP_DUP,
      OPS.OP_HASH160,
      hash,
      OPS.OP_EQUALVERIFY,
      OPS.OP_CHECKSIG
    ])
  }

  let result = {}
  if (hash) result.hash = hash
  if (input) result.input = input
  if (output) result.output = output
  if (pubkey) result.pubkey = pubkey
  if (signature) result.signature = signature
  if (address) result.address = address
  if (network) result.network = network
  return result
}

function p2wpkh () {

}

function p2sh () {

}

function p2wsh () {

}

function p2ms () {

}

module.exports = {
  p2pk, p2pkh, p2wpkh, p2sh, p2wsh, p2ms
}
