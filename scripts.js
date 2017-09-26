var bitcoin = require('bitcoinjs-lib')
let bcrypto = bitcoin.crypto
let bscript = bitcoin.script
let types = require('../bitcoinjs-lib/src/types')
let typeforce = require('typeforce')
let OPS = require('bitcoin-ops')

function p2pk () {

}

// {signature} {pubkey}
// OP_DUP OP_HASH160 {pubkeyhash} OP_EQUALVERIFY OP_CHECKSIG
function p2pkh (a) {
  typeforce({
    hash: types.maybe(types.Hash160bit),
    input: types.maybe(types.Buffer),
    output: types.maybe(types.Buffer),
    pubkey: types.maybe(bscript.isCanonicalPubKey),
    signature: types.maybe(bscript.isCanonicalSignature)
//      address: types.maybe(types.Base58),
//      network: types.maybe(types.Network)
  }, a)

  if (a.hash && a.pubkey && !bcrypto.hash160(a.pubkey).equals(a.hash)) throw new TypeError('P2PKH hash mismatch')

  let pubkey = a.pubkey
  let hash = a.hash
  let output = a.output
  let input = a.input
  let signature = a.signature
  if (input) {
    let chunks = bscript.decompile(input)
    if (chunks.length !== 2 ||
      bscript.isCanonicalSignature(chunks[0]) ||
      bscript.isCanonicalPubKey(chunks[1])) throw new TypeError('P2PKH input is invalid')

    if (pubkey && !pubkey.equals(chunks[1])) throw new TypeError('P2PKH pubkey mismatch')
    if (hash && !pubkey && !hash.equals(bcrypto.hash160(chunks[1]))) throw new TypeError('P2PKH hash mismatch')
    pubkey = chunks[1]
    signature = chunks[0]
  } else if (signature && pubkey) {
    input = bscript.compile([signature, pubkey])
  }

  if (pubkey) {
    hash = bcrypto.hash160(pubkey)
  }

  if (output) {
    if (output.length !== 25 ||
      output[0] !== OPS.OP_DUP ||
      output[1] !== OPS.OP_HASH160 ||
      output[2] !== 0x14 ||
      output[23] !== OPS.OP_EQUALVERIFY ||
      output[24] !== OPS.OP_CHECKSIG) throw new TypeError('P2PKH output is invalid')

    let tmp = output.slice(3, 23)
    if (hash && !hash.equals(tmp)) throw new TypeError('P2PKH hash mismatch')
    hash = tmp
  } else if (hash) {
    output = bscript.compile([
      OPS.OP_DUP,
      OPS.OP_HASH160,
      hash,
      OPS.OP_EQUALVERIFY,
      OPS.OP_CHECKSIG
    ])
  }

  var result = {}
  if (hash) result.hash = hash
  if (input) result.input = input
  if (output) result.output = output
  if (pubkey) result.pubkey = pubkey
  if (signature) result.signature = signature
//    if (address) result.address = address
//    if (network) result.network = network
  return result
}

var keyPair = bitcoin.ECPair.makeRandom()
var result = p2pkh({ pubkey: keyPair.getPublicKeyBuffer() })
console.log(p2pkh({
  pubkey: keyPair.getPublicKeyBuffer()
}))

console.log(p2pkh({
  hash: bcrypto.hash160(keyPair.getPublicKeyBuffer())
}))

console.log(p2pkh({
  output: result.output
}))

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
