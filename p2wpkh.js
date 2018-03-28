let {
  address: baddress,
  crypto: bcrypto,
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
let EMPTY_BUFFER = Buffer.alloc(0)

// witness: {signature} {pubKey}
// input: <>
// output: OP_0 {pubKeyHash}
function p2wpkh (a) {
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

  let input = a.input
  let pubkey = a.pubkey
  let signature = a.signature
  let witness = a.witness

  if (pubkey && signature) {
    if (witness && (
      witness.length !== 2 ||
      !witness[0].equals(signature) ||
      !witness[1].equals(pubkey)
    )) throw new TypeError('Witness mismatch')
    if (!input) input = EMPTY_BUFFER
    if (!witness) witness = [signature, pubkey]

  // use witness for data
  } else if (witness) {
    if (witness.length !== 2 ||
      !bscript.isCanonicalSignature(witness[0]) ||
      !bscript.isCanonicalPubKey(witness[1])) throw new TypeError('Witness is invalid')

    if (signature && !signature.equals(witness[0])) throw new TypeError('Signature mismatch')
    if (!signature) signature = witness[0]

    if (pubkey && !pubkey.equals(witness[1])) throw new TypeError('Pubkey mismatch')
    if (!pubkey) pubkey = witness[1]

    if (!input) input = EMPTY_BUFFER
  }

  if (!witness && input) throw new TypeError('Missing Witness')

  let hash = a.hash
  if (pubkey) {
    let pubKeyHash = bcrypto.hash160(pubkey)

    if (hash && !hash.equals(pubKeyHash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = pubKeyHash
  }

  let network = a.network || bnetworks.bitcoin
  let address = a.address
  if (address) {
    let decode = baddress.fromBech32(address)
    if (network && network.bech32 !== decode.prefix) throw new TypeError('Network mismatch')
    if (decode.version !== 0x00) throw new TypeError('Invalid version')
    if (decode.data.length !== 20) throw new TypeError('Invalid data')

    if (hash && !hash.equals(decode.data)) throw new TypeError('Hash mismatch')
    if (!hash) hash = decode.data
  }

  let output = a.output
  if (output) {
    if (
      output.length !== 22 ||
      output[0] !== OPS.OP_0 ||
      output[1] !== 0x14) throw new TypeError('Output is invalid')

    let pubKeyHash = output.slice(2, 22)
    if (hash && !hash.equals(pubKeyHash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = pubKeyHash
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
  if (pubkey) result.pubkey = pubkey
  if (signature) result.signature = signature
  if (witness) result.witness = witness
  return result
}

module.exports = p2wpkh
