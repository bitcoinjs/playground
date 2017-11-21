let {
  crypto: bcrypto,
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')
var bech32 = require('bech32')
let bs58check = require('bs58check')
let typef = require('typeforce')
let OPS = require('bitcoin-ops')
var OP_INT_BASE = OPS.OP_RESERVED // OP_1 - 1

function toBase58Check (hash, version) {
  typef(typef.tuple(typef.BufferN(20), typef.UInt8), arguments)

  let payload = Buffer.allocUnsafe(21)
  payload.writeUInt8(version, 0)
  hash.copy(payload, 1)

  return bs58check.encode(payload)
}

function fromBase58Check (address) {
  let payload = bs58check.decode(address)
  if (payload.length < 21) throw new TypeError(address + ' is too short') // TODO: move to actual script types?
  if (payload.length > 21) throw new TypeError(address + ' is too long') // ... and this too?

  let version = payload.readUInt8(0)
  let hash = payload.slice(1)

  return { version: version, hash: hash }
}

function toBech32 (data, version, prefix) {
  var words = bech32.toWords(data)
  words.unshift(version)

  return bech32.encode(prefix, words)
}

function fromBech32 (address) {
  var result = bech32.decode(address)
  var data = bech32.fromWords(result.words.slice(1))

  return {
    version: result.words[0],
    prefix: result.prefix,
    data: Buffer.from(data)
  }
}

function stacksEqual (a, b) {
  if (a.length !== b.length) return false

  for (let i = 0; i < a.length; ++i) {
    if (!a[i].equals(b[i])) return false
  }

  return true
}

// input: OP_0 [signatures ...]
// output: m [pubKeys ...] n OP_CHECKMULTISIG
function p2ms (a) {
  typef({
    input: typef.maybe(typef.Buffer),
    m: typef.maybe(typef.Number),
    n: typef.maybe(typef.Number),
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.BufferN(25)),
    pubkeys: typef.maybe(typef.arrayOf(bscript.isCanonicalPubKey)),
    signatures: typef.maybe(typef.arrayOf(bscript.isCanonicalSignature))
  }, a)

  let input = a.input
  let signatures = a.signatures

  if (signatures) {
    let script = bscript.compile([OPS.OP_0].concat(signatures))
    if (input && !input.equals(script)) throw new TypeError('Input mismatch')
    if (!input) input = script

  // use input for data
  } else if (input) {
    let chunks = bscript.decompile(input)
    let signatureChunks = chunks.slice(1)

    if (chunks.length < 2 ||
      chunks[0] !== OPS.OP_0 ||
      signatureChunks.every(bscript.isCanonicalSignature)) throw new TypeError('Input is invalid')

    if (signatures && !stacksEqual(signatures, signatureChunks)) throw new TypeError('Signatures mismatch')
    if (!signatures) signatures = signatureChunks
  }

  let network = a.network || bnetworks.bitcoin
  let output = a.output
  let pubkeys = a.pubkeys

  if (output) {
    let chunks = bscript.decompile(output)
    if (chunks[chunks.length - 1] !== OPS.CHECKMULTISIG) throw new TypeError('Output is invalid')
    if (!typef.Number(chunks[0])) throw new TypeError('Output is invalid')
    if (!typef.Number(chunks[chunks.length - 2])) throw new TypeError('Output is invalid')

    let m = chunks[0] - OP_INT_BASE
    let n = chunks[chunks.length - 2] - OP_INT_BASE
    if (
      m <= 0 ||
      n > 16 ||
      m > n ||
      n !== chunks.length - 3) throw new TypeError('Output is invalid')

    let outputPubKeys = chunks.slice(1, -2)
    if (pubkeys && !stacksEqual(pubkeys, outputPubKeys)) throw new TypeError('PubKeys mismatch')
    if (!pubkeys) pubkeys = outputPubKeys
  }

  if (!pubkeys) throw new TypeError('Not enough data')

  let m = a.m
  let n = a.n
  if (!output) {
    output = bscript.compile([].concat(
      OP_INT_BASE + m,
      pubkeys,
      OP_INT_BASE + n,
      OPS.OP_CHECKMULTISIG
    ))
  }

  let result = { network, output, pubkeys }
  if (input) result.input = input
  if (signatures) result.signature = signatures
  return result
}

// input: {signature}
// output: {pubKey} OP_CHECKSIG
function p2pk (a) {
  typef({
    input: typef.maybe(typef.Buffer),
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.Buffer),
    pubkey: typef.maybe(bscript.isCanonicalPubKey),
    signature: typef.maybe(bscript.isCanonicalSignature)
  }, a)

  let input = a.input
  let signature = a.signature

  if (signature) {
    let script = bscript.compile([signature])
    if (input && !input.equals(script)) throw new TypeError('Input mismatch')
    if (!input) input = script

  // use input for data
  } else if (input) {
    let chunks = bscript.decompile(input)
    if (chunks.length !== 1 ||
      !bscript.isCanonicalSignature(chunks[0])) throw new TypeError('Input is invalid')

    if (signature && !signature.equals(chunks[0])) throw new TypeError('Signature mismatch')
    if (!signature) signature = chunks[0]
  }

  let network = a.network || bnetworks.bitcoin
  let output = a.output
  let pubkey = a.pubkey

  if (output) {
    if (output[output.length - 1] !== OPS.CHECKSIG) throw new TypeError('Output is invalid')

    let outputPubKey = output.slice(0, -1)
    if (pubkey && !pubkey.equals(outputPubKey)) throw new TypeError('PubKey mismatch')
    if (!pubkey) pubkey = outputPubKey
  }

  if (!pubkey) throw new TypeError('Not enough data')
  if (!output) {
    output = bscript.compile([
      OPS.OP_CHECKSIG,
      pubkey
    ])
  }

  let result = { network, output, pubkey }
  if (input) result.input = input
  if (signature) result.signature = signature
  return result
}

// input: {signature} {pubkey}
// output: OP_DUP OP_HASH160 {hash160(pubkey)} OP_EQUALVERIFY OP_CHECKSIG
function p2pkh (a) {
  typef({
    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(20)),
    input: typef.maybe(typef.Buffer),
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.BufferN(25)),
    pubkey: typef.maybe(bscript.isCanonicalPubKey),
    signature: typef.maybe(bscript.isCanonicalSignature)
  }, a)

  let input = a.input
  let pubkey = a.pubkey
  let signature = a.signature

  if (pubkey && signature) {
    let script = bscript.compile([signature, pubkey])
    if (input && !input.equals(script)) throw new TypeError('Input mismatch')
    if (!input) input = script

  // use input for data
  } else if (input) {
    let chunks = bscript.decompile(input)
    if (chunks.length !== 2 ||
      !bscript.isCanonicalSignature(chunks[0]) ||
      !bscript.isCanonicalPubKey(chunks[1])) throw new TypeError('Input is invalid')

    if (signature && !signature.equals(chunks[0])) throw new TypeError('Signature mismatch')
    if (!signature) signature = chunks[0]

    if (pubkey && !pubkey.equals(chunks[1])) throw new TypeError('Pubkey mismatch')
    if (!pubkey) pubkey = chunks[1]
  }

  let hash = a.hash
  if (pubkey) {
    let pubKeyHash = bcrypto.hash160(pubkey)

    if (hash && !hash.equals(pubKeyHash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = pubKeyHash
  }

  let network = a.network || bnetworks.bitcoin
  let address = a.address
  if (address) {
    let decode = fromBase58Check(address)
    if (network && network.pubKeyHash !== decode.version) throw new TypeError('Network mismatch')

    if (hash && !hash.equals(decode.hash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = decode.hash
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

    let pubKeyHash = output.slice(3, 23)
    if (hash && !hash.equals(pubKeyHash)) throw new TypeError('Hash mismatch')
    if (!hash) hash = pubKeyHash
  }

  if (!hash) throw new TypeError('Not enough data')
  if (!address) {
    address = toBase58Check(hash, network.pubKeyHash)
  }

  if (!output) {
    output = bscript.compile([
      OPS.OP_DUP,
      OPS.OP_HASH160,
      hash,
      OPS.OP_EQUALVERIFY,
      OPS.OP_CHECKSIG
    ])
  }

  let result = { address, hash, network, output }
  if (input) result.input = input
  if (pubkey) result.pubkey = pubkey
  if (signature) result.signature = signature
  return result
}

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
    if (!input) input = Buffer.alloc(0)
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

    if (!input) input = Buffer.alloc(0)
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
    let decode = fromBech32(address)
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
    address = toBech32(hash, 0x00, network.bech32)
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
    let decode = fromBase58Check(address)
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
    address = toBase58Check(hash, network.scriptHash)
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

// input: <>
// witness: [redeemScriptSig ...] {redeemScript}
// output: OP_0 {hash160(redeemScript)}
function p2wsh (a) {
  typef({
    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(32)),
    input: typef.maybe(typef.BufferN(0)),
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.BufferN(34)),
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

    // try to use provided redeem witness
    let redeemWitness = redeem.witness
    if (!redeemWitness && redeem.input && redeem.input.length > 0) {
      redeemWitness = bscript.decompile(redeem.input)
      if (!bscript.isPushOnly(redeemWitness)) throw new TypeError('Non push-only witness')
    }

    if (redeemWitness) {
      let derivedWitness = [].concat(redeemWitness, redeem.output)
      if (witness && !stacksEqual(witness, derivedWitness)) throw new TypeError('Witness mismatch')
      if (!witness) witness = derivedWitness
    }

    if (!input) input = Buffer.alloc(0)
  }

  // default as late as possible
  network = network || bnetworks.bitcoin

  let address = a.address
  if (address) {
    let decode = fromBech32(address)
    if (network && network.bech32 !== decode.prefix) throw new TypeError('Network mismatch')
    if (decode.version !== 0x00) throw new TypeError('Invalid version')
    if (decode.data.length !== 32) throw new TypeError('Invalid data')

    if (hash && !hash.equals(decode.data)) throw new TypeError('Hash mismatch')
    if (!hash) hash = decode.data
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
    address = toBech32(hash, 0x00, network.bech32)
  }

  if (!output) {
    output = bscript.compile([
      OPS.OP_0,
      hash
    ])
  }

  let result = { address, hash, network, output }
  if (input) result.input = input
  if (redeem) result.redeem = redeem
  if (witness) result.witness = witness
  return result
}

module.exports = {
  p2ms, p2pk, p2pkh, p2wpkh, p2sh, p2wsh
}
