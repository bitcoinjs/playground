let {
  ECPair,
  opcodes: OPS,
  script
} = require('bitcoinjs-lib')
let p2ms = require('../p2ms')
let p2pk = require('../p2pk')
let p2pkh = require('../p2pkh')
let p2sh = require('../p2sh')
let p2wpkh = require('../p2wpkh')

function tryHex (x) {
  if (Buffer.isBuffer(x)) return x.toString('hex')
  if (Array.isArray(x)) return x.map(tryHex)
  return x
}
function tryASM (x) {
  if (Buffer.isBuffer(x)) return script.toASM(x)
  return x
}
function equate (t, a, b) {
  b = Object.assign({}, b)

  // if null, we imply 'undefined', but JSON
  for (let k in b) {
    if (b[k] === null) b[k] = undefined
  }

  if ('output' in b) t.equal(tryASM(a.output), tryASM(b.output), 'Same output')
  if ('input' in b) t.equal(tryASM(a.input), tryASM(b.input), 'Same input')
  if ('witness' in b) {
    t.same(tryHex(a.witness), tryHex(b.witness), 'Same witness')
  }
  if (b.network) t.same(a.network, b.network)
  if (b.redeem) {
    if ('output' in b.redeem) t.equal(tryASM(a.redeem.output), tryASM(b.redeem.output), 'Same redeem output')
    if ('input' in b.redeem) t.equal(tryASM(a.redeem.input), tryASM(b.redeem.input), 'Same redeem input')
    if ('witness' in b.redeem) {
      t.same(tryHex(a.redeem.witness), tryHex(b.redeem.witness), 'Same redeem witness')
    }
  }

  // contextual
  if ('address' in b) t.equal(a.address, b.address, 'Same address')
  if ('hash' in b) t.equal(tryHex(a.hash), tryHex(b.hash), 'Same hash(output)')
  if ('pubkey' in b) t.equal(tryHex(a.pubkey), tryHex(b.pubkey), 'Same pubkey')
  if ('signature' in b) t.equal(tryHex(a.signature), tryHex(b.signature), 'Same signature')
  if ('m' in b) t.equal(a.m, b.m, 'Same m')
  if ('n' in b) t.equal(a.n, b.n, 'Same n')
  if ('pubkeys' in b) t.same(tryHex(a.pubkeys), tryHex(b.pubkeys), 'Same pubkeys')
  if ('signatures' in b) t.same(tryHex(a.signatures), tryHex(b.signatures), 'Same signatures')
}

function preform (x) {
  x = Object.assign({}, x)
  if (x.output) x.output = script.fromASM(x.output)
  if (x.input) x.input = script.fromASM(x.input)

  if (x.hash) x.hash = Buffer.from(x.hash, 'hex')
  if (x.pubkey) x.pubkey = Buffer.from(x.pubkey, 'hex')
  if (x.signature) x.signature = Buffer.from(x.signature, 'hex')
  if (x.pubkeys) x.pubkeys = x.pubkeys.map(function (y) { return Buffer.from(y, 'hex') })
  if (x.signatures) x.signatures = x.signatures.map(function (y) { return Number.isFinite(y) ? y : Buffer.from(y, 'hex') })
  if (x.witness) x.witness = x.witness.map(function (y) { return Buffer.from(y, 'hex') })

  return x
}

// useful constants
let keyPair = ECPair.fromWIF('KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42')
let keyPairs2 = [
  'Kys5pPp2GAy8GZW5tkdEAHF1DQbN8mMmpfvBEvbF4u9CWfFGKge5',
  'L2yA6eWsYmR8fGKS8XThWeBp4Fze1P8trC8hKsvudYywjMZMaasR'
].map(x => ECPair.fromWIF(x))
let keyPairs3 = [
  'KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42',
  'Kys5pPp2GAy8GZW5tkdEAHF1DQbN8mMmpfvBEvbF4u9CWfFGKge5',
  'L2yA6eWsYmR8fGKS8XThWeBp4Fze1P8trC8hKsvudYywjMZMaasR'
].map(x => ECPair.fromWIF(x))
let HASH20 = Buffer.alloc(20, 0x01)
let HASH32 = Buffer.alloc(32, 0x01)

function sign (kp) {
  return kp.sign(HASH32).toScriptSignature(0x01)
}

let PUBKEYS2 = keyPairs2.map(x => x.getPublicKeyBuffer())
let PUBKEYS3 = keyPairs3.map(x => x.getPublicKeyBuffer())
let SIGNATURES2 = keyPairs2.map(sign)
let SIGNATURES2_INCOMPLETE = [SIGNATURES2[0], OPS.OP_0]
let SIGNATURES3 = keyPairs3.map(sign)
let pubkey = keyPair.getPublicKeyBuffer()
let signature = sign(keyPair)

let P2MS_S_EXAMPLE = p2ms({
  m: 2,
  pubkeys: PUBKEYS3,
  signatures: SIGNATURES2
})
let P2MS_S_SIGNATURES_INCOMPLETE = [OPS.OP_0, signature]
let P2MS_S_INPUT_INCOMPLETE = script.compile([OPS.OP_0].concat(P2MS_S_SIGNATURES_INCOMPLETE))
let P2PKH_EXAMPLE = p2pkh({ pubkey })
let P2PKH_S_EXAMPLE = p2pkh({ pubkey, signature })
let P2PK_EXAMPLE = p2pk({ pubkey })
let P2PK_S_EXAMPLE = p2pk({ pubkey, signature })
let P2SH_EXAMPLE = p2sh({ hash: HASH20 })
let P2WPKH_EXAMPLE = p2wpkh({ pubkey })
let P2WPKH_S_EXAMPLE = p2wpkh({ pubkey, signature })

module.exports = {
  HASH20,
  HASH32,
  PUBKEY: pubkey,
  PUBKEYS2,
  PUBKEYS3,
  SIGNATURE: signature,
  SIGNATURES2,
  SIGNATURES2_INCOMPLETE,
  SIGNATURES3,
  P2MS_S_EXAMPLE,
  P2MS_S_INPUT_INCOMPLETE,
  P2MS_S_SIGNATURES_INCOMPLETE,
  P2PKH_EXAMPLE,
  P2PKH_S_EXAMPLE,
  P2PK_EXAMPLE,
  P2PK_S_EXAMPLE,
  P2SH_EXAMPLE,
  P2WPKH_EXAMPLE,
  P2WPKH_S_EXAMPLE,
  equate,
  preform
}
