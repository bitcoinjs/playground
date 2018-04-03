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

function tryHex (x) { return Buffer.isBuffer(x) ? x.toString('hex') : x }
function tryMapHex (x) { return Array.isArray(x) ? x.map(tryHex) : x }
function equate (t, a, b) {
  if ('address' in b) t.same(a.address, b.address, 'Same address')
  if ('output' in b) t.same(tryHex(a.output), tryHex(b.output), 'Same output')
  if ('input' in b) t.same(tryHex(a.input), tryHex(b.input), 'Same input')
  if ('witness' in b) {
    t.same(tryMapHex(a.witness), tryMapHex(b.witness), 'Same witness')
  }
  if (b.network) t.equal(a.network, b.network)
  if (b.redeem) {
    if ('output' in b.redeem) t.same(tryHex(a.redeem.output), tryHex(b.redeem.output), 'Same redeem output')
    if ('input' in b.redeem) t.same(tryHex(a.redeem.input), tryHex(b.redeem.input), 'Same redeem input')
    if ('witness' in b.redeem) {
      t.same(tryMapHex(a.redeem.witness), tryMapHex(b.redeem.witness), 'Same redeem witness')
    }
  }

  // contextual
  if ('hash' in b) t.same(tryHex(a.hash), tryHex(b.hash), 'Same hash(output)')
  if ('pubkey' in b) t.same(tryMapHex(a.pubkey), tryMapHex(b.pubkey), 'Same pubkeys')
  if ('signature' in b) t.same(tryHex(a.signature), tryHex(b.signature), 'Same signatures')
  if ('m' in b) t.same(a.m, b.m, 'Same m')
  if ('n' in b) t.same(a.n, b.n, 'Same n')
  if ('pubkeys' in b) t.same(tryMapHex(a.pubkeys), tryMapHex(b.pubkeys), 'Same pubkeys')
  if ('signatures' in b) t.same(tryMapHex(a.signatures), tryMapHex(b.signatures), 'Same signatures')
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
let P2MS_S_SIGNATURES_INCOMPLETE = [OPS.OP_0, OPS.OP_0, signature]
let P2MS_S_INPUT_INCOMPLETE = script.compile(P2MS_S_SIGNATURES_INCOMPLETE)
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
  equate
}
