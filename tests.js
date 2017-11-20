let {
  crypto: bcrypto,
  ECPair,
  script: bscript
} = require('bitcoinjs-lib')
let tape = require('tape')
let typef = require('typeforce')
let { p2pk, p2pkh, p2wpkh, p2sh, p2wsh, p2ms } = require('./scripts')

let keyPair = ECPair.makeRandom()
let pubkey = keyPair.getPublicKeyBuffer()
let signature = keyPair.sign(Buffer.alloc(32)).toScriptSignature(0x01)

let result1 = p2pkh({ pubkey, signature })
let result2 = p2pkh({ pubkey })
let result3 = p2sh({ redeem: p2pkh({ pubkey }) })

tape('derives everything', (t) => {
  function hasEverything (a) {
    return typef({
      address: typef.String,
      hash: typef.BufferN(20),
      input: typef.Buffer,
      network: typef.Object,
      output: typef.BufferN(25),
      pubkey: bscript.isCanonicalPubKey,
      signature: bscript.isCanonicalSignature
    }, a)
  }

  t.plan(2)
  t.ok(hasEverything(p2pkh({ pubkey, signature })))
  t.ok(hasEverything(p2pkh({ input: result1.input })))
})

tape('derives output only', (t) => {
  function hasSome (a) {
    return typef({
      address: typef.String,
      hash: typef.BufferN(20),
      input: typef.maybe(typef.Buffer),
      network: typef.Object,
      output: typef.BufferN(25),
      pubkey: typef.maybe(bscript.isCanonicalPubKey),
      signature: typef.maybe(bscript.isCanonicalSignature)
    }, a)
  }

  t.plan(3)
  t.ok(hasSome(p2pkh({ pubkey })))
  t.ok(hasSome(p2pkh({ hash: bcrypto.hash160(pubkey) })))
  t.ok(hasSome(p2pkh({ output: result2.output })))
})
