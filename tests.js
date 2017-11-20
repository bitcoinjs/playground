let {
  crypto: bcrypto,
  ECPair,
  script: bscript
} = require('bitcoinjs-lib')
let tape = require('tape')
let types = require('bitcoinjs-lib/src/types')
let typeforce = require('typeforce')
let { p2pk, p2pkh, p2wpkh, p2sh, p2wsh, p2ms } = require('./scripts')

let keyPair = ECPair.makeRandom()
let pubkey = keyPair.getPublicKeyBuffer()
let signature = keyPair.sign(Buffer.alloc(32)).toScriptSignature(0x01)

let result1 = p2pkh({ pubkey, signature })
let result2 = p2pkh({ pubkey })

tape('derives everything', (t) => {
  function hasEverything (a) {
    return typeforce({
      hash: types.Hash160bit,
      input: types.Buffer,
      output: types.BufferN(25),
      pubkey: bscript.isCanonicalPubKey,
      signature: bscript.isCanonicalSignature
  //      address: types.maybe(types.Base58),
  //      network: types.maybe(types.Network)
    }, a)
  }

  t.plan(2)
  t.ok(hasEverything(p2pkh({ pubkey, signature })))
  t.ok(hasEverything(p2pkh({ input: result1.input })))
})

tape('derives output only', (t) => {
  function hasSome (a) {
    return typeforce({
      hash: types.Hash160bit,
      output: types.BufferN(25)
  //      address: types.maybe(types.Base58),
  //      network: types.maybe(types.Network)
    }, a)
  }

  t.plan(3)
  t.ok(hasSome(p2pkh({ pubkey })))
  t.ok(hasSome(p2pkh({ hash: bcrypto.hash160(pubkey) })))
  t.ok(hasSome(p2pkh({ output: result2.output })))
})

module.exports = {
  p2pk, p2pkh, p2wpkh, p2sh, p2wsh, p2ms
}
