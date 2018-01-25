let {
  crypto: bcrypto,
  ECPair,
  script: bscript
} = require('bitcoinjs-lib')
let tape = require('tape')
let typef = require('typeforce')
let { p2pkh, p2wsh } = require('../scripts')
let EMPTY_BUFFER = Buffer.alloc(0)

tape('can recover input (dewitnessify)', (t) => {
  let keyPair = ECPair.fromWIF('KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42')
  let pubkey = keyPair.getPublicKeyBuffer()
  let signature = keyPair.sign(Buffer.alloc(32)).toScriptSignature(0x01)

  // see p2sh/result3 for test data match here
  let result1 = p2wsh({ redeem: p2pkh({ pubkey, signature }) })
  t.same(result1.input, EMPTY_BUFFER)
  t.same(result1.witness.length, 3)
  // ... match witness

  let recover1 = p2wsh({
    address: result1.address,
    witness: result1.witness
  })

  // TODO: stack()/unstack() could be a function on its own... solely.  The usage is very niche specific,  aka,  for specific hardcore TX development.
  // These tools dont need that over-generalization?  And if they did,  we could easily extend the API!
  // The stack/unstack approach supports that.
  // -- We could also isolate these tools to TXB for now if needed.

  console.log(recover1)
  return t.end()

  let recover2 = p2pkh(recover1.redeem)
  t.same(recover2.input.toString('hex'), '47304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd23012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058')
  t.end()
})

return

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

  let keyPair = ECPair.makeRandom()
  let pubkey = keyPair.getPublicKeyBuffer()
  let signature = keyPair.sign(Buffer.alloc(32)).toScriptSignature(0x01)
  let result1 = p2pkh({ pubkey, signature })

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

  let keyPair = ECPair.makeRandom()
  let pubkey = keyPair.getPublicKeyBuffer()
  let result2 = p2pkh({ pubkey })

  t.plan(3)
  t.ok(hasSome(p2pkh({ pubkey })))
  t.ok(hasSome(p2pkh({ hash: bcrypto.hash160(pubkey) })))
  t.ok(hasSome(p2pkh({ output: result2.output })))
})

tape('throws with not enough data', (t) => {
  t.plan(1)
  t.throws(() => {
    p2pkh({})
  }, /Not enough data/)
})
