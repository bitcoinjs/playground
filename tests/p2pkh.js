let tape = require('tape')
let p2pkh = require('../p2pkh')
let u = require('./util')

tape('throws with not enough data', (t) => {
  t.plan(1)
  t.throws(() => {
    p2pkh({})
  }, /Not enough data/)
})

tape('derives output only', (t) => {
  let base = p2pkh({ pubkey: u.PUBKEY })

  u.equate(t, base, {
    address: '',
    hash: '',
    output: '',
    pubkey: u.PUBKEY,
    signature: undefined,
    input: undefined,
    witness: undefined
  })
  u.equate(t, p2pkh({ address: base.address }), base)
  u.equate(t, p2pkh({ hash: base.hash }), base)
  u.equate(t, p2pkh({ output: base.output }), base)
})

tape('derives both', (t) => {
  let keyPair = ECPair.fromWIF('KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42')
  let pubkey = keyPair.getPublicKeyBuffer()
  let signature = keyPair.sign(Buffer.alloc(32)).toScriptSignature(0x01)
  let result1 = p2pkh({ pubkey, signature })

  t.plan(7)
  t.same(result1.output.toString('hex'), '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac')
  t.same(result1.input.toString('hex'), '47304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd23012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058')
  t.same(result1.witness, undefined)
  t.same(result1.pubkey, pubkey)
  t.same(result1.signature, signature)
  t.same(result1.address, '1JnHvAd2m9YqykjpF11a4y59hpt5KoqRmn')
  t.same(result1.hash.toString('hex'), 'c30afa58ae0673b00a45b5c17dff4633780f1400')
})
