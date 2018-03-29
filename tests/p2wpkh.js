let { ECPair } = require('bitcoinjs-lib')
let tape = require('tape')
let p2wpkh = require('../p2wpkh')

tape('throws with not enough data', (t) => {
  t.plan(1)
  t.throws(() => {
    p2wpkh({})
  }, /Not enough data/)
})

tape('derives output only', (t) => {
  let keyPair = ECPair.fromWIF('KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42')
  let pubkey = keyPair.getPublicKeyBuffer()
  let result1 = p2wpkh({ pubkey })

  t.plan(7)
  t.same(result1.output.toString('hex'), '0014c30afa58ae0673b00a45b5c17dff4633780f1400')
  t.same(result1.input.toString('hex'), '')
  t.same(result1.witness, undefined)
  t.same(result1.pubkey.toString('hex'), '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058')
  t.same(result1.signature, undefined)
  t.same(result1.address, 'bc1qcv905k9wqeemqzj9khqhml6xxduq79qqy745vn')
  t.same(result1.hash.toString('hex'), 'c30afa58ae0673b00a45b5c17dff4633780f1400')
})

tape('derives both', (t) => {
  let keyPair = ECPair.fromWIF('KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42')
  let pubkey = keyPair.getPublicKeyBuffer()
  let signature = keyPair.sign(Buffer.alloc(32)).toScriptSignature(0x01)
  let result1 = p2wpkh({ pubkey, signature })

  t.plan(9)
  t.same(result1.output.toString('hex'), '0014c30afa58ae0673b00a45b5c17dff4633780f1400')
  t.same(result1.input.toString('hex'), '')
  t.same(result1.witness.length, 2)
  t.same(result1.witness[0].toString('hex'), '304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd2301')
  t.same(result1.witness[1].toString('hex'), '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058')
  t.same(result1.pubkey.toString('hex'), '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058')
  t.same(result1.signature.toString('hex'), '304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd2301')
  t.same(result1.address, 'bc1qcv905k9wqeemqzj9khqhml6xxduq79qqy745vn')
  t.same(result1.hash.toString('hex'), 'c30afa58ae0673b00a45b5c17dff4633780f1400')
})
