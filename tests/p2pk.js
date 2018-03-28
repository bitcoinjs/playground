let { ECPair } = require('bitcoinjs-lib')
let tape = require('tape')
let p2pk = require('../p2pk')

tape('throws with not enough data', (t) => {
  t.plan(1)
  t.throws(() => {
    p2pk({})
  }, /Not enough data/)
})

tape('derives output only', (t) => {
  let keyPair = ECPair.fromWIF('KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42')
  let pubkey = keyPair.getPublicKeyBuffer()
  let result1 = p2pk({ pubkey })

  t.plan(5)
  t.same(result1.output.toString('hex'), '2103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058ac')
  t.same(result1.input, undefined)
  t.same(result1.witness, undefined)
  t.same(result1.pubkey, pubkey)
  t.same(result1.signature, undefined)
})

tape('derives both', (t) => {
  let keyPair = ECPair.fromWIF('KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42')
  let pubkey = keyPair.getPublicKeyBuffer()
  let signature = keyPair.sign(Buffer.alloc(32)).toScriptSignature(0x01)
  let result1 = p2pk({ pubkey, signature })

  t.plan(5)
  t.same(result1.output.toString('hex'), '2103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058ac')
  t.same(result1.input.toString('hex'), '47304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd2301')
  t.same(result1.witness, undefined)
  t.same(result1.pubkey, pubkey)
  t.same(result1.signature, signature)
})

tape('throws with bad data', (t) => {
  t.plan(2)
  t.throws(() => {
    p2pk({
      output: Buffer.from('ff00', 'hex')
    })
  }, /Output is invalid/)

  t.throws(() => {
    p2pk({
      output: Buffer.from('ffac', 'hex')
    })
  }, /Output pubkey is invalid/)
})
