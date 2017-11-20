let {
  ECPair
} = require('bitcoinjs-lib')
let tape = require('tape')
let typef = require('typeforce')
let { p2pkh, p2wpkh, p2sh } = require('../scripts')

tape('throws with not enough data', (t) => {
  t.plan(1)
  t.throws(() => {
    p2sh({})
  }, /Not enough data/)
})

tape('derives output only', (t) => {
  function hasSome (a) {
    return typef({
      address: typef.String,
      hash: typef.BufferN(20),
      network: typef.Object,
      output: typef.BufferN(23)
    }, a)
  }

  t.plan(15)
  let hash = Buffer.alloc(20, 0x01)
  let result1 = p2sh({ hash })
  t.same(result1.address, '31nKoVLBc2BXUeKQKhnimyrt9DD12VwG6p')
  t.same(result1.output.toString('hex'), 'a914010101010101010101010101010101010101010187')
  t.same(result1.hash.toString('hex'), '0101010101010101010101010101010101010101')

  let keyPair = ECPair.fromWIF('KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42')
  let pubkey = keyPair.getPublicKeyBuffer()
  let result2 = p2sh({ redeem: p2pkh({ pubkey }) })

  t.ok(hasSome(result2))
  t.ok(hasSome(p2sh({ output: result2.output })))
  t.same(result2.address, '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT')
  t.same(result2.redeem.address, '1JnHvAd2m9YqykjpF11a4y59hpt5KoqRmn')
  t.same(result2.redeem.hash.toString('hex'), 'c30afa58ae0673b00a45b5c17dff4633780f1400')
  t.same(result2.redeem.output.toString('hex'), '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac')
  t.same(result2.redeem.pubkey.toString('hex'), '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058')

  let result3 = p2sh({ redeem: p2wpkh({ pubkey }) })
  t.same(result3.address, '325CuTNSYmvurXaBmhNFer5zDkKnDXZggu')
  t.same(result3.redeem.address, 'bc1qcv905k9wqeemqzj9khqhml6xxduq79qqy745vn')
  t.same(result3.redeem.hash.toString('hex'), 'c30afa58ae0673b00a45b5c17dff4633780f1400')
  t.same(result3.redeem.output.toString('hex'), '0014c30afa58ae0673b00a45b5c17dff4633780f1400')
  t.same(result3.redeem.pubkey.toString('hex'), '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058')
})
