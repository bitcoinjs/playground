let tape = require('tape')
let p2wpkh = require('../p2wpkh')
let u = require('./util')

tape('throws with not enough data', (t) => {
  t.plan(1)
  t.throws(() => {
    p2wpkh({})
  }, /Not enough data/)
})

tape('derives output only', (t) => {
  let base = p2wpkh({ hash: u.HASH20 })

  u.equate(t, base, {
    address: 'bc1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpyfl4f3',
    hash: '0101010101010101010101010101010101010101',
    output: '00140101010101010101010101010101010101010101',
    pubkey: undefined,
    signature: undefined,
    input: undefined,
    witness: undefined
  })
  u.equate(t, p2wpkh({ address: base.address }), base)
  u.equate(t, p2wpkh({ hash: base.hash }), base)
  u.equate(t, p2wpkh({ output: base.output }), base)
  t.end()
})

tape('derives both', (t) => {
  let base = p2wpkh({ pubkey: u.PUBKEY, signature: u.SIGNATURE })
  u.equate(t, base, {
    address: 'bc1qcv905k9wqeemqzj9khqhml6xxduq79qqy745vn',
    hash: 'c30afa58ae0673b00a45b5c17dff4633780f1400',
    output: '0014c30afa58ae0673b00a45b5c17dff4633780f1400',
    pubkey: u.PUBKEY,
    signature: u.SIGNATURE,
    input: '',
    witness: [
      '3045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a9501',
      '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058'
    ]
  })

  // derives from witness
  t.same(p2wpkh({ witness: base.witness }), base)

  t.end()
})
