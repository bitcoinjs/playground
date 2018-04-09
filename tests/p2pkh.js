let p2pkh = require('../p2pkh')
let tape = require('tape')
let u = require('./util')
let fixtures = require('./fixtures/p2pkh')

fixtures.valid.forEach(function (f, i) {
  tape('returns for ' + (f.description || ('vector ' + i)), function (t) {
    let args = u.preform(f.arguments)
    let actual = p2pkh(args, f.options)

    u.equate(t, actual, f.expected)
    t.end()
  })
})

fixtures.invalid.forEach(function (f) {
  tape('throws ' + (f.description || f.exception), function (t) {
    let args = u.preform(f.arguments)

    t.plan(1)
    t.throws(function () {
      p2pkh(args, f.options)
    }, new RegExp(f.exception))
  })
})

tape('derives output only', (t) => {
  let base = p2pkh({ hash: u.HASH20 })
  u.equate(t, base, {
    address: '16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf',
    hash: '0101010101010101010101010101010101010101',
    output: '76a914010101010101010101010101010101010101010188ac',
    pubkey: undefined,
    signature: undefined,
    input: undefined,
    witness: undefined
  })
  t.same(p2pkh({ address: base.address }), base)
  t.same(p2pkh({ hash: base.hash }), base)
  t.same(p2pkh({ output: base.output }), base)

  let base2 = p2pkh({ pubkey: u.PUBKEY })
  u.equate(t, base2, {
    address: '1JnHvAd2m9YqykjpF11a4y59hpt5KoqRmn',
    hash: 'c30afa58ae0673b00a45b5c17dff4633780f1400',
    output: '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
    pubkey: u.PUBKEY,
    signature: undefined,
    input: undefined,
    witness: undefined
  })
  t.end()
})

tape('derives from input', (t) => {
  let base = p2pkh({ pubkey: u.PUBKEY, signature: u.SIGNATURE })
  u.equate(t, base, {
    address: '1JnHvAd2m9YqykjpF11a4y59hpt5KoqRmn',
    hash: 'c30afa58ae0673b00a45b5c17dff4633780f1400',
    output: '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
    pubkey: u.PUBKEY,
    signature: u.SIGNATURE,
    input: '483045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a95012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058',
    witness: undefined
  })

  // derives from input
  t.same(p2pkh({ input: base.input }), base)

  t.end()
})
