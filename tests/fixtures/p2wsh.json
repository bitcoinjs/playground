let p2wsh = require('../p2wsh')
let tape = require('tape')
let u = require('./util')

tape('throws with not enough data', (t) => {
  t.plan(1)
  t.throws(() => {
    p2wsh({})
  }, /Not enough data/)
})

tape('derives from output', (t) => {
  let base = p2wsh({ address: 'bc1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsw9e2a9' })
  u.equate(t, base, {
    address: 'bc1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsw9e2a9',
    output: '00200101010101010101010101010101010101010101010101010101010101010101',
    hash: '0101010101010101010101010101010101010101010101010101010101010101'
  })
  t.same(p2wsh({ hash: base.hash }), base)
  t.same(p2wsh({ output: base.output }), base)

  u.equate(t, p2wsh({ redeem: u.P2PKH_EXAMPLE }), {
    address: 'bc1qusxlgq9quu27ucxs7a2fg8nv0pycdzvxsjk9npyupupxw3y892ss2cq5ar',
    hash: 'e40df400a0e715ee60d0f754941e6c784986898684ac59849c0f026744872aa1',
    output: '0020e40df400a0e715ee60d0f754941e6c784986898684ac59849c0f026744872aa1',
    redeem: u.P2PKH_EXAMPLE
  })

  u.equate(t, p2wsh({ redeem: u.P2WPKH_EXAMPLE }), {
    address: 'bc1qpsl7el8wcx22f3fpdt3lm2wmzug7yyx2q3n8wzgtf37kps9tqy7skc7m3e',
    hash: '0c3fecfceec194a4c5216ae3fda9db1711e210ca046677090b4c7d60c0ab013d',
    output: '00200c3fecfceec194a4c5216ae3fda9db1711e210ca046677090b4c7d60c0ab013d',
    redeem: u.P2WPKH_EXAMPLE
  })

  u.equate(t, p2wsh({ redeem: u.P2PK_EXAMPLE }), {
    address: 'bc1q6rgl33d3s9dugudw7n68yrryajkr3ha9q8q24j20zs62se4q9tsqdy0t2q',
    hash: 'd0d1f8c5b1815bc471aef4f4720c64ecac38dfa501c0aac94f1434a866a02ae0',
    output: '0020d0d1f8c5b1815bc471aef4f4720c64ecac38dfa501c0aac94f1434a866a02ae0',
    redeem: u.P2PK_EXAMPLE
  })

  t.end()
})

tape('derives everything', (t) => {
  let base = p2wsh({ redeem: u.P2WPKH_S_EXAMPLE })
  u.equate(t, base, {
    address: 'bc1qpsl7el8wcx22f3fpdt3lm2wmzug7yyx2q3n8wzgtf37kps9tqy7skc7m3e',
    hash: '0c3fecfceec194a4c5216ae3fda9db1711e210ca046677090b4c7d60c0ab013d',
    output: '00200c3fecfceec194a4c5216ae3fda9db1711e210ca046677090b4c7d60c0ab013d',
    input: '',
    witness: [
      '3045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a9501',
      '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058',
      '0014c30afa58ae0673b00a45b5c17dff4633780f1400'
    ]
  })

  u.equate(t, p2wsh({ witness: base.witness }), base)

  // derives redeem input
  let base2 = p2wsh({ redeem: u.P2PKH_S_EXAMPLE })
  u.equate(t, base2, {
    address: 'bc1qusxlgq9quu27ucxs7a2fg8nv0pycdzvxsjk9npyupupxw3y892ss2cq5ar',
    hash: 'e40df400a0e715ee60d0f754941e6c784986898684ac59849c0f026744872aa1',
    output: '0020e40df400a0e715ee60d0f754941e6c784986898684ac59849c0f026744872aa1',
    redeem: {
      input: '', // different! transformed to a witness stack
      witness: [
        '3045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a9501',
        '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058'
      ]
    },
    input: '',
    witness: [
      '3045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a9501',
      '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058',
      '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac'
    ]
  })

  t.end()
})

tape('recurses... even if that will never work', (t) => {
  let base = p2wsh({ redeem: u.P2PKH_S_EXAMPLE })
  t.same(base.address, 'bc1qusxlgq9quu27ucxs7a2fg8nv0pycdzvxsjk9npyupupxw3y892ss2cq5ar')

  let depth1 = p2wsh({ redeem: base })
  t.same(depth1.address, 'bc1qjq4h58fg22ty65pznrm4v9lsd2djty2qymdr725rcydxlmfd6ymqrsg8wy')

  let depth2 = p2wsh({ redeem: depth1 })
  u.equate(t, depth2, {
    address: 'bc1qeulza7498qu5ugxv7d76nnsl432sy7kyp09ajxurl5v9pmwnzafq5h93y9',
    input: '',
    witness: [
      '3045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a9501',
      '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058',
      '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac', // base
      '0020e40df400a0e715ee60d0f754941e6c784986898684ac59849c0f026744872aa1', // depth1
      '0020902b7a1d2852964d502298f75617f06a9b25914026da3f2a83c11a6fed2dd136' // depth2
    ]
  })

  t.end()
})
