let p2sh = require('../p2sh')
let tape = require('tape')
let u = require('./util')

tape('throws with not enough data', (t) => {
  t.plan(1)
  t.throws(() => {
    p2sh({})
  }, /Not enough data/)
})

tape('derives output', (t) => {
  u.equate(t, p2sh({ address: '31nKoVLBc2BXUeKQKhnimyrt9DD12VwG6p' }), {
    address: '31nKoVLBc2BXUeKQKhnimyrt9DD12VwG6p',
    output: 'a914010101010101010101010101010101010101010187',
    hash: '0101010101010101010101010101010101010101'
  })

  u.equate(t, p2sh({ hash: u.HASH20 }), {
    address: '31nKoVLBc2BXUeKQKhnimyrt9DD12VwG6p',
    output: 'a914010101010101010101010101010101010101010187',
    hash: '0101010101010101010101010101010101010101'
  })

  u.equate(t, p2sh({ output: u.P2SH_EXAMPLE.output }), {
    address: '31nKoVLBc2BXUeKQKhnimyrt9DD12VwG6p',
    output: 'a914010101010101010101010101010101010101010187',
    hash: '0101010101010101010101010101010101010101'
  })

  u.equate(t, p2sh({ redeem: u.P2PKH_EXAMPLE }), {
    address: '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT',
    hash: '9f840a5fc02407ef0ad499c2ec0eb0b942fb0086',
    output: 'a9149f840a5fc02407ef0ad499c2ec0eb0b942fb008687',
    redeem: u.P2PKH_EXAMPLE
  })

  u.equate(t, p2sh({ redeem: u.P2WPKH_EXAMPLE }), {
    address: '325CuTNSYmvurXaBmhNFer5zDkKnDXZggu',
    hash: '0432515d8fe8de31be8207987fc6d67b29d5e7cc',
    output: 'a9140432515d8fe8de31be8207987fc6d67b29d5e7cc87',
    redeem: u.P2WPKH_EXAMPLE
  })

  u.equate(t, p2sh({ redeem: u.P2PK_EXAMPLE }), {
    address: '36TibC8RrPB9WrBdPoGXhHqDHJosyFVtVQ',
    hash: '3454c084887afe854e80221c69d6282926f809c4',
    output: 'a9143454c084887afe854e80221c69d6282926f809c487',
    redeem: u.P2PK_EXAMPLE
  })

  t.end()
})

tape('supports recursion, better or worse', (t) => {
  let base = p2sh({ redeem: u.P2PKH_S_EXAMPLE })
  u.equate(t, base, {
    address: '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT',
    redeem: {
      address: '1JnHvAd2m9YqykjpF11a4y59hpt5KoqRmn',
      hash: 'c30afa58ae0673b00a45b5c17dff4633780f1400',
      output: '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac'
    },
    input: '483045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a95012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd2830581976a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
    witness: undefined
  })

  // derives from output redeem only
  let depth1 = p2sh({ redeem: base })
  u.equate(t, depth1, {
    address: '31vZNjEeCDbwAbgpXX5NV9H3exzKmMakn8',
    redeem: {
      address: '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT',
      hash: '9f840a5fc02407ef0ad499c2ec0eb0b942fb0086',
      output: 'a9149f840a5fc02407ef0ad499c2ec0eb0b942fb008687'
    },
    input: '483045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a95012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd2830581976a914c30afa58ae0673b00a45b5c17dff4633780f140088ac17a9149f840a5fc02407ef0ad499c2ec0eb0b942fb008687',
    witness: undefined
  })

  t.end()
})

tape('derives both, and can be self-derived', (t) => {
  let base = p2sh({ redeem: u.P2PKH_S_EXAMPLE })
  u.equate(t, base, {
    address: '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT',
    hash: '9f840a5fc02407ef0ad499c2ec0eb0b942fb0086',
    output: 'a9149f840a5fc02407ef0ad499c2ec0eb0b942fb008687',
    redeem: {
      address: '1JnHvAd2m9YqykjpF11a4y59hpt5KoqRmn',
      hash: 'c30afa58ae0673b00a45b5c17dff4633780f1400',
      output: '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
      witness: undefined
    },
    input: '483045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a95012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd2830581976a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
    witness: undefined
  })

  // derives from input
  let baseDerived = p2sh({ input: base.input })
  u.equate(t, baseDerived, {
    address: '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT',
    hash: '9f840a5fc02407ef0ad499c2ec0eb0b942fb0086',
    output: 'a9149f840a5fc02407ef0ad499c2ec0eb0b942fb008687',
    redeem: {
      address: undefined, // missing, as no context
      output: '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
      input: base.redeem.input,
      witness: undefined
    },
    input: '483045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a95012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd2830581976a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
    witness: undefined
  })

  // P2SH ( P2PK ) - signed
  let c = p2sh({ redeem: u.P2PK_S_EXAMPLE })
  u.equate(t, c, {
    address: '36TibC8RrPB9WrBdPoGXhHqDHJosyFVtVQ',
    redeem: u.P2PK_S_EXAMPLE,
    input: '483045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a9501232103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058ac',
    witness: undefined
  })

  // self-derivation (from input)
  let d = p2sh({ input: c.input })
  u.equate(t, d, {
    address: c.address,
    hash: c.hash,
    output: c.output,
    redeem: {
      output: '2103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058ac',
      witness: undefined
    },
    input: c.input,
    witness: undefined
  })

  t.end()
})

tape('handles witness, incl. minimalist derivation', (t) => {
  // P2SH ( P2WPKH ) - signed
  let base = p2sh({ redeem: u.P2WPKH_S_EXAMPLE })

  u.equate(t, base, {
    address: '325CuTNSYmvurXaBmhNFer5zDkKnDXZggu',
    hash: '0432515d8fe8de31be8207987fc6d67b29d5e7cc',
    output: 'a9140432515d8fe8de31be8207987fc6d67b29d5e7cc87',
    redeem: {
      address: 'bc1qcv905k9wqeemqzj9khqhml6xxduq79qqy745vn'
    },
    input: '160014c30afa58ae0673b00a45b5c17dff4633780f1400',
    witness: [
      '3045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a9501',
      '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058'
    ]
  })

  // self-derivation (from input & witness)
  let derived = p2sh({ input: base.input, witness: base.witness })
  u.equate(t, derived, {
    address: '325CuTNSYmvurXaBmhNFer5zDkKnDXZggu',
    hash: '0432515d8fe8de31be8207987fc6d67b29d5e7cc',
    output: 'a9140432515d8fe8de31be8207987fc6d67b29d5e7cc87',
    redeem: {
      address: undefined, // missing, as no context
      output: base.redeem.output, // derived
      input: base.redeem.input // derived
    },
    input: '160014c30afa58ae0673b00a45b5c17dff4633780f1400',
    witness: [
      '3045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a9501',
      '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058'
    ]
  })

  // self-derivation, from input only, fails
  t.throws(function () {
    p2sh({ input: base.input })
  }, /TypeError: Redeem.input is invalid/)

  t.end()
})
