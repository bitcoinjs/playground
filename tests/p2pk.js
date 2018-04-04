let tape = require('tape')
let p2pk = require('../p2pk')
let u = require('./util')

tape('throws with not enough, or bad data', (t) => {
  t.throws(() => {
    p2pk({})
  }, /Not enough data/)

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

  t.end()
})

tape('derives output only', (t) => {
  let base = p2pk({ pubkey: u.PUBKEY })
  u.equate(t, base, {
    address: undefined, // p2pk has no address
    output: '2103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058ac',
    pubkey: u.PUBKEY,
    signature: undefined,
    input: undefined,
    witness: undefined
  })

  t.same(p2pk({ output: base.output }), base)
  t.end()
})

tape('derives from input and output', (t) => {
  let base = p2pk({ pubkey: u.PUBKEY, signature: u.SIGNATURE })
  u.equate(t, base, {
    address: undefined, // p2pk has no address
    output: '2103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058ac',
    pubkey: u.PUBKEY,
    signature: '3045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a9501',
    input: '483045022100e4fce9ec72b609a2df1dc050c20dcf101d27faefb3e686b7a4cb067becdd5e8e022071287fced53806b08cf39b5ad58bbe614775b3776e98a9f8760af0d4d1d47a9501',
    witness: undefined
  })

  t.same(p2pk({ output: base.output, input: base.input }), base)
  t.end()
})
