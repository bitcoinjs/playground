let {
  ECPair
} = require('bitcoinjs-lib')
let tape = require('tape')
let p2ms = require('../p2ms')
let p2pk = require('../p2pk')
let p2pkh = require('../p2pkh')
let p2sh = require('../p2sh')
let p2wpkh = require('../p2wpkh')

let keyPair = ECPair.fromWIF('KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42')
let pubkey = keyPair.getPublicKeyBuffer()
let signature = keyPair.sign(Buffer.alloc(32)).toScriptSignature(0x01)
let hash = Buffer.alloc(20, 0x01)

tape('throws with not enough data', (t) => {
  t.plan(1)
  t.throws(() => {
    p2sh({})
  }, /Not enough data/)
})

function tryHex (x) { return Buffer.isBuffer(x) ? x.toString('hex') : x }
function tryMapHex (x) { return Array.isArray(x) ? x.map(tryHex) : x }
function tsame (t, a, b) {
  if ('address' in b) t.same(a.address, b.address, 'Same address')
  if ('output' in b) t.same(tryHex(a.output), tryHex(b.output), 'Same output')
  if ('hash' in b) t.same(tryHex(a.hash), tryHex(b.hash), 'Same hash(output)')
  if ('input' in b) t.same(tryHex(a.input), tryHex(b.input), 'Same input')
  if ('witness' in b) {
    t.same(tryMapHex(a.witness), tryMapHex(b.witness), 'Same witness')
  }
  if (b.network) t.equal(a.network, b.network)
  if (b.redeem) {
    if ('output' in b.redeem) t.same(tryHex(a.redeem.output), tryHex(b.redeem.output), 'Same redeem output')
    if ('input' in b.redeem) t.same(tryHex(a.redeem.input), tryHex(b.redeem.input), 'Same redeem input')
    if ('witness' in b.redeem) {
      t.same(tryMapHex(a.redeem.witness), tryMapHex(b.redeem.witness), 'Same redeem witness')
    }
  }
}

let P2PK_EXAMPLE = p2pk({ pubkey })
let P2PKH_EXAMPLE = p2pkh({ pubkey })
let P2WPKH_EXAMPLE = p2wpkh({ pubkey })
let P2WPKH_S_EXAMPLE = p2wpkh({ pubkey, signature })
let P2PKH_S_EXAMPLE = p2pkh({ pubkey, signature })
let P2PK_S_EXAMPLE = p2pk({ pubkey, signature })
let P2MS_S_EXAMPLE = p2ms({
  m: 2,
  pubkeys: [pubkey, pubkey, pubkey, pubkey],
  signatures: [signature, signature]
})

tape('derives output', (t) => {
  tsame(t, p2sh({ address: '31nKoVLBc2BXUeKQKhnimyrt9DD12VwG6p' }), {
    address: '31nKoVLBc2BXUeKQKhnimyrt9DD12VwG6p',
    output: 'a914010101010101010101010101010101010101010187',
    hash: '0101010101010101010101010101010101010101'
  })

  tsame(t, p2sh({ hash }), {
    address: '31nKoVLBc2BXUeKQKhnimyrt9DD12VwG6p',
    output: 'a914010101010101010101010101010101010101010187',
    hash: '0101010101010101010101010101010101010101'
  })
  tsame(t, p2sh({
    output: Buffer.from('a914010101010101010101010101010101010101010187', 'hex')
  }), {
    address: '31nKoVLBc2BXUeKQKhnimyrt9DD12VwG6p',
    output: 'a914010101010101010101010101010101010101010187',
    hash: '0101010101010101010101010101010101010101'
  })

  tsame(t, p2sh({ redeem: P2PKH_EXAMPLE }), {
    address: '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT',
    redeem: {
      address: '1JnHvAd2m9YqykjpF11a4y59hpt5KoqRmn',
      hash: 'c30afa58ae0673b00a45b5c17dff4633780f1400',
      output: '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac'
    }
  })

  tsame(t, p2sh({ redeem: P2WPKH_EXAMPLE }), {
    address: '325CuTNSYmvurXaBmhNFer5zDkKnDXZggu',
    redeem: {
      address: 'bc1qcv905k9wqeemqzj9khqhml6xxduq79qqy745vn',
      hash: 'c30afa58ae0673b00a45b5c17dff4633780f1400',
      output: '0014c30afa58ae0673b00a45b5c17dff4633780f1400'
    }
  })

  tsame(t, p2sh({ redeem: P2PK_EXAMPLE }), {
    address: '36TibC8RrPB9WrBdPoGXhHqDHJosyFVtVQ',
    redeem: {
      output: '2103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058ac'
    }
  })

  t.end()
})

tape('supports recursion, better or worse', (t) => {
  let base = p2sh({ redeem: P2PKH_S_EXAMPLE })
  tsame(t, base, {
    address: '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT',
    redeem: {
      address: '1JnHvAd2m9YqykjpF11a4y59hpt5KoqRmn',
      hash: 'c30afa58ae0673b00a45b5c17dff4633780f1400',
      output: '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac'
    },
    input: '47304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd23012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd2830581976a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
    witness: undefined
  })

  let depth1 = p2sh({ redeem: base })
  tsame(t, depth1, {
    address: '31vZNjEeCDbwAbgpXX5NV9H3exzKmMakn8',
    redeem: {
      address: '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT',
      hash: '9f840a5fc02407ef0ad499c2ec0eb0b942fb0086',
      output: 'a9149f840a5fc02407ef0ad499c2ec0eb0b942fb008687'
    },
    input: '47304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd23012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd2830581976a914c30afa58ae0673b00a45b5c17dff4633780f140088ac17a9149f840a5fc02407ef0ad499c2ec0eb0b942fb008687',
    witness: undefined
  })

  t.end()
})

tape('derives both, and can be self-derived', (t) => {
  let base = p2sh({ redeem: P2PKH_S_EXAMPLE })
  tsame(t, base, {
    address: '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT',
    hash: '9f840a5fc02407ef0ad499c2ec0eb0b942fb0086',
    output: 'a9149f840a5fc02407ef0ad499c2ec0eb0b942fb008687',
    redeem: {
      address: '1JnHvAd2m9YqykjpF11a4y59hpt5KoqRmn',
      hash: 'c30afa58ae0673b00a45b5c17dff4633780f1400',
      output: '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
      witness: undefined
    },
    input: '47304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd23012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd2830581976a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
    witness: undefined
  })

  // derives from input
  let baseDerived = p2sh({ input: base.input })
  tsame(t, baseDerived, {
    address: '3GETYP4cuSesh2zsPEEYVZqnRedwe4FwUT',
    hash: '9f840a5fc02407ef0ad499c2ec0eb0b942fb0086',
    output: 'a9149f840a5fc02407ef0ad499c2ec0eb0b942fb008687',
    redeem: {
      address: undefined, // missing, as no context
      output: '76a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
      input: base.redeem.input,
      witness: undefined
    },
    input: '47304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd23012103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd2830581976a914c30afa58ae0673b00a45b5c17dff4633780f140088ac',
    witness: undefined
  })

  // P2SH ( P2PK ) - signed
  let c = p2sh({ redeem: P2PK_S_EXAMPLE })
  tsame(t, c, {
    address: '36TibC8RrPB9WrBdPoGXhHqDHJosyFVtVQ',
    redeem: P2PK_S_EXAMPLE,
    input: '47304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd2301232103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058ac',
    witness: undefined
  })

  // self-derivation (from input)
  let d = p2sh({ input: c.input })
  tsame(t, d, {
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
  let base = p2sh({ redeem: P2WPKH_S_EXAMPLE })

  tsame(t, base, {
    address: '325CuTNSYmvurXaBmhNFer5zDkKnDXZggu',
    hash: '0432515d8fe8de31be8207987fc6d67b29d5e7cc',
    output: 'a9140432515d8fe8de31be8207987fc6d67b29d5e7cc87',
    redeem: {
      address: 'bc1qcv905k9wqeemqzj9khqhml6xxduq79qqy745vn'
    },
    input: '160014c30afa58ae0673b00a45b5c17dff4633780f1400',
    witness: [
      '304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd2301',
      '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058'
    ]
  })

  // self-derivation (from input & witness)
  let derived = p2sh({ input: base.input, witness: base.witness })
  tsame(t, derived, {
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
      '304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd2301',
      '03e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058'
    ]
  })

  // self-derivation, from input only, fails
  t.throws(function () {
    p2sh({ input: base.input })
  }, /TypeError: Redeem.input is invalid/)

  t.end()
})
