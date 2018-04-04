let p2ms = require('../p2ms')
let tape = require('tape')
let u = require('./util')

tape('throws with not enough data', (t) => {
  t.throws(() => {
    p2ms({})
  }, /Not enough data/)

  t.throws(() => {
    p2ms({ pubkeys: u.PUBKEYS2 })
  }, /Not enough data/)

  t.throws(() => {
    p2ms({ m: 3, n: 4, pubkeys: u.PUBKEYS3 })
  }, /n Pubkeys mismatch/)

  t.throws(() => {
    p2ms({ m: 4, n: 3, pubkeys: u.PUBKEYS3 })
  }, /Not enough pubkeys provided/)

  t.throws(() => {
    p2ms({ m: 3, n: 3, pubkeys: u.PUBKEYS3, signatures: u.SIGNATURES2 })
  }, /Not enough signatures provided/)

  t.end()
})

tape('derives output only', (t) => {
  let base = p2ms({ m: 2, pubkeys: u.PUBKEYS3 })
  u.equate(t, base, {
    m: 2,
    n: 3,
    output: '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae'
  })

  // derives from output only
  t.same(p2ms({ output: base.output }), base)

  // matches the pubkeys AND the outputs
  t.throws(function () {
    p2ms({ output: base.output, pubkeys: u.PUBKEYS2 })
  }, /Pubkeys mismatch/)

  t.end()
})

tape('derives input and output', (t) => {
  let base = p2ms({ m: 2, pubkeys: u.PUBKEYS3, signatures: u.SIGNATURES2 })
  u.equate(t, base, {
    m: 2,
    n: 3,
    output: '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae',
    pubkeys: u.PUBKEYS3,
    signatures: u.SIGNATURES2,
    input: '0047304402203ca2d4a92e210f9467384ea867d8a9931503266747d6bdc7d3dbd51fd73aadbd022071534d8e65358333bfa92b2bb1f8d3d148084ab03c8142e67cc2e3f989e4525a0147304402206a32818921cfeb9d4780bc0919a6914c8c79fd7db67792e0f6e7a36ac00b3f6202203c4896942ab2993d03d037dc35e208c8f22af1109d7abf25f31c7abc268e323701',
    witness: undefined
  })

  // derives with output and signatures
  t.same(p2ms({ output: base.output, signatures: base.signatures }), base)

  // derives from output/input
  t.same(p2ms({ output: base.output, input: base.input }), base)

  // derives, even if incomplete
  u.equate(t, p2ms({
    output: base.output,
    input: u.P2MS_S_INPUT_INCOMPLETE,
    allowIncomplete: true
  }), {
    m: 2,
    n: 3,
    pubkeys: u.PUBKEYS3, // contextual, derived
    signatures: u.P2MS_S_SIGNATURES_INCOMPLETE // contextual, derived
  })

  t.end()
})
