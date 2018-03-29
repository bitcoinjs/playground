let {
  ECPair,
  opcodes: OPS,
  script: bscript
} = require('bitcoinjs-lib')
let tape = require('tape')
let p2ms = require('../p2ms')

let keyPairs = [
  'KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42',
  'Kys5pPp2GAy8GZW5tkdEAHF1DQbN8mMmpfvBEvbF4u9CWfFGKge5',
  'L2yA6eWsYmR8fGKS8XThWeBp4Fze1P8trC8hKsvudYywjMZMaasR'
].map(x => ECPair.fromWIF(x))
let pubkeys = keyPairs.map(x => x.getPublicKeyBuffer())
let signatures = keyPairs.slice(1).map(x => x.sign(Buffer.alloc(32)).toScriptSignature(0x01))

tape('throws with not enough data', (t) => {
  t.plan(3)
  t.throws(() => {
    p2ms({})
  }, /Not enough data/)

  t.throws(() => {
    p2ms({ pubkeys })
  }, /Not enough data/)

  t.throws(() => {
    p2ms({ pubkeys, m: 4 })
  }, /Not enough pubKeys provided/)
})

tape('derives output only', (t) => {
  let result1 = p2ms({ m: 2, pubkeys })
  t.same(result1.m, 2)
  t.same(result1.n, 3)
  t.same(result1.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')

  let result2 = p2ms({ output: result1.output })
  t.same(result2.m, 2)
  t.same(result2.n, 3)
  t.same(result2.pubkeys, pubkeys)
  t.same(result2.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')

  let result3 = p2ms({ output: result1.output, pubkeys })
  t.same(result3.m, 2)
  t.same(result3.n, 3)
  t.same(result3.pubkeys, pubkeys)
  t.same(result3.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')

  let result4 = p2ms({ m: 1, pubkeys })
  t.same(result4.m, 1)
  t.same(result4.n, 3)
  t.same(result4.output.toString('hex'), '512103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')

  let result5 = p2ms({ output: result1.output })
  t.same(result5.m, 2)
  t.same(result5.n, 3)
  t.same(result5.pubkeys, pubkeys)
  t.same(result5.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')

  t.end()
})

tape('derives both', (t) => {
  let result1 = p2ms({ m: 2, pubkeys, signatures })
  t.same(result1.m, 2)
  t.same(result1.n, 3)
  t.same(result1.input.toString('hex'), '0048304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301473044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe001')
  t.same(result1.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')
  t.same(result1.pubkeys, pubkeys)
  t.same(result1.signatures, signatures)

  let result2 = p2ms({ output: result1.output, signatures })
  t.same(result2.m, 2)
  t.same(result2.n, 3)
  t.same(result2.input.toString('hex'), '0048304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301473044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe001')
  t.same(result2.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')
  t.same(result2.pubkeys, pubkeys)
  t.same(result2.signatures, signatures)

  t.end()
})

tape('derives incomplete', (t) => {
  let pubkeys2 = pubkeys.slice(1)
  let signaturesIncomplete = [
    signatures[0],
    OPS.OP_0
  ]

  let result1 = p2ms({
    m: 2,
    pubkeys: pubkeys2,
    signatures: signaturesIncomplete,
    allowIncomplete: true
  })
  t.same(result1.m, 2)
  t.same(result1.n, 2)
  t.same(bscript.toASM(result1.input), 'OP_0 304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301 OP_0')
  t.same(result1.output.toString('hex'), '52210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa52ae')

  t.throws(() => {
    p2ms({ m: 2, pubkeys, signatures: signaturesIncomplete })
  }, /got Number 0/)

  t.end()
})
