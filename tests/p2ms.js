let {
  ECPair,
  opcodes: OPS,
  script: bscript
} = require('bitcoinjs-lib')
let tape = require('tape')
let { p2wsh, p2sh, p2ms } = require('../scripts')

tape('throws with not enough data', (t) => {
  t.plan(1)
  t.throws(() => {
    p2ms({})
  }, /Not enough data/)
})

tape('derives output only', (t) => {
  let keyPairs = [
    'KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42',
    'Kys5pPp2GAy8GZW5tkdEAHF1DQbN8mMmpfvBEvbF4u9CWfFGKge5',
    'L2yA6eWsYmR8fGKS8XThWeBp4Fze1P8trC8hKsvudYywjMZMaasR'
  ].map(x => ECPair.fromWIF(x))
  let pubkeys = keyPairs.map(x => x.getPublicKeyBuffer())

  let result1 = p2ms({ m: 2, pubkeys })
  t.same(result1.m, 2)
  t.same(result1.n, 3)
  t.same(result1.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')
  t.end()
})

tape('derives everything', (t) => {
  let keyPairs = [
    'KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42',
    'Kys5pPp2GAy8GZW5tkdEAHF1DQbN8mMmpfvBEvbF4u9CWfFGKge5',
    'L2yA6eWsYmR8fGKS8XThWeBp4Fze1P8trC8hKsvudYywjMZMaasR'
  ].map(x => ECPair.fromWIF(x))
  let pubkeys = keyPairs.map(x => x.getPublicKeyBuffer())
  let signatures = keyPairs.slice(1).map(x => x.sign(Buffer.alloc(32)).toScriptSignature(0x01))

  let result1 = p2ms({ m: 2, pubkeys, signatures })
  t.same(result1.m, 2)
  t.same(result1.n, 3)
  t.same(result1.input.toString('hex'), '0048304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301473044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe001')
  t.same(result1.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')

  let result2 = p2sh({ redeem: p2ms({ m: 2, pubkeys, signatures }) })
  t.same(result2.address, '3La374ybb3kpJ1noXJgShcMU7Yk6G4b8FA')
  t.same(result2.redeem.m, 2)
  t.same(result2.redeem.n, 3)
  t.same(result2.redeem.input.toString('hex'), '0048304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301473044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe001')
  t.same(result2.redeem.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')
  t.same(result2.input.toString('hex'), '0048304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301473044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe0014c69522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')
  t.same(result2.output.toString('hex'), 'a914cf1876e34c4b234421f1a9d17f946dcdd4e0867787')

  let result3 = p2wsh({ redeem: p2ms({ m: 2, pubkeys, signatures }) })
  t.same(result3.address, 'bc1qw2m46pffl5flnsj445cplfrrp82hj6dvxu79xss2yufwh8zfu9cs30ky5y')
  t.same(result3.redeem.m, 2)
  t.same(result3.redeem.n, 3)
  t.same(result3.redeem.input, undefined)
  t.same(result3.redeem.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')
  t.same(result3.redeem.witness.length, 3)
  t.same(result3.redeem.witness[0].toString('hex'), '') // OP_0
  t.same(result3.redeem.witness[1].toString('hex'), '304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301')
  t.same(result3.redeem.witness[2].toString('hex'), '3044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe001')
  t.same(result3.input.toString('hex'), '')
  t.same(result3.output.toString('hex'), '002072b75d0529fd13f9c255ad301fa46309d57969ac373c53420a2712eb9c49e171')
  t.same(result3.witness.length, 4)
  t.same(result3.witness[0].toString('hex'), '') // OP_0
  t.same(result3.witness[1].toString('hex'), '304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301')
  t.same(result3.witness[2].toString('hex'), '3044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe001')
  t.same(result3.witness[3].toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')

  let result4 = p2sh({ redeem: { input: result1.input, output: result1.output, network: result1.network } })
  t.same(result4.address, '3La374ybb3kpJ1noXJgShcMU7Yk6G4b8FA')
  t.same(result4.redeem.input.toString('hex'), '0048304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301473044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe001')
  t.same(result4.redeem.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')
  t.same(result4.input.toString('hex'), '0048304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301473044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe0014c69522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')
  t.same(result4.output.toString('hex'), 'a914cf1876e34c4b234421f1a9d17f946dcdd4e0867787')

  let result5 = p2wsh({ redeem: { input: result1.input, output: result1.output, network: result1.network } })
  t.same(result5.address, 'bc1qw2m46pffl5flnsj445cplfrrp82hj6dvxu79xss2yufwh8zfu9cs30ky5y')
  t.same(result5.redeem.input, undefined) // different! we transformed redeem.input to a witness stack
  t.same(result5.redeem.witness.length, 3)
  t.same(result5.redeem.witness[0].toString('hex'), '') // OP_0
  t.same(result5.redeem.witness[1].toString('hex'), '304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301')
  t.same(result5.redeem.witness[2].toString('hex'), '3044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe001')
  t.same(result5.redeem.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')
  t.same(result5.input.toString('hex'), '')
  t.same(result5.output.toString('hex'), '002072b75d0529fd13f9c255ad301fa46309d57969ac373c53420a2712eb9c49e171')
  t.same(result5.witness.length, 4)
  t.same(result5.witness[0].toString('hex'), '') // OP_0
  t.same(result5.witness[1].toString('hex'), '304502210095f184337a2be4c6a31dc3835045fb462844c41fd4e876d8e018513e5aa3f2a902200cb2fc719df8356c8ac6b03397651dc39baf5984375e6aadd1dfe75e6874654301')
  t.same(result5.witness[2].toString('hex'), '3044022062f97b9bfd402afa9db670fc746597aced9e827a8a305485a84e472495b9c2000220434432ca8050a8106511cca160774d33a1e91eb54a29014a4b93dae27db6ebe001')
  t.same(result5.witness[3].toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd283058210310ca07a66272760b08e611004b30f87fa5a25798b5803df68fc81d86e4d19fc42102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa53ae')

  t.end()
})

tape('derives malformed WIP P2MS', (t) => {
  let keyPairs = [
    'KxJknBSZjp9WwnrgkvfG1zpHtuEqRjcnsr9RFpxWnk2GNJbkGe42',
    'L2yA6eWsYmR8fGKS8XThWeBp4Fze1P8trC8hKsvudYywjMZMaasR'
  ].map(x => ECPair.fromWIF(x))
  let pubkeys = keyPairs.map(x => x.getPublicKeyBuffer())
  let signatures = [
    keyPairs[0].sign(Buffer.alloc(32)).toScriptSignature(0x01),
    OPS.OP_0
  ]

  let result1 = p2ms({ m: 2, pubkeys, signatures, allowIncomplete: true })
  t.same(result1.m, 2)
  t.same(result1.n, 2)
  t.same(bscript.toASM(result1.input), 'OP_0 304402203f016fdb065b990a23f6b5735e2ef848e587861f620500ce35a2289da08a8c2802204ab76634cb4ca9646908941690272ce4115d54e78e0584008ec90f624c3cdd2301 OP_0')
  t.same(result1.output.toString('hex'), '522103e15819590382a9dd878f01e2f0cbce541564eb415e43b440472d883ecd2830582102eab44de9d1834ce26a690e32e7247ec9beaa9c3e0afa9cc92c7160c06201ecfa52ae')

  t.throws(() => {
    p2ms({ m: 2, pubkeys, signatures })
  }, /got Number 0/)

  t.end()
})
