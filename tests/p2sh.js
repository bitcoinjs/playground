let {
  ECPair
} = require('bitcoinjs-lib')
let tape = require('tape')
let typef = require('typeforce')
let { p2pkh, p2sh } = require('../scripts')

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
      output: typef.BufferN(25)
    }, a)
  }

  t.plan(5)
  let hash = Buffer.alloc(20, 0x01)
  let result1 = p2sh({ hash })
  t.same(result1.address, '31nKoVLBc2BXUeKQKhnimyrt9DD12VwG6p')
  t.same(result1.output.toString('hex'), 'a914010101010101010101010101010101010101010187')
  t.same(result1.hash.toString('hex'), '0101010101010101010101010101010101010101')

  let keyPair = ECPair.makeRandom()
  let pubkey = keyPair.getPublicKeyBuffer()
  let result2 = p2sh({ redeem: p2pkh({ pubkey }) })

  t.ok(hasSome(result2))
  t.ok(hasSome(p2sh({ output: result2.output })))
})
