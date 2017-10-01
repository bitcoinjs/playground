let bn = require('bn.js')
let secp256k1 = require('node-secp256k1')

function intAdd (a, b) {
  var A = bn.fromBuffer(a)
  var B = bn.fromBuffer(b)

  return A.add(B).toBuffer(32)
}

function intCheck (a) {
  var A = bn.fromBuffer(a)

  return A.signum() > 0 && A.compareTo(secp256k1.n) < 0
}

function intSign (a) {
  return bn.fromBuffer(a).signum()
}

function pointAdd (p, q) {
  var P = secp256k1.Point.decodeFrom(p)
  var Q = secp256k1.Point.decodeFrom(q)
  var R = P.add(Q)

  if (secp256k1.isInfinity(R)) return null
  return R.getEncoded(P.compressed)
}

function pointDerive (d, compressed) {
  return secp256k1.G.multiply(d).getEncoded(compressed)
}

function pointVerify (q) {
  var Q = secp256k1.Point.decodeFrom(q)

  return secp256k1.validate(Q)
}

module.exports = {
  intAdd: intAdd,
  intCheck: intCheck,
  intSign: intSign,
  pointAdd: pointAdd,
  pointDerive: pointDerive,
  pointVerify: pointVerify
}
