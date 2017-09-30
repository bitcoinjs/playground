function intAdd (a, b) {
  var A = BigInteger.fromBuffer(a)
  var B = BigInteger.fromBuffer(b)

  return A.add(B).toBuffer(32)
}

function intCheck (a) {
  var A = BigInteger.fromBuffer(a)

  return A.signum() > 0 && A.compareTo(secp256k1.n) < 0
}

function intSign (a) {
  return BigInteger.fromBuffer(a).signum()
}

function pointAdd (p, q) {
  var P = ecurve.Point.decodeFrom(p)
  var Q = ecurve.Point.decodeFrom(q)
  var R = P.add(Q)

  if (secp256k1.isInfinity(R)) return null
  return R.getEncoded(P.compressed)
}

function pointDerive (d, compressed) {
  return secp256k1.G.multiply(d).getEncoded(compressed)
}

function pointVerify (q) {
  var Q = ecurve.Point.decodeFrom(q)

  return secp256k1.validate(Q)
}

module.exports = {
  calcPubKeyRecoveryParam: calcPubKeyRecoveryParam,
  deterministicGenerateK: deterministicGenerateK,
  recoverPubKey: recoverPubKey,
  sign: sign,
  verify: verify,

  intAdd: intAdd,
  intCheck: intCheck,
  intSign: intSign,
  pointAdd: pointAdd,
  pointDerive: pointDerive,
  pointVerify: pointVerify
}
