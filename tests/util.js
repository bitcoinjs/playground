let t = require('assert')
let {
  networks: bnetworks,
  script: bscript
} = require('bitcoinjs-lib')

function tryHex (x) {
  if (Buffer.isBuffer(x)) return x.toString('hex')
  if (Array.isArray(x)) return x.map(tryHex)
  return x
}
function tryASM (x) {
  if (Buffer.isBuffer(x)) return bscript.toASM(x)
  return x
}
function asmToBuffer (s) {
  if (s === '') return Buffer.alloc(0)
  return bscript.fromASM(s)
}
function carryOver (expected, args) {
  for (let k in args) {
    if (k in expected && k === 'redeem') {
      carryOver(expected[k], args[k])
      continue
    }

    // don't, the value was specified
    if (k in expected) continue

    // otherwise, we expect arguments to pass through
    expected[k] = args[k]
  }
}

function equateBase (a, b) {
  if ('output' in b) t.strictEqual(tryASM(a.output), tryASM(b.output))
  if ('input' in b) t.strictEqual(tryASM(a.input), tryASM(b.input))
  if ('witness' in b) t.deepEqual(tryHex(a.witness), tryHex(b.witness))
}

function equate (a, b, args) {
  b = Object.assign({}, b)
  carryOver(b, args)

  // by null, we mean 'undefined', but JSON
  if (b.input === null) b.input = undefined
  if (b.output === null) b.output = undefined
  if (b.witness === null) b.witness = undefined
  if (b.redeem) {
    if (b.redeem.input === null) b.redeem.input = undefined
    if (b.redeem.output === null) b.redeem.output = undefined
    if (b.redeem.witness === null) b.redeem.witness = undefined
  }

  equateBase(a, b)
  if (b.redeem) equateBase(a.redeem, b.redeem)
  if (b.network) t.deepEqual(a.network, b.network)

  // contextual
  if ('address' in b) t.strictEqual(a.address, b.address)
  if ('hash' in b) t.strictEqual(tryHex(a.hash), tryHex(b.hash))
  if ('pubkey' in b) t.strictEqual(tryHex(a.pubkey), tryHex(b.pubkey))
  if ('signature' in b) t.strictEqual(tryHex(a.signature), tryHex(b.signature))
  if ('m' in b) t.strictEqual(a.m, b.m)
  if ('n' in b) t.strictEqual(a.n, b.n)
  if ('pubkeys' in b) t.deepEqual(tryHex(a.pubkeys), tryHex(b.pubkeys))
  if ('signatures' in b) t.deepEqual(tryHex(a.signatures), tryHex(b.signatures))
}

function preform (x) {
  x = Object.assign({}, x)

  if (x.network) x.network = bnetworks[x.network]
  if (typeof x.output === 'string') x.output = asmToBuffer(x.output)
  if (typeof x.input === 'string') x.input = asmToBuffer(x.input)
  if (Array.isArray(x.witness)) x.witness = x.witness.map(function (y) { return Buffer.from(y, 'hex') })

  if (x.hash) x.hash = Buffer.from(x.hash, 'hex')
  if (x.pubkey) x.pubkey = Buffer.from(x.pubkey, 'hex')
  if (x.signature) x.signature = Buffer.from(x.signature, 'hex')
  if (x.pubkeys) x.pubkeys = x.pubkeys.map(function (y) { return Buffer.from(y, 'hex') })
  if (x.signatures) x.signatures = x.signatures.map(function (y) { return Number.isFinite(y) ? y : Buffer.from(y, 'hex') })
  if (x.redeem) {
    if (typeof x.redeem.input === 'string') x.redeem.input = asmToBuffer(x.redeem.input)
    if (typeof x.redeem.output === 'string') x.redeem.output = asmToBuffer(x.redeem.output)
    if (Array.isArray(x.redeem.witness)) x.redeem.witness = x.redeem.witness.map(function (y) { return Buffer.from(y, 'hex') })
    x.redeem.network = bnetworks[x.redeem.network] || bnetworks.bitcoin
  }

  return x
}

module.exports = {
  equate,
  preform
}
