var SOLVE_TYPES = {}
SOLVE_TYPES[scriptTypes.MULTISIG] = [types.tuple(ECPair, types.maybe(types.Number))]
SOLVE_TYPES[scriptTypes.P2PKH] = types.tuple(ECPair, types.maybe(types.Number))
SOLVE_TYPES[scriptTypes.P2PK] = types.tuple(ECPair, types.maybe(types.Number))
SOLVE_TYPES[scriptTypes.P2SH] = types.tuple(types.Buffer, types.Array)
SOLVE_TYPES[scriptTypes.P2WPKH] = types.tuple(ECPair, types.maybe(types.Number))
SOLVE_TYPES[scriptTypes.P2WSH] = types.tuple(types.Buffer, types.Array)

TransactionBuilder.prototype.solve = function (txOut, data) {
  typeforce({
    txId: types.HexN(64),
    vout: types.Number,
    script: types.Buffer, // XXX: could be optional, sometimes, maybe later
    value: types.Satoshi
  }, txOut)

  var txOutId = txOut.txId + ':' + txOut.vout
  var vin = this.prevTxMap[txOutId]
  var input = this.inputs[vin]
  if (!input) throw new Error(txOutId + ' is not an input')

  var type = bscript.classifyOutput(txOut.script)
  var solveType = SOLVE_TYPES[type]
  if (solveType === undefined) throw new TypeError('Unable to solve ' + type)
//   if (input.prevOutType !== type) throw new TypeError('Inconsistent type')
  typeforce(solveType, data)

  if (solveType === scriptTypes.P2PK ||
      solveType === scriptTypes.P2PKH ||
      solveType === scriptTypes.MULTISIG
     ) {
    this.__sign(vin, data[0], null, data[1])
    return true
  }

  if (solveType === scriptTypes.P2SH) {
    var redeemScript = data[0]
    var redeemType = bscript.classifyOutput(redeemScript)
    var redeemSolveType = SOLVE_TYPES[type]
    if (redeemSolveType === undefined) throw new TypeError('Unable to solve ' + redeemType)
    if (redeemSolveType === scriptTypes.P2WSH) throw new TypeError('TODO')
    var redeemData = data[1]
    typeforce(redeemSolveType, redeemData)

    this.__sign(vin, redeemData[0], redeemScript, redeemData[1], txOut.value)
    return true
  }

  if (solveType === scriptTypes.P2WPKH) {
    this.__sign(vin, data[0], txOut.script, data[1], txOut.value)
    return true
  }

  if (solveType === scriptTypes.P2WSH) throw new TypeError('TODO')
  return false
}
