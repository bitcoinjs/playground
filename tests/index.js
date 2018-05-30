/* global describe, it */

let assert = require('assert')
let u = require('./util')

;['p2ms', 'p2pk', 'p2pkh', 'p2sh', 'p2wpkh', 'p2wsh'].forEach(function (p) {
  describe(p, function () {
    let fn = require('../' + p)
    let fixtures = require('./fixtures/' + p)

    fixtures.valid.forEach(function (f, i) {
      it(f.description + ' as expected', function () {
        let args = u.preform(f.arguments)
        let actual = fn(args, f.options)
        let actualUV = fn(args, Object.assign({}, f.options, {
          validate: false
        }))

        u.equate(actual, f.expected, f.arguments)
        u.equate(actualUV, f.expected, f.arguments)
      })
    })

    fixtures.invalid.forEach(function (f) {
      it('throws ' + (f.description || f.exception), function () {
        let args = u.preform(f.arguments)

        assert.throws(function () {
          fn(args, f.options)
        }, new RegExp(f.exception))
      })
    })
  })
})
