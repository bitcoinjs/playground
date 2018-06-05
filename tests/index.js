/* global describe, it */

let assert = require('assert')
let u = require('./util')

;['p2ms', 'p2pk', 'p2pkh', 'p2sh', 'p2wpkh', 'p2wsh'].forEach(function (p) {
  describe(p, function () {
    let fn = require('../' + p)
    let fixtures = require('./fixtures/' + p)

    fixtures.valid.forEach(function (f, i) {
      let args = u.preform(f.arguments)

      it(f.description + ' as expected', function () {
        let actual = fn(args, f.options)
        u.equate(actual, f.expected, f.arguments)
      })

      it(f.description + ' as expected (no validation)', function () {
        let actual = fn(args, Object.assign({}, f.options, {
          validate: false
        }))

        u.equate(actual, f.expected, f.arguments)
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

    // cross-verify dynamically too
    if (!fixtures.dynamic) return
    let { depends, details } = fixtures.dynamic

    details.forEach(function (f) {
      let detail = u.preform(f)
      let disabled = {}
      if (f.disabled) f.disabled.forEach(function (k) { disabled[k] = true })

      for (let key in depends) {
        if (key in disabled) continue
        let dependencies = depends[key]

        dependencies.forEach(function (dependency) {
          if (!Array.isArray(dependency)) dependency = [dependency]

          let args = {}
          dependency.forEach(function (d) { u.from(d, detail, args) })
          let expected = u.from(key, detail)

          it(f.description + ', ' + key + ' derives from ' + JSON.stringify(dependency), function () {
            u.equate(fn(args), expected)
          })
        })
      }
    })
  })
})
