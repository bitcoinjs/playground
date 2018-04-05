let p2ms = require('../p2ms')
let tape = require('tape')
let u = require('./util')
let fixtures = require('./fixtures/p2ms')

fixtures.valid.forEach(function (f, i) {
  tape('returns for ' + (f.description || ('vector ' + i)), function (t) {
    let args = u.preform(f.arguments)
    let actual = p2ms(args, f.options)

    u.equate(t, actual, f.expected)
    t.end()
  })
})

fixtures.invalid.forEach(function (f) {
  tape('throws ' + (f.description || f.exception), function (t) {
    let args = u.preform(f.arguments)

    t.plan(1)
    t.throws(function () {
      p2ms(args, f.options)
    }, new RegExp(f.exception))
  })
})
