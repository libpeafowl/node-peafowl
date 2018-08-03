var bindings = require('node-gyp-build')(__dirname)

console.log(bindings.times_two(42))

module.exports = {
  init: function(){ return; },
  times_two: bindings.times_two
}
