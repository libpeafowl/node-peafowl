var bindings = require('node-gyp-build')(__dirname)

console.log(bindings.test_mul(42))

module.exports = {
  times_two: bindings.test_mul, // Params: INT
  pfw_init: bindings.pfw_init, // Params: INT (1 stateful, 0 stateless)
  pfw_get_protocol: bindings.pfw_get_protocol, // Params: struct pcap_pkthdr *, header
  pfw_get_protocol_pair: bindings.pfw_get_protocol_pair, // Params: struct pcap_pkthdr *, header
  pfw_terminate: bindings.pfw_terminate // Params: VOID
}
