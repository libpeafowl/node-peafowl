var bindings = require('node-gyp-build')(__dirname)

console.log(bindings.test_mul(42))

module.exports = {
    //TEST  
    times_two: bindings.test_mul,                          // Params: INT  
    pfw_init: bindings.pfw_init,                           // Params: VOID
    pfw_get_protocol_l7: bindings.pfw_get_protocol_l7,     // Params: struct pcap_pkthdr *, header
    pfw_get_protocol_l4: bindings.pfw_get_protocol_l4,     // Params: struct pcap_pkthdr *, header
    pfw_get_protocol_pair: bindings.pfw_get_protocol_pair, // Params: struct pcap_pkthdr *, header
    pfw_terminate: bindings.pfw_terminate                  // Params: VOID
}
