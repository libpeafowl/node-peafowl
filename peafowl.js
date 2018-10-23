var bindings = require('node-gyp-build')(__dirname);

console.log(bindings.test_mul(42));

module.exports = {
    //TEST
    times_two: bindings.test_mul,                                  // Params: INT
    bind_pfwl_init: bindings.bind_pfwl_init,                       // Params: VOID
    bind_pfwl_get_protocol_l7: bindings.bind_pfwl_get_protocol_l7, // Params: struct pcap_pkthdr *, header, link type
    // pfwl_GetProtocolL4: bindings.pfw_get_protocol_l4,           // Params: struct pcap_pkthdr *, header, link type
    bind_pfwl_terminate: bindings.bind_pfwl_terminate              // Params: VOID
};
