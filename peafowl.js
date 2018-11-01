var bindings = require('node-gyp-build')(__dirname);

console.log(bindings.test_mul(42));

module.exports = {
    times_two: bindings.test_mul, // TEST FUNC
    init: bindings.init,
    convert_pcap_dlt: bindings.convert_pcap_dlt,
    dissect_from_L2: bindings.dissect_from_L2,
    dissect_from_L3: bindings.dissect_from_L3,
    dissect_from_L4: bindings.dissect_from_L4,
    get_L7_protocol_name: bindings.get_L7_protocol_name,
    terminate: bindings.terminate
};
