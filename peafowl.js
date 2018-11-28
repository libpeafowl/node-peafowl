var bindings = require('node-gyp-build')(__dirname);

console.log(bindings.test_mul(42));

module.exports = {
    times_two: bindings.test_mul, // TEST FUNC
    init: bindings.init,
    convert_pcap_dlt: bindings.convert_pcap_dlt,
    dissect_from_L2: bindings.dissect_from_L2,
    dissect_from_L3: bindings.dissect_from_L3,
    dissect_from_L4: bindings.dissect_from_L4,
    protocol_L7_enable: bindings.protocol_L7_enable,
    protocol_L7_disable: bindings.protocol_L7_disable,
    guess_protocol: bindings.guess_protocol,
    get_L7_protocol_name: bindings.get_L7_protocol_name,
    get_L7_protocol_id: bindings.get_L7_protocol_id,
    get_L7_from_L2: bindings.get_L7_from_L2,
    field_add_L7: bindings.field_add_L7,
    field_remove_L7: bindings.field_remove_L7,
    set_protocol_accuracy_L7: bindings.set_protocol_accuracy_L7,
    field_string_get: bindings.field_string_get,
    field_number_get: bindings.field_number_get,
    field_array_get_pair: bindings.field_array_get_pair,
    http_get_header: bindings.http_get_header,
    http_get_header_value: bindings.http_get_header_value,
    terminate: bindings.terminate
};
