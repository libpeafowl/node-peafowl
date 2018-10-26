var bindings = require('node-gyp-build')(__dirname);

console.log(bindings.test_mul(42));

module.exports = {
    //TEST
    times_two: bindings.test_mul,
    init: bindings.init,
    dissect_from_L2:bindings.dissect_from_L2,
    dissect_from_L3:bindings.dissect_from_L3,
    dissect_from_L4:bindings.dissect_from_L4,
    get_L7_protocol_name: bindings.get_L7_protocol_name,
    terminate: bindings.terminate
};
