# Test
```
npm install
node pcap.js ./pcap/http.pcap
```

### Functions
```
    // DISSECT AND GET PROTOCOL
    protoL7 = new Buffer(peafowl.pfw_get_protocol_l7( raw_packet.data, newHdr.rawBuffer ));

    // CONVERT DPI BUFFER TO STRING
    protoL7 = protoL7.toString()
 ```
