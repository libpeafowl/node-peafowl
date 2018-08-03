/*  Peafowl Node.js Binding PoC 		*/
/*  (c) 2018 QXIP BV 	*/
/*  http://qxip.net 			*/

var VERSION = "1.0.0";
var peafowl = require('../peafowl.js');

/* PCAP Header  */
var Struct = require('ref-struct');
var pcap_pkthdr = Struct({
	  'ts_sec': 'uint64', 
	  'ts_usec': 'uint64',
	  'incl_len': 'uint32',
	  'orig_len': 'uint32'
});

/* PCAP Parser */
var pcapp = require('pcap-parser');
if (process.argv[2]) {
	  var pcap_parser = pcapp.parse(process.argv[2]);
} else {
    console.error("usage: node pcap.js /path/to/file.pcap");
    console.error();
    process.exit();
}

/* APP */
console.log("Peafowl Node v"+VERSION);
counter = 0;

peafowl.init();

pcap_parser.on('packet', function (raw_packet) {
	counter++;
	var header = raw_packet.header;
	  // Build PCAP Hdr Struct
	  var newHdr = new pcap_pkthdr();
		newHdr.ts_sec=header.timestampSeconds;
		newHdr.ts_usec=header.timestampMicroseconds;
		newHdr.incl_len=header.capturedLength;
		newHdr.orig_len=header.originalLength;
    // DISSECT AND GET PROTOCOL
    console.log( peafowl.getProtocol( raw_packet.data, newHdr.ref() ) );
});

pcap_parser.on('end', function () {
	peafowl.finish();
});

var exit = false;
process.on('exit', function() {
		exports.callback;
		console.log('Total Packets: '+counter);
});

process.on('SIGINT', function() {
    console.log();
    if (exit) {
    	console.log("Exiting...");
	      peafowl.finish();
        process.exit();
    } else {
    	  console.log("Press CTRL-C within 2 seconds to Exit...");
        exit = true;
        setTimeout(function () {
          exit = false;
        }, 2000)
    }
});
