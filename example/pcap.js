/*  Peafowl Node.js Binding PoC 		*/
/*  (c) 2018 QXIP BV 	*/
/*  http://qxip.net 			*/

var VERSION = "1.0.0";
var peafowl = require('../peafowl.js');

/* PCAP Header  */
const sharedStructs = require('shared-structs');
const structs = sharedStructs(`
  struct pcap {
    uint64_t ts_sec;
    uint64_t ts_usec;
    uint64_t incl_len;
    uint64_t orig_len;
  }
`);

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

console.log('Initializing...');
peafowl.pfw_init();

pcap_parser.on('packet', function (raw_packet) {
	//console.log('Got a packet...');
	counter++;
	var header = raw_packet.header;
	// Build PCAP Hdr Struct
	var newHdr = structs.pcap();
		newHdr.ts_sec=header.timestampSeconds;
		newHdr.ts_usec=header.timestampMicroseconds;
		newHdr.incl_len=header.capturedLength;
		newHdr.orig_len=header.originalLength;
    	// DISSECT AND GET PROTOCOL
	//console.log('Dissecting...');
    	console.log( 'Protocol:', peafowl.pfw_get_protocol( raw_packet.data, newHdr.rawBuffer ) );
});

pcap_parser.on('end', function () {
	console.log('Terminating...');
	peafowl.pfw_terminate();
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
	      peafowl.terminate();
        process.exit();
    } else {
    	  console.log("Press CTRL-C within 2 seconds to Exit...");
        exit = true;
        setTimeout(function () {
          exit = false;
        }, 2000)
    }
});
