/*  Peafowl Node.js Binding PoC */
/*  (c) 2018 QXIP BV 	        */
/*  http://qxip.net 			*/

var VERSION = "1.0.0";
var peafowl = require('../peafowl.js');

var protoL4 = ""
var protoL7 = ""

/* Packet Stats */
var packetStats = { bytes: [], count: [] };
function formatBytes(a,b){if(0==a)return"0 Bytes";var c=1024,d=b||2,e=["Bytes","KB","MB","GB","TB","PB","EB","ZB","YB"],f=Math.floor(Math.log(a)/Math.log(c));return parseFloat((a/Math.pow(c,f)).toFixed(d))+" "+e[f]}

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
peafowl.init();

/* EXTRACTION SETUP */
var buf = Buffer.from('DNS_NAME_SRV');
peafowl.field_add_L7(buf)
var buf = Buffer.from('HTTP_BODY');
peafowl.field_add_L7(buf)


// L2 type
var pcap = require('pcap');
var pcap_session = pcap.createOfflineSession(process.argv[2], "");
var LinkType = -1;
pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    LinkType = packet.link_type;
    switch (LinkType) {
    case "LINKTYPE_ETHERNET":
        LinkType = 1;
        break;
    case "LINKTYPE_NULL":
        LinkType = 0;
        break;
    case "LINKTYPE_RAW":
        LinkType = 101;
        break;
    case "LINKTYPE_IEEE802_11_RADIO":
        LinkType = 127;
        break;
    case "LINKTYPE_LINUX_SLL":
        LinkType = 113;
    default:
        console.log("Datalink type not supported");
    }
});

var http_count = 0;
var dns_count = 0;

pcap_parser.on('packet', function (raw_packet) {
    counter++;
    var header = raw_packet.header;
    // Build PCAP Hdr Struct
    var newHdr = structs.pcap();
    newHdr.ts_sec = header.timestampSeconds;
    newHdr.ts_usec = header.timestampMicroseconds;
    newHdr.incl_len = header.capturedLength;
    newHdr.orig_len = header.originalLength;

    // DISSECT AND GET PROTOCOL
    protoL7 = new Buffer.from(peafowl.get_L7_from_L2( raw_packet.data, newHdr.rawBuffer, LinkType ));

    // From object to String
    protoL7 = protoL7.toString();
    console.log("L7: ", protoL7);
    var tmpStats = packetStats.bytes[ protoL7 ];
    if (!tmpStats) {
        packetStats.bytes[ protoL7 ] = raw_packet.data.length;
        packetStats.count[ protoL7 ] = 1;
    } else {
        packetStats.bytes[ protoL7 ] += raw_packet.data.length;
        packetStats.count[ protoL7 ] += 1;
    }

    // Add http header extraction
    if(protoL7 == 'HTTP' && http_count < 1){
       // Add some fields to be extracted
       var buf = Buffer.from('HTTP_BODY');
       if (peafowl.field_present(buf)) {
          var HttpBody = peafowl.field_string_get(buf);
          console.log('HTTP EXTRACT:', buf.toString(), HttpBody.toString());
	  http_count++;
       }
    }

    // Add some fields to be extracted
    if(protoL7 == 'DNS' && dns_count < 1){
      var buf = Buffer.from('DNS_NAME_SRV');
      if (peafowl.field_present(buf)) {
          var NameServer = peafowl.field_string_get(buf);
          console.log('DNS EXTRACT:', buf.toString(), NameServer.toString());
	  dns_count++;
      }
    }
});

pcap_parser.on('end', function () {
    console.log('Terminating...');
    peafowl.terminate();
});

var exit = false;
process.on('exit', function() {
    exports.callback;
    console.log('Total Packets: '+ counter);
    for (var key in packetStats.bytes) {
	    var id = key.split('.');
	    console.log('L7: ' + id[0] +
                    '\t Count: ' + packetStats.count[key] +
                    '\t Size: ' + formatBytes(packetStats.bytes[key]));
    }
    console.table(packetStats);
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
