/*  Peafowl Node.js Binding PoC */
/*  (c) 2018 QXIP BV 	        */
/*  http://qxip.net 			*/

var VERSION = "1.0.0";
var peafowl = require('../peafowl.js');

/* PCAP Parser */
var pcapp = require('pcap-parser');
var param = require('param');

var protoL4 = ""
var protoL7 = ""

/* APP */
console.log("Peafowl Node v"+VERSION);
counter = 0;

console.log('Initializing...');
peafowl.init();

/* EXTRACTION SETUP */
var pcaps = param('pcap');
pcaps.forEach(function(file){
  if (!file.enable) return;
  file.protocols.forEach(function(proto){
    if(proto.rules){
    	proto.rules.forEach(function(proto){
	  console.log('Extraction rule for:',proto);
	  var buf = Buffer.from(proto);
	  peafowl.field_add_L7(buf);
    	});

    } else if (proto.extract_int){
    	proto.extract_int.forEach(function(proto){
	  console.log('Extraction rule for:',proto);
	  var buf = Buffer.from(proto);
	  peafowl.field_add_L7(buf);
    	});
    } else if (proto.extract_str){
    	proto.extract_str.forEach(function(proto){
	  console.log('Extraction rule for:',proto);
	  var buf = Buffer.from(proto);
	  peafowl.field_add_L7(buf);
    	});
    }
  });
});

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


var pcaps = param('pcap');
if (pcaps.length < 1) process.exit();

async function doPcaps () {
  for (const pcap of pcaps) {

	if (!pcap.enable || !pcap.file) {
		console.log('Bypassing..',pcap.file);
		continue;
	}
    	var pcap_parser = await pcapp.parse(pcap.file);
	// L2 type
	var LinkType = -1;
	pcap_parser.on('globalHeader', function (globalHeader) {
		LinkType = globalHeader.linkLayerType;
		console.log('Set LinkType',LinkType);
	})

	pcap_parser.on('packet', function (raw_packet) {
	    counter++;

		if (!raw_packet) return;

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
	    // console.log("L7: ", protoL7);
	    var tmpStats = packetStats.bytes[ protoL7 ];
	    if (!tmpStats) {
	        packetStats.bytes[ protoL7 ] = raw_packet.data.length;
	        packetStats.count[ protoL7 ] = 1;
	    } else {
	        packetStats.bytes[ protoL7 ] += raw_packet.data.length;
	        packetStats.count[ protoL7 ] += 1;
	    }

	    // Add header extraction from config file
	    // var xprotos = JSON.parse(JSON.stringify(protos));;
	    pcap.protocols.forEach(function(proto){
	      if(proto.name == protoL7){
		if(proto.extract_str){
		 proto.extract_str.forEach(function(rule){
		       var buf = Buffer.from(rule);
		       //console.log('TRY EXTRACT STR',rule,peafowl.field_present(buf))
		       if (peafowl.field_present(buf) && proto.max >0 ) {
		          var Body = peafowl.field_string_get(buf);
		          console.log('EXTRACT STR:',proto.max,'CONTENT:', buf.toString(), Body.toString());
			  proto.max--;
		       }
		 });
		} else if(proto.extract_int){
		 proto.extract_int.forEach(function(rule){
		       var buf = Buffer.from(rule);
		       //console.log('TRY EXTRACT NUM',rule,peafowl.field_present(buf))
		       if (peafowl.field_present(buf) && proto.max >0 ) {
		          var Body = peafowl.field_number_get(buf);
		          console.log('EXTRACT NUM:',proto.max,'CONTENT:', buf.toString(), Body.toString());
			  proto.max--;
		       }
		 });
		}

	      }
	    });
	});

	pcap_parser.on('end', function () {
	    console.log('Terminating...');
	    // peafowl.terminate();
	});

        console.log('Next...');
  }
}

doPcaps();

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
