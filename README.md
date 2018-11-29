

<img src="https://i.imgur.com/jrQX0Of.gif" width=250>

# node-Peafowl
Native Node Bindings for the [Peafowl DPI Library](https://github.com/DanieleDeSensi/Peafowl)

[![Build Status](https://travis-ci.org/libpeafowl/node-peafowl.svg?branch=master)](https://travis-ci.org/libpeafowl/node-peafowl)
[![dependencies Status](https://david-dm.org/libpeafowl/node-peafowl/status.svg)](https://david-dm.org/libpeafowl/node-peafowl)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/libpeafowl/node-peafowl/issues)

## About
Peafowl is a flexible and extensible DPI framework which can be used to identify the application protocols carried by IP (IPv4 and IPv6) packets and to extract and process data and metadata carried by those protocols. This module allows NodeJS projects to leverage the power of Peafowl for Deep-Packet Inspection of live and recorded network traffic.

### Installation
```
var peaFowl = require('node-peafowl')
```

##### Custom Build
The install script will automatically attempt compiling peafowl and building node gyp bindings
```
npm install
```

### Usage
```javascript
/* INITIALIZE LIBRARY */
peafowl.init();

/* DISSECT PACKETS AND RESOLVE PROTOCOL NAME */
peafowl.get_L7_from_L2( PCAP_packet, PCAP_header, PCAP_LinkType ) );

/* EXTRACTION SETUP */
var buf = Buffer.from('DNS_NAME_SRV');
peafowl.field_add_L7(buf)

/* EXTRACT PROTOCOL FIELDS */
var field = Buffer.from('DNS_NAME_SRV')
if (peafowl.field_present(field)) {
         console.log( peafowl.field_string_get(field) );
}
```
See a fully working [Example](https://github.com/lmangani/node-peafowl/tree/master/example) using PCAP files

### Test
You can test our example by running ```npm test```

------------

#### Main Functions
| function  | parameters  |  description |
|---|---|---|
| _init_  | (void) |  Initialize the library for statefull env |
| _terminate_ | (void) | Teardown the library |
| _get_L7_protocol_name_ | (packet, header, link type) | Dissect and return Protocol name as char * (l7) |

#### Extraction Functions
| function  | parameters  |  description |
|---|---|---|
| field_add_L7()  | (string Buffer) |  Initialize extraction for the selected protocol field |
| field_present() | (string Buffer) | Check if an extraction is present in a processed packet |
| field_number_get | (string Buffer) | Return the extracted value as int * |
| field_string_get | (string Buffer) | Return the extracted value as char * |



### Todo
* Implement int64 response from library
* Add more test cases

<br/>
<br/>

### Credits & Acknowledgements

Peafowl has been mainly developed by [Daniele De Sensi](https://github.com/DanieleDeSensi)

Node-Peafowl is developed by [L. Mangani](https://github.com/lmangani), [M. Campus](https://github.com/kYroL01) using the awesome [NAPI-macros](https://github.com/mafintosh/napi-macros) by [Mathias Buus](https://github.com/mafintosh)


-------------

If you use Peafowl or Node-Peafowl for scientific purposes, please cite the following paper:

```"Deep Packet Inspection on Commodity Hardware using FastFlow", M. Danelutto, L. Deri, D. De Sensi, M. Torquati```

###### This Project is sponsored by [QXIP BV](http://qxip.net)
