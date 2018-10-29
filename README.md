

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

#### Functions
| function  | parameters  |  description |
|---|---|---|
| bind_pfwl_init  | void  |  Initialize the library for statefull env |
|  bind_pfwl_terminate | void  | Teardown the library |
| bind_pfwl_get_protocol_l4  | struct pcap_pkthdr *, header  | Dissect and return Protocol name as char * (l4) |
| bind_pfwl_get_protocol_l7  | struct pcap_pkthdr *, header  | Dissect and return Protocol name as char * (l7) |

### Usage
See our fully working [Example](https://github.com/lmangani/node-peafowl/tree/master/example) using PCAP files

<br/>
<br/>

### Credits & Acknowledgements

Peafowl has been mainly developed by [Daniele De Sensi](https://github.com/DanieleDeSensi)

Node-Peafowl is developed by [L. Mangani](https://github.com/lmangani), [M. Campus](https://github.com/kYroL01) using the awesome [NAPI-macros](https://github.com/mafintosh/napi-macros) by [Mathias Buus](https://github.com/mafintosh)


-------------

If you use Peafowl or Node-Peafowl for scientific purposes, please cite the following paper:

```"Deep Packet Inspection on Commodity Hardware using FastFlow", M. Danelutto, L. Deri, D. De Sensi, M. Torquati```

###### This Project is sponsored by [QXIP BV](http://qxip.net)
