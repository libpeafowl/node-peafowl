<img src="https://i.imgur.com/jrQX0Of.gif" width=300>

# node-Peafowl
Native Node Bindings for the [Peafowl DPI Library](https://github.com/DanieleDeSensi/Peafowl)

## Peafowl
Peafowl is a flexible and extensible DPI framework which can be used to identify the application protocols carried by IP (IPv4 and IPv6) packets and to extract and process data and metadata carried by those protocols.

## Build
The build process will automatically attempt compiling peafowl and gyp bindings
```
npm install
```

## Installation
```
var peaFowl = require('node-peafowl')
```

### Functions
| function  | parameters  |  description | 
|---|---|---|
| pfw_init  | int  |  Initialize the library, 1 stateful, 0 stateless |
|  pfw_terminate | void  | Teardown the library  |
| pfw_get_protocol  | struct pcap_pkthdr *, header  | Dissect and return Protocol ID (l7) |
| pfw_get_protocol_pair  | struct pcap_pkthdr *, header  | Dissect and return Protocol Pair (l4,l7)  |

## Usage
See our fully working [Example] using PCAP sources


### Credits

Peafowl has been mainly developed by [Daniele De Sensi](https://github.com/DanieleDeSensi)

Node-Peafowl is sponsored by [QXIP BV](http://qxip.net)
