# Basic Test
The basic test simply reads a single PCAP file and performs DPI detection and breakdown.
```
npm install
node pcap.js ./pcap/http.pcap
```

# Dynamic Test
The advanced test can use multiple pcap files with multiple detection and extraction rules.

### Example Config
Each block defines a `file` resource plus a set of `protocols` with corresponding `name`, `extract` rule and `max` (limit)
```
{
    "pcap": [
        { "file": "./pcap/http.pcap",
	  "protocols": [
		{ "name": "DNS", "extract_str": ["DNS_NAME_SRV"], "max": 3 }
	  ],
	  "enable": true
	},
        { "file": "./pcap/http-jpeg.pcap",
	  "protocols": [
		{ "name": "HTTP", "extract_str": ["HTTP_BODY"], "max": 1 }
	  ],
	  "enable": true
	},
        { "file": "./pcap/rtcp.pcap",
	  "protocols": [
		{ "name": "RTCP", "extract_int": ["RTCP_SENDER_SSRC"], "rules": ["RTCP_SENDER_ALL"], "max": 3 }
	  ],
	  "enable": true
	},
        { "file": "./pcap/rtcp.pcap",
	  "protocols": [
		{ "name": "RTP", "extract_int": ["RTP_SEQNUM"], "max": 3 }
	  ],
	  "enable": true
	}
    ]
}
```
