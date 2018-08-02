{
  "targets": [{
    "target_name": "node-peafowl",
    "include_dirs": [
      "<!(node -e \"require('../')\")"
    ],
    "sources": [ "./peafowl.c" ]
  }]
}
