{
  "targets": [{
    "target_name": "peafowl",
    "include_dirs": [
      "<!(node -e \"require('napi-macros')\")"
    ],
    "sources": [ "./peafowl.c" ]
  }]
}
