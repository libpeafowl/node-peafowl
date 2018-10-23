{
  "targets": [{
    "target_name": "peafowl",
    "include_dirs": [
      "<!(node -e \"require('napi-macros')\")"
    ],
    "include_dirs": [
            "./include", "../peafowl_lib/lib"
    ],
    "libraries": ["<(module_root_dir)/include/libpeafowl.so"],
    "sources": [ "./peafowl.c" ]
  }]
}
