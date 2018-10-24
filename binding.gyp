{
  "targets": [{
    "target_name": "peafowl",
    "include_dirs": [
      "<!(node -e \"require('napi-macros')\")"
    ],
    "include_dirs": [
            "<(module_root_dir)/include", "<(module_root_dir)/peafowl_lib/include"
    ],
    "libraries": ["<(module_root_dir)/peafowl_lib/build/src/libpeafowl.so"],
    "sources": [ "./peafowl.c" ]
  }]
}
