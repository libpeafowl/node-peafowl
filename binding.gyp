{
  "targets": [{
    "target_name": "peafowl",
    "include_dirs": [
      "<!(node -e \"require('napi-macros')\")"
    ],
    "include_dirs": [
            "<(module_root_dir)/include", "<(module_root_dir)/peafowl_lib/include"
    ],
    "sources": [ "./peafowl.c" ],
    "libraries": ["-Wl,-rpath,<(module_root_dir)/peafowl_lib/build/src/ -L<(module_root_dir)/peafowl_lib/build/src/ -lpeafowl"]
  }]
}
