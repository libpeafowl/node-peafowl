{
  "targets": [{
    "target_name": "peafowl",
    "include_dirs": [
      "<!(node -e \"require('napi-macros')\")"
    ],
    "include_dirs": [
            "<(module_root_dir)/include", "<(module_root_dir)/peafowl_lib/include", "./node_modules/node-addon-api/src"
    ],
    "sources": [ "./peafowl.c" ],
    "libraries": ["-Wl,-rpath,<(module_root_dir)/peafowl_lib/build/src/ -L<(module_root_dir)/peafowl_lib/build/src/ -lpeafowl"]
  }],
  "build_v8_with_gn%": "false"
}
