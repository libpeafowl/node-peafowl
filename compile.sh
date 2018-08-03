#!/bin/bash

if [ ! -d "peafowl_lib" ]; then
  echo "Cloning Peafowl..."
  git clone https://github.com/DanieleDeSensi/Peafowl.git peafowl_lib
  echo "Compiling Peafowl..."
  make -C peafowl_lib
  cp peafowl_lib/lib/libdpi.* ./include/
  echo "Peafowl lib ready!"
fi

if [ -d "build" ]; then
  rm -rf build
fi








