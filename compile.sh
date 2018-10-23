#!/bin/bash

if [ ! -d "peafowl_lib" ]; then
  echo "Cloning Peafowl..."
  git clone https://github.com/DanieleDeSensi/Peafowl.git peafowl_lib
  echo "Compiling Peafowl..."
  cd peafowl_lib
  mkdir build && cd build
  cmake ../ && make && cd ../../
  echo $PWD
  cp peafowl_lib/build/src/libpeafowl.* ./include/
  echo "Peafowl lib ready!"
fi

if [ -d "build" ]; then
  rm -rf build
fi
