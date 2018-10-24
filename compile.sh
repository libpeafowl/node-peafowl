#!/bin/bash

TAG="v1.0.0"

if [ ! -d "peafowl_lib" ]; then
  echo "Cloning Peafowl..."
  git clone https://github.com/DanieleDeSensi/Peafowl.git peafowl_lib  
  cd peafowl_lib
  echo "Getting tag " $TAG
  git checkout tags/$TAG
  echo "Compiling Peafowl..."
  mkdir build && cd build
  cmake ../ && make && cd ../../
  echo $PWD
  echo "Peafowl lib ready!"
fi

if [ -d "build" ]; then
  rm -rf build
fi
