#!/bin/bash

TAG="v1.0.0"

if [ ! -d "peafowl_lib" ]; then
  echo "Cloning Peafowl..."
  git clone https://github.com/DanieleDeSensi/Peafowl.git peafowl_lib  
  cd peafowl_lib
  echo "Getting tag " $TAG
  git checkout master
  git checkout 48d82243470932af3f0aadf6f15eb5d927cfa6d6
  echo "Compiling Peafowl..."
  mkdir build && cd build
  cmake ../ && make && cd ../../
  echo $PWD
  echo "Peafowl lib ready!"
fi

if [ -d "build" ]; then
  rm -rf build
fi
