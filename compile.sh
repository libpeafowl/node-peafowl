#!/bin/bash

echo "Cloning Peafowl..."
git clone https://github.com/DanieleDeSensi/Peafowl.git peafowl_lib
echo "Compiling Peafowl..."
make -C peafowl_lib
cp peafowl_lib/lib/libdpi.so ./include/
echo "Peafowl lib ready!"







