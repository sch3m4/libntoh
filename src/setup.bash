#!/bin/bash

script_directory=$(realpath $(dirname $BASH_SOURCE))

source "${script_directory}/../../buildrc"

cd "${script_directory}"

rm -rf build
mkdir -p build
cd build
cmake ../
make clean
make
