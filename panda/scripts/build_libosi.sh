#!/bin/bash

set -e
echo "Building libosi..."
if [ ! -d "libosi" ]; then
    git clone https://github.com/panda-re/libosi.git
else
    echo "Directory 'libosi' already exists. Skipping clone."
fi

pushd libosi
mkdir -p build && cd build
cmake -GNinja ..
ninja
ninja package
sudo dpkg -i libosi-*.deb
popd
rm -rf libosi
