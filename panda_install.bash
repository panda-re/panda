#!/bin/bash

# This is just everything in compile.md
# turned into a script
# you should be able to run it, type in
# sudo passwd and have it install all of panda.
# Verified that this script works
# from a clean install of deb7.
#
#
# This script installs all of PANDA after first taking care of current dependencies. 
# Known to work on debian 7 install.

progress() {
  echo
  echo -e "\e[32m[panda_install]\e[0m \e[1m$1\e[0m"
}

# Exit on error.
set -e

progress "Installing qemu dependencies..."
sudo apt-get update -qq
sudo apt-get -y install build-essential 
progress "Installing PANDA dependencies..."
sudo apt-get -y install nasm libssl-dev libpcap-dev subversion curl autoconf libtool \
  python-pip git protobuf-compiler protobuf-c-compiler libprotobuf-c0-dev libprotoc-dev \
  libglib2.0-dev

cwd=$(pwd)
cd /tmp

progress "Trying to install LLVM 3.3..."
if ! sudo apt-get -y install llvm-3.3-dev clang-3.3
then
  progress "Couldn't find OS package for LLVM 3.3. Proceeding without..."
fi

if [ ! -e "/usr/local/lib/libdistorm3.so" ]
then
  curl -O http://ragestorm.net/distorm/distorm3.3-package.zip
  unzip distorm3.3-package.zip
  cd distorm3/make/linux
  make -j$(nproc)
  progress "Installing distorm..."
  sudo make install
  cd ../../..
  cd distorm3/include
  sudo cp * /usr/local/include
else
  progress "Skipping distorm..."
fi

if python -c 'import pycparser' 2>/dev/null
then
  if python <<EOF
import sys
import pycparser
version = [int(x) for x in pycparser.__version__.split(".")]
if version[0] < 2 or (version[0] == 2 and version[1] < 10):
  print "pycparser too old. Please upgrade it!"
  sys.exit(1)
else:
  print "pycparser version good."
  sys.exit(0)
EOF
  then
    progress "Skipping pycparser..."
  else
    progress "Your pycparser is too old. Please upgrade using your method of choice."
    exit 1
  fi
else
  progress "Installing pycparser..."
  sudo -H pip install pycparser
fi

cd "$cwd"

if [ ! -e "qemu/build.sh" ]
then
  progress "Cloning PANDA into $cwd ..."
  git clone https://github.com/moyix/panda.git
  cd panda/qemu
else
  progress "Already in PANDA directory."
  cd qemu
fi
progress "Building PANDA..."
./build.sh

progress "PANDA is built and ready to use in panda/qemu/[arch]-softmmu/qemu-system-[arch]."
