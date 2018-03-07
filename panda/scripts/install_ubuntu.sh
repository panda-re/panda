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
sudo apt-get update
sudo apt-get -y build-dep qemu

progress "Installing PANDA dependencies..."
sudo apt-get -y install python-pip git protobuf-compiler protobuf-c-compiler \
  libprotobuf-c0-dev libprotoc-dev python-protobuf libelf-dev libc++-dev pkg-config

pushd /tmp

if lsb_release -d | grep -E 'Ubuntu (14\.04|16\.04)'
then
  sudo apt-get -y install software-properties-common
  sudo add-apt-repository -y ppa:phulin/panda
  sudo apt-get update
  sudo apt-get -y install libcapstone-dev libdwarf-dev python-pycparser
else
  if [ ! \( -e "/usr/local/lib/libdwarf.so" -o -e "/usr/lib/libdwarf.so" \) ]
  then
    git clone git://git.code.sf.net/p/libdwarf/code libdwarf-code
    pushd libdwarf-code
    progress "Installing libdwarf..."
    ./configure --enable-shared
    make -j$(nproc)
    sudo mkdir -p /usr/local/include/libdwarf
    sudo cp libdwarf/libdwarf.h /usr/local/include/libdwarf/
    sudo cp libdwarf/dwarf.h /usr/local/include/libdwarf/
    sudo cp libdwarf/libdwarf.so /usr/local/lib/
    popd
  else
    progress "Skipping libdwarf..."
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
fi

# Install libclang for apigen.py
sudo apt-get -y install libclang-3.8 python-clang-3.8

# Upgrading protocol buffers python support
sudo pip install --upgrade protobuf

progress "Trying to install LLVM 3.3..."
if ! sudo apt-get -y install llvm-3.3-dev clang-3.3
then
  progress "Couldn't find OS package for LLVM 3.3. Proceeding without..."
fi

popd

if [ ! -e "build.sh" ]
then
  progress "Cloning PANDA into $(pwd) ..."
  git clone https://github.com/panda-re/panda.git
  cd panda
else
  progress "Already in PANDA directory."
fi
progress "Building PANDA..."
mkdir build
cd build
../build.sh "$@"

progress "PANDA is built and ready to use in panda/build/[arch]-softmmu/qemu-system-[arch]."
