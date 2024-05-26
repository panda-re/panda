#!/bin/bash

# This is just everything in compile.md
# turned into a script
# you should be able to run it, type in
# sudo passwd and have it install all of panda.
# Verified that this script works
# from a clean install of OS X El Capitan.
#
progress() {
  echo
  echo -e "[32m[panda_install][0m [1m$1[0m"
}

# Exit on error.
set -e

progress "Installing homebrew..."
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

progress "Installing qemu dependencies..."
brew install $(brew deps qemu)
brew install dtc pkg-config

progress "Installing PANDA dependencies..."
brew install moyix/homebrew-libdwarf/libdwarf
brew install capstone
brew install homebrew/versions/llvm33
brew install protobuf-c

if [ ! -e "$(which pip)" ]
then
  progress "Python pip not found, installing it..."
  sudo -H easy_install pip
fi

if [ ! -e "build.sh" ]
then
  progress "Cloning PANDA into $(pwd) ..."
  git clone --depth=1 https://github.com/panda-re/panda.git
  cd panda
else
  progress "Already in PANDA directory."
fi
progress "Building PANDA..."
mkdir build
cd build
../build.sh

progress "PANDA is built and ready to use in panda/build/[arch]-softmmu/panda-system-[arch]."
