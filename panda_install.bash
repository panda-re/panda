#!/bin/bash

#
# This script installs all of PANDA after first taking care of current dependencies. 
# Known to work on debian 7 install.
#
# The only prereq is llvm.  You need to put that in ~/llvm

sudo apt-get -y install build-essential 
sudo apt-get -y build-dep qemu
sudo apt-get -y install nasm
sudo apt-get -y install libssl-dev
sudo apt-get -y install libpcap-dev
sudo apt-get -y install subversion
sudo apt-get -y install curl
sudo apt-get -y install autoconf
sudo apt-get -y install libtool


# this will install panda in ~/git/panda

mkdir -p ~/git

cd ~/git
git clone https://github.com/moyix/panda.git

cd ~/git/panda
ln -s ~/llvm ./llvm

cd ~

mkdir software
cd software
svn checkout http://distorm.googlecode.com/svn/trunk/ distorm
cd distorm/make/linux
make
sudo make install
cd ../../..
cd distorm/include
sudo cp * /usr/local/include
cd 


cd ~/software
git clone https://github.com/google/protobuf.git
cd protobuf
sh ./autogen.sh
./configure --disable-shared
make
sudo make install

cd ~/software
git clone https://github.com/protobuf-c/protobuf-c.git
cd protobuf-c
sh ./autogen.sh
./configure --disable-shared
make
sudo make install

cd ~/git/panda/qemu
sh ./build.sh

