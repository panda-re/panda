#!/bin/bash

sudo apt-get update -y
#Needed for add-apt-repository command
sudo apt-get install software-properties-common python-software-properties -y

#Add PANDA repo
sudo add-apt-repository ppa:phulin/panda -y

#Add all the source repos
sudo sed -i 's/# deb-src http:\/\/archive\.ubuntu\.com\/ubuntu/deb-src http:\/\/archive.ubuntu.com\/ubuntu/g' /etc/apt/sources.list

#Update repos
sudo apt-get update -y 

#At least the taint plugin needs this
sudo apt-get install -y libc++-dev
sudo apt-get install -y pkg-config python-pip git protobuf-compiler protobuf-c-compiler libprotobuf-c0-dev libprotoc-dev libelf-dev libcapstone-dev libdwarf-dev python-pycparser llvm-3.3 clang-3.3 libc++-de
sudo apt-get build-dep qemu
git clone https://github.com/komasa/panda

mkdir panda/build-panda
cd panda/build-panda
./build.sh
