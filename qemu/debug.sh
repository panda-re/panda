#!/bin/bash

set -e

# creates api code for plugins
python ../scripts/apigen.py

# creates pandalog code
sh ./pp.sh


# only 
LLVM_BIT=""
if [ -e ../llvm/Debug+Asserts ]
then
  echo "Found ../llvm -- LLVM SUPPORT IS ENABLED"
  llvm=`/bin/readlink -f ../llvm/Debug+Asserts`
  LLVM_BIT="--enable-llvm --with-llvm=$llvm"
else
  echo "No Debug+Asserts llvm dir found -- LLVM SUPPORT IS DISABLED"
fi

echo $LLVM_BIT

./configure --target-list=x86_64-softmmu,i386-softmmu,arm-softmmu \
--prefix=`pwd`/install \
--disable-pie \
--disable-xen \
--disable-libiscsi \
$LLVM_BIT \
--extra-cflags="-O0 -g -I/usr/local/include" \
--extra-cxxflags="-O0 -g" \
--extra-ldflags="-L/usr/local/lib -L/usr/local/lib64 -L/usr/local/lib -lprotobuf-c -lprotobuf -lpthread"

make -j $(nproc)
