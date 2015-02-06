#!/bin/bash

# creates api code for plugins
python ../scripts/apigen.py

# creates pandalog code
sh ./pp.sh


# only 
LLVM_BIT=""
if [ -f ../llvm ]
then
  LLVM_BIT="--enable-llvm --with-llvm=../llvm/${PANDA_LLVM_BUILD:=Release}"
else
  echo "No ../llvm dir found -- LLVM SUPPORT IS DISABLED"
fi  
    

./configure --target-list=x86_64-softmmu,i386-softmmu,arm-softmmu \
--cc=${CC:=gcc-4.7} \
--cxx=${CXX:=g++-4.7} \
--prefix=`pwd`/install \
--disable-pie \
--disable-xen \
--disable-libiscsi \
$LLVM_BIT \
--extra-cflags="-O2 -I/usr/local/include" \
--extra-cxxflags="-O2" \
--extra-ldflags="-L/usr/local/lib -L/usr/local/lib64 -L/usr/local/lib -lprotobuf-c -lprotobuf -lpthread" \
&& make -j $(nproc)
