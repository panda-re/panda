#!/bin/bash

set -e

# creates api code for plugins
python ../scripts/apigen.py

# creates pandalog code
sh ./pp.sh


# only 
LLVM_BIT=""
if [ -e ../llvm/Release ]
then
  echo "Found ../llvm -- LLVM SUPPORT IS ENABLED"
  llvm=`/bin/readlink -f ../llvm/Release`
  LLVM_BIT="--enable-llvm --with-llvm=$llvm"
else
  if llvm-config --version >/dev/null 2>/dev/null && [ $(llvm-config --version) == "3.3" ]
  then
    echo "Found system llvm -- LLVM SUPPORT IS ENABLED"
    LLVM_BIT="--enable-llvm --with-llvm=$(llvm-config --prefix)"
  else
    if llvm-config-3.3 --version >/dev/null 2>/dev/null
    then
      echo "Found system llvm -- LLVM SUPPORT IS ENABLED"
      LLVM_BIT="--enable-llvm --with-llvm=$(llvm-config-3.3 --prefix)"
    else
      echo "No llvm dir found -- LLVM SUPPORT IS DISABLED"
    fi
  fi
fi  

echo $LLVM_BIT

./configure --target-list=x86_64-softmmu,i386-softmmu,arm-softmmu \
--prefix=`pwd`/install \
--disable-pie \
--disable-xen \
--disable-libiscsi \
$LLVM_BIT \
--extra-cflags="-O2 -I/usr/local/include" \
--extra-cxxflags="-O2" \
--extra-ldflags="-L/usr/local/lib -L/usr/local/lib64 -L/usr/local/lib -lprotobuf-c -lprotobuf -lpthread"

make -j ${PANDA_NPROC:-$(nproc)}
