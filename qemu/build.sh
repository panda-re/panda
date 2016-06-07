#!/bin/bash

# Get the location of the LLVM compiled for PANDA, respecting environment variables.
PANDA_LLVM_ROOT="${PANDA_LLVM_ROOT:-../llvm}"
PANDA_LLVM_BUILD="${PANDA_LLVM_BUILD:-Release}"
PANDA_LLVM="$(/bin/readlink -f "${PANDA_LLVM_ROOT}/${PANDA_LLVM_BUILD}" 2>/dev/null)"

# stop on any error
set -e

# creates api code for plugins
python ../scripts/apigen.py

# creates pandalog code
sh ./pp.sh

# set the LLVM_BIT
if [ "$PANDA_LLVM" != "" ]; then
  # Using PANDA LLVM.
  echo "Found PANDA LLVM on ${PANDA_LLVM_ROOT} -- LLVM SUPPORT IS ENABLED"
  LLVM_BIT="--enable-llvm --with-llvm=${PANDA_LLVM}"
else
  # Fallback to system LLVM.
  if llvm-config --version >/dev/null 2>/dev/null && [ $(llvm-config --version) == "3.3" ]; then
    echo "Found SYSTEM LLVM -- LLVM SUPPORT IS ENABLED"
    LLVM_BIT="--enable-llvm --with-llvm=$(llvm-config --prefix)"
  elif llvm-config-3.3 --version >/dev/null 2>/dev/null; then
    echo "Found SYSTEM LLVM -- LLVM SUPPORT IS ENABLED"
    LLVM_BIT="--enable-llvm --with-llvm=$(llvm-config-3.3 --prefix)"
  else
    echo "No suitable LLVM found -- LLVM SUPPORT IS DISABLED"
    LLVM_BIT=""
  fi
fi  

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

