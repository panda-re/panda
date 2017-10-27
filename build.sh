#!/bin/bash

# Get the location of the LLVM compiled for PANDA, respecting environment variables.
PANDA_LLVM_ROOT="${PANDA_LLVM_ROOT:-$(dirname $0)/../llvm}"
PANDA_LLVM_BUILD="${PANDA_LLVM_BUILD:-Release}"
PANDA_LLVM="$(/bin/readlink -f "${PANDA_LLVM_ROOT}/${PANDA_LLVM_BUILD}" 2>/dev/null)"

# stop on any error
set -e

#Check if the path actually exists
if [ "$PANDA_LLVM" != "" ] && [ ! -d "$PANDA_LLVM" ]; then
    echo "$PANDA_LLVM does not exist"
    if [ -f "$PANDA_LLVM_ROOT/bin/llvm-config" ]; then
        echo "llvm-config found in ${PANDA_LLVM_ROOT}/bin/llvm-config, setting llvm path to just $PANDA_LLVM_ROOT"
        PANDA_LLVM="$(/bin/readlink -f "${PANDA_LLVM_ROOT}")"
    else
        echo "$PANDA_LLVM_ROOT/bin/llvm-config not found either, are you sure that PANDA_LLVM_ROOT is correct?"
        PANDA_LLVM=""
    fi

fi
# set the LLVM_BIT
if [ "$PANDA_LLVM" != "" ]; then
  ## Using PANDA LLVM.
  echo "Found PANDA LLVM on ${PANDA_LLVM_ROOT} -- LLVM SUPPORT IS ENABLED"
  LLVM_BIT="--enable-llvm --with-llvm=${PANDA_LLVM}"
else
  ## Fallback to system LLVM.
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


"$(dirname $0)/configure" \
    --disable-vhost-net \
    --target-list=x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu \
    --prefix="$(pwd)/install" \
    $LLVM_BIT \
    "$@"

make -j ${PANDA_NPROC:-$(nproc || sysctl -n hw.ncpu)}
