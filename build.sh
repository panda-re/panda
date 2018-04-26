#!/bin/bash

# Prefer greadlink over readlink if present. Important for OSX (incompatible readlink).
if type greadlink >/dev/null 2>&1; then
    READLINK=greadlink
else
    READLINK=readlink
fi

# Get the location of the LLVM compiled for PANDA, respecting environment variables.
PANDA_LLVM_ROOT="${PANDA_LLVM_ROOT:-$(dirname $0)/../llvm}"
PANDA_LLVM_BUILD="${PANDA_LLVM_BUILD:-Release}"
PANDA_LLVM="$("$READLINK" -f "${PANDA_LLVM_ROOT}/${PANDA_LLVM_BUILD}" 2>/dev/null)"

# stop on any error
set -e

### Check gcc/g++ versions. 5 is currently the supported version.
### PANDA no longer builds with versions 4.x.
### Versions >5 may not compile due to more aggressive sanitization defaults.
GCC_TOOLCHAIN_VERSION_REQ=5
GCC_VERSION_MAJOR=$(gcc -dumpversion | cut -d. -f1)
GCXX_VERSION_MAJOR=$(g++ -dumpversion | cut -d. -f1)
if [ $GCC_VERSION_MAJOR -eq $GCC_TOOLCHAIN_VERSION_REQ -a $GCXX_VERSION_MAJOR -ge $GCC_TOOLCHAIN_VERSION_REQ ]; then
    echo "Building with default gcc/g++."
    COMPILER_CONFIG=""
elif (type gcc-$GCC_TOOLCHAIN_VERSION_REQ && type g++-$GCC_TOOLCHAIN_VERSION_REQ) >/dev/null 2>&1; then
    echo "Building with gcc-$GCC_TOOLCHAIN_VERSION_REQ/g++-$GCC_TOOLCHAIN_VERSION_REQ."
    COMPILER_CONFIG="--cc=gcc-$GCC_TOOLCHAIN_VERSION_REQ --cxx=g++-$GCC_TOOLCHAIN_VERSION_REQ"
else
    echo "No suitable gcc/g++ found. Trying with default."
    COMPILER_CONFIG=""
fi

### Check for protobuf v2.
if pkg-config --exists protobuf "protobuf > 1 protobuf < 3"; then
    echo "Using protobuf $(pkg-config --modversion protobuf)."
else
    echo "Found incompatible protobuf $(pkg-config --modversion protobuf) -- ABORTING"
    echo "See panda/docs/compile.md for instructions on building protobuf v2."
    exit 1
fi

### Check that PANDA_LLVM is correct and attempt to fix it if not.
if [ "$PANDA_LLVM" != "" ] && [ ! -d "$PANDA_LLVM" ]; then
    echo "$PANDA_LLVM does not exist"
    if [ -f "$PANDA_LLVM_ROOT/bin/llvm-config" ]; then
        echo "llvm-config found in ${PANDA_LLVM_ROOT}/bin/llvm-config, setting llvm path to just $PANDA_LLVM_ROOT"
        PANDA_LLVM="$("$READLINK" -f "${PANDA_LLVM_ROOT}")"
    else
        echo "$PANDA_LLVM_ROOT/bin/llvm-config not found either, are you sure that PANDA_LLVM_ROOT is correct?"
        PANDA_LLVM=""
    fi

fi

### Set LLVM_CONFIG to be used with the configure script.
if [ "$PANDA_LLVM" != "" ]; then
    ## Using PANDA LLVM.
    echo "Found PANDA LLVM on ${PANDA_LLVM_ROOT} -- LLVM SUPPORT IS ENABLED"
    LLVM_CONFIG="--enable-llvm --with-llvm=${PANDA_LLVM}"
else
  ## Fallback to system LLVM.
    if llvm-config --version >/dev/null 2>/dev/null && [ $(llvm-config --version) == "3.3" ]; then
        echo "Found SYSTEM LLVM -- LLVM SUPPORT IS ENABLED"
        LLVM_CONFIG="--enable-llvm --with-llvm=$(llvm-config --prefix)"
    elif llvm-config-3.3 --version >/dev/null 2>/dev/null; then
        echo "Found SYSTEM LLVM -- LLVM SUPPORT IS ENABLED"
        LLVM_CONFIG="--enable-llvm --with-llvm=$(llvm-config-3.3 --prefix)"
    else
        echo "No suitable LLVM found -- LLVM SUPPORT IS DISABLED"
        LLVM_CONFIG=""
    fi
fi

### Set other configuration flags, depending on environment.
MISC_CONFIG="--python=python2 --disable-vhost-net"
if pkg-config --exists --atleast-version 4.9 xencontrol; then
    ## Enable xencontrol compat API for libxen-4.9 (Ubuntu 18.04LTS).
    MISC_CONFIG="$MISC_CONFIG --extra-cflags=-DXC_WANT_COMPAT_DEVICEMODEL_API"

    ## Alternatively disable Xen altogether and wait for an upstream fix.
    #MISC_CONFIG="$MISC_CONFIG --disable-xen"
fi

"$(dirname $0)/configure" \
    --target-list=x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu \
    --prefix="$(pwd)/install" \
    $COMPILER_CONFIG \
    $LLVM_CONFIG \
    $MISC_CONFIG \
    "$@"

make -j ${PANDA_NPROC:-$(nproc || sysctl -n hw.ncpu)}

# vim: set et ts=4 sts=4 sw=4 ai ft=sh :
