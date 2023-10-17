#!/bin/bash
# Usage ./build.sh [--python]  [architectures] [Configure flags...]
# example: ./build.sh i386-softmmu,arm-softmmu
#          ./build.sh --python i386-softmmu,arm-softmmu
#          ./build.sh small # small = i386-softmmu
#          LLVM_CONFIG_BINARY=llvm-config-11-64 ./build.sh small # set custom llvm-config path

# Note the --python flag installs using `pip -e` which leaves files in a local
# directory (panda/python/core) instead of installing to your system.
# This allows you to edit those scripts, but means you can't delete the directory
# and still use pypanda.

# printf wrapper - messages sent to stderr
msg() { 
    local fmt=$1
    shift
    printf "%s: $fmt\n" build.sh $* >&2
}

# Default targets to build. Change with argument. small = i386-softmmu
TARGET_LIST="x86_64-softmmu,i386-softmmu,arm-softmmu,aarch64-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu,mips64-softmmu"
LLVM_CONFIG_BINARY="${LLVM_CONFIG_BINARY:-llvm-config-11}"

pypanda=""
# Check if first argument is --python
if [ $# -ge 1 ]; then
    if [ "$1" = "--python" ]; then
        echo "Installing PyPANDA"
        pypanda="yes"
        shift
    fi
fi

# If there are more arguments, the first arg is target list or 'small'. subsequent args are passed to configure
if [ $# -ge 1 ]; then if [ "$1" = "small" ]; then
        TARGET_LIST="i386-softmmu"
    else
        if [[ "$1" == *"-softmmu" ]]; then
            TARGET_LIST="$1"
        else
            TARGET_LIST="$1-softmmu"
        fi
    fi
    echo "Building PANDA for target(s): $TARGET_LIST"
    shift
fi

echo "Build arguments: $@"

# Prefer greadlink over readlink if present. Important for OSX (incompatible readlink).
if type greadlink >/dev/null 2>&1; then
    READLINK=greadlink
else
    READLINK=readlink
fi

# Set source path variables.
PANDA_DIR_REL="$(dirname $0)"
PANDA_DIR="$("$READLINK" -f "${PANDA_DIR_REL}")"

# Number of concurrent make jobs.
PANDA_NPROC=${PANDA_NPROC:-$(nproc || sysctl -n hw.ncpu)}

# stop on any error
set -e

### Check gcc/g++ versions: 7.1-9.3.0 are supported. If you want to build with clang, you might need to disable this
gcc --version | awk '/gcc/ && ($3+0)<7.1{print "Fatal error: GCC too old"; exit 1}' || exit 1
g++ --version | awk '/g\+\+/ && ($3+0)<7.1{print "Fatal error: G++ too old"; exit 1}' || exit 1

# Untested GCC - it's probably going to have some warnings - Just disable Werror and hope it works
COMPILER_CONFIG=""
gcc --version | awk '/gcc/   && ($3+0)>11.2{print "WARNING: Your GCC is too new: disabling -Werror and hoping this builds"; exit 1}' || COMPILER_CONFIG+="--extra-cflags=-Wno-error"
g++ --version | awk '/g\+\+/ && ($3+0)>11.2{print "WARNING: Your G++ is too new: disabling -Werror and hoping this builds"; exit 1}' ||  COMPILER_CONFIG+=" --extra-cxxflags=-Wno-error"

### Check for protobuf v2.
if ! pkg-config --exists protobuf; then
    msg "No pkg-config for protobuf. Continuing anyway..."
elif pkg-config --exists protobuf "protobuf >= 2"; then
    msg "Using protobuf $(pkg-config --modversion protobuf)."
else
    msg "Found incompatible protobuf $(pkg-config --modversion protobuf) -- ABORTING"
    msg "See panda/docs/compile.md for instructions on building protobuf v2."
    exit 1
fi

### Set LLVM_CONFIG to be used with the configure script.
# No LLVM binary: Disable LLVM
if ! command -v $LLVM_CONFIG_BINARY &> /dev/null; then
    echo "LLVM 11 not installed. LLVM SUPPORT IS DISABLED."
    LLVM_CONFIG=""
fi
# OSX: Disable LLVM
if [ $(getconf LONG_BIT) = 32 ]; then
    msg "Running on a 32bit OS -- LLVM SUPPORT IS DISABLED"
    LLVM_CONFIG=""
fi

## Use system LLVM-11
if $LLVM_CONFIG_BINARY --version >/dev/null 2>/dev/null; then
    msg "Found LLVM on $($LLVM_CONFIG_BINARY --prefix) -- LLVM SUPPORT IS ENABLED"
    LLVM_CONFIG="--enable-llvm --with-llvm=$($LLVM_CONFIG_BINARY --prefix)"
else
    msg "No suitable LLVM found -- LLVM SUPPORT IS DISABLED"
    LLVM_CONFIG=""
fi

### Ensure Rust version is up to date
if ! command -v cargo &> /dev/null
then
    msg ""
    msg ""
    msg "Rust could not be found. Install it using the following command:"
    msg ""
    msg "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    msg ""

    exit 1
fi

RUST_VERSION="$(cargo --version | grep -o -E '1\.[0-9]+' | cut -c 3-)"

if [[ "$RUST_VERSION" -lt "64" ]]; then
    echo "Rust version 1.$RUST_VERSION is not compatible! Updating to latest."
    rustup update stable
    rustup default stable
fi

### Force QEMU options definitions to be regenerated.
rm -f "${PANDA_DIR}/qemu-options.def"

### Include any local build configurations options.
BUILD_LOCAL="${PANDA_DIR}/build.inc.sh"
if [ -f "$BUILD_LOCAL" ]; then
    msg "Including local configuration from $BUILD_LOCAL."
    . "$BUILD_LOCAL"
fi

# will install to $(pwd)/install UNLESS $prefix is set when script is run
if [ -z "$prefix" ]; then
    prefix="$(pwd)/install"
    echo "Using default prefix: $prefix"
else
    echo "Using specified prefix: $prefix"
fi

## Configure/compile/test.
msg "Configuring PANDA..."
set -x
"${PANDA_DIR_REL}/configure" \
    --target-list=$TARGET_LIST \
    --prefix=$prefix \
    $COMPILER_CONFIG \
    $LLVM_CONFIG \
    "$@"
set +x

msg "Compiling PANDA..."
make -j ${PANDA_NPROC}

if [ -n "$pypanda" ]; then
    msg "Installing PyPANDA (developer mode)..."
    pip install -e ../panda/python/core
fi

# vim: set et ts=4 sts=4 sw=4 ai ft=sh :
