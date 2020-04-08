#!/bin/bash

# Default targets to build. Change with argument. small = i386-softmmu
TARGET_LIST="x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu"

# If there are arguments, the first arg is target list or 'small'. subsequent args are passed to configure
if [ $# -ge 1 ]; then
    if [ "$1" = "small" ]; then
        TARGET_LIST="i386-softmmu"
    else
        TARGET_LIST="$1"
    fi
    echo "Building PANDA for target(s): $TARGET_LIST"
    shift
fi

# Prefer greadlink over readlink if present. Important for OSX (incompatible readlink).
if type greadlink >/dev/null 2>&1; then
    READLINK=greadlink
else
    READLINK=readlink
fi

# printf wrapper - messages sent to stderr
msg() {
    local fmt=$1
    shift
    printf "%s: $fmt\n" $scriptname $* >&2
}

# Set script related variables.
scriptname=$(basename $0)
scriptdir=$(dirname $0)

# Set source path variables.
PANDA_DIR_REL="$(dirname $0)"
PANDA_DIR="$("$READLINK" -f "${PANDA_DIR_REL}")"

# Get the location of the LLVM compiled for PANDA, respecting environment variables.
PANDA_LLVM_ROOT="${PANDA_LLVM_ROOT:-"${PANDA_DIR_REL}/../llvm"}"
PANDA_LLVM_BUILD="${PANDA_LLVM_BUILD:-Release}"
PANDA_LLVM="$("$READLINK" -f "${PANDA_LLVM_ROOT}/${PANDA_LLVM_BUILD}" 2>/dev/null)"

# Number of concurrent make jobs.
PANDA_NPROC=${PANDA_NPROC:-$(nproc || sysctl -n hw.ncpu)}

# stop on any error
set -e

# Find paths to python2.7 and pip3
# As part of building we need python2 for qemu and pip3 to install pypanda dependencies
# Either use python and pip3 or use pyenv with 3.6.6 and 2.7.9
# This is just a temporary hack until we merge with qemu 4.1 which adds supports python3
#if which pyenv; then
#  eval "$(pyenv init -)"
#  pyenv shell 3.6.6 2.7.9
#  PYTHON2PATH=$(pyenv which python2)
#else
PYTHON2PATH=$(which python2) # First try python2, then python
if [ -z "${PYTHON2PATH}" ] || ! $PYTHON2PATH --version 2>&1 | grep -q 'Python 2\.7'; then
  PYTHON2PATH=$(which python)
  if [ -z "${PYTHON2PATH}" ] || ! $PYTHON2PATH --version 2>&1 | grep -q 'Python 2\.7'; then
    echo "Could not find python2.7. Tried python2 and python"
    exit 1
  fi
fi
#fi

msg "Using python2 at: $PYTHON2PATH"

### Check gcc/g++ versions. 5 and 7 are currently  supported version.
### PANDA no longer builds with versions 4.x.
GCC_TOOLCHAIN_VERSION_MIN=5
GCC_TOOLCHAIN_VERSION_MAX=7
GCC_VERSION_MAJOR=$(gcc -dumpversion | cut -d. -f1)
GCXX_VERSION_MAJOR=$(g++ -dumpversion | cut -d. -f1)

# If c and C++ version >= min and <= max
if [ $GCC_VERSION_MAJOR -ge $GCC_TOOLCHAIN_VERSION_MIN ] && [ $GCXX_VERSION_MAJOR -ge $GCC_TOOLCHAIN_VERSION_MIN ] && [ $GCC_VERSION_MAJOR -le $GCC_TOOLCHAIN_VERSION_MAX ] && [ $GCXX_VERSION_MAJOR -le $GCC_TOOLCHAIN_VERSION_MAX ]; then
    msg "Building with default gcc/g++."
    COMPILER_CONFIG=""


# If we have gcc-7 (max) installed, use it
elif (type gcc-$GCC_TOOLCHAIN_VERSION_MAX && type g++-$GCC_TOOLCHAIN_VERSION_MAX) >/dev/null 2>&1; then
    msg "Building with gcc-$GCC_TOOLCHAIN_VERSION_MAX/g++-$GCC_TOOLCHAIN_VERSION_MAX."
    COMPILER_CONFIG="--cc=gcc-$GCC_TOOLCHAIN_VERSION_MAX --cxx=g++-$GCC_TOOLCHAIN_VERSION_MAX"

# If we have gcc-5 (min) installed, use it
elif (type gcc-$GCC_TOOLCHAIN_VERSION_MIN && type g++-$GCC_TOOLCHAIN_VERSION_MIN) >/dev/null 2>&1; then
    msg "Building with gcc-$GCC_TOOLCHAIN_VERSION_MIN/g++-$GCC_TOOLCHAIN_VERSION_MIN."
    COMPILER_CONFIG="--cc=gcc-$GCC_TOOLCHAIN_VERSION_MIN --cxx=g++-$GCC_TOOLCHAIN_VERSION_MIN"

# Old GCC & G++
elif [ $GCC_VERSION_MAJOR -lt $GCC_TOOLCHAIN_VERSION_MIN -a $GCXX_VERSION_MAJOR -lt $GCC_TOOLCHAIN_VERSION_MIN ]; then
    msg "Older gcc/g++ found. Enforcing gnu11 mode."
    COMPILER_CONFIG="--extra-cflags=-std=gnu11"

else
    msg "Unsupported gcc/g++ found. Trying with default flags. This might fail"
    COMPILER_CONFIG=""
fi

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

### Check that PANDA_LLVM is correct and attempt to fix it if not.
if [ "$PANDA_LLVM" != "" ] && [ ! -d "$PANDA_LLVM" ]; then
    msg "$PANDA_LLVM does not exist"
    if [ -f "$PANDA_LLVM_ROOT/bin/llvm-config" ]; then
        msg "llvm-config found in ${PANDA_LLVM_ROOT}/bin/llvm-config, setting llvm path to just $PANDA_LLVM_ROOT"
        PANDA_LLVM="$("$READLINK" -f "${PANDA_LLVM_ROOT}")"
    else
        msg "$PANDA_LLVM_ROOT/bin/llvm-config not found either, are you sure that PANDA_LLVM_ROOT is correct?"
        PANDA_LLVM=""
    fi
fi

### Set LLVM_CONFIG to be used with the configure script.
if [ $(getconf LONG_BIT) = 32 ]; then
    msg "Running on a 32bit OS -- LLVM SUPPORT IS DISABLED"
    LLVM_CONFIG=""
elif [ "$PANDA_LLVM" != "" ]; then
    ## Using PANDA LLVM.
    msg "Found PANDA LLVM on ${PANDA_LLVM_ROOT} -- LLVM SUPPORT IS ENABLED"
    LLVM_CONFIG="--enable-llvm --with-llvm=${PANDA_LLVM}"
else
    ## Fallback to system LLVM.
    if llvm-config-3.3 --version >/dev/null 2>/dev/null; then
        msg "Found LLVM on $(llvm-config-3.3 --prefix) -- LLVM SUPPORT IS ENABLED"
        LLVM_CONFIG="--enable-llvm --with-llvm=$(llvm-config-3.3 --prefix)"
    elif llvm-config --version >/dev/null 2>/dev/null && [ $(llvm-config --version) == "3.3" ]; then
        msg "Found LLVM on $(llvm-config --prefix) -- LLVM SUPPORT IS ENABLED"
        LLVM_CONFIG="--enable-llvm --with-llvm=$(llvm-config --prefix)"
    else
        msg "No suitable LLVM found -- LLVM SUPPORT IS DISABLED"
        LLVM_CONFIG=""
    fi
fi

### Set other configuration flags, depending on environment.
MISC_CONFIG="--python=$PYTHON2PATH --disable-vhost-net --enable-capstone"
if pkg-config --exists --atleast-version 4.9 xencontrol; then
    ## Enable xencontrol compat API for libxen-4.9 (Ubuntu 18.04LTS).
    MISC_CONFIG="$MISC_CONFIG --extra-cflags=-DXC_WANT_COMPAT_DEVICEMODEL_API"

    ## Alternatively disable Xen altogether and wait for an upstream fix.
    #MISC_CONFIG="$MISC_CONFIG --disable-xen"
fi

### Enable extra osi plugin functionality and debugging.
#MISC_CONFIG="$MISC_CONFIG --extra-cflags=-DOSI_PROC_EVENTS --extra-cflags=-DOSI_MAX_PROC=256"
#MISC_CONFIG="$MISC_CONFIG --extra-cflags=-DOSI_LINUX_PSDEBUG"

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
"${PANDA_DIR_REL}/configure" \
    --target-list=$TARGET_LIST \
    --prefix=$prefix \
    $COMPILER_CONFIG \
    $LLVM_CONFIG \
    $MISC_CONFIG \
    "$@"

msg "Compiling PANDA..."
make -j ${PANDA_NPROC}

if [ "$PANDA_TEST" = "yes" ]; then
    msg "Testing PANDA..."
    make -j ${PANDA_NPROC} check
fi

# vim: set et ts=4 sts=4 sw=4 ai ft=sh :
