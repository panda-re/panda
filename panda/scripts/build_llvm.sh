#!/bin/bash

# https://gist.github.com/ouankou/27c1fc22aee9125190492ea126125249
export LLVM_VERSION=11
export LLVM_SRC=$HOME/llvm/llvm_src
export LLVM_PATH=$HOME/llvm/llvm_install
export LLVM_BUILD=$HOME/llvm/llvm_build
export CC=`which clang`
export CXX=`which clang++`

mkdir -p $LLVM_SRC
mkdir -p $LLVM_PATH
mkdir -p $LLVM_BUILD

cd $LLVM_SRC

# Clone the repository from the old URL (replace the $LLVM_VERSION with actual version, e.g., 11)
git clone --depth 1 -b release/$LLVM_VERSION.x https://github.com/llvm/llvm-project .

# siglans-missing-cstdint-include-patch
sed -i '/#include <string>/a #include <cstdint>' $LLVM_SRC/llvm/include/llvm/Support/Signals.h
# fix-missing-header-limits-patch
sed -i '/^#include /a #include <limits>' $LLVM_SRC/llvm/utils/benchmark/src/benchmark_register.cc
sed -i '/^#include /a #include <limits>' $LLVM_SRC/llvm/utils/benchmark/src/benchmark_register.h

cd $LLVM_BUILD

# Configure the build using CMake
cmake -G Ninja -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DLLVM_USE_LINKER=gold -DCMAKE_BUILD_TYPE=RELEASE -DCMAKE_INSTALL_PREFIX=$LLVM_PATH -DLLVM_ENABLE_PROJECTS="clang" $LLVM_SRC/llvm

# Build and install LLVM
# Use j1 for less memory consumption -> fixes kill clang process
ninja -j2 -l2
ninja install -j2

# Update environment variables for LLVM
export PATH=$LLVM_PATH/bin:$PATH
export LD_LIBRARY_PATH=$LLVM_PATH/libexec:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=$LLVM_PATH/lib:$LD_LIBRARY_PATH
export LIBRARY_PATH=$LLVM_PATH/libexec:$LIBRARY_PATH
export LIBRARY_PATH=$LLVM_PATH/lib:$LIBRARY_PATH
export MANPATH=$LLVM_PATH/share/man:$MANPATH
export C_INCLUDE_PATH=$LLVM_PATH/include:$C_INCLUDE_PATH
export CPLUS_INCLUDE_PATH=$LLVM_PATH/include:$CPLUS_INCLUDE_PATH
export LLVM_CONFIG_BINARY=$LLVM_PATH/bin/llvm-config
