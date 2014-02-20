#!/bin/sh

./configure --target-list=mipsel-softmmu \
--cc=gcc-4.7 \
--cxx=g++-4.7 \
--prefix=`pwd`/install \
--disable-pie \
--enable-llvm \
--with-llvm=/home/tleek/software/llvm-3.0.src/Debug+Asserts \
--enable-debug \
--extra-cflags="-DDEBUG_UNASSIGNED -g" \
--extra-cxxflags="-g" \
&& make -j $(nproc)
