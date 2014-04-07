#!/bin/sh

./configure --target-list=x86_64-softmmu,x86_64-linux-user,i386-linux-user,\
arm-linux-user,arm-softmmu \
--cc=gcc-4.7 \
--cxx=g++-4.7 \
--prefix=`pwd`/install \
--disable-pie \
--enable-llvm \
--with-llvm=../../llvm-3.3/Debug+Asserts \
--extra-cflags="-O2" \
--extra-cxxflags="-O2" \
&& make -j $(nproc)
