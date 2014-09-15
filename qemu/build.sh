#!/bin/sh

python ../scripts/apigen.py

./configure --target-list=x86_64-softmmu,i386-softmmu,arm-softmmu \
--cc=gcc-4.7 \
--cxx=g++-4.7 \
--prefix=`pwd`/install \
--disable-pie \
--enable-llvm \
--with-llvm=../../llvm-3.3/Release/  \
--extra-cflags="-O2" \
--extra-cxxflags="-O2" \
&& make -j $(nproc)
