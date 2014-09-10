#!/bin/sh

python ../scripts/apigen.py
./configure --target-list=x86_64-softmmu,i386-softmmu,arm-softmmu,x86_64-linux-user,i386-linux-user,arm-linux-user,arm-softmmu \
--cc=gcc-4.8 \
--cxx=g++-4.8 \
--prefix=`pwd`/install \
--disable-pie \
--enable-llvm \
--with-llvm=../llvm/Debug+Asserts \
--extra-cflags="-O2" \
--extra-cxxflags="-O2" \
--extra-ldflags="-L/usr/local/lib -L/usr/local/lib64"\
&& make -j $(nproc)
