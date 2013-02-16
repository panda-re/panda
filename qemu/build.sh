#!/bin/sh

./configure --target-list=x86_64-softmmu,x86_64-linux-user,i386-linux-user,\
arm-linux-user,arm-softmmu \
--prefix=`pwd`/install \
--disable-pie \
--enable-llvm \
--with-llvm=../llvm-3.0/Release+Debug+Asserts \
--extra-cflags="-O2" \
--extra-cxxflags="-O2" \
&& make -j8

