#!/bin/sh

#./configure --target-list=i386-softmmu,i386-linux-user,\
#arm-linux-user,x86_64-linux-user,x86_64-softmmu \
./configure --target-list=x86_64-softmmu \
--enable-llvm \
--with-llvm=../laredo/llvm-3.0/Release+Debug+Asserts \
--enable-llvm-trace \
--enable-instr-helpers \
--with-laredo=../laredo/llvm-3.0/projects/laredo/Release+Debug+Asserts \
--extra-cflags="-O2" \
--extra-cxxflags="-O2"

#,x86_64-linux-user,x86_64-softmmu\
#,arm-linux-user,arm-softmmu\

#--enable-instr-helpers \
#--with-laredo=../llvm-3.0/projects/laredo/Release+Debug+Asserts \

