#!/bin/bash
#
# runqemu.sh arch replay cmdlineargs 
#
# arch is either x86_64, i386, or arm
# replay is replay file prefix
# rest of args are what cmd line args you need passed to qemu

source testing.defs

echo pwd=[$PWD]

arch=$1
binary=qemu-system-$arch
bindir=../../build/${arch}-softmmu
shift 
replay=$1
shift


# run qemu
cmdline="$bindir/$binary -replay $replay $@"
echo "running [$cmdline]"

$cmdline

