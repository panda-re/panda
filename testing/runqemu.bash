#!/bin/bash
#
# runqemu.sh arch replay outfile cmdlineargs 
#
# arch is either x86_64, i386, or arm
# replay is replay file prefix
# outfile is where we expect output to go
# rest of args are what cmd line args you need passed to qemu

source ${HOME}/git/panda/testing/testing.defs

echo pwd=[$PWD]

arch=$1
binary=qemu-system-$arch
bindir=${arch}-softmmu
shift 
replay=$1
shift
outfile=$1
shift

# delete outfile to ensure because we want to make sure that this run creates it
/bin/rm -f $outfile

# run qemu
cmdline="${pandadir}/qemu/$bindir/$binary -replay $replay $@"
echo "running [$cmdline]"

$cmdline

