#!/bin/bash

if [ $# != 1 ]
then
    echo "try again with asidstory.bash regressiondir"
    exit 1
fi

regressiondir=$1  

source testing.defs

tst=asidstory1

# this is a fn defined in testing.defs
set_outputs $tst

# delete output b/c we want to make sure this script creates it
/bin/rm -f ./asidstory

# run qemu with asidstory & pandalog
${testingdir}/runqemu.bash i386 ${replaydir}/${tst}/netstat-recording -os linux-32-lava32 -panda asidstory

# output is textual output of asidstory

# move asidstory to outdir
out1=${outdir}/${tst}-asidstory.txt
/bin/mv ./asidstory $testout



