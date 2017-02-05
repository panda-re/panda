#!/bin/bash

if [ $# != 1 ]
then
    echo "try again with stringsearch.bash regressiondir"
    exit 1
fi

regressiondir=$1  

source testing.defs

tst=stringsearch1

# this is a fn defined in testing.defs
set_outputs $tst

# delete pandalog & asidstory because we want to make sure that this run creates them
#/bin/rm -f ./asidstory

# run qemu with asidstory & pandalog
echo replaydir $replaydir
${testingdir}/runqemu.bash i386 ${replaydir}/${tst}/cat-recording -panda stringsearch:name=tests/stringsearch1/cat

# save output
/bin/mv tests/stringsearch1/cat_string_matches.txt $testout




