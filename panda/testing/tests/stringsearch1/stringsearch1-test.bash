#!/bin/bash

if [ -z "$PANDA_REGRESSION_DIR" ]; then
    echo "Need to set PANDA_REGRESSION_DIR"
    exit 1
fi  

regressiondir=$PANDA_REGRESSION_DIR

source testing.defs

tst=stringsearch1

# this is a fn defined in testing.defs
set_outputs $tst

# run qemu with asidstory & pandalog

rm tests/stringsearch1/cat_string_matches.txt
${testingdir}/runqemu.bash i386 ${replaydir}/${tst}/cat/cat -panda stringsearch:name=tests/stringsearch1/cat

# save output
mv tests/stringsearch1/cat_string_matches.txt $testout


