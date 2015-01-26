#!/bin/bash
# 

if [ $# != 1 ]
then
    echo "try again with asidstory.bash regressiondir"
    exit 1
fi


regressiondir=$1  

source ${HOME}/git/panda/testing/testing.defs

tst=asidstory1

# this is a fn defined in testing.defs
set_outputs $tst


# this is where pandlog will go
pandalog=${outdir}/asidstory1.pandalog

# delete pandalog & asidstory because we want to make sure that this run creates them
/bin/rm -f $pandalog
/bin/rm -f ./asidstory


# run qemu with asidstory & pandalog
${testingdir}/runqemu.bash i386 ${replaydir}/NotExploitable/notexploitable -pandalog $pandalog -panda 'debianwheezyx86intro;asidstory'

# really there are two outputs here.
# 1. the textual asidstory (in the file ./asidstory)
# 2. the pandalog

# move asidstory to outdir
out1=${outdir}/${tst}-asidstory.txt
/bin/mv ./asidstory $out1

# convert pandalog into text
out2=${outdir}/${tst}-pandalog.txt
${pandadir}/qemu/panda/pandalog_reader $pandalog > $out2

# cat the two results together for a single output

# concat asidstory + textified pandalog.  this is complete test output
testout=${outdir}/${tst}.${testoutsuff}
/bin/cat $out1 $out2 > $testout

