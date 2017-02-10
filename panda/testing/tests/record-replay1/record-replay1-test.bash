#!/bin/bash

#
# record the following executing under 32-bit linux:
#  '/usr/bin/file /bin/ls'
# and then make sure replay works
#

if [ -z "$PANDA_REGRESSION_DIR" ]; then
    echo "Need to set PANDA_REGRESSION_DIR"
    exit 1
fi  

regressiondir=$PANDA_REGRESSION_DIR

source testing.defs

tst=record-replay1

set_outputs $tst


# delete recording to make sure we really create it here. 
/bin/rm -f ${testingdir}/replays/file/file*

# create the recording
${pandadir}/panda/scripts/run_on_32bitlinux.py guest:/usr/bin/file guest:/bin/ls
if [ $? != 0 ]
then
    echo "record failed" > $testout
    exit 1
else
    echo "record succeed" > $testout
fi

${pandadir}/build/i386-softmmu/qemu-system-i386 -replay ${testingdir}/replays/file/file
if [ $? != 0 ]
then
    echo "replay failed" > $testout
    exit 1
else
    echo "replay succeed" > $testout
fi

