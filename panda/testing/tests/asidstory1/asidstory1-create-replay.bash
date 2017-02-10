#!/bin/bash

if [ -z "$PANDA_REGRESSION_DIR" ]; then
    echo "Need to set PANDA_REGRESSION_DIR"
    exit 1
fi  

# create the replay to use for reference / test
~/git/panda/panda/scripts/run_on_32bitlinux.py guest:/bin/netstat -a

# now you have to install it
mkdir -p ${PANDA_REGRESSION_DIR}/replays/asidstory1
cd replays
cp -r netstat ${PANDA_REGRESSION_DIR}/replays/asidstory1



