#!/bin/bash
# 
# If you put this in your crontab with something like
# 0 0 * * * /home/tleek/git/panda/panda/testing/test.sh
#
# and you fix that path, then you will regress panda every day at midnight

PWD=`pwd`
PANDADIR=/home/tleek/git/panda-regression

PTESTOUT=/tmp/ptest.out


echo PANDA REGRESSION TESTS BEGIN > $PTESTOUT
echo "-------------------------------------" >> $PTESTOUT
date >> $PTESTOUT

echo "Getting up-to-date version of panda"  >> $PTESTOUT
echo "-------------------------------------" >> $PTESTOUT
cd $PANDADIR
git pull >> $PTESTOUT


echo "Building panda"  >> $PTESTOUT
echo "-------------------------------------" >> $PTESTOUT

cd build
../build.sh >> $PTESTOUT
make >> $PTESTOUT


echo "Testing panda"  >> $PTESTOUT
echo "-------------------------------------" >> $PTESTOUT

cd ../panda/testing


export PANDA_REGRESSION_DIR=/home/tleek/ptest
./ptest.py test | sed '/^\s*$/d' | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g"  >> $PTESTOUT

subj=`grep ptest.py /tmp/ptest.out | tail -1`

cat /tmp/ptest.out  | mail -s "$subj" trleek@gmail.com

echo "-------------------------------------" >> $PTESTOUT
echo PANDA REGRESSION TESTS END >> $PTESTOUT

date >> $PTESTOUT
