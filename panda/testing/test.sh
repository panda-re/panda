#!/bin/bash
# 
# If you put this in your crontab with something like
# 0 0 * * * /home/tleek/git/panda/panda/testing/test.sh
#
# and you fix that path, then you will regress panda every day at midnight


PWD=`pwd`
PANDADIR=/home/tleek/git/panda-regression

PTESTOUT=/tmp/ptest.out

progress () {
  echo $1
  echo $1 >> $PTESTOUT
}


echo " " > $PTESTOUT 
progress "REGRESSION TESTS BEGIN"
progress "-------------------------------------"
progress "`date`"

progress "Getting up-to-date version of panda" 
progress "-------------------------------------"
cd $PANDADIR
git pull &>> $PTESTOUT
result="$?"

if [ "$result" -ne 0 ]; then
    subj="git pull FAILED"
else 
    
    progress "Building panda" 
    progress "-------------------------------------"
    
    cd build
    rm -rf *
    ../build.sh &>> $PTESTOUT
    result="$?"
    
    if [ "$result" -ne 0 ]; then
        progress "build.sh failed"
        subj="build.sh FAILED"
    else
        progress "build.sh succeeded"
        
        progress "Testing panda"
        progress "-------------------------------------"
            
        cd ../panda/testing        
        export PANDA_REGRESSION_DIR=/home/tleek/ptest
        ./ptest.py test | sed '/^\s*$/d' | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g"  &>> $PTESTOUT            
        result="$?"
        
        if [ "$result" -ne 0 ]; then
            progress "ptest.py failed"
            subj="ptest.py FAILED" 
        else                
            progress "ptest.py suceeded"
            subj=`grep ptest.py /tmp/ptest.out | tail -1`
        fi
    fi
fi

cd $PANDADIR/panda/testing
        
progress "-------------------------------------"
progress "PANDA REGRESSION TESTS END"
progress "result: $subj"

date >> $PTESTOUT

cat /tmp/ptest.out  | mail -s "$subj" trleek@gmail.com

python ./irccat.py -l DEBUG 18.126.0.30 ptest \#panda-regression 
