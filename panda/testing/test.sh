#!/bin/bash -l
# 
# If you put this in your crontab with something like
# 0 0 * * * /home/tleek/git/panda/panda/testing/test.sh
#
# and you fix that path, then you will regress panda every day at midnight



PWD=`pwd`
PANDADIR=/home/tleek/git/panda-regression

PTESTOUT=/tmp/ptest.out

progress () {
    echo $@
    echo $@ >> $PTESTOUT
}

# as in 'we are done'
wearedone () {
    progress $@

    finalresult=$@

    cd $PANDADIR/panda/testing
        
    progress "Panda regression test end"
    progress "`date`"
    progress "-------------------------------------"
    
    cat /tmp/ptest.out  | mail -s "$finalresult" trleek@gmail.com
    
    python ./irccat.py 18.126.0.30 ptest \#panda-regression 

    exit 0
}


echo " " > $PTESTOUT 
progress "-------------------------------------"
progress "`date`"
progress "Panda regression test begin"

cd $PANDADIR
x=`git ls-files -m | grep -v test.sh`

if [[ $x ]]; then
    wearedone "Repo in $PANDADIR has modified but unchecked in files"
else
    progress "Repo in $PANDADIR has no modified files"
fi

progress "Getting up-to-date version of panda" 
    
x=`git pull` # &>> $PTESTOUT
result="$?"

if [ "$result" -ne 0 ]; then
    weardone progress "Git pull failed"
else
    progress "Git pull succeeded"
fi

if [[ $x == *"Already"* ]]; then
    wearedone "no source change"
else
    progress "source changed"
fi
 
progress "Building panda" 

cd build
rm -rf *
../build.sh # &>> $PTESTOUT
result="$?"
        
if [ "$result" -ne 0 ]; then
    wearedone "build.sh failed"
else
    progress "build.sh succeeded"
fi
        
progress "Testing panda"
            
cd ../panda/testing        
export PANDA_REGRESSION_DIR=/home/tleek/ptest
./ptest.py test > /tmp/ptesttmp
result="$?"
cat /tmp/ptesttmp | sed '/^\s*$/d' | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g"  &>> $PTESTOUT            

if [ "$result" -ne 0 ]; then
    wearedone "ptest.py failed"
else
    progress "ptest.py succeeded"
fi

wearedone "Everything seems hunky-dory; regression pased"
