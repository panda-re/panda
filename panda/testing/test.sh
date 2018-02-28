#!/bin/bash -l
# 
# If you put this in your crontab with something like
# 0 0 * * * /home/tleek/git/panda/panda/testing/test.sh
#
# and you fix that path, then you will regress panda every day at midnight

if [ "$#" -eq 1 ]; then
    if [[ $1 -eq "full" ]]; then
        full=1
    fi
fi

echo $full

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

enabled_tests=`grep -v \# tests/config.testing`
disabled_tests=`grep \# tests/config.testing`

progress "enabled tests:"
for et in $enabled_tests
do
  progress " -- $et"
done
progress "disabled tests:"
for dt in $disabled_tests
do
  t=`echo $dt | sed s/\#//g`
  progress " -- $t"
done

export PANDA_REGRESSION_DIR=/home/tleek/ptest

LASTRES=$PANDA_REGRESSION_DIR/LAST_RESULT
last=`cat $LASTRES`

progress "Last regression test result was $last"

cd $PANDADIR
x=`git ls-files -m | grep -v test.sh | grep -v ptest | grep -v tests`

if [[ $x ]]; then
    # quit if there are un-checked-in files
    wearedone "Repo in $PANDADIR has modified but unchecked in files"
else
    progress "Repo in $PANDADIR has no modified files"
    if [[ $full ]]; then
        progress "-- re running anyhow since you said *full*"
    else
        progress "-- no reason to continue"
        exit 0
    fi
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
    # src hasnt changed.  but if last result was failed regression then
    # we need to go ahead and try to pass
    if [[ $last == "PASS" ]]; then
        wearedone "no source change"
    else
        progress "no source change -- but last result was fail so trying for a pass"
    fi
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

./ptest.py test > /tmp/ptesttmp
result="$?"
cat /tmp/ptesttmp | sed '/^\s*$/d' | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g"  &>> $PTESTOUT            

if [ "$result" -ne 0 ]; then
    wearedone "ptest.py failed"
else
    progress "ptest.py succeeded"
    echo "PASS" > $LASTRES
fi

wearedone "Everything seems hunky-dory; regression pased"
