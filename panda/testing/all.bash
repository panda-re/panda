#!/bin/bash
#
# all.bash mode regressiondir
#
# arg 1, mode, must be present.  
# allowable values are 'set' and 'test' 
# if 'ref' then we run this test and install its output as
# reference or gold standard
# if 'test' then we run this test and compare its output to
# reference  
#
# arg 2, regressiondir, also must be present
# 
usage="try again with all.bash mode regressiondir"

if [ $# != 2 ]
then
    echo $usage
    exit 1
fi

mode=$1
regressiondir=$2

if [[ $mode != "ref" ]] && [[ $mode != "test" ]]
then
    echo $usage
    exit 1
fi


allstarttime=$(date +%s%N)



source testing.defs


echo "mode=[$mode]"
echo "regressiondir=[$regressiondir]"


num_passed=0
num_failed=0
num_tests=0

declare -A times
declare -A result

for tst in `/bin/ls tests`
do  
    starttime=$(date +%s%N)
    echo "=============="
    echo "test [${tst}] BEGIN"
    #
    # NB: echo of these test scripts does just one thing
    # and that is it creates an output in $testout
    echo "--------------"
    echo "test [${tst}] output BEGIN"
    testcmds="./tests/${tst}/${tst}.bash $regressiondir"
    echo "testcmds=[$testcmds]"
    time $testcmds
    echo "test [${tst}] output END"
    echo "--------------"
    set_outputs $tst
    if [[ $mode == "ref" ]]
    then
	# install output in reference dir
	echo "installing test [$testout] in reference [$refout]"
	cp $testout $refout
    elif [[ $mode == "test" ]]
    then 
	# compare output with reference
	echo "comparing test output with reference"
	echo "diff $testout $refout"
	diff $testout $refout
	if [ $? -eq 0 ]
	then
	    echo "*** test [${tst}] PASSED"
	    num_passed=$((num_passed + 1))
	    result[${tst}]="PASS"
	else
	    echo "*** test [${tst}] FAILED"
	    num_failed=$((num_failed + 1))
	    result[${tst}]="FAIL"
	fi
    fi
    endtime=$(date +%s%N)
    elapsed=$(( $endtime - $starttime ))
    elapsed=$(bc <<< "scale=2; $elapsed / 1000000000" )
    echo "test [${tst}] END.  $elapsed seconds"
    num_tests=$((num_tests + 1))
    time[${tst}]=$elapsed
done

allendtime=$(date +%s%N)
elapsed=$(( $allendtime - $allstarttime ))
elapsed=$(bc <<< "scale=2; $elapsed / 1000000000" )


echo " "
echo "//////////////////"


echo " "
echo "SUMMARY"
for tst in `/bin/ls tests`
do  
    echo "$tst ${result[${tst}]} ${time[${tst}]} sec"
done

echo " "
echo "A total of $num_tests tests completed."
echo "total time required: $elapsed seconds"

if [[ $mode == "test" ]]
then
    echo "** $num_passed PASSED. $num_failed FAILED."
    if [ $num_passed -eq $num_tests ]
    then
	exit 0
    else
	exit 1
    fi
fi
if [[ $mode == "ref" ]]
then
    echo "** references created"
fi


