#!/bin/bash
set -ex

# To be run inside panda docker container where PANDA is already built
# in /panda/build and pypanda is installed - run pypanda tests

major_version=$(lsb_release --release | awk -F':[\t ]+' '{print $2}' | awk -F'.' '{print $1}')

if [ $major_version -le 16 ]; then
    echo "Skipping PYPANDA tests for old version of Ubuntu"
    exit 0
else
    echo "Starting PYPANDA tests"
fi

# Run pypanda tests
cd tests
make # Build binaries we run in guest

pip3 install -q -r requirements.txt

# Read enabled_tests.txt and run each. If any exit 0 log failure but run the rest
failures=()
while read test_line; do
    echo -e "\n./$test_line"
    ./$test_line
    [ $? != 0 ] && echo "Failure $test_line" && failures+=($test_line)
done < enabled_tests.txt

if [ "${#failures[@]}" -ge "1" ]; then
  echo "Test(s) failed: $failures"
  exit 1
fi
