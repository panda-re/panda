#!/bin/bash
set -ex

# To be run inside panda docker container where PANDA is already built
# in /panda/build (from pre-built container) and /panda.new is mapped in
# from host with newer panda source.

# The /panda.new code will be copied on top of the (old) /panda directory
# Then /panda will be rebuilt
# If called with an argument of 'clean' /panda will first be made clean

# Sync new code on top of old - Preservs old build artifacts
time rsync -rh  /panda.new /panda
cd /panda/build

# Build 
NPROC=$(nproc || sysctl -n hw.ncpu)

if [ "$1" = "clean" ]; then
    make clean
fi

make -j${NPROC}

# Install Pypanda for Bionic and newer
cd /panda/panda/python/core/
pip3 install -q pycparser cffi colorama protobuf # Pypanda dependencies
python3 setup.py install >/dev/null

# XXX: For now disabling tests here since they'll be run in Jenkins
exit 0


#####################

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
