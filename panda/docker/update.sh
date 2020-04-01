#!/bin/bash
set -ex

# To be run inside panda_bionic docker container where PANDA is already built
# Given an argument of a git SHA1, checkout that commit, build panda and run tests
# If run with a second argument of "clean" run make clean before building

echo "Running update for commit $1"
# Get the current commit
cd /panda/build

# If container modified any tracked files during build (e.g., panda_datatypes.h)
# we need to forget abolut those before we can pull/checkout
git reset --hard

if [ "$2" = "clean" ]; then # We'll fetch by ref (for a PR)
   git fetch origin $1 # for examplerefs/pull/533/head
   git checkout FETCH_HEAD
else
  git fetch -a
  git checkout --force $1
fi

# Build 
NPROC=$(nproc || sysctl -n hw.ncpu)

if [ "$2" = "clean" ]; then # We'll fetch by ref
    make clean
fi

make -j${NPROC}


# Run test suite
#make -j${NPROC} check

# Install Pypanda for Bionic and newer
cd /panda/panda/python/core/
pip3 install -q pycparser cffi colorama protobuf # Pypanda dependencies
python3 setup.py install >/dev/null

# For now disabling tests here since they'll be run in Jenkins
exit 0

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

python3 multi_proc_cbs.py
python3 taint_reg.py
python3 taint_ram.py
# Run record_then_replay on multiple architectures
python3 record_then_replay.py i386
python3 record_then_replay.py x86_64
python3 record_then_replay.py arm
python3 record_then_replay.py ppc
# Test hooking framework
python3 hooking.py
# Regression tests
python3 sleep_in_cb.py
