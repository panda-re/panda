#!/bin/bash
set -e

# To be run inside panda_bionic docker container where PANDA is already built
# Given an argument of a git SHA1, checkout that commit, build panda and run tests

NPROC=$(nproc || sysctl -n hw.ncpu)

cd /panda/build
git fetch -a
git checkout $1
make -j${NPROC}

# Run test suite
make -j${NPROC} check

# Install Pypanda for Bionic and newer
cd /panda/panda/pypanda
pip3 install -q pycparser cffi colorama protobuf # Pypanda dependencies
python3 setup.py install >/dev/null

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
