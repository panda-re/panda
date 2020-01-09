#!/bin/bash
set -e

# To be run inside one of our docker containers where PANDA is already built
# Given an argument of a git SHA1, checkout that commit, build panda and run tests

echo "Testing commit $1"

cd /panda/build
git fetch -a
git checkout $1
make -j4
