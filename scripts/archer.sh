#!/bin/bash
# Written by xVlaze for [FORKED]PANDA, June 2016
# Original project by Moyix & team
# Revised 6th June, 2016
# This script is called from build.sh in order to copy some important files required for
# later actions.
# Licensed under the GNU General Public License version 3 or later.

ARCH=$(arch)
cp ../qemu/$ARCH-softmmu/config-devices.mak ..
cp ../qemu/$ARCH-softmmu/config-target.mak ..
cp ../qemu/$ARCH-softmmu/config-devices.mak ../qemu
cp ../qemu/$ARCH-softmmu/config-target.mak ../qemu
cp ../qemu/$ARCH-softmmu/config-target.h ..
cp ../qemu/$ARCH-softmmu/config-target.h ../qemu

