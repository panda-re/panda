#!/usr/bin/env python3

import os
from enum import Enum
from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

monitor_lines = []
bb_count = 0

@panda.queue_blocking
def my_runcmd():
    panda.revert_sync('root')
    panda.run_serial_cmd("find . /proc/self")

@panda.queue_blocking
def info_reg():
    global monitor_lines
    result = panda.run_monitor_cmd("info registers")
    monitor_lines = result.split("\n")
    panda.end_analysis()

@panda.cb_before_block_exec
def before_block_exec(env,tb):
    global bb_count
    bb_count += 1

panda.run()

assert(len(monitor_lines) > 5), "Not enough output from monitor"
assert(bb_count > 10000), "Not enough blocks run"
