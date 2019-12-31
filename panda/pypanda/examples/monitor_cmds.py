#!/usr/bin/env python3

import os
from enum import Enum
from sys import argv
from panda import Panda, ffi, blocking

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

queued = False
bb_count = 0

@blocking
def my_runcmd():
    panda.revert_sync('root')
    panda.run_serial_cmd("find . /proc/self")

@blocking
def info_mem():
    result = panda.run_monitor_cmd("info mem")
    lines = [x for x in result.split("\n") if x]
    lines.sort(key=lambda x: int(x.split(" ")[-2], 16) if len(x.split(" ")) >= 3 else 0)

    print("info mem returned information on {} allocations!\n\t Biggest: {}\n\t" \
            "Smallest: {}".format(len(lines), lines[-1], lines[0]))
    panda.end_analysis()

@panda.cb_before_block_exec
def before_block_exec(env,tb):
    global queued, bb_count
    bb_count += 1

panda.queue_async(my_runcmd)
panda.queue_async(info_mem)
panda.run()

print("Saw {} BBs".format(bb_count))
