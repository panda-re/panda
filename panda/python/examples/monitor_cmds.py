#!/usr/bin/env python3
'''
monitor_cmds.py

This example shows running monitor commands.

Run with python3 monitor_cmds.py
'''

from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

queued = False
bb_count = 0

@panda.queue_blocking
def my_runcmd():
    panda.revert_sync('root')
    panda.run_serial_cmd("find . /proc/self")

@panda.queue_blocking
def info_mem():
    result = panda.run_monitor_cmd("info mem")
    lines = [x for x in result.split("\n") if x]
    lines.sort(key=lambda x: int(x.split(" ")[-2], 16) if len(x.split(" ")) >= 3 else 0)

    print(f"info mem returned information on {len(lines)} allocations!\n\t Biggest: {lines[-1]}\n\t" \
            "Smallest: {lines[0]}")
    panda.end_analysis()

@panda.cb_before_block_exec
def before_block_exec(cpu, tb):
    global queued, bb_count
    bb_count += 1

panda.run()

print(f"Saw {bb_count} BBs")
