#!/usr/bin/env python3
'''
run_cmd.py

This example queues an asynchronous task to run a bash command and print the result to the screen.
It also counts the number of unique basics blocks seen for just that process.

Run with: python3 run_cmd.py
'''

from sys import argv
from pandare import Panda

# No arguments, i386. Otherwise argument should be guest arch
generic_type = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=generic_type)
unique_bbs = set()

@panda.cb_after_block_exec(procname="uname")
def bb_after_exec_usr(cpu, tb, exit_code):
    global unique_bbs
    if panda.in_kernel(cpu) or panda.in_kernel_code_linux(cpu) or exit_code > 1:
        return
    else:
        assert(tb.pc < 0xc0000000)          # Not 32-bit Linux kernel space
        assert(tb.pc < 0x00ffffffffffffff)  # Not 64-bit Linux kernel space
        unique_bbs.add(tb.pc)

@panda.queue_blocking
def run_cmd():
    # First revert to root snapshot, then type a command via serial
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    print(f"Unique BBs observed for \'uname\' process: {len(unique_bbs)}")
    panda.end_analysis()

panda.run()
