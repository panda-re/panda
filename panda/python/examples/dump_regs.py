#!/usr/bin/env python3
'''
dump_regs.py

Displays the register state of the CPU at the first 10 blocks it sees.

Run with: python3 dump_regs.py
'''
from time import sleep
from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.queue_blocking
def run_my_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    panda.end_analysis()

ctr = 0

@panda.cb_before_block_exec()
def before_block_execute(cpu, tb):
    global ctr
    ctr += 1

    print(f"\n\n===== State after block {ctr} =====")
    panda.arch.dump_state(cpu)

    if ctr > 10: panda.end_analysis()

panda.run()
