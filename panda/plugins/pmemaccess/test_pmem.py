#!/usr/bin/env python3
import sys
from sys import argv
from pandare import Panda

panda = Panda(generic="i386")

@panda.queue_blocking
def run_cmd():
    global name
    panda.revert_sync("root")
    #print(panda.run_serial_cmd("cat /proc/kallsyms | grep access"))
    panda.end_analysis()

#panda.plugins["pmemaccess"].inject_syscall(cpu, EXIT_GROUP, 2, raw_args)

panda.enable_precise_pc()
panda.disable_tb_chaining()
panda.run()
