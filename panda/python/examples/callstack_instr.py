#!/usr/bin/env python3

from sys import argv
from os import path
from pandare import Panda

arch = "x86_64" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

panda.load_plugin("callstack_instr", #{"verbose": "true"}
        )

@panda.ppp("callstack_instr", "on_call")
def call_to(cpu, target):
    print(hex(target))

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("whoami"))
    panda.end_analysis()

panda.run()
