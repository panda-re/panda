#!/usr/bin/env python3

from sys import argv
from pandare import Panda

# Record the address of every function we call using callstack_instr

generic_type = argv[1] if len(argv) > 1 else "mipsel"
panda = Panda(generic=generic_type)

if (generic_type == "i386") or (generic_type == "x86_64"):
    panda.load_plugin("callstack_instr")
else:
    panda.load_plugin("callstack_instr", args = {"stack_type":"heuristic"})

@panda.queue_async
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    panda.end_analysis()

@panda.ppp("callstack_instr", "on_call")
def on_call(cpu, func):
    print(f"Call to 0x{func:x}")

panda.disable_tb_chaining()
panda.run()
