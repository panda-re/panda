#!/usr/bin/env python3

from sys import argv
from panda import Panda, blocking, ffi

# Record the address of every function we call using callstack_instr

panda = Panda(generic="i386")
panda.load_plugin("callstack_instr")

@blocking
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    panda.end_analysis()

@panda.ppp("callstack_instr", "on_call")
def on_call(cpu, func):
    print(f"Call to 0x{func:x}")

panda.queue_async(run_cmd)

panda.run()
