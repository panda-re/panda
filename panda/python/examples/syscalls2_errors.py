#!/usr/bin/env python3

from sys import argv
from panda import Panda, blocking, ffi

# Record the address of every function we call using callstack_instr

panda = Panda(generic="x86_64")

@blocking
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    print(panda.run_serial_cmd("cat /tmp/fakefile"))

@panda.ppp("syscalls2_errors", "on_get_error")
def on_call(cpu, pc, call, ctx, sys_errorno, sys_error_description):
    sys_error = ffi.string(sys_error_description)
    if call != ffi.NULL:
        print(f"Got syscall {ffi.string(call.name)} {sys_errorno} {sys_error}")
    else:
        print(f"Got syscall {ctx.no} {sys_errorno} {sys_error}")

panda.queue_async(run_cmd)

panda.run()
