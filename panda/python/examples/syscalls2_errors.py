#!/usr/bin/env python3

from sys import argv
from panda import Panda, blocking, ffi

# Record the address of every function we call using callstack_instr

panda = Panda(generic="x86_64")#,extra_args=["-panda", "syscalls2:load-info=true"])

panda.load_plugin("syscalls2", {"load-info":"true"})


'''

do string reads and save them early on
'''

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
    for i in range(call.nargs):
        callargtype = call.argt[i]
        callargtype_s = ffi.string(ffi.cast("syscall_argtype_t", callargtype))
        if "STR" in callargtype_s:
            try:
                str_ptr = ffi.cast("target_ulong", ctx.args[i])
                print(f"STR FOUND {panda.read_str(cpu,str_ptr)}")
                import ipdb
                ipdb.set_trace()
            except:
                str_ptr = ffi.cast("target_ulong", ctx.args[i])
                print(f"FAILED STRING FIND")

panda.queue_async(run_cmd)

panda.run()
