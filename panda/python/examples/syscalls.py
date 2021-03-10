#!/usr/bin/env python3
from pandare import Panda

panda = Panda(generic="x86_64")

@panda.ppp("syscalls2", "on_sys_read_return")
def on_sys_read_return(cpu, pc, fd, buf, count):
    print("read return")

@panda.ppp("syscalls2", "on_sys_execve_enter")
def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
    print("execve enter")

@panda.queue_async
def start():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("cat /etc/passwd"))
    panda.end_analysis()

panda.run()
