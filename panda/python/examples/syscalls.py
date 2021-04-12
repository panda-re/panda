#!/usr/bin/env python3
'''
syscalls.py

This shows off using PPP to register various syscalls2 returns.

Run with: python3 syscalls.py
'''
from pandare import Panda
from sys import argv

arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.ppp("syscalls2", "on_sys_read_return")
def on_sys_read_return(cpu, pc, fd, buf, count):
    print("read return")

@panda.ppp("syscalls2", "on_sys_execve_enter")
def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
    print("execve enter")

@panda.queue_blocking
def start():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("cat /etc/passwd"))
    panda.end_analysis()

panda.run()
