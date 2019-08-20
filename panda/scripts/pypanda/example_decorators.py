#!/usr/bin/env python3

from pypanda import *
from sys import argv
import subprocess
import os
import shlex
import threading

# Record some programs running in the guest
# for some programs, register python callbacks

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

seen_bbs = set()
seen_bbs2 = set()

# Run a command in the guest
@blocking
def my_runcmd():
    panda.revert_sync("root")
    #panda.run_serial_cmd("cat /proc/self/environ; echo 'hi'; cat /dev/random | head -n 1000")
    panda.run_serial_cmd("cat /proc/self")
    r = panda.run_serial_cmd("whoami")
    print("WHOAMI:", r)

    # By quitting here main thread can continue executing after panda.run
    # XXX: Need a better way to transfer control back to main thread - maybe via main_loop_wait callbacks?
    panda.run_monitor_cmd("quit")

"""
@panda.cb_virt_mem_after_read(name="test_vmread", procname="wget", enabled=False)
def virt_mem_after_read(cpustate, pc, addr, size, buf):
    print("AHHHH\n")
    curbuf = ffi.cast("char*", buf)
    if size >= 5:
        from string import printable
        buf_addr = hex(int(ffi.cast("uint64_t", buf)))
        buf_chr = ffi.cast("uint8_t*", buf)
        b = "".join([chr(buf_chr[i]) if printable else '' for i in range(size)])
        progress("Read buf: %s, size: %x, at pc: %x %s" %(buf_addr[2:], size, addr, b))
    return 0
"""

@panda.cb_before_block_exec(name="test_vmread", procname="whoami")
def before_block_execute(env, tb):
    pc = panda.current_pc(env)
    global seen_bbs
    seen_bbs.add(pc)
    return 0

@panda.cb_after_block_exec(name="test_vmread2", procname="cat")
def before_block_execute2(env, tb):
    pc = panda.current_pc(env)
    global seen_bbs2
    seen_bbs2.add(pc)
    return 0

panda.queue_async(my_runcmd)
panda.run()

# We get here after we quit via the monitor in the async thread
print("All done running commands")
print("whoami", hex(min(seen_bbs)), hex(max(seen_bbs)))
print("cat", hex(min(seen_bbs2)), hex(max(seen_bbs2)))
