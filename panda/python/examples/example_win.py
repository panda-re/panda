#!/usr/bin/env python3
'''
example_win.py

This is an example for taking a recording of windows and then replaying it and 
using it to do analysis.
'''
from pandare import Panda

rec = False

if rec:
    panda = Panda(qcow="win7pro_x86.qcow2",mem="4G", extra_args=["-vnc", "127.0.0.1:5900", "-monitor","telnet:127.0.0.1:55555,server,nowait"])
else:
    panda = Panda(qcow="win7pro_x86.qcow2",mem="4G", extra_args=["-nographic"],os_version="windows-32-7sp1")

first = True

@panda.cb_asid_changed
def asidchange(cpu, old_asid, new_asid):
    if old_asid != new_asid:
        global first
        if first:
            print("processes:")
            for proc in panda.get_processes(cpu):
                print(f"{panda.ffi.string(proc.name)} {proc.pid} {proc.ppid}")
            first = False
        else:
            print(f"process: {panda.get_process_name(cpu)}")
    return 0

if rec:
    panda.run()
else:
    panda.run_replay("rec_name")

