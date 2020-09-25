#!/usr/bin/env python3
from pandare import Panda, blocking, ffi
import ipdb

panda = Panda(generic="x86_64")
#panda = Panda(generic="i386")

panda.load_plugin("syscalls2")
panda.load_plugin("osi")
panda.load_plugin("osi_linux")

printed = set()
ctr = 0
@panda.cb_before_block_exec
def bbe(cpu, tb):
    proc = panda.plugins['osi'].get_current_process(cpu) 
    name = ffi.string(proc.name)
    if name not in printed:
        printed.add(name)
        print(name)

@blocking
def start():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("cat /etc/passwd"))
    panda.end_analysis()

panda.queue_async(start)
panda.run()
