#!/usr/bin/env python3
from pandare import Panda

panda = Panda(generic="i386")

printed = set()
ctr = 0
@panda.cb_before_block_exec
def bbe(cpu, tb):
    proc = panda.plugins['osi'].get_current_process(cpu) 
    if proc == panda.ffi.NULL:
        return
    name = panda.ffi.string(proc.name)
    if name not in printed:
        printed.add(name)
        print(name.decode())

@panda.queue_async
def start():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("cat /etc/passwd"))
    panda.end_analysis()

panda.run()