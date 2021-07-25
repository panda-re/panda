#!/usr/bin/env python3
'''
asid.py

To give the machine something to do we queue an asynchronous command which
reverts the machine to a snapshot, runs a command, and then ends.

In our analysis we register the asid_changed callback and prints the ASID
output when it changes.

Run with: python3 after_init.py
'''
from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    panda.end_analysis()

@panda.cb_asid_changed()
def asidchange(cpu, old_asid, new_asid):
    if old_asid != new_asid:
        print(f"Asid changed from 0x{old_asid:x} to 0x{new_asid:x}")
    return 0

panda.run()
