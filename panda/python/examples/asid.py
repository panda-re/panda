#!/usr/bin/env python3

from sys import argv
from panda import Panda, blocking, ffi

panda = Panda(generic="x86_64" if len(argv) < 2 else argv[1])

@blocking
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    panda.end_analysis()

@panda.cb_asid_changed()
def asidchange(env, old_asid, new_asid):
    if old_asid != new_asid:
        print("Asid changed from %d to %d" % (old_asid, new_asid))
    return 0

panda.queue_async(run_cmd)

panda.run()
