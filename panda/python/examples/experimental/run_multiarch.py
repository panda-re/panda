#!/usr/bin/env python3

# Use different panda libraries for different archs

from sys import argv
from pandare import Panda, blocking


@blocking
def run_cmd():
    # First revert to root snapshot, then type a command via serial
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    panda.end_analysis()

# XXX: Generally you can't recreate the panda object, but it can be done here because the arch is changing
for arch in ["x86_64", "i386", "arm", "ppc"]:
    print(f"Starting {arch}")
    panda = Panda(generic=arch)

    panda.queue_async(run_cmd)
    panda.run()

    print(f"Finished with {arch}")
