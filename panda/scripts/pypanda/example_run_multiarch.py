#!/usr/bin/env python3

from pypanda import *
from sys import argv

# Re-initialize panda object as various pandas of different archicectures

# XXX: Doesn't currently work

@blocking
def run_cmd():
    # First revert to root snapshot, then type a command via serial
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))

@blocking
def quit():
    panda.run_monitor_cmd("quit")

for arch in ["x86_64", "i386", "arm", "ppc"]:
    progress(f"Starting {arch}")
    panda = Panda(generic=arch)

    panda.queue_async(run_cmd)
    panda.queue_async(quit)

    panda.run()
    progress(f"Finished with {arch}")
    del panda
