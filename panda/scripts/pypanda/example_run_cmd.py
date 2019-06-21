#!/usr/bin/env python3

from pypanda import *
from sys import argv

# No arguments, i386. Otherwise argument should be guest arch
generic_type = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=generic_type)

@blocking
def run_cmd():
    # First revert to root snapshot, then type a command via serial
    panda.revert_sync("root")

    print("Finding cat in cat's memory map:")
    maps = panda.run_serial_cmd("cat /proc/self/maps")
    for line in maps.split("\n"):
        if "cat" in line:
            print(line)

@blocking
def quit():
    print("Finished with run_it, let's quit")
    panda.run_monitor_cmd("quit")

panda.queue_async(run_cmd)
panda.queue_async(quit)

panda.run()
