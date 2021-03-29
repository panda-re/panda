#!/usr/bin/env python3
'''
run_cmd.py

This example queues an asynchronous task to run various bash commands and print
them to the screen.

Run with: python3 run_cmd.py
'''

from sys import argv
from pandare import Panda

# No arguments, i386. Otherwise argument should be guest arch
generic_type = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=generic_type)

@panda.queue_blocking
def run_cmd():
    # First revert to root snapshot, then type a command via serial
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))

    print("Finding cat in cat's memory map:")
    maps = panda.run_serial_cmd("cat /proc/self/maps")
    for line in maps.split("\n"):
        if "cat" in line:
            print(line)
    panda.end_analysis()

panda.run()
