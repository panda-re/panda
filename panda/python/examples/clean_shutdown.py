#!/usr/bin/env python3
# Example script to stop an analysis after 100 blocks

from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

block_count = 0
@panda.cb_before_block_exec(name="before")
def before_block_execute(cpustate, transblock):
    global block_count

    if block_count == 10:
        print("Finished with 10 BBs. Loading coverage plugin to start analysis")
        panda.load_plugin("coverage")

    if block_count == 100:
        print("\n\n")
        print("Saw 100 BBs. End analysis")
        panda.end_analysis()
        print("\n\n")

    assert(block_count <= 100), "Callback run after call to end analysis"

    block_count += 1

panda.run()
print("Finished")  # Note this won't run until after end_analysis