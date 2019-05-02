#!/usr/bin/env python3

from pypanda import *
import qcows
from sys import argv
from time import sleep

# Single arg of arch, defaults to i386

arg1 = "i386" if len(argv) <= 1 else argv[1]
q = qcows.get_qcow(arg1)

panda = Panda(qcow=q, extra_args="-panda coverage")
#panda = Panda(qcow=q)

@panda.callback.init
def init(handle):
    print("Started - in init")
    panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
    return True

# After 10 blocks, stop

blocks = 0

@panda.callback.before_block_exec
def before_block_execute(cpustate, transblock):
    global blocks
    if blocks == 10:
        progress("Finished with 10 BBs. Stop coverage analysis")
        panda.unload_plugin("coverage")
        progress("Unloaded all c-plugins")

    if blocks > 100:
        progress("Saw 100 BBs. Stopping")
        panda.stop()

    blocks += 1
    return 0

panda.load_python_plugin(init,"on-init")
#panda.load_plugin("coverage") # TESTING
panda.run()

