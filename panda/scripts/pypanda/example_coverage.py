#!/usr/bin/env python3
from pypanda import *
import qcows
from sys import argv

# Single arg of arch, defaults to i386
arg1 = "i386" if len(argv) <= 1 else argv[1]

q = qcows.get_qcow(arg1)
panda = Panda(qcow=q)

@panda.callback.init
def init(handle):
    # Register a python before-BB callback
    panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
    return True


blocks = 0
@panda.callback.before_block_exec
def before_block_execute(cpustate, transblock):
    global blocks
    if blocks == 10:
        progress("Finished with 10 BBs. Loading coverage plugin to start analysis")
        panda.load_plugin("coverage")

    if blocks == 50:
        progress("Finished with 50 BBs. Ending coverage analysis")
        panda.unload_plugin("coverage")
        progress("Unloaded coverage plugin")

    if blocks > 100:
        progress("Saw 100 BBs. Stopping")
        panda.stop()

    blocks += 1
    return 0

# Register a python plugin, the init function above
panda.load_python_plugin(init,"on-init")

# Register a c plugin, coverage
#panda.load_plugin("coverage")

# Start running
panda.run()
