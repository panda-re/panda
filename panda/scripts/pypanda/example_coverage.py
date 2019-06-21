#!/usr/bin/env python3
'''
example_coverage.py

Registers the before_block_execute callback. It then dynamically loads and
unloads the coverage plugin.

Run with: python3 example_coverage.py
'''


from pypanda import *
from sys import argv

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.callback.init
def init(handle):
    # Register a python before-BB callback
    panda.register_callback(handle, panda.callback.before_block_exec,\
	 					before_block_execute)
    return True


blocks = 0
@panda.callback.before_block_exec
def before_block_execute(cpustate, transblock):
    global blocks

    if blocks == 10:
        progress("Finished with 10 BBs. Loading coverage plugin to start \
					analysis")
        panda.load_plugin("coverage")

    if blocks == 50:
        progress("Finished with 50 BBs. Ending coverage analysis")
        panda.unload_plugin("coverage")
        progress("Unloaded coverage plugin")

    if blocks == 100:
        progress("Finished with 100 BBs. Loading coverage plugin to start \
					analysis")
        panda.load_plugin("coverage")

    if blocks == 150:
        progress("Finished with 50 BBs. Ending coverage analysis")
        panda.unload_plugin("coverage")
        progress("Unloaded coverage plugin")

    if blocks > 200:
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
