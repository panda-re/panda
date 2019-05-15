#!/usr/bin/env python3
'''
example_plugin.py

This is the simplest of plugins. It registers a callback for `before_block_exec`
and gives the user a pdb trace each time it is hit.

Run this with python3 example_plugin.py

'''
from pypanda import *
from time import sleep
import qcows
from sys import argv

# Single arg of arch, defaults to i386
arg1 = "i386" if len(argv) <= 1 else argv[1]

q = qcows.get_qcow(arg1)
panda = Panda(qcow=q)

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.before_block_exec, \
	 						before_block_execute)
	return True

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	progress("Before Block Run")
	return 0

panda.load_python_plugin(init,"example_plugin")
panda.run()
