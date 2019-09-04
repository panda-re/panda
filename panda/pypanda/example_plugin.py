#!/usr/bin/env python3
'''
example_plugin.py

This is the simplest of plugins. It registers a callback for `before_block_exec`
and gives the user a pdb trace each time it is hit.

Run this with python3 example_plugin.py

'''
from pypanda import *
from sys import argv

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.cb_before_block_exec()
def before_block_execute(cpustate,transblock):
	progress("Before Block Run")
	return 0

panda.run()