#!/usr/bin/env python3
'''
example_plugin.py

This is the simplest of plugins. It registers a callback for `before_block_exec`
and gives the user a pdb trace each time it is hit.

Run this with python3 example_plugin.py

'''
from pypanda import *
from time import sleep
from sys import argv


# Single arg of arch, defaults to i386
arch = "arm" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch,arch=arch)


@panda.cb_before_block_exec()
def before_block_execute(cpustate,transblock):
	arm_cpustate = panda.get_cpu(cpustate)
	progress("PC: "+str(arm_cpustate.pc))
	return 0

panda.run()
