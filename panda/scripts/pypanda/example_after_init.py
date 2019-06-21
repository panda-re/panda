#!/usr/bin/env python3
'''
example_after_init.py

Registers the after_machine_init callback and prints "hit machine init" when
hit.

Run with: python3 example_after_init.py
'''
from pypanda import *
from time import sleep
from sys import argv

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, \
			panda.callback.after_machine_init, after_machine_init)
	return True

@panda.callback.after_machine_init
def after_machine_init(cpustate):
	progress("hit machine init")

panda.load_python_plugin(init,"example_after_init")
panda.run()
