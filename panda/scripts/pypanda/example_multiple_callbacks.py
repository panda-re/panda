#!/usr/bin/env python3
'''
example_multiple_callbacks.py

This example registers the before_block_exec and after_block_exec callbacks and
prints a message and sleeps each time the callback is hit.

Run with: python3 example_multiple_callbacks.py
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
	panda.register_callback(handle, panda.callback.before_block_exec,\
							before_block_execute)
	panda.register_callback(handle, panda.callback.after_block_exec, \
							after_block_execute)
	return True

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	progress("before block in python")
	sleep(sleeptime)
	return 0

@panda.callback.after_block_exec
def after_block_execute(cpustate,transblock):
	progress("after block in python")
	sleep(sleeptime)
	return 0

sleeptime = 1
panda.load_python_plugin(init,"example_multiple_callbacks")
panda.run()
