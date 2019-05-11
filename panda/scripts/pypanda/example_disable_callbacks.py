#!/usr/bin/env python3
'''
example_disable_callbacks.py

This example shows registering, enabling, and disabling of callbacks during 
runtime of a program. In particular, it enables before_block_execute and
after_block_execute. After 2 blocks hit it disables after_block_execute. After 2
additional blocks hit it enables after_block_execute again.
 
Run with: python3 example_disable_callbacks.py

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
	panda.register_callback(handle, panda.callback.after_block_exec,  \
							after_block_execute)
	return True

count = 0

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	global count
	if count < 9:
		progress("before block in python %d" %count)
	if count == 2:
		panda.disable_callback(panda.callback.after_block_exec)
	if count == 4:
		panda.enable_callback(panda.callback.after_block_exec)
	count+=1
	return 0

@panda.callback.after_block_exec
def after_block_execute(cpustate,transblock):
	global count
	if count < 9:
		progress("after block in python %d" % count)
	return 0

panda.load_python_plugin(init,"example_disable_callbacks")
panda.run()
