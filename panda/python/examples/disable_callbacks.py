#!/usr/bin/env python3
'''
example_disable_callbacks.py

This example shows registering, enabling, and disabling of callbacks during 
runtime of a program. In particular, it enables before_block_execute and
after_block_execute. After 2 blocks hit it disables after_block_execute. After 2
additional blocks hit it enables after_block_execute again.

Run with: python3 example_disable_callbacks.py

'''
from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

count = 0

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    res = panda.run_serial_cmd("whoami")
    print("whoami returns:", res)
    panda.end_analysis()

@panda.cb_before_block_exec
def before_block_execute(cpustate,transblock):
	global count
	if count < 9:
		print("before block in python %d" %count)
	if count == 2:
		panda.disable_callback("after")
	if count == 4:
		panda.enable_callback("after")
	count+=1

@panda.cb_after_block_exec
def after_block_execute(cpustate,transblock,exit):
	global count
	if count < 9:
		print("after block in python %d" % count)
	else:
		panda.end_analysis()

panda.run()
