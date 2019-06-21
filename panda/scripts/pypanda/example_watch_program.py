#!/usr/bin/env python3
'''
example_watch_program.py

This example allows us to debug a specific program by name. It registers 
asid_changed  and waits for the osi process name to match the name_of_program
variable.

Run with: python3 example_watch_program.py

'''
from pypanda import *
from time import sleep
from sys import argv

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

name_of_program = "wget" # replace with your program name
bbe_enabled = False

def process_name_convert(name):
	if name == ffi.NULL:
		return ""
	a = ""
	for i in range(16):
		char = name[i].decode()
		if ord(char) == 0:
			break
		a += char
	return a	

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.before_block_exec, \
							before_block_execute)
	panda.register_callback(handle, panda.callback.asid_changed, asid_changed)
	panda.disable_callback(panda.callback.before_block_exec)
	return True

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	progress("Called before block exec")	
	return 0

@panda.callback.asid_changed
def asid_changed(cpustate,old_asid, new_asid):
	if old_asid != new_asid:
		progress("asid changed from %d to %d" % (old_asid, new_asid))
		global asid_of_program, bbe_enabled
		current = panda.get_current_process(cpustate)
		current_name = process_name_convert(current.name)
		
		if current_name == name_of_program:
			bbe_enabled = True
			panda.enable_callback(panda.callback.before_block_exec)
		elif enabled:
			bbe_enabled = False
			panda.disable_callback(panda.callback.before_block_exec)
	return 0

panda.require("osi")
panda.require("osi_linux")
panda.load_osi()
panda.load_python_plugin(init,"example_watch_program")
panda.run()
