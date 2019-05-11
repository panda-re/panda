#!/usr/bin/env python3
'''
example_virt_mem_read_callback.py

This plugin registers the virt_mem_after_write callback and attempts to find
strings in the buffers.

Run with: python3 example_virt_mem_read_callback.py
'''
from pypanda import *
from time import sleep
from string import printable
import qcows
import unicodedata


# Single arg of arch, defaults to i386
arg1 = "i386" if len(argv) <= 1 else argv[1]

q = qcows.get_qcow(arg1)
panda = Panda(qcow=q)

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.virt_mem_after_write,\
							 virt_mem_after_write)
	return True

@panda.callback.virt_mem_after_write
def virt_mem_after_write(cpustate,pc, addr, size, buf):
	z = ffi.cast("char*", buf)
	str_build = ""
	for i in range(size):
		value = str(z[i].decode('utf-8','ignore'))
		if value in printable and value != " ":
			str_build += value
	if len(str_build) >= 5:
		progress("cool string: "+str(str_build))
	return 0


panda.enable_memcb()
panda.load_python_plugin(init,"example_virt_mem_read")
panda.run()
