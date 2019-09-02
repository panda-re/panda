from pypanda import *
from time import sleep
from string import printable
import unicodedata

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.enable_precise_pc()
	panda.enable_memcb()
	panda.register_callback(handle, panda.virt_mem_after_write, mem_write_callback)
	panda.register_callback(handle, panda.virt_mem_after_read, mem_read_callback)
	return True

read_tracker =  []

def mem_callback(cpustate, pc, addr, size, buf):
	return 0

@panda.callback.virt_mem_after_write
def mem_write_callback(cpustate,pc, addr, size, buf):
	return 0

@panda.callback.virt_mem_after_read
def mem_read_callback(cpustate,pc, addr, size, buf):
	return 0

