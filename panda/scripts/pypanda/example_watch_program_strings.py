#!/usr/bin/env python3
from pypanda import *
from time import sleep
from sys import argv

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

name_of_program = "wget" # replace with your program name
cb_enabled = False

def program_name_convert(name, null="(NULL)",length=16):
	if name == ffi.NULL:
		return null
	a = ""
	try:
		for i in range(length):
			char = name[i].decode()
			if ord(char) == 0:
				break
			a += char
		return a	
	except:
		return null

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.asid_changed, asid_changed)
	panda.register_callback(handle, panda.callback.virt_mem_after_read, virt_mem_after_read)
	panda.disable_callback(panda.callback.virt_mem_after_read)
	panda.enable_memcb()
	return True

@panda.callback.virt_mem_after_read
def virt_mem_after_read(cpustate, pc, addr, size, buf):
	curbuf = ffi.cast("char*", buf)
	current = panda.get_current_process(cpustate)
	if current != ffi.NULL:
		if size >= 5:
			from string import printable
			current_name = program_name_convert(current.name)
			buf_addr = hex(int(ffi.cast("uint64_t", buf)))
			buf_chr = ffi.cast("uint8_t*", buf)
			b = "".join([chr(buf_chr[i]) if printable else '' for i in range(size)])
			progress("Read buf: %s, size: %x, at pc: %x %s" %(buf_addr[2:], size, addr, b))
	else:
		progress("current is NULL")
	return 0

@panda.callback.asid_changed
def asid_changed(cpustate,old_asid, new_asid):
	if old_asid != new_asid:
		global cb_enabled
		current = panda.get_current_process(cpustate)
		current_name = program_name_convert(current.name)
		if current_name == name_of_program and not cb_enabled:
			cb_enabled = True
			progress("program name is "+current_name)
			panda.enable_callback(panda.callback.virt_mem_after_read)
		elif cb_enabled and current_name != name_of_program:
			cb_enabled = False
			progress("program name is "+current_name)
			panda.disable_callback(panda.callback.virt_mem_after_read)
	return 0

panda.load_python_plugin(init,"example_watch_program_strings")
panda.begin_replay(argv[2])
panda.run()
