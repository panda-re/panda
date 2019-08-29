#!/usr/bin/env python3
from pypanda import *
from sys import argv
import time
import pickle
from panda_x86_helper import *

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4444,server,nowait"
panda = Panda(generic=arch,extra_args=extra)

with open("libc_syms.pickle", "rb") as f:
    libc = pickle.load(f)

f = open("fwrite.out","wb")


# #@panda.hook(syms["open64"],libraryname="libc", kernel=False)
# def fopen_hook(cpustate, tb):
# 	# grab arguments ESP, arg1, arg2, arg3...
# 	ret = ffi.new("uint32_t[]", 5)
# 	size = ffi.cast("target_ptr_t", ffi.sizeof(ret))
# 	faddr = ffi.cast("target_ptr_t", cpustate.env_ptr.regs[R_ESP]) # esp
# 	panda.virtual_memory_read(cpustate,faddr, ret, size) 
# 	string_arg = ffi.new("char[]", 100)
# 	panda.virtual_memory_read(cpustate, ret[1], string_arg, ffi.sizeof(string_arg))
# 	string_thing = ffi.string(string_arg).decode(errors='ignore')
# 	print("Got FOPEN with", ffi.string(string_arg).decode(errors='ignore'))
# 	strq = bytearray([ord(i) for i in string_arg])
# 	f.write(strq)
# 	return False	

#fwrite(const void *ptr, size_t size, size_t nmemb, FILE*stream)
#pdb.set_trace()
@panda.hook(libc["fwrite"],libraryname="libc",kernel=False)
def fwrite_hook(cpustate, tb):
	# grab arguments ESP, arg1, arg2, arg3...
	ret = ffi.new("uint32_t[]", 5)
	size = ffi.cast("target_ptr_t", ffi.sizeof(ret))
	faddr = ffi.cast("target_ptr_t", cpustate.env_ptr.regs[R_ESP]) # esp
	panda.virtual_memory_read(cpustate,faddr, ret, size) 
	string_arg = ffi.new("char[]", ret[2]*ret[3])
	panda.virtual_memory_read(cpustate, ret[1], string_arg, ffi.sizeof(string_arg))
	string_thing = ffi.string(string_arg).decode(errors='ignore')
	print("Got FWRITE with", ffi.string(string_arg).decode(errors='ignore'))
	f.write(bytearray([ord(i) for i in string_arg]))
	return False	

panda.begin_replay(argv[2])
panda.run()
