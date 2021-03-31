#!/usr/bin/env python3
from sys import argv, path
import time
import pickle
path.append("..")
from pandare import Panda
from pandare.helper.x86 import *

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4444,server,nowait"
panda = Panda(generic=arch,extra_args=extra)

with open("libc_syms.pickle", "rb") as f:
    libc = pickle.load(f)

f = open("fwrite.out","wb")
@panda.hook_single_insn("fwrite_hook", libc["fwrite"],libraryname="libc",kernel=False)
def fwrite_hook(cpustate, tb):
	# grab arguments ESP, arg1, arg2, arg3...
	ret = ffi.new("uint32_t[]", 5)
	size = ffi.cast("target_ptr_t", ffi.sizeof(ret))
	faddr = ffi.cast("target_ptr_t", cpustate.env_ptr.regs[R_ESP]) # esp
	panda.virtual_memory_read(cpustate,faddr, ret, size)  # XXX bad argus for virtual_memory_write
	string_arg = ffi.new("char[]", ret[2]*ret[3])
	panda.virtual_memory_read(cpustate, ret[1], string_arg, ffi.sizeof(string_arg))
	string_thing = ffi.string(string_arg).decode(errors='ignore')
	print("Got FWRITE with", ffi.string(string_arg).decode(errors='ignore'))
	f.write(bytearray([ord(i) for i in string_arg]))
	return False	

panda.begin_replay(argv[2])
panda.run()
