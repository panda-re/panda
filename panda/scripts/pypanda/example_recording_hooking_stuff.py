#!/usr/bin/env python3

from pypanda import *
from sys import argv
import time
import pickle
from panda_x86_helper import *

# Record some programs running in the guest
# for some programs, register python callbacks

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

# Generate with example_generate_kallsyms.py
with open("i386_syms.pickle", "rb") as f:
		kallsyms = pickle.load(f)

# Register bkpt on sysfs_open_file
#@panda.hook(kallsyms["system_call"])
def call_hook(env, tb):
		pc = panda.current_pc(env)
		progress("System call at 0x{:x}: {}".format(pc, env.env_ptr.regs[0]))
		return False

#@panda.hook(kallsyms["sys_send"])
def call_hook2(env, tb):
	pc = panda.current_pc(env)
	r = env.env_ptr.regs
	progress("\t SYS_SEND EAX=%d EBX=%d ECX=%d EDX=%d" %(r[R_EAX], r[R_EBX],r[R_ECX],r[R_EDX]))
	return False

def get_string(in_str):
	if in_str != ffi.NULL:
			return ffi.string(in_str).decode(errors='ignore')
	return ffi.NULL

prognames = []

@panda.cb_virt_mem_after_read(name="test_vmread", procname="bash")
def virt_mem_after_read(cpustate, pc, addr, size, buf):
	current = panda.get_current_process(cpustate)
	libs = panda.get_libraries(cpustate,current)
	programname = get_string(current.name)
	global prognames
	if	programname == "bash": return 0
	if libs != ffi.NULL:
		for i in range(libs.num):
				lib = libs.module[i]
				if lib.file != ffi.NULL:
					filename = ffi.string(lib.file).decode()
					if "libc" in filename:
						programname = get_string(current.name)
						print("In process", get_string(current.name), "LIBRARY",  get_string(lib.file), hex(lib.base), hex(lib.size))
						prognames.append(programname)
						
	curbuf = ffi.cast("char*", buf)
	if current != ffi.NULL:
		if size >= 5:
			buf_addr = hex(int(ffi.cast("uint64_t", buf)))
			buf_str = pyp.string(pyp.cast("char*",buf)).decode(errors='ignore')
#			progress("Read buf: %s, size: %x, at pc: %x %s" %(buf_addr[2:], size, addr, buf_str))
	return 0

#@panda.hook(kallsyms["open_exec"])
def printk_hook(cpustate,tb):
#	regs = cpustate.env_ptr.regs
#	ret = ffi.new("char[]", 100)
#	panda.virtual_memory_read(cpustate,regs[R_EAX],ret, 100)
	print("OPEN EXEC")#, ffi.string(ret).decode())
	return False

# sock_sendmsg(struct socket *sock, struct msghdr *msg size_t size
tick = 0
#@panda.hook(kallsyms["sched_clock_tick"])
def printk_hook(cpustate,tb):
	print("GOT TICK on CPU", cpustate.env_ptr.regs[R_EAX])
	global tick
	tick+=1
	return False


base = 0
#base = 0xb7410000 #wget
#base = 0xb7603000 #bash
malloc = 0x75890+base
printf = 0x49e60+base
fprintf = 0x49e30+base
send = 0xd6da0+base
puts = 0x635d0+base
fwrite = 0x62670+base
fopen = 0x61d30+base
#char* strncpy(char*dest, const char *src, size_t n);
#@panda.hook(base+0x79330)
def strncpy_hook(cpustate, tb):
	# read stack arguments
	ret = ffi.new("uint32_t[]", 5)
	size = ffi.cast("target_ptr_t", ffi.sizeof(ret))
	faddr = ffi.cast("target_ptr_t", cpustate.env_ptr.regs[R_ESP]) # esp
	panda.virtual_memory_read(cpustate,faddr, ret, size) 
	string_arg = ffi.new("char[]", 100)
	panda.virtual_memory_read(cpustate, ret[2], string_arg, ffi.sizeof(string_arg))
	print("STRINGCPY",ffi.string(string_arg).decode())
	return False


# FILE* fopen(const char* fname, const char* mode);
#@panda.hook(fopen)
def fopen_hook(cpustate, tb):
	ret = ffi.new("uint32_t[]", 5)
	size = ffi.cast("target_ptr_t", ffi.sizeof(ret))
	faddr = ffi.cast("target_ptr_t", cpustate.env_ptr.regs[R_ESP]) # esp
	panda.virtual_memory_read(cpustate,faddr, ret, size) 
	string_arg = ffi.new("char[]", 100)
	panda.virtual_memory_read(cpustate, ret[1], string_arg, ffi.sizeof(string_arg))
	print("Got FOPEN with", ffi.string(string_arg).decode(errors='ignore'))	
	return False	

#fwrite(const void *ptr, size_t size, size_t nmemb, FILE*stream)
#@panda.hook(fwrite,libraryname="libc",kernel=False)
def fwrite_hook(cpustate, tb):
	ret = ffi.new("uint32_t[]", 5)
	size = ffi.cast("target_ptr_t", ffi.sizeof(ret))
	faddr = ffi.cast("target_ptr_t", cpustate.env_ptr.regs[R_ESP]) # esp
	panda.virtual_memory_read(cpustate,faddr, ret, size) 
	string_arg = ffi.new("char[]", ret[2]*ret[3])
	panda.virtual_memory_read(cpustate, ret[1], string_arg, ffi.sizeof(string_arg))
	print("Got FWRITE with", ffi.string(string_arg).decode(errors='ignore'))	
	return False	

#@panda.hook(malloc)
def malloc_hook(cpustate,tb):
	ret = ffi.new("uint32_t[]", 5)
	size = ffi.cast("target_ptr_t", ffi.sizeof(ret))
	faddr = ffi.cast("target_ptr_t", cpustate.env_ptr.regs[R_ESP]) # esp
	panda.virtual_memory_read(cpustate,faddr, ret, size) 
	print("Got MALLOC with", ret[1])	
	return False	


panda.enable_memcb()
panda.begin_replay("/home/luke/workspace/replays/wget")
panda.run()
#print("got %d ticks" %(tick))
