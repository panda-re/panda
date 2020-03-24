#!/usr/bin/env python3
'''
file_network_taint.py

The goal of this demonstration is to taint reads from a specific file
and see if that file is involved in outbound network traffic. 

Here we use syscalls2 to check each file that is opened. If the open
file matches the file we expect (here it is /tmp/panda.panda) we
observe the cr3 and file descriptor. 

We again use syscalls2 to monitor all sys_reads on the system. We 
check the reads against our known cr3 and file descriptor. If it
matches we taint the resulting data.

Lastly, we use syscalls2 to monitor sys_sendto for network traffic.
We must check each byte in the packet to check if it is tainted and
we alert if it is tainted.
'''

from sys import argv
from os import path
from panda import Panda, blocking, ffi
from panda.x86.helper import *

arch = "x86_64" if len(argv) <= 1 else argv[1]
extra = "-nographic"
#qcow = "/home/luke/workspace/qcows/instance-1.qcow2"
#panda = Panda(arch=arch, qcow=qcow, extra_args=extra, mem="1G")
panda = Panda(generic=arch)

interesting_file_name = b"panda.panda2"

panda.set_os_name("linux-64-ubuntu")
panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
panda.require("syscalls2")

cb_name = "on_sys_read_return"
cb_args = "CPUState *, target_ulong, uint32_t, uint64_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

file_info = None

@ffi.callback(f"void({cb_args})")
def on_sys_read_return(cpustate, pc, fd, buf, count):
	global file_info
	if file_info:
		cr3, fd1 = file_info
		if cr3 == cpustate.env_ptr.cr[3] and fd == fd1:
			returned = cpustate.env_ptr.regs[R_EAX]
			if returned >= 0:
				a_buf  = (10 * b"a") + b"\x00"
				buf_read = panda.virtual_memory_write(cpustate, buf, a_buf)
	file_info = None

panda.plugins["syscalls2"].__getattr__(f"ppp_add_cb_{cb_name}")(on_sys_read_return)

cb_name = "on_sys_open_return"
cb_args = "CPUState *, target_ulong, uint64_t, int32_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ffi.callback(f"void({cb_args})")
def on_sys_open_return(cpustate, pc, filename, flags, mode):
	global file_info
	fname = panda.virtual_memory_read(cpustate, filename, 100)
	fname_total = fname[:fname.find(b'\x00')]
	if interesting_file_name in fname_total:
		print(f"on_sys_open_enter: {fname_total}")
		global info
		if cpustate.env_ptr.regs[R_EAX] > 255: # hack for -1
			print("Changing return value to 99")
			cpustate.env_ptr.regs[R_EAX] = 99
		file_info = cpustate.env_ptr.cr[3], cpustate.env_ptr.regs[R_EAX]
		

panda.plugins["syscalls2"].__getattr__(f"ppp_add_cb_{cb_name}")(on_sys_open_return)


cb_name = "on_sys_fstat_return"
cb_args = "CPUState *, target_ulong, int32_t, uint32_t"
cb_args = "CPUState *, uint64_t, uint64_t, int32_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ffi.callback(f"void({cb_args})")
def on_sys_fstat_return(cpustate, pc, fd, statbuf):
	print(fd)
	global file_info
	global file_info
	if file_info:
		cr3, fd1 = file_info
		if cr3 == cpustate.env_ptr.cr[3] and fd == fd1:
			import pdb
			pdb.set_trace()
		


panda.plugins["syscalls2"].__getattr__(f"ppp_add_cb_{cb_name}")(on_sys_open_return)


panda.disable_tb_chaining()

@blocking
def mycmd():
	panda.revert_sync("root")
	#print("Cmd:", panda.run_serial_cmd("echo 'bcbddbdbd' > panda.panda"))
	print("Cmd:", panda.run_serial_cmd("cat panda.panda2"))
	panda.end_analysis()


#panda.run_replay("taint_taint")
panda.queue_async(mycmd)
panda.run()
