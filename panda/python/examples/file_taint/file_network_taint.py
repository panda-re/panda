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

arch = "x86_64" if len(argv) <= 1 else argv[1]
extra = "-nographic"
qcow = argv[1]
panda = Panda(arch=arch, qcow=qcow, extra_args=extra, mem="1G", expect_prompt=rb"root@ubuntu:.*")

panda.set_os_name("linux-64-ubuntu")
panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
panda.require("syscalls2")

file_info = None
tainted = False

@panda.ppp("syscalls2", "on_sys_read_return")
def on_sys_read_return(cpustate, pc, fd, buf, count):
	global file_info, tainted
	if file_info and not tainted:
		cr3, fd1 = file_info
		if cr3 == cpustate.env_ptr.cr[3] and fd == fd1:
			returned = panda.arch.get_reg(cpustate, "EAX")
			buf_read = panda.virtual_memory_read(cpustate, buf, returned)
			for idx in range(returned):
				taint_vaddr = buf+idx
				taint_paddr = panda.virt_to_phys(cpustate, taint_vaddr)  # Physical address
				print("Taint character #{} '{}' at 0x{} (phys 0x{:x}) with label {}".format(
					idx, chr(buf_read[idx]), taint_vaddr, taint_paddr, idx))
				panda.taint_label_ram(taint_paddr, idx)
			tainted = True

@panda.ppp("syscalls2", "on_sys_open_return")
def on_sys_open_return(cpustate, pc, filename, flags, mode):
	global file_info
	fname = panda.virtual_memory_read(cpustate, filename, 100)
	fname_total = fname[:fname.find(b'\x00')]
	print(f"on_sys_open_enter: {fname_total}")
	if b"panda" in fname_total:
		global info
		file_info = panda.current_asid(cpustate), panda.arch.get_reg(cpustate, "EAX")

finished = False

@panda.ppp("syscalls2", "on_sys_sendto_return")
def on_sys_sendto_return(cpustate, a, fd, buff, length, sockaddr, z, flags):
	global tainted, finished
	if tainted and not finished:
		buff_physaddr = panda.virt_to_phys(cpustate,buff)
		for i in range(length):
			if panda.taint_check_ram(buff_physaddr + i):
				tq = panda.taint_get_ram(buff_physaddr + i)
				print("Result is tainted. " + str(tq) +" at "+hex(buff_physaddr + i) +" at offset "+str(i) +" in the packet")
				finished = True
				panda.end_analysis()

panda.disable_tb_chaining()
panda.run_replay("taint_taint")
