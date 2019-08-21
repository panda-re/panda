#!/usr/bin/env python3
from pypanda import *
from time import sleep
from sys import argv
from scapy.all import Ether, wrpcap

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.cb_virt_mem_after_read(name="test_vmread", procname="bash")
def virt_mem_after_read(cpustate, pc, addr, size, buf):
	curbuf = ffi.cast("char*", buf)
	current = panda.get_current_process(cpustate)
	if current != ffi.NULL:
		if size >= 5:
			buf_addr = hex(int(ffi.cast("uint64_t", buf)))
			buf_str = pyp.string(pyp.cast("char*",buf)).decode(errors='ignore')
			progress("Read buf: %s, size: %x, at pc: %x %s" %(buf_addr[2:], size, addr, buf_str))
	return 0

packets = []
@panda.cb_replay_handle_packet(name="test_vmnet",procname="wget")
def handle_packet(cpustate,buf,size,direction,old_buf_addr):
	buf_uint8 = pyp.cast("uint8_t*", buf)
	packets.append(Ether([buf_uint8[i] for i in range(size)]))
	return 0

panda.enable_memcb()
panda.begin_replay(argv[2])
panda.run()
wrpcap(argv[3], packets)
