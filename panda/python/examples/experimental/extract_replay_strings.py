#!/usr/bin/env python3
from time import sleep
from sys import argv
from string import printable
from pandare import Panda

# Pull strings from wget out of a replay (named specified by arg 2)

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.cb_virt_mem_after_read(procname="wget")
def virt_mem_after_read(cpustate, pc, addr, size, buf):
	curbuf = ffi.cast("char*", buf)
	current = panda.get_current_process(cpustate)
	if current != ffi.NULL:
		if size >= 5:
			current_name = ffi.string(current.name)
			buf_addr = hex(int(ffi.cast("uint64_t", buf)))
			buf_chr = ffi.cast("uint8_t*", buf)
			b = "".join([chr(buf_chr[i]) if printable else '' for i in range(size)])
			progress("Read buf: %s, size: %x, at pc: %x %s" %(buf_addr[2:], size, addr, b))
	else:
		progress("current is NULL")

panda.run_replay(argv[2])
