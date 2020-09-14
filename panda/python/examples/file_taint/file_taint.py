#!/usr/bin/env python3
'''
Demonstration of file_taint from python.

Using recording that just runs taint/taint in the local machine.

Uses syscalls2 to find files that are opened, then taints data of interesting files.
Checks for file taint on taint_query.
'''

from sys import argv
from os import path
import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from panda import Panda, blocking, ffi

arch = "x86_64" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4445,server,nowait  -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5556-:22 -cdrom /home/luke/workspace/qcows/instance-1-cidata.iso"
qcow = "/home/luke/workspace/qcows/instance-1.qcow2"
panda = Panda(arch=arch, qcow=qcow, extra_args=extra, mem="1G")

out = []
mappings = {}
bin_dir = "taint"
bin_name = "taint"

# Read symbols from bin into mappings
with open(path.join(bin_dir, bin_name), 'rb') as f:
	our_elf = ELFFile(f)
	for section in our_elf.iter_sections():
		if not isinstance(section, SymbolTableSection): continue
		for symbol in section.iter_symbols():
			if len(symbol.name):  # Sometimes empty
				mappings[symbol['st_value']] = symbol.name

tainted = False
g_phys_addrs = []

@panda.cb_before_block_exec()
def bbe(cpu, tb):
	if tb.pc in mappings:
		print('\nRunning function: {}'.format(mappings[tb.pc]))
		if mappings[tb.pc] == "query_taint":
			assert(tainted), "Can't query taint before tainting"
			# RAX contains our result variable which should be tainted
			virt_addr = cpu.env_ptr.regs[7]
			phys_addr = panda.virt_to_phys(cpu, virt_addr)
			assert(panda.taint_check_ram(phys_addr)
				   ), "Final result is not tainted"
			tq = panda.taint_get_ram(phys_addr)
			print("Result is tainted. " + str(tq) +" at "+hex(phys_addr))
			panda.end_analysis()
	return None


panda.set_os_name("linux-64-ubuntu")
panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
panda.require("syscalls2")
cb_name = "on_sys_read_return"
cb_args = "CPUState *, target_ulong, uint32_t, uint64_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

info = None
tainted = False

@ffi.callback(f"void({cb_args})")
def on_sys_read_return(cpustate, pc, fd, buf, count):
	global info, tainted
	if info and not tainted:
		cr3, fd1 = info
		if cr3 == cpustate.env_ptr.cr[3] and fd == fd1:
			returned = panda.arch.get_reg(cpustate, "RAX")
			buf_read = panda.virtual_memory_read(cpustate, buf, returned)
			for idx in range(returned):
				taint_vaddr = buf+idx
				taint_paddr = panda.virt_to_phys(cpustate, taint_vaddr)  # Physical address
				print("Taint character #{} '{}' at 0x{} (phys 0x{:x}) with label {}".format(
					idx, chr(buf_read[idx]), taint_vaddr, taint_paddr, idx))
				panda.taint_label_ram(taint_paddr, idx)
			tainted = True

panda.plugins["syscalls2"].__getattr__(f"ppp_add_cb_{cb_name}")(on_sys_read_return)

cb_name = "on_sys_open_return"
cb_args = "CPUState *, target_ulong, uint64_t, int32_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ffi.callback(f"void({cb_args})")
def on_sys_open_return(cpustate, pc, filename, flags, mode):
	fname = panda.virtual_memory_read(cpustate, filename, 100)
	fname_total = fname[:fname.find(b'\x00')]
	print(f"on_sys_open_enter: {fname_total}")
	if b"panda" in fname_total:
		global info
		info = panda.current_asid(cpustate), panda.arch.get_reg(cpustate, "RAX")

panda.plugins["syscalls2"].__getattr__(f"ppp_add_cb_{cb_name}")(on_sys_open_return)
panda.disable_tb_chaining()
panda.run_replay("taint_taint")
