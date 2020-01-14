#!/usr/bin/env python3

from sys import argv
from os import path
import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from panda import Panda, blocking, ffi
from panda.x86.helper import *

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]

arch = "x86_64" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4445,server,nowait  -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5556-:22 -cdrom /home/luke/workspace/qcows/instance-1-cidata.iso"
qcow = "/home/luke/workspace/qcows/instance-1.qcow2"
panda = Panda(arch=arch, qcow=qcow, extra_args=extra, mem="1G")
@blocking
def it():
	panda.revert("cmdline")


# panda.queue_async(it)
# panda.run()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

bin_dir = "taint"
bin_name = "taint"

assert(path.isfile(path.join(bin_dir, bin_name))
	   ), "Missing file {}".format(path.join(bin_dir, bin_name))
# Take a recording of toy running in the guest if necessary
recording_name = bin_dir+"_"+bin_name
if not path.isfile(recording_name + "-rr-snp"):
	@blocking
	def run_it():
		import pdb
		pdb.set_trace()
		panda.run_serial_cmd("echo hello world | tee /tmp/panda.panda")
		panda.record_cmd(path.join(bin_dir, bin_name),
						 copy_directory=bin_dir, recording_name=recording_name)
		panda.stop_run()

	print("Generating " + recording_name + " replay")
	panda.queue_async(run_it)
	panda.run()

out = []
mappings = {}

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

# @panda.cb_before_block_exec_invalidate_opt


def taint_it(cpu, tb):
	if tb.pc in mappings and mappings[tb.pc] == "apply_taint":
		global tainted
		if not tainted:
			# Apply taint to the string that begins at *(ESP+4)
			tainted = True
			string_base_p = cpu.env_ptr.regs[R_ESP] + 0x4  # esp + 0x4

			str_base = panda.virtual_memory_read(
				cpu, string_base_p, 4, fmt='int')  # *(esp+0x4)

			s = panda.virtual_memory_read(
				cpu, str_base, 16, fmt='str').decode('utf8')
			print("Tainting string '{}'".format(s))

			global g_phys_addrs  # Save all our tainted addresses for abe() check

			# Taint each character with a taint label of its index
			for idx in range(len(s)):
				taint_vaddr = str_base+idx
				taint_paddr = panda.virt_to_phys(
					cpu, taint_vaddr)  # Physical address
				print("Taint character #{} '{}' at 0x{} (phys 0x{:x}) with label {}".format(
					idx, chr(s[idx]), taint_vaddr, taint_paddr, idx))
				panda.taint_label_ram(taint_paddr, idx)
				g_phys_addrs.append(taint_paddr)

			return 1
	return 0

# @panda.cb_after_block_exec


def abe(cpu, tb, exit):
	if tb.pc in mappings:
		if mappings[tb.pc] == "apply_taint":
			global g_phys_addrs
			for idx, g_phys_addr in enumerate(g_phys_addrs):
				assert(panda.taint_check_ram(g_phys_addr)
					   ), "Taint2 failed to identify same address as tainted"
				assert([idx] == panda.taint_get_ram(
					g_phys_addr).get_labels()), "Incorrect labels"
			print("Success! Tracked taint with no propagation (test 1 of 2)")


@panda.cb_before_block_exec()
def bbe(cpu, tb):
	if tb.pc in mappings:
		print('\nRunning function: {}'.format(mappings[tb.pc]))
		if mappings[tb.pc] == "query_taint":
			assert(tainted), "Can't query taint before tainting"
			# EAX contains our result variable which should be tainted
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


def get_task_from_cr3(task_list, cr3):
	# for some reason the cr3 we get is 32 bit from PANDA
	matching = [t for t in task_list.tasks if t.mm and t.mm.pgd and t.mm.pgd &
		0xffffffff == cr3 & 0xffffffff]
	if matching:
		return matching[0]
	else:
		return "[none]"


info = None
tainted = False

@ffi.callback(f"void({cb_args})")
def on_sys_read_return(cpustate, pc, fd, buf, count):
	global info, tainted
	if info and not tainted:
		cr3, fd1 = info
		if cr3 == cpustate.env_ptr.cr[3] and fd == fd1:
			returned = cpustate.env_ptr.regs[R_EAX]
			buf_read = panda.virtual_memory_read(cpustate, buf, returned)
			for idx in range(returned):
				taint_vaddr = buf+idx
				taint_paddr = panda.virt_to_phys(cpustate, taint_vaddr)  # Physical address
				print("Taint character #{} '{}' at 0x{} (phys 0x{:x}) with label {}".format(
					idx, buf_read[idx], taint_vaddr, taint_paddr, idx))
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
		info = cpustate.env_ptr.cr[3], cpustate.env_ptr.regs[R_EAX]
		#panda.disable_callback("on_sys_open_return")


panda.plugins["syscalls2"].__getattr__(f"ppp_add_cb_{cb_name}")(on_sys_open_return)
panda.disable_tb_chaining()
panda.run_replay(recording_name)
