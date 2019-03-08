from enum import Enum
from ctypes import *
from collections import namedtuple
from cffi import FFI

ffi = FFI()
pyp = ffi
ffi.cdef("typedef uint32_t target_ulong;")
ffi.cdef(open("include/pthreadtypes.h").read())
ffi.cdef(open("include/panda_x86_support.h").read())
ffi.cdef(open("include/panda_qemu_support.h").read())
ffi.cdef(open("include/panda_datatypes.h").read())
ffi.cdef(open("include/header.h").read())
ffi.cdef(open("include/header2.h").read())

class PandaState(Enum):
	UNINT = 1
	INIT_DONE = 2
	IN_RECORD = 3
	IN_REPLAY = 4

# class pandacbtype():
#	def __init__(self, name, number, decorator):
#		self.name = name
#		self.number = number
#		self.decorator = decorator
#	def __str__(self):
#		return self.decorator
#	
#	def __repr__():
#		return self.decorator

#class CB_types():
#	before_block_exec = Callback("before_block_exec", 3)
#	before_block_exec_invalidate_opt = Callback("before_block_exec_invalidate_opt", 2)
#	after_block_exec = Callback("after_block_exec", 4)
#	before_block_translate = Callback("before_block_translate", 5)
#	after_block_translate = Callback("after_block_translate", 6)
	
	



PandaCB = namedtuple("PandaCB", "init \
before_block_exec_invalidate_opt \
before_block_exec \
after_block_exec \
before_block_translate \
after_block_translate \
insn_translate \
insn_exec \
after_insn_translate \
after_insn_exec \
guest_hypercall \
monitor \
virt_mem_before_read \
virt_mem_before_write \
phys_mem_before_read \
phys_mem_before_write \
virt_mem_after_read \
virt_mem_after_write \
phys_mem_after_read \
phys_mem_after_write \
cpu_restore_state \
before_loadvm \
asid_changed \
replay_hd_transfer \
replay_before_dma \
replay_after_dma \
replay_handle_packet \
replay_net_transfer \
replay_serial_receive \
replay_serial_read \
replay_serial_send \
replay_serial_write \
after_machine_init \
top_loop")



pcb = PandaCB(pyp.callback("bool(void*)"),
pyp.callback("bool(CPUState*, TranslationBlock*)"),
pyp.callback("int(CPUState*, TranslationBlock*)"),
pyp.callback("int(CPUState*, TranslationBlock*)"),
pyp.callback("int(CPUState*, target_ulong)"),
pyp.callback("int(CPUState*, TranslationBlock*)"),
pyp.callback("bool(CPUState*, target_ulong)"),
pyp.callback("int(CPUState*, target_ulong)"),
pyp.callback("bool(CPUState*, target_ulong)"),
pyp.callback("int(CPUState*, target_ulong)"),
pyp.callback("int(CPUState*)"),
pyp.callback("int(Monitor*, char*)"),
pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong)"),
pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong)"),
pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
pyp.callback("int(CPUState*, TranslationBlock*)"),
pyp.callback("int(void)"),
pyp.callback("int(CPUState*, target_ulong, target_ulong)"),
pyp.callback("int(CPUState*, uint32_t, uint64_t , uint64_t , uint32_t )"),
pyp.callback("int(CPUState*, uint32_t, uint8_t* , uint64_t , uint32_t )"),
pyp.callback("int(CPUState*, uint32_t , uint8_t* , uint64_t , uint32_t )"),
pyp.callback("int(CPUState*, uint8_t *, int , uint8_t , uint64_t )"),
pyp.callback("int(CPUState*, uint32_t, uint64_t , uint64_t , uint32_t )"),
pyp.callback("int(CPUState*, uint64_t, uint8_t )"),
pyp.callback("int(CPUState*, uint64_t, uint32_t , uint8_t )"),
pyp.callback("int(CPUState*, uint64_t, uint8_t )"),
pyp.callback("int(CPUState*, uint64_t, uint32_t , uint8_t )"),
pyp.callback("void(CPUState*)"),
pyp.callback("void(CPUState*)"))



pandacbtype = namedtuple("pandacbtype", "name number")

callback_dictionary = {
pcb.init : pandacbtype("init", -1), 
pcb.before_block_exec_invalidate_opt : pandacbtype("before_block_exec_invalidate_opt", 2),
pcb.before_block_exec : pandacbtype("before_block_exec", 3),
pcb.after_block_exec : pandacbtype("after_block_exec", 4),
pcb.before_block_translate : pandacbtype("before_block_translate", 0),
pcb.after_block_translate : pandacbtype("after_block_translate", 1),
pcb.insn_translate :  pandacbtype("insn_translate", 5),
pcb.insn_exec : pandacbtype("insn_exec", 6),
pcb.after_insn_translate : pandacbtype("after_insn_translate", 7),
pcb.after_insn_exec :  pandacbtype("after_insn_exec", 8),
pcb.guest_hypercall : pandacbtype("guest_hypercall", 19), 
pcb.monitor : pandacbtype("monitor", 20),
pcb.virt_mem_before_read : pandacbtype("virt_mem_before_read", 9),
pcb.virt_mem_before_write : pandacbtype("virt_mem_before_write", 10),
pcb.phys_mem_before_read : pandacbtype("phys_mem_before_read", 11),
pcb.phys_mem_before_write : pandacbtype("phys_mem_before_write", 12),
pcb.virt_mem_after_read : pandacbtype("virt_mem_after_read", 13),
pcb.virt_mem_after_write : pandacbtype("virt_mem_after_write", 14),
pcb.phys_mem_after_read : pandacbtype("phys_mem_after_read", 15),
pcb.phys_mem_after_write : pandacbtype("phys_mem_after_write", 16),
pcb.cpu_restore_state : pandacbtype("cpu_restore_state", 21),
pcb.before_loadvm : pandacbtype("before_replay_loadvm", 22),
pcb.asid_changed : pandacbtype("asid_changed", 23),
pcb.replay_hd_transfer : pandacbtype("replay_hd_transfer", 24),
pcb.replay_before_dma : pandacbtype("replay_before_dma", 30),
pcb.replay_after_dma : pandacbtype("replay_after_dma", 31),
pcb.replay_handle_packet : pandacbtype("replay_handle_packet", 32),
pcb.replay_net_transfer : pandacbtype("replay_net_transfer", 25),
pcb.replay_serial_receive : pandacbtype("replay_serial_receive", 26),
pcb.replay_serial_read : pandacbtype("replay_serial_read", 27),
pcb.replay_serial_send : pandacbtype("replay_serial_send", 28),
pcb.replay_serial_write :  pandacbtype("replay_serial_write", 29),
pcb.after_machine_init :  pandacbtype("after_machine_init", 33),
pcb.top_loop : pandacbtype("top_loop", 34)}


''',\
pandacbtype("hd_read", 17),\
pandacbtype("hd_write", 18),\
pandacbtype("panda_cb_last", 35))
'''
