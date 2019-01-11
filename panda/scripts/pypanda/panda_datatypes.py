from enum import Enum
from ctypes import *
from collections import namedtuple
from cffi import FFI

ffi = FFI()
ffi.cdef("typedef uint32_t target_ulong;")
ffi.cdef(open("./include/pthreadtypes.h").read())
ffi.cdef(open("./include/panda_x86_support.h").read())
ffi.cdef(open("./include/panda_qemu_support.h").read())
ffi.cdef(open("./include/panda_datatypes.h").read())

class PandaState(Enum):
	UNINT = 1
	INIT_DONE = 2
	IN_RECORD = 3
	IN_REPLAY = 4

class Callback():
	def __init__(name, number):
		self.name = name
		self.number = number

#class CB_types():
#	before_block_exec = Callback("before_block_exec", 3)
#	before_block_exec_invalidate_opt = Callback("before_block_exec_invalidate_opt", 2)
#	after_block_exec = Callback("after_block_exec", 4)
#	before_block_translate = Callback("before_block_translate", 5)
#	after_block_translate = Callback("after_block_translate", 6)
	
	

pandacbtype = namedtuple("pandacbtype", "name number")

PandaCB = namedtuple("PandaCB", "before_block_translate \
after_block_translate \
before_block_exec_invalidate_opt \
before_block_exec \
after_block_exec \
insn_translate \
insn_exec \
after_insn_translate \
after_insn_exec \
virt_mem_before_read \
virt_mem_before_write \
phys_mem_before_read \
phys_mem_before_write \
virt_mem_after_read \
virt_mem_after_write \
phys_mem_after_read \
phys_mem_after_write \
hd_read \
hd_write \
guest_hypercall \
monitor \
cpu_restore_state \
before_replay_loadvm \
asid_changed \
replay_hd_transfer \
replay_net_transfer \
replay_serial_receive \
replay_serial_read \
replay_serial_send \
replay_serial_write \
replay_before_dma \
replay_after_dma \
replay_handle_packet \
after_machine_init \
top_loop \
panda_cb_last")

pcb = PandaCB(pandacbtype("before_block_translate", 0),\
pandacbtype("after_block_translate", 1),\
pandacbtype("before_block_exec_invalidate_opt", 2),\
pandacbtype("before_block_exec", 3),\
pandacbtype("after_block_exec", 4),\
pandacbtype("insn_translate", 5),\
pandacbtype("insn_exec", 6),\
pandacbtype("after_insn_translate", 7),\
pandacbtype("after_insn_exec", 8),\
pandacbtype("virt_mem_before_read", 9),\
pandacbtype("virt_mem_before_write", 10),\
pandacbtype("phys_mem_before_read", 11),\
pandacbtype("phys_mem_before_write", 12),\
pandacbtype("virt_mem_after_read", 13),\
pandacbtype("virt_mem_after_write", 14),\
pandacbtype("phys_mem_after_read", 15),\
pandacbtype("phys_mem_after_write", 16),\
pandacbtype("hd_read", 17),\
pandacbtype("hd_write", 18),\
pandacbtype("guest_hypercall", 19),\
pandacbtype("monitor", 20),\
pandacbtype("cpu_restore_state", 21),\
pandacbtype("before_replay_loadvm", 22),\
pandacbtype("asid_changed", 23),\
pandacbtype("replay_hd_transfer", 24),\
pandacbtype("replay_net_transfer", 25),\
pandacbtype("replay_serial_receive", 26),\
pandacbtype("replay_serial_read", 27),\
pandacbtype("replay_serial_send", 28),\
pandacbtype("replay_serial_write", 29),\
pandacbtype("replay_before_dma", 30),\
pandacbtype("replay_after_dma", 31),\
pandacbtype("replay_handle_packet", 32),\
pandacbtype("after_machine_init", 33),\
pandacbtype("top_loop", 34),\
pandacbtype("panda_cb_last", 35))

