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
ffi.cdef(open("include/panda_osi.h").read())
ffi.cdef(open("include/panda_osi_linux.h").read())

# so we need access to some data structures, but don't actually
# want to open all of libpanda yet because we don't have all the
# file information. So we just open libc to access this.
C = ffi.dlopen(None)

class PandaState(Enum):
	UNINT = 1
	INIT_DONE = 2
	IN_RECORD = 3
	IN_REPLAY = 4


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
top_loop \
main_loop_wait \
pre_shutdown \
during_machine_init")



pcb = PandaCB(init = pyp.callback("bool(void*)"),
before_block_exec_invalidate_opt = pyp.callback("bool(CPUState*, TranslationBlock*)"),
before_block_exec = pyp.callback("int(CPUState*, TranslationBlock*)"),
after_block_exec = pyp.callback("int(CPUState*, TranslationBlock*)"),
before_block_translate = pyp.callback("int(CPUState*, target_ulong)"),
after_block_translate = pyp.callback("int(CPUState*, TranslationBlock*)"),
insn_translate = pyp.callback("bool(CPUState*, target_ulong)"),
insn_exec = pyp.callback("int(CPUState*, target_ulong)"),
after_insn_translate = pyp.callback("bool(CPUState*, target_ulong)"),
after_insn_exec = pyp.callback("int(CPUState*, target_ulong)"),
guest_hypercall = pyp.callback("int(CPUState*)"),
monitor = pyp.callback("int(Monitor*, char*)"),
virt_mem_before_read = pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong)"),
virt_mem_before_write = pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
phys_mem_before_read = pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong)"),
phys_mem_before_write = pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
virt_mem_after_read = pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
virt_mem_after_write = pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
phys_mem_after_read = pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
phys_mem_after_write = pyp.callback("int(CPUState*, target_ulong, target_ulong, target_ulong, void*)"),
cpu_restore_state = pyp.callback("int(CPUState*, TranslationBlock*)"),
before_loadvm = pyp.callback("int(void)"),
asid_changed = pyp.callback("int(CPUState*, target_ulong, target_ulong)"),
replay_hd_transfer = pyp.callback("int(CPUState*, uint32_t, uint64_t , uint64_t , uint32_t )"),
replay_before_dma = pyp.callback("int(CPUState*, uint32_t, uint8_t* , uint64_t , uint32_t )"),
replay_after_dma = pyp.callback("int(CPUState*, uint32_t , uint8_t* , uint64_t , uint32_t )"),
replay_handle_packet = pyp.callback("int(CPUState*, uint8_t *, int , uint8_t , uint64_t )"),
replay_net_transfer = pyp.callback("int(CPUState*, uint32_t, uint64_t , uint64_t , uint32_t )"),
replay_serial_receive = pyp.callback("int(CPUState*, uint64_t, uint8_t )"),
replay_serial_read = pyp.callback("int(CPUState*, uint64_t, uint32_t , uint8_t )"),
replay_serial_send = pyp.callback("int(CPUState*, uint64_t, uint8_t )"),
replay_serial_write = pyp.callback("int(CPUState*, uint64_t, uint32_t , uint8_t )"),
after_machine_init = pyp.callback("void(CPUState*)"),
top_loop = pyp.callback("void(CPUState*)"),
#main_loop_wait = pyp.callback("int(int)"), # XXX: the qemu function main_loop_wait is an int(int), but we expect it to be a void(void) based on its usage?
main_loop_wait = pyp.callback("void(void)"),
pre_shutdown = pyp.callback("void(void)"),
during_machine_init = pyp.callback("void(MachineState*)"))



pandacbtype = namedtuple("pandacbtype", "name number")

callback_dictionary = {
pcb.init : pandacbtype("init", -1),
pcb.before_block_exec_invalidate_opt : pandacbtype("before_block_exec_invalidate_opt", C.PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT),
pcb.before_block_exec : pandacbtype("before_block_exec", C.PANDA_CB_BEFORE_BLOCK_EXEC),
pcb.after_block_exec : pandacbtype("after_block_exec", C.PANDA_CB_AFTER_BLOCK_EXEC),
pcb.before_block_translate : pandacbtype("before_block_translate", C.PANDA_CB_BEFORE_BLOCK_TRANSLATE),
pcb.after_block_translate : pandacbtype("after_block_translate", C.PANDA_CB_AFTER_BLOCK_TRANSLATE),
pcb.insn_translate :  pandacbtype("insn_translate", C.PANDA_CB_INSN_TRANSLATE),
pcb.insn_exec : pandacbtype("insn_exec", C.PANDA_CB_INSN_EXEC),
pcb.after_insn_translate : pandacbtype("after_insn_translate", C.PANDA_CB_AFTER_INSN_TRANSLATE),
pcb.after_insn_exec :  pandacbtype("after_insn_exec", C.PANDA_CB_AFTER_INSN_EXEC),
pcb.guest_hypercall : pandacbtype("guest_hypercall", C.PANDA_CB_GUEST_HYPERCALL),
pcb.monitor : pandacbtype("monitor", C.PANDA_CB_MONITOR),
pcb.virt_mem_before_read : pandacbtype("virt_mem_before_read", C.PANDA_CB_VIRT_MEM_BEFORE_READ),
pcb.virt_mem_before_write : pandacbtype("virt_mem_before_write", C.PANDA_CB_VIRT_MEM_BEFORE_WRITE),
pcb.phys_mem_before_read : pandacbtype("phys_mem_before_read", C.PANDA_CB_PHYS_MEM_BEFORE_READ),
pcb.phys_mem_before_write : pandacbtype("phys_mem_before_write", C.PANDA_CB_PHYS_MEM_BEFORE_WRITE),
pcb.virt_mem_after_read : pandacbtype("virt_mem_after_read", C.PANDA_CB_VIRT_MEM_AFTER_READ),
pcb.virt_mem_after_write : pandacbtype("virt_mem_after_write", C.PANDA_CB_VIRT_MEM_AFTER_WRITE),
pcb.phys_mem_after_read : pandacbtype("phys_mem_after_read", C.PANDA_CB_PHYS_MEM_AFTER_READ),
pcb.phys_mem_after_write : pandacbtype("phys_mem_after_write", C.PANDA_CB_PHYS_MEM_AFTER_WRITE),
pcb.cpu_restore_state : pandacbtype("cpu_restore_state", C.PANDA_CB_CPU_RESTORE_STATE),
pcb.before_loadvm : pandacbtype("before_replay_loadvm", C.PANDA_CB_BEFORE_REPLAY_LOADVM),
pcb.asid_changed : pandacbtype("asid_changed", C.PANDA_CB_ASID_CHANGED),
pcb.replay_hd_transfer : pandacbtype("replay_hd_transfer", C.PANDA_CB_REPLAY_HD_TRANSFER),
pcb.replay_before_dma : pandacbtype("replay_before_dma", C.PANDA_CB_REPLAY_BEFORE_DMA),
pcb.replay_after_dma : pandacbtype("replay_after_dma", C.PANDA_CB_REPLAY_AFTER_DMA),
pcb.replay_handle_packet : pandacbtype("replay_handle_packet", C.PANDA_CB_REPLAY_HANDLE_PACKET),
pcb.replay_net_transfer : pandacbtype("replay_net_transfer", C.PANDA_CB_REPLAY_NET_TRANSFER),
pcb.replay_serial_receive : pandacbtype("replay_serial_receive", C.PANDA_CB_REPLAY_SERIAL_RECEIVE),
pcb.replay_serial_read : pandacbtype("replay_serial_read", C.PANDA_CB_REPLAY_SERIAL_READ),
pcb.replay_serial_send : pandacbtype("replay_serial_send", C.PANDA_CB_REPLAY_SERIAL_SEND),
pcb.replay_serial_write :  pandacbtype("replay_serial_write", C.PANDA_CB_REPLAY_SERIAL_WRITE),
pcb.after_machine_init :  pandacbtype("after_machine_init", C.PANDA_CB_AFTER_MACHINE_INIT),
pcb.top_loop : pandacbtype("top_loop", C.PANDA_CB_TOP_LOOP),
pcb.main_loop_wait : pandacbtype("main_loop_wait", C.PANDA_CB_MAIN_LOOP_WAIT),
pcb.pre_shutdown : pandacbtype("pre_shutdown", C.PANDA_CB_PRE_SHUTDOWN),
pcb.during_machine_init:pandacbtype("during_machine_init",C.PANDA_CB_DURING_MACHINE_INIT)
}


''',\
pandacbtype("hd_read", 17),\
pandacbtype("hd_write", 18),\
pandacbtype("panda_cb_last", 35))
'''
