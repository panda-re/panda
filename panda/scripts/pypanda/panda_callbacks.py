from dataclasses import dataclass

@dataclass
class pandacbtype:
    name: str
    number: int

@dataclass
class PandaCB:
	before_block_translate: pandacbtype
	after_block_translate: pandacbtype
	before_block_exec_invalidate_opt: pandacbtype
	before_block_exec: pandacbtype
	after_block_exec: pandacbtype
	insn_translate: pandacbtype
	insn_exec: pandacbtype
	after_insn_translate: pandacbtype
	after_insn_exec: pandacbtype
	virt_mem_before_read: pandacbtype
	virt_mem_before_write: pandacbtype
	phys_mem_before_read: pandacbtype
	phys_mem_before_write: pandacbtype
	virt_mem_after_read: pandacbtype
	virt_mem_after_write: pandacbtype
	phys_mem_after_read: pandacbtype
	phys_mem_after_write: pandacbtype
	hd_read: pandacbtype
	hd_write: pandacbtype
	guest_hypercall: pandacbtype
	monitor: pandacbtype
	cpu_restore_state: pandacbtype
	before_replay_loadvm: pandacbtype
	asid_changed: pandacbtype
	replay_hd_transfer: pandacbtype
	replay_net_transfer: pandacbtype
	replay_serial_receive: pandacbtype
	replay_serial_read: pandacbtype
	replay_serial_send: pandacbtype
	replay_serial_write: pandacbtype
	replay_before_dma: pandacbtype
	replay_after_dma: pandacbtype
	replay_handle_packet: pandacbtype
	after_machine_init: pandacbtype
	top_loop: pandacbtype
	during_machine_init: pandacbtype
	panda_cb_last: pandacbtype

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
pandacbtype("top_loop", 34,\
pandacbtype("during_machine_init",35),\
pandacbtype("panda_cb_last", 36))
print(pcb.before_block_translate.name)
