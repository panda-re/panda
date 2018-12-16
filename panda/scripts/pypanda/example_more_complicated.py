from pypanda import *
from time import sleep

asid_count = {}
kernel_count = 0
user_count = 0

@pyp.callback("int(CPUState*, TranslationBlock*)")
def before_block_execute(cpustate, transblock):
#	progress("before block in python")
#	sleep(1)
	return 0

@pyp.callback("int(CPUState*, uint32_t, uint32_t)")
def asid_changed(cpustate, old_asid, new_asid):
	if panda.in_kernel(cpustate) == 0:
		print("panda in kernel")	
	progress("asid changed from "+ str(old_asid) +" to "+ str(new_asid))
	sleep(10)
	return 0

@pyp.callback("bool(void*)")
def init(handle):
	progress("init in python. handle="+str(handle))
#	panda.require("osi")
	panda.register_callback(handle, "before_block_exec", 3, before_block_execute) 
	panda.register_callback(handle, "asid_changed", 23, asid_changed)
	return True
panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"Cool Plugin")
panda.run()
