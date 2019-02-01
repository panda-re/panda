from pypanda import *
from time import sleep

@pyp.callback("bool(void*)")
def init(handle):
	panda.register_callback(handle, "before_block_exec", 3, before_block_execute)
	return True

@pyp.callback("int(CPUState*, TranslationBlock*)")
def before_block_execute(cpustate,transblock):
	if panda.static_var == 10000:
		fregs = ["{:08x}".format(i) for i in cpustate.env_ptr.regs]
		fregs.append("{:08x}".format(cpustate.env_ptr.eip))
		fregs.append("{:08x}".format(cpustate.env_ptr.eflags))
		progress("EAX: %s EBX: %s ECX: %s EDX: %s ESP: %s EBP: %s ESI: %s EDI: %s EIP: %s EFLAGS: %s" %(fregs[0], fregs[3], fregs[1], fregs[2], fregs[4], fregs[5], fregs[6], fregs[7], fregs[8], fregs[9]))
		sleep(0.4)
	panda.static_var = (panda.static_var+1) % (10001)
	return 0

panda = Panda(qcow="/home/alom/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"register_printer")
panda.init()
panda.run()
