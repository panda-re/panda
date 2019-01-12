from pypanda import *
from time import sleep

@panda.callback.init
def init(handle):
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	return True

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	pdb.set_trace()
	if panda.static_var == 10000:
		fregs = ["{:08x}".format(i) for i in cpustate.env_ptr.regs]
		fregs.append("{:08x}".format(cpustate.env_ptr.eip))
		fregs.append("{:08x}".format(cpustate.env_ptr.eflags))
		progress("EAX: %s EBX: %s ECX: %s EDX: %s ESP: %s EBP: %s EIP: %s" %(fregs[0], fregs[3], fregs[1], fregs[2], fregs[4], fregs[5] , fregs[8]))
		sleep(1.2)
	panda.static_var = (panda.static_var+1) % (10001)
	return 0

panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"register_printer")
panda.run()
