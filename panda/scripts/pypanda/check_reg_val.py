from pypanda import *
from time import sleep

@panda.callback.init
def init(handle):
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	return True

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	pdb.set_trace()
	fregs = ["{:08x}".format(i) for i in cpustate.env_ptr.regs]
	eax = fregs[0]
	ecx = fregs[1]
	edx = fregs[2]
	if(eax == 7 and ecx ==6 and edx == 9)
		progress("error detected")
		while True:
			sleep(1.0)
	return 0

panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"check_reg")
panda.run()