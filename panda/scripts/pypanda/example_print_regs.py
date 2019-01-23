from pypanda import *
from panda_x86_helper import *
from time import sleep

panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")

@panda.callback.init
def init(handle):
	panda.disable_tb_chaining()
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	return True

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	if panda.in_kernel(cpustate):
		fregs = ["{:08x}".format(i) for i in cpustate.env_ptr.regs]
		fregs.append("{:08x}".format(cpustate.env_ptr.eip))
		fregs.append("{:08x}".format(cpustate.env_ptr.eflags))
		in_kernel = "Yes" if panda.in_kernel(cpustate) else "No"
		progress("EAX: %s EBX: %s ECX: %s EDX: %s ESP: %s EBP: %s EIP: %s In_Kernel: %s" %(fregs[R_EAX], fregs[R_EBX], fregs[R_ECX], fregs[R_EDX], fregs[R_ESP], fregs[R_EBP] , fregs[8], in_kernel))
#	sleep(sleeptime)
	return 0



sleeptime = 0.5
# this is unncecessary because we do this when before_block_exec is registered.
panda.load_python_plugin(init,"register_printer")
panda.run()
