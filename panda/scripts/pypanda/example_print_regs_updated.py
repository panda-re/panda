from pypanda import *
from time import sleep

@panda.callback.init
def init(handle):
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	return True

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	if panda.static_var == 100000:
		pdb.set_trace()
		fregs = ["{:08x}".format(i) for i in cpustate.env_ptr.regs]
		fregs.append("{:08x}".format(cpustate.env_ptr.eip))
		fregs.append("{:08x}".format(cpustate.env_ptr.eflags))
		progress("EAX: %s EBX: %s ECX: %s EDX: %s ESP: %s EBP: %s ESI: %s EDI: %s EIP: %s EFLAGS: %s KERNEL: %s" %(fregs[0], fregs[3], fregs[1], fregs[2], fregs[4], fregs[5], fregs[6], fregs[7], fregs[8], fregs[9], "Y" if panda.in_kernel(cpustate) else "N"))
		sleep(0.4)
	panda.static_var = (panda.static_var+1) % (100001)
	return 0

extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4444,server,nowait".split() 
panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img", extra_args=extra)
panda.load_python_plugin(init,"register_printer")
panda.run()
