from pypanda import *
from time import sleep

@panda.callback.guest_hypercall
def guest_hypercall(cpustate)
	progress("guest hypercall in python")

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.enable_memcb()
	panda.disable_tb_chaining()
	
	if taint2_hypercalls:
		panda.register_callback(handle, panda.callback.guest_hypercall, guest_hypercall) 
	
	
		
	return True


# plugin options
taint2_hypercalls = True
inline_taint = True

# 
panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"pytaint2")
panda.run()

