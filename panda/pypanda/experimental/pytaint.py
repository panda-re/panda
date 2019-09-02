'''
Experimental: broken
'''
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
	
	progress("taint operations inlining: "+str(inline_taint))
	progress("llvm optimizations: " +str(optimize_llvm))
	progress("taint debugging: " + str(debug_taint))
	progress("detaint if control bits 0: " + str(detaint_cb0_bytes))
	progress("maximum taint compute number (0=unlimited): "+str(max_tcn))
	progress("maximum taintset cardinality (0=unlimited): " + str(max_taintset_card))

	panda.require("callstack_instr")
		
		
	return True


# plugin options
taint2_hypercalls = True
inline_taint = True
optimize_llvm = True
debug_taint = True
detaint_cb0_bytes = True
max_tcn = 0
max_taintset_card = 0

# set up your system
panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"pytaint2")
panda.run()

