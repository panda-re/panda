from pypanda import *
from time import sleep
@ffi.callback("bool(void*)")
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, "virt_mem_before_read", 9, before_block_execute)
	return True

@ffi.callback("int(int*, int, int, int)")
def before_block_execute(a,b,c,d):
	progress("before block in python")
	sleep(1)
	return 0


panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"Cool Plugin")
panda.run()
