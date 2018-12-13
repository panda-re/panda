from pypanda import *

@ffi.callback("bool(void*)")
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, "before_block_exec", 3, before_block_execute)
	return True

@ffi.callback("int(int*, int*)")
def before_block_execute(a,b):
	progress("before block in python")
	return 0


panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"Cool Plugin")
panda.run()
