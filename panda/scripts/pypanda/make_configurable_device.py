from pypanda import *
from time import sleep

@pyp.callback("bool(void*)")
def init(handle):
	panda.register_callback(handle, "after_machine_init", 33, after_machine_init)
	return True

@pyp.callback("void(CPUState*)")
def after_machine_init(name, addr):
	print("hit")
	print(libpanda.sysbus_create_varargs(name,addr))



panda = Panda(qcow="/home/alom/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"make_configurable_device")
panda.run()
