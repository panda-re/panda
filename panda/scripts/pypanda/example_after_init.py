from pypanda import *
from time import sleep


panda = Panda(qcow="/home/alom/ubuntu-14.04-server-cloudimg-i386-disk1.img")

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.after_machine_init, after_machine_init)
	return True

@panda.callback.after_machine_init
def after_machine_init(cpustate):
	progress("before block in python")
	return 0

panda.load_python_plugin(init,"after-machine-init-plugin")
panda.run()
