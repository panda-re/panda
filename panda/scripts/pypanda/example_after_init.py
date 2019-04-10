from pypanda import *
from time import sleep
from sys import argv

panda = Panda(qcow=argv[1])

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
