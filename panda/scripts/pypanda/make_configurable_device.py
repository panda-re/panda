from pypanda import *
from time import sleep

@pyp.callback("bool(void*)")
def init(handle):
	panda.register_callback(handle, "after_machine_init", 33, after_machine_init)
	return True

@pyp.callback("void(CPUState*)")
def after_machine_init(cpustate):
	print(panda.libpanda.sysbus_create_varargs("something", 0xdeadbeef))
        

panda = Panda(qcow="/home/tleek/ubuntu-14.04-server-cloudimg-i386-disk1.img")
print ("pypanda: done with pre")

panda.load_python_plugin(init,"make_configurable_device")
print ("pypanda: loaded plugin -- running")

panda.init()
print ("pypanda: panda initialized")

panda.run()
