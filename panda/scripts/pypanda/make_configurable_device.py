from pypanda import *
from time import sleep

@pyp.callback("bool(void*)")
def init(handle):
	panda.register_callback(handle, "after_machine_init", 33, after_machine_init)
	return True

@pyp.callback("void(CPUState*)")
def after_machine_init(cpustate):
	print("running sysbus_create_varargs")
#	print(panda.sysbus_create_varargs("sysbus-fdc", 503357440))
#	print(panda.cpu_class_by_name("arm-cpu","cortex-a15"))
	print(panda.object_class_by_name("arm-cpu"))
        

#panda = Panda(qcow="/home/alom/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda = Panda(arch="arm",qcow="/home/alom/.panda/arm_wheezy.qcow",extra_args=["-M","virt"])
print ("pypanda: done with pre")

panda.load_python_plugin(init,"make_configurable_device")
print ("pypanda: loaded plugin -- running")

panda.init()
print ("pypanda: panda initialized")

panda.run()
