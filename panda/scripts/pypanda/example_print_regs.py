from pypanda import *
from time import sleep

EAX = 0
EBX = 3
ECX = 1
EDX = 2
ESP = 4
EBP = 5
ESI = 6
EDI = 7

@pyp.callback("bool(void*)")
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, "before_block_exec", 3, before_block_execute)
	return True

@pyp.callback("int(CPUState*, TranslationBlock*)")
def before_block_execute(cpustate,transblock):
#	progress("before block in python")
	regs = cpustate.env_ptr.regs
	fregs = ["{:08x}".format(i) for i in regs]
	progress("EAX: %s EBX: %s ECX: %s EDX: %s ESP: %s EBP: %s ESI: %s EDI: %s" %(fregs[EAX], fregs[EBX], fregs[ECX], fregs[EDX], fregs[ESP], fregs[EBP], fregs[ESI], fregs[EDI]))
	sleep(sleeptime)
	return 0

sleeptime = 0.01
panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"Cool Plugin")
panda.run()
