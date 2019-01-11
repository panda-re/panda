from pypanda import *
from time import sleep
@pyp.callback("bool(void*)")
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	return True

@pyp.callback("int(CPUState*, TranslationBlock*)")
def before_block_execute(cpustate,transblock):
	progress("before block in python")
	pdb.set_trace()
	return 0

panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")

callback = panda.callback.before_block_translate
print(callback.name, callback.number)

panda.load_python_plugin(init,"Cool Plugin")
panda.run()
