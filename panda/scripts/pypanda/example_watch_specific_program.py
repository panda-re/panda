from pypanda import *
from time import sleep
from sys import argv

panda = Panda(qcow=argv[1])
asid_of_program = 95760384

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	panda.register_callback(handle, panda.callback.asid_changed, asid_changed)
	panda.disable_callback(panda.callback.before_block_exec)
	return True

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	progress("Called before block exec")	
	return 0

enabled = False

@panda.callback.asid_changed
def asid_changed(cpustate,old_asid, new_asid):
	if old_asid != new_asid:
		progress("asid changed from %d to %d" % (old_asid, new_asid))
		global asid_of_program, enabled
		if new_asid == asid_of_program:
			enabled = True
			panda.enable_callback(panda.callback.before_block_exec)
		elif enabled:
			enabled = False
			panda.disable_callback(panda.callback.before_block_exec)
	return 0

panda.load_python_plugin(init,"before block exec on specific asid")
panda.run()
