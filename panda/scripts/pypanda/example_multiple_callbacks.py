from pypanda import *
from time import sleep

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	panda.register_callback(handle, panda.callback.after_block_exec, after_block_execute)
	return True

@panda.callback.before_block_exec
def before_block_execute(a,b):
	progress("before block in python")
	sleep(sleeptime)
	return 0

@panda.callback.after_block_exec
def after_block_execute(a,b):
	progress("after block in python")
	sleep(sleeptime)
	return 0

sleeptime = 1
panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")
panda.load_python_plugin(init,"Cool Plugin")
panda.run()
