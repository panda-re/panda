from pypanda import *
from time import sleep
from sys import argv

@pyp.callback("int(struct kernelinfo*)")
def fill_structure(kernelinfo):
	pdb.set_trace()
	pass

fill_struct_ptr = pyp.cast("long long", (pyp.cast("void*", fill_structure)))
pargs = "-os linux-32-debian:3.2.0-4-686-pae -panda osi -panda osi_linux:python_ptr=%d" % fill_struct_ptr
panda = Panda(qcow=argv[1], extra_args=pargs)
panda.set_os_name("linux-32-debian:3.2.0-4-686-pae")


@panda.callback.init
def init(handle):
	#global fill_struct_ptr
	#panda.libpanda.panda_add_arg("osi_linux", "python_ptr=%d" % fill_struct_ptr)
	#panda.load_plugin("osi_linux")
	progress("init in python. handle="+str(handle))
	#panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
	return True

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	progress("before block in python")
	pdb.set_trace()
	return 0

panda.run()
panda.load_python_plugin(init,"OSI Example")
