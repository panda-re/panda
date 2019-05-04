from pypanda import *
from time import sleep
from sys import argv
from osi_linux import *

panda = Panda(qcow=argv[1], extra_args="")
o = osi_linux(panda,"kernelinfo.conf", "debian:3.2.0-4-686-pae:32")

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.asid_changed, asid_changed)
	return True

@panda.callback.asid_changed
def asid_changed(cpustate,old_asid, new_asid):
	if old_asid != new_asid and new_asid != 0:
		proc = o.get_current_process(cpustate)
		progress("asid changed from %d to %d with name %s" %(old_asid,new_asid,process_name_convert(proc.name)))
	return 0


panda.load_python_plugin(init,"OSI Example")
panda.begin_replay("/home/luke/recordings/debian_recording/wget")
panda.run()
