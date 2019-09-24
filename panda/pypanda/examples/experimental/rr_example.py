#!/usr/bin/env python3

from pypanda import *
from time import sleep
from sys import argv
from qcows import qcow_from_arg

extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4449,server,nowait"

q = qcow_from_arg(1)
panda = Panda(qcow=q, extra_args=extra)

@panda.callback.init
def init(handle):
	panda.register_callback(handle, panda.callback.asid_changed, asid_changed)
	return True

@panda.callback.asid_changed
def asid_changed(cpustate,old_asid, new_asid):
	if old_asid != new_asid:
		progress("asid changed from %d to %d" %(old_asid, new_asid))
	return 0

panda.load_python_plugin(init,"register_printer")
panda.begin_replay("/home/luke/recordings/debian_recording/wget")
panda.run()
