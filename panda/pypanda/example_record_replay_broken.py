#!/usr/bin/env python3
'''
example_record_replay.py

Registers asid_changed and runs a replay from a file specified.

Run with: python3 example_record_replay.py i386 /path/to/recording
'''
from pypanda import *
from time import sleep
from sys import argv

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

#@panda.callback.init
#def init(handle):
#	panda.register_callback(handle, panda.callback.asid_changed, asid_changed)
#	return True

@panda.cb_asid_changed()
def asid_changed(cpustate,old_asid, new_asid):
	if old_asid != new_asid:
		progress("asid changed from %d to %d" %(old_asid, new_asid))
	return 0

#replay_file = argv[2]
#panda.begin_replay(replay_file)
panda.run()
