#!/usr/bin/env python3

from pypanda import *
import os

#
# snaps.py
#
# A simple demo script of precise control over taking and restoring
# snapshots with pypanda.  Makes use of prior knowledge of what code
# will be executed when we revert to the 'root' snapshot in the
# indicated qcow.
#
# 1. A after machine init callback lets us start that guest and
# immediate revert it to the snapshot 'root' which is a booted machine
# logged in to the root account.
#
# 2. A before block exec callback lets us wait until we encounter a very
# particular pc (0xc101dfec) which we only knew about bc we ran qemu -d
# in_asm before.  At this pc we take a snapshot.  This callback actually
# contains a little state machine.  After we have taken the snapshot, we
# are in state 3, where we increment a counter with each call, i.e. for
# each new basic block we execute.  After 10 blocks, we revert to the
# snapshot at 0xc101dfec.
#
# Obviously there are more interesting uses for this kind of thing.  Two
# important things to notice.  First, we can take a snapshot that will
# in fact revert to a specific block's start pc.  Second, when we
# revert, we don't keep executing any code.  We snap back to exactly
# that bloc.

qcowpath = os.getenv("HOME") + "/.panda/debian:3.2.0-4-686-pae-i386-128M.qcow"


panda = Panda(qcow=qcowpath, extra_args="-D ./qemu.log -d in_asm") 



state = 0 # before snapshot load

@panda.callback.after_machine_init
def machinit(env):
	global state

	progress("Machine initialized -- disabling chaining & reverting to booted snapshot\n")
	panda.disable_tb_chaining()
	panda.delvm("newroot", now=True)
	pc = panda.current_pc(env)
	panda.revert("root", now=True)
	pc = panda.current_pc(env)
	progress("After revert: pc=%lx" % pc)
	state = 1



init_done = False

nt = 0


@panda.callback.before_block_exec
def before_block_exec(env,tb):
	global nt
	global state
	if not init_done:
		return 0

	if state == 0:
		return 0

	pc = panda.current_pc(env)
#	print("state = %d pc=%x" % (state,pc))
	
	if (state <= 33):
		progress("Before block exec: state=%d pc=%lx" % (state,pc))

	if (state == 1):
		assert (pc == 0xc12c4648)
		state = 2

	if (state == 2 and pc == 0xc101dfec):
		progress ("\nCreating 'newroot' snapshot at 0xc101dfec")
		panda.snap("newroot")
		state = 3
		return 1

	if state == 3:
		nt = nt + 1
		if nt == 10:
			progress("\nRestoring 'newroot' snapshot")
			panda.revert("newroot", now=False)
			nt = 0
			state = 3
		return 1
			
	return 0

	

# this is the initialiation for this plugin
@panda.callback.init
def init(handle):
	progress("Init of Fwi plugin -- in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.after_machine_init, machinit)
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_exec)
	return True


panda.load_python_plugin(init,"Fwi")
progress ("--- pypanda done with fwi init")

panda.init()
progress ("--- pypanda done with INIT")
init_done = True


panda.run()
