#!/usr/bin/env python3

from pypanda import *

panda = Panda(qcow="/home/tleek/.panda/debian:3.2.0-4-686-pae-i386-128M.qcow", extra_args="-D ./qemu.log -d in_asm") 



print ("--- pypanda done with PRE")


state = 0 # before snapshot load

@panda.callback.after_machine_init
def machinit(env):
	global state

	progress("Machine initialized -- disabling chaining & reverting to booted snapshot\n")
	panda.disable_tb_chaining()
	progress("foo")
	print ("instr = %d" % (panda.rr_get_guest_instr_count()))
	panda.delvm("newroot", now=True)
	progress("bar")

	pc = panda.current_pc(env)
	progress("Before revert: pc=%lx" % pc)

	panda.revert("root", now=True)
	progress("meh")
	
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


	print ("state=%d" % state)

	if state == 0:
		return 0

	pc = panda.current_pc(env)
	if (state <= 33):
		progress("Before block exec: state=%d pc=%lx" % (state,pc))

	if (state == 1):
		if (pc == 0xc12c4648):
			print ("\nGreat!	Start pc is what we expected")
		assert (pc == 0xc12c4648)
		state = 2

	if (state == 2 and pc == 0xc101dfec):
		print ("\nCreating newroot snapshot at 0xc101dfec")
		panda.snap("newroot")
		state = 3
		return 1
	if state == 3:
		nt = nt + 1
		if nt == 10:
			print("\nRestoring newroot snapshot")
			panda.revert("newroot", now=False)
			nt = 0
			state = 3
		return 1
	if state == 5:
		if pc == 0xc101dfec:
			print ("\nSuccessfully restored\n")
			
	return 0

	

# this is the initialiation for this plugin
@panda.callback.init
def init(handle):
	progress("Init of Fwi plugin -- in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.after_machine_init, machinit)
	panda.register_callback(handle, panda.callback.before_block_exec, before_block_exec)
#	panda.register_callback(handle, panda.callback.main_loop_wait, ml_revert)
	return True


panda.load_python_plugin(init,"Fwi")
print ("--- pypanda done with fwi init")

panda.init()
print ("--- pypanda done with INIT")
init_done = True


panda.run()
