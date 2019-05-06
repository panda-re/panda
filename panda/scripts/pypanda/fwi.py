from pypanda import *

panda = Panda(qcow="/home/tleek/.panda/debian:3.2.0-4-686-pae-i386-128M.qcow", extra_args="-D ./qemu.log -d in_asm") 



print ("--- pypanda done with PRE")


the_handle = None

state = 0 # before snapshot load

@panda.callback.after_machine_init
def machinit(env):
#	global the_handle
	global state

	print (str(the_handle))
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

	if state == 0:
		return 0

	pc = panda.current_pc(env)
	progress("Before block exec: pc=%lx" % pc)

	if (state == 1):
		if (pc == 0xc12c4648):
			print ("Great!	Start pc is what we expected")
		assert (pc == 0xc12c4648)
		state = 2

	if (state == 2 and pc == 0xc101dfec):
		print ("creating newroot snapshot")
		panda.snap("newroot2")
		state = 3
		return 1
#	if state == 3:
#		nt = nt + 1
#		if nt == 10:
#			print("snap back to newroot")
#			panda.revert("newroot", now=False)
#			nt = 0
	return 0



# this is the initialiation for this plugin
@panda.callback.init
def init(handle):
	global the_handle
	the_handle = handle
	print ("handle = %s" % (str(the_handle)))
	progress("Init of Fwi plugin -- in python. handle="+str(handle))
	panda.register_callback(handle, panda.callback.after_machine_init, machinit)
	panda.register_callback(the_handle, panda.callback.before_block_exec, before_block_exec)
	return True


panda.load_python_plugin(init,"Fwi")
print ("--- pypanda done with fwi init")

panda.init()
print ("--- pypanda done with INIT")
init_done = True


panda.run()
