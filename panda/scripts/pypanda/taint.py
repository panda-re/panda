#!/usr/bin/env python3

from pypanda import *
import os

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

        # we just happen to know we will encounter this bb ...
        # we just happen to know we will encounter this pc
        label_pc == 0xc12c4648
        if pc == label_pc:
                progress("I'm at label_pc=%x" % label_pc)
                # we just about to executed this bb and we are returning
                # so we want to taint eax
                panda.taint_reg(R_EAX, label=R_EAX)
                panda.taint_reg(R_EBX, label=R_EBX)
                panda.taint_reg(R_ECX, label=R_ECX)
                panda.taint_reg(R_EDX, label=R_EDX)
                state = 1
                return

        if state == 1:
                tqr = panda.query_taint_regs()
                for tq in tqr:
                        print (tq)
#IN:
#0xc1020c9c:  mov    ecx,DWORD PTR ds:0xc13e62c4
#0xc1020ca2:  lea    eax,[eax+ecx-0x4000]
#0xc1020ca9:  mov    DWORD PTR [eax],edx
#0xc1020cab:  ret


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
