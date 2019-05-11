#!/usr/bin/env python3
'''
example_print_regs.py

This example displays the register state of the cpu in x86 at each 
`before_block_exec` callback.

Run this with `python3 example_print_regs.py`

'''
from pypanda import *
from panda_x86_helper import *
from time import sleep
from sys import argv
import qcows

# Single arg of arch, defaults to i386
arg1 = "i386" if len(argv) <= 1 else argv[1]

q = qcows.get_qcow(arg1)
panda = Panda(qcow=q)

@panda.callback.init
def init(handle):
	panda.disable_tb_chaining()
	panda.register_callback(handle, panda.callback.before_block_exec, \
							before_block_execute)
	return True

@panda.callback.before_block_exec
def before_block_execute(cpustate,transblock):
	fregs = ["{:08x}".format(i) for i in cpustate.env_ptr.regs]
	fregs.append("{:08x}".format(cpustate.env_ptr.eip))
	fregs.append("{:08x}".format(cpustate.env_ptr.eflags))
	in_kernel = "Yes" if panda.in_kernel(cpustate) else "No"
	progress("EAX: %s EBX: %s ECX: %s EDX: %s ESP: %s EBP: %s EIP: %s \
			In_Kernel: %s" %(fregs[R_EAX], fregs[R_EBX], fregs[R_ECX],\
			 fregs[R_EDX], fregs[R_ESP], fregs[R_EBP] , fregs[8], in_kernel))
	sleep(sleeptime)
	return 0

sleeptime = 0.5
# this is unncecessary because we do this when before_block_exec is registered.
panda.load_python_plugin(init,"example_print_regs")
panda.run()
