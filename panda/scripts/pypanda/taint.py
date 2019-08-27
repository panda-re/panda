#!/usr/bin/env python3

from pypanda import *
from panda_x86_helper import *
from sys import argv, stdout
import os
#from capstone import *

#md = Cs(CS_ARCH_X86, CS_MODE_64)



arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

#qcowpath = os.getenv("HOME") + "/.panda/debian:3.2.0-4-686-pae-i386-128M.qcow"


#panda = Panda(qcow=qcowpath, extra_args="-D ./qemu.log -d in_asm") 



state = 0 # before snapshot load

@panda.cb_after_machine_init(name="init")
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



#init_done = False

nt = 0

@panda.cb_before_block_exec_invalidate_opt(name="bb")
def before_block_exec(env,tb):
        global nt
        global state

        if state == 0:
                return 0

        pc = panda.current_pc(env)
        progress("NEW BASIC BLOCK\n")
        progress("---------------\n")
        progress("pc=%x" % pc)

        

        # we just happen to know we will encounter this pc
        label_pc = 0xc12c4648
        if state == 1 and pc == label_pc:
                progress("I'm at label_pc=%x" % label_pc)
                # we just about to executed this bb and we are returning
                # so we want to taint eax
                panda.taint_label_reg(R_EAX, 1+R_EAX)
                panda.taint_label_reg(R_EBX, 1+R_EBX)
                panda.taint_label_reg(R_ECX, 1+R_ECX)
                panda.taint_label_reg(R_EDX, 1+R_EDX)
                # so we don't keep trying to label over and over
                state = 2

                # this should trigger re-translation of this bb s.t. its code will 
                # get taint instrumentation
                return 1


        def spit_taint(reg_num):
                taint = panda.taint_get_reg(reg_num)                
                for offset in range(panda.register_size):
                        tq = taint[offset]
                        if tq is None:
                                progress("offset=%d  NOTAINT")
                        else:
                                progress("offset=%d  n=%d tcn=%d  cb_mask=%x" % (offset, tq.num_labels, tq.tcn, tq.cb_mask))
                        for l in tq:
                                progress("  label=%d" % l)

                
        if panda.taint_enabled:
                if panda.taint_check_reg(R_EAX):
                        progress("pc=%x EAX tainted" % pc)
                        spit_taint(R_EAX)
                if panda.taint_check_reg(R_EBX):
                        progress("pc=%x EBX tainted" % pc)
                        spit_taint(R_EBX)
                if panda.taint_check_reg(R_ECX):
                        progress("pc=%x ECX tainted" % pc)
                        spit_taint(R_ECX)
                if panda.taint_check_reg(R_EDX):
                        progress("pc=%x EDX tainted" % pc)
                        spit_taint(R_EDX)
                        
        return 0

panda.run()
