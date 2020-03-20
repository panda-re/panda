#!/usr/bin/env python3

# Demonstartion of using PANDA to run shellcode. Example modified from Unicorn Engine
# https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/sample_arm.py

import capstone
import os

from panda import Panda, ffi
#from panda.ppc.helper import dump_regs, registers

from ipdb import set_trace as d

PPC_CODE   = b"\x60\x00\x00\x00\x38\x20\x00\x10" # nop; li 1, 0x100
ADDRESS = 0
stop_addr = ADDRESS + len(PPC_CODE)

# Create a machine of type 'configurable' but with just a CPU specified (no peripherals or memory maps)
panda = Panda("ppc", extra_args=["-M", "configurable", "-nographic", "-d", "unimp,guest_errors,in_asm,cpu,int"])

@panda.cb_after_machine_init
def setup(cpu):
    '''
    After our CPU has been created, allocate memory and set starting state
    '''
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, PPC_CODE)

    # Set up registers
    # Stolen without understanding from hw/ppc/e500.c
    #cpu.halted = 0
    cpu.env_ptr.gpr[1] = (16<<20) - 8

    cpu.env_ptr.gpr[3] = ADDRESS # start addr?
    cpu.env_ptr.gpr[4] = 0
    cpu.env_ptr.gpr[5] = 0
    cpu.env_ptr.gpr[6] = 0x45504150 # 'EPAPR_MAGIC'
    cpu.env_ptr.gpr[7] = 0x1000 # something map size
    cpu.env_ptr.gpr[8] = 0
    cpu.env_ptr.gpr[9] = 0

    # Set starting_pc
    cpu.env_ptr.nip = ADDRESS

    # Apply taint label to r2
    #panda.taint_label_reg(registers['R2'], 10) # Taint R2 with label 10. Should prop into R1
    print("Machine state initialized")

@panda.cb_insn_translate
def should_run_on_insn(env, pc):
    '''
    At each basic block, decide if we run on_insn for each contained
    instruction. For now, always return True unless we're past stop_addr

    Alternatively could be implemented  as
        panda.cb_insn_translate(lambda x,y: True)
    '''
    return True

md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32)
@panda.cb_insn_exec
def on_insn(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    When we reach stop_addr, dump registers and shutdown
    '''
    print("Insn!")
    if pc == stop_addr:
        print("Finished execution. CPU registers are:")
        d()

        '''
        dump_regs(panda, cpu)

        print("Taint results\n")
        if panda.taint_check_reg(registers['R1']):
            for idx, byte_taint in enumerate(panda.taint_get_reg(registers['R1'])):
                labels = byte_taint.get_labels()
                print(f"Register R1 byte {idx} tainted by {labels}")

        # TODO: we need a better way to stop execution in the middle of a basic block
        '''
        os._exit(0)

    code = panda.virtual_memory_read(cpu, pc, 12)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

# Start PANDA running. Callback functions will be called as necessary
print("Go PANDA, go!")
panda.run()
