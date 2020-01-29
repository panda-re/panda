#!/usr/bin/env python3

# Demonstartion of using PANDA to run shellcode. Example modified from Unicorn Engine
# https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/sample_arm.py

import capstone
import os

from panda import Panda, ffi
from panda.arm.helper import dump_regs, registers

ARM_CODE   = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0" # mov r0, #0x37; sub r1, r2, r3
ADDRESS = 0x1000
stop_addr = ADDRESS + len(ARM_CODE)

# Create a machine of type 'basic' which just has an arm CPU with no peripherals/memory
panda = Panda("arm", extra_args=["-M", "basic", "-nographic"])

@panda.cb_after_machine_init
def setup(cpu):
    '''
    After our CPU has been created, allocate memory and set starting state
    '''
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, ARM_CODE)

    # Set up registers
    cpu.env_ptr.regs[registers['R0']] = 0x1234
    cpu.env_ptr.regs[registers['R2']] = 0x6789
    cpu.env_ptr.regs[registers['R3']] = 0x3333

    # Set starting_pc
    cpu.env_ptr.regs[registers['IP']] = ADDRESS

@panda.cb_insn_translate
def should_run_on_insn(env, pc):
    '''
    At each basic block, decide if we run on_insn for each contained
    instruction. For now, always return True unless we're past stop_addr

    Alternatively could be implemented  as
        panda.cb_insn_translate(lambda x,y: True)
    '''
    return True

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
@panda.cb_insn_exec
def on_insn(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    When we reach stop_addr, dump registers and shutdown
    '''
    if pc == stop_addr:
        print("Finished execution. CPU registers are:")
        dump_regs(panda, cpu)

        # TODO: we need a better way to stop execution in the middle of a basic block
        os._exit(0)

    code = panda.virtual_memory_read(cpu, pc, 12)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

# Start PANDA running. Callback functions will be called as necessary
panda.run()
