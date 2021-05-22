#!/usr/bin/env python3

from pandare import Panda, ffi
from capstone import *
from capstone.mips import *
from keystone import *
import os

CODE = b"""
addiu $t0, 1  # $t0++
j .mid
nop

.mid:
li  $t1, 2    # t1 = 2
j .end
nop

.end:
addiu $t1, 1  # t1++
"""

ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

ADDRESS = 0x1000
encoding, count = ks.asm(CODE, ADDRESS)
stop_addr = ADDRESS + len(encoding)

panda = Panda("mips",
        extra_args=["-M", "configurable", "-nographic"],
        raw_monitor=True) # Allows for a user to ctrl-a + c then type quit if things go wrong

@panda.cb_after_machine_init
def setup(cpu):
    '''
    After our CPU has been created, allocate memory and set starting state
    '''
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, bytes(encoding))

    # Set up registers
    #cpu.env_ptr.active_tc.gpr[panda.arch.registers['t0']] = 0x10
    panda.arch.set_reg(cpu, 't0', 0x10)

    # Set starting_pc
    cpu.env_ptr.active_tc.PC = ADDRESS

# Always run insn_exec
panda.cb_insn_translate(lambda x,y: True)

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+ CS_MODE_BIG_ENDIAN) # misp32
@panda.cb_insn_exec
def on_insn(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    '''
    if pc >= stop_addr:
        print("Finished execution")
        #dump_regs(panda, cpu)
        print("Register t0 contains:", hex(panda.arch.get_reg(cpu, 't0')))
        print("Register t1 contains:", hex(panda.arch.get_reg(cpu,'t1')))
        os._exit(0) # TODO: we need a better way to stop here

    code = panda.virtual_memory_read(cpu, pc, 4)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

# Start PANDA running. Callback functions will be called as necessary
panda.run()
