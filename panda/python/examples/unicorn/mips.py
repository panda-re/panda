#!/usr/bin/env python3

from panda import Panda, ffi
import capstone
import keystone
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

ks = keystone.Ks(keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32)
#ks = keystone.Ks(keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

ADDRESS = 0x1000
encoding, count = ks.asm(CODE, ADDRESS)
stop_addr = ADDRESS + len(encoding)

panda = Panda("mipsel",
        extra_args=["-M", "configurable", "-nographic"],
        raw_monitor=True)

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
    cpu.env_ptr.active_tc.gpr[8] = 0x10

    # Set starting_pc
    cpu.env_ptr.active_tc.PC = ADDRESS

# Always run insn_exec
panda.cb_insn_translate(lambda x,y: True)

md = capstone.Cs(capstone.CS_ARCH_MIPS, 4) # misp32
@panda.cb_insn_exec
def on_insn(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    '''
    if pc >= stop_addr:
        print("Finished execution")
        #dump_regs(panda, cpu)
        print("Register t0 contains:", hex(cpu.env_ptr.active_tc.gpr[8]))
        print("Register t1 contains:", hex(cpu.env_ptr.active_tc.gpr[9]))
        os._exit(0) # TODO: we need a better way to stop here

    code = panda.virtual_memory_read(cpu, pc, 12)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

# Start PANDA running. Callback functions will be called as necessary
panda.run()
