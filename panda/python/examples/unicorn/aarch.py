#!/usr/bin/env python3

from pandare import Panda, ffi
import capstone
import keystone
import os

CODE = b"""
 mov     x0, #1
 mov x1, #64
"""

ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

ADDRESS = 0x1000
encoding, count = ks.asm(CODE, ADDRESS)
stop_addr = ADDRESS + len(encoding)

panda = Panda("aarch64",
        extra_args=["-M", "configurable", "-nographic", "-d", "in_asm"],
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

    # Set starting_pc
    panda.arch.set_pc(cpu, ADDRESS)

# Always run insn_exec
panda.cb_insn_translate(lambda x,y: True)

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM) # misp32
@panda.cb_insn_exec
def on_insn(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    '''
    if pc >= stop_addr:
        print("Finished execution")
        panda.arch.dump_state(cpu)
        os._exit(0) # TODO: we need a better way to stop here

    code = panda.virtual_memory_read(cpu, pc, 12)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

# Start PANDA running. Callback functions will be called as necessary
panda.run()
