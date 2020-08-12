'''
Helper constants and functions specific to x86
Work in progress
'''

import binascii
from panda.utils import telescope


# See target/i386/cpu.h
# types:
#   0 full-width: env_ptr->regs[X]
#   1 sub-register
#   2 segment registers env_ptr->segs[X]
all_registers = { # Name: (IDX, type, size)
    "EAX":    (0, 0, 32),
    "EBX":    (3, 0, 32), # XXX Note the IDX order is weird - EAX, ECX, EDX, EBX
    "ECX":    (1, 0, 32),
    "EDX":    (2, 0, 32),
    "ESP":    (4, 0, 32),
    "EBP":    (5, 0, 32),
    "ESI":    (6, 0, 32),
    "EDI":    (7, 0, 32),

    # TODO: subregisters

    # XXX names might be bad?
    "ES": (0, 2, 32),
    "CS": (1, 2, 32),
    "SS": (2, 2, 32),
    "DS": (3, 2, 32),
    "FS": (4, 2, 32),
    "GS": (5, 2, 32),
}

registers = {name:idx for name, (idx, typ, sz) in all_registers.items() if typ == 0}

def dump_regs(panda, cpu):
    '''
    Print (telescoping) each register and its values
    '''
    for (regname, reg) in registers.items():
        val = cpu.env_ptr.regs[reg]
        print("{}: 0x{:x}".format(regname, val), end="\t")
        telescope(panda, cpu, val)
    print("{}: 0x{:x}".format("EIP", cpu.env_ptr.eip))
    print("{}: 0x{:x}".format("EFLAGS", cpu.env_ptr.eflags))

def dump_stack(panda, cpu):
    '''
    Print (telescoping) most recent 8 words on the stack (from ESP ESP+8*word_size)
    '''
    base_reg = R_ESP
    base_reg_s = "ESP"

    word_size = 4
    N_WORDS = 8

    base_reg_val = cpu.env_ptr.regs[base_reg]
    for word_idx in range(N_WORDS):
        val_b = panda.virtual_memory_read(cpu, base_reg_val+word_idx*word_size, word_size)
        val = int.from_bytes(val_b, byteorder='little')
        print("[{}+0x{:0>2x} == 0x{:0<8x}]: 0x{:0<8x}".format(base_reg_s, word_idx*word_size, base_reg_val+word_idx*word_size, val), end="\t")
        telescope(panda, cpu, val)

def dump_state(panda, cpu):
    """Dumps registers and stack to stdout."""
    dump_regs(panda, cpu)
    print("")
    dump_stack(panda, cpu)

