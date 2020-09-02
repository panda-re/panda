'''
Helper constants and functions specific to arm (little endian)
Work in progress
'''

import binascii
from panda.utils import telescope

# R0 through 12 are just accessed by number
R_SP = 13
R_LR = 14
R_IP = 15

registers = {
    "R0": 0,
    "R1": 1,
    "R2": 2,
    "R3": 3,
    "R4": 4,
    "R5": 5,
    "R6": 6,
    "R7": 7,
    "R8": 8,
    "R9": 9,
    "R10": 10,
    "R11": 11,
    "R12": 12,
    "SP": R_SP,
    "LR": R_LR,
    "IP": R_IP,
    }
"""Register array for ARM"""

def dump_regs(panda, cpu):
    '''
    Print (telescoping) each register and its values
    '''
    for (regname, reg) in registers.items():
        val = cpu.env_ptr.regs[reg]
        print("{}: 0x{:x}".format(regname, val), end="\t")
        telescope(panda, cpu, val)

def dump_stack(panda, cpu):
    '''
    Print (telescoping) most recent 8 words on the stack (from ESP ESP+8*word_size)
    '''
    base_reg = R_SP
    base_reg_s = "SP"

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
    print("Registers:")
    dump_regs(panda, cpu)
    print("Stack:")
    dump_stack(panda, cpu)

