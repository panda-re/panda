'''
Helper constants and functions specific to mips
'''

import binascii
from panda.utils import telescope

'''
Register Number	Conventional Name	Usage
$0	        $zero	Hard-wired to 0
$1	        $at	Reserved for pseudo-instructions
$2 - $3	        $v0, $v1	Return values from functions
$4 - $7	        $a0 - $a3	Arguments to functions - not preserved by subprograms
$8 - $15	$t0 - $t7	Temporary data, not preserved by subprograms
$16 - $23	$s0 - $s7	Saved registers, preserved by subprograms
$24 - $25	$t8 - $t9	More temporary registers, not preserved by subprograms
$26 - $27	$k0 - $k1	Reserved for kernel. Do not use.
$28	        $gp	Global Area Pointer (base of global data segment)
$29	        $sp	Stack Pointer
$30	        $fp	Frame Pointer
$31	        $ra	Return Address
'''

regnames = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
            't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
            's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
            't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra']

R_SP = regnames.index('sp')

registers = {regnames[idx]: idx for idx in range(len(regnames)) }

def dump_regs(panda, cpu):
    '''
    Print (telescoping) each register and its values
    '''
    for (regname, reg) in registers.items():
        val = cpu.env_ptr.active_tc.gpr[reg]
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

    base_reg_val = cpu.env_ptr.active_tc.gpr[base_reg]
    for word_idx in range(N_WORDS):
        val_b = panda.virtual_memory_read(cpu, base_reg_val+word_idx*word_size, word_size)
        val = int.from_bytes(val_b, byteorder='little')
        print("[{}+0x{:0>2x} == 0x{:0<8x}]: 0x{:0<8x}".format(base_reg_s, word_idx*word_size, base_reg_val+word_idx*word_size, val), end="\t")
        telescope(panda, cpu, val)

def dump_state(panda, cpu):
    print("Registers:")
    dump_regs(panda, cpu)
    print("Stack:")
    dump_stack(panda, cpu)

