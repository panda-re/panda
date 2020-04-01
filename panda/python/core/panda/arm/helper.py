'''
Helper constants and functions specific to arm (little endian)
Work in progress
'''

import binascii

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

def telescope(panda, cpu, val):
    '''
    Given a value, check if it's a pointer by seeing if we can map it to physical memory.
    If so, recursively print where it points
    to until
    1) It points to a string (then print the string)
    2) It's code (then disassembly the insn)
    3) It's an invalid pointer
    4) It's the 5th time we've done this, break

    TODO Should use memory protections to determine string/code/data
    '''
    for _ in range(5): # Max chain of 5
        potential_ptr =  panda.virt_to_phys(cpu, val)
        if potential_ptr == 0xffffffff:
            print()
            return
        else:
            print("-> 0x{:0>8x}".format(val), end="\t")

            if val == 0:
                print()
                return
            # Consider that val points to a string. Test and print
            str_data = panda.virtual_memory_read(cpu, val, 16)
            str_val = ""
            for d in str_data:
                if d >= 0x20 and d < 0x7F:
                    str_val += chr(d)
                else:
                    break
            if len(str_val) > 2:
                print("== \"{}\"".format(str_val))
                return


            data = str_data[:4] # Truncate to 4 bytes
            val = int.from_bytes(data, byteorder='little')

    print("-> ...")

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
    print("Registers:")
    dump_regs(panda, cpu)
    print("Stack:")
    dump_stack(panda, cpu)

