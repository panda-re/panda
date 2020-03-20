'''
Helper constants and functions specific to x86
Work in progress
'''

import binascii

R_EAX = 0
R_ECX = 1
R_EDX = 2
R_EBX = 3
R_ESP = 4
R_EBP = 5
R_ESI = 6
R_EDI = 7

registers = {
    "EAX": R_EAX,
    "EBX": R_EBX,
    "ECX": R_ECX,
    "EDX": R_EDX,
    "ESP": R_ESP,
    "EBP": R_EBP,
    "ESI": R_ESI,
    "EDI": R_EDI}

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
    '''
    X86 only (for now)
    '''
    dump_regs(panda, cpu)
    print("")
    dump_stack(panda, cpu)

