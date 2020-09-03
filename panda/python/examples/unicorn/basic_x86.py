#!/usr/bin/env python3

# Demonstartion of using PANDA to run shellcode. Example modified from Unicorn Engine
# https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/sample_arm.py

import capstone
import os

from panda import Panda, ffi

X86_CODE   = b"\x40\x01\xC3\x41" # inc eax; add ebx, eax; inc ecx;
ADDRESS = 0x1000
stop_addr = ADDRESS + len(X86_CODE)

# Create a machine of type 'configurable' but with just a CPU specified (no peripherals or memory maps)
panda = Panda("i386", extra_args=["-M", "configurable", "-nographic"])

@panda.cb_after_machine_init
def setup(cpu):
    '''
    After our CPU has been created, allocate memory and set starting state
    '''
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, X86_CODE)

    # Set up registers
    panda.arch.set_reg(cpu, "EAX", 0x1)
    panda.arch.set_reg(cpu, "EBX", 0x2)
    panda.arch.set_reg(cpu, "ECX", 0x3)
    panda.arch.set_reg(cpu, "EDX", 0x4)

    # Set starting_pc
    panda.arch.set_pc(cpu, ADDRESS)
    print(f"PC is 0x{panda.arch.get_pc(cpu):x}")

    # Apply taint label to EAX
    panda.taint_label_reg(panda.arch.registers["EAX"], 10) # Taint eax with label 10. Should prop into ebx

@panda.cb_insn_translate
def should_run_on_insn(env, pc):
    '''
    At each basic block, decide if we run on_insn for each contained
    instruction. For now, always return True unless we're past stop_addr

    Alternatively could be implemented  as
        panda.cb_insn_translate(lambda x,y: True)
    '''
    return True

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
@panda.cb_insn_exec
def on_insn(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    When we reach stop_addr, dump registers and shutdown
    '''
    if pc == stop_addr:
        print("Finished execution. CPU registers are:")
        panda.arch.dump_regs(cpu)

        print("Taint results\n")
        if panda.taint_check_reg(panda.arch.registers["EBX"]):
            for idx, byte_taint in enumerate(panda.taint_get_reg(panda.arch.registers["EBX"])):
                labels = byte_taint.get_labels()
                print(f"Register EBX byte {idx} tainted by {labels}")

        # TODO: we need a better way to stop execution in the middle of a basic block
        os._exit(0)

    code = panda.virtual_memory_read(cpu, pc, 12)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

# Start PANDA running. Callback functions will be called as necessary
panda.run()
