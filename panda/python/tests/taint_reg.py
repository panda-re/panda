#!/usr/bin/env python3
from sys import argv
from os import path
import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pandare import Panda
from pandare.helper.x86 import R_EAX, R_EBX, R_ECX, registers

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

bin_dir = "taint"
bin_name = "taint_asm"

assert(path.isfile(path.join(bin_dir, bin_name))), "Missing file {}".format(path.join(bin_dir, bin_name))

# Take a recording of toy running in the guest if necessary
recording_name = bin_dir+"_"+bin_name
if not path.isfile(recording_name +"-rr-snp"):
    @panda.queue_blocking
    def run_it():
        panda.record_cmd(path.join(bin_dir, bin_name), copy_directory=bin_dir, recording_name=recording_name)
        panda.stop_run()

    print("Generating " + recording_name + " replay")
    panda.run()

out = []
mappings = {}

# Read symbols from bin into mappings
with open(path.join(bin_dir, bin_name), 'rb') as f:
    our_elf = ELFFile(f)
    for section in our_elf.iter_sections():
        if not isinstance(section, SymbolTableSection): continue
        for symbol in section.iter_symbols():
            if len(symbol.name): # Sometimes empty
                mappings[symbol['st_value']] = symbol.name

tainted = False

@panda.cb_before_block_exec_invalidate_opt(procname=bin_name)
def taint_it(env, tb):
    if tb.pc in mappings and mappings[tb.pc] == "taint_me":
        global tainted
        if not tainted:
            print("Applying taint in taint_me function")
            tainted = True
            panda.taint_label_reg(R_EAX, 10)
            panda.taint_label_reg(R_EBX, 20)
            panda.taint_label_reg(R_ECX, 30)

            return 1
    return 0

@panda.cb_before_block_exec(procname=bin_name)
def bbe(env, tb):
    if tb.pc in mappings:
        print(mappings[tb.pc])
        if mappings[tb.pc] == "query_taint":
            print("\nTAINT INFO")
            for reg_name, reg in registers.items():
                if panda.taint_check_reg(reg):
                    for idx, byte_taint in enumerate(panda.taint_get_reg(reg)):
                        labels = byte_taint.get_labels()
                        print("Taint of register {}, byte {}".format(reg_name, idx), labels)
                        if reg_name == "EAX":
                            assert([10] == labels), "Incorrect taint on EAX"
                        elif reg_name == "EBX":
                            assert([10, 20] == labels), "Incorrect taint on EBX"
                        elif reg_name == "ECX":
                            assert([10, 20, 30] == labels), "Incorrect taint on ECX"
            panda.end_analysis()

panda.disable_tb_chaining()
panda.run_replay(recording_name)
print("Success! Tracked taint propagation across registers and final taint labels match expected (test 1 of 1)!")
