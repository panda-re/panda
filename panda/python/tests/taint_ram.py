#!/usr/bin/env python3

from sys import argv
from os import path
import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pandare import Panda, blocking, ffi
from pandare.helper.x86 import *

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

bin_dir = "taint"
bin_name = "taint"

assert(path.isfile(path.join(bin_dir, bin_name))), "Missing file {}".format(path.join(bin_dir, bin_name))
# Take a recording of toy running in the guest if necessary
recording_name = bin_dir+"_"+bin_name
if not path.isfile(recording_name +"-rr-snp"):
    @blocking
    def run_it():
        panda.record_cmd(path.join(bin_dir, bin_name), copy_directory=bin_dir, recording_name=recording_name)
        panda.stop_run()

    print("Generating " + recording_name + " replay")
    panda.queue_async(run_it)
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
g_phys_addrs = []

@panda.cb_before_block_exec_invalidate_opt(procname=bin_name)
def taint_it(cpu, tb):
    if tb.pc in mappings and mappings[tb.pc] == "apply_taint":
        global tainted
        if not tainted:
            # Apply taint to the string that begins at *(ESP+4)
            tainted = True
            string_base_p = cpu.env_ptr.regs[R_ESP] + 0x4 # esp + 0x4

            str_base = panda.virtual_memory_read(cpu, string_base_p, 4, fmt='int') # *(esp+0x4)

            s = panda.virtual_memory_read(cpu, str_base, 16, fmt='str').decode('utf8')
            print("Tainting string '{}'".format(s))

            global g_phys_addrs # Save all our tainted addresses for abe() check

            # Taint each character with a taint label of its index
            for idx in range(len(s)):
                taint_vaddr = str_base+idx
                taint_paddr = panda.virt_to_phys(cpu, taint_vaddr) # Physical address
                print("Taint character #{} '{}' at 0x{} (phys 0x{:x}) with label {}".format(idx, s[idx], taint_vaddr, taint_paddr, idx))
                panda.taint_label_ram(taint_paddr, idx)
                g_phys_addrs.append(taint_paddr)

            return 1
    return 0

@panda.cb_after_block_exec(procname=bin_name) # After we've executed the block applying taint, make sure everything is tainted as expected
def abe(cpu, tb, exit):
    if tb.pc in mappings:
        if mappings[tb.pc] == "apply_taint":
            global g_phys_addrs
            for idx, g_phys_addr in enumerate(g_phys_addrs):
                assert(panda.taint_check_ram(g_phys_addr)), "Taint2 failed to identify same address as tainted"
                assert([idx] == panda.taint_get_ram(g_phys_addr).get_labels()), "Incorrect labels"
            print("Success! Tracked taint with no propagation (test 1 of 2)")

@panda.cb_before_block_exec(procname=bin_name)
def bbe(cpu, tb):
    if tb.pc in mappings:
        print('\nRunning function: {}'.format(mappings[tb.pc]))
        if mappings[tb.pc] == "query_taint":
            assert(tainted), "Can't query taint before tainting"

            # EAX contains our result variable which should be tainted
            virt_addr = cpu.env_ptr.regs[R_EAX]
            phys_addr = panda.virt_to_phys(cpu, virt_addr)
            assert(panda.taint_check_ram(phys_addr)), "Final result is not tainted"
            tq = panda.taint_get_ram(phys_addr)
            taint_labels = tq.get_labels()
            assert([0,2,4,6,8,10] == taint_labels), "Taint labels {} are incorrect".format(taint_labels)
            print("Success! Tracked taint propagation and final taint labels match expected (test 2 of 2)!")
            panda.end_analysis()

panda.disable_tb_chaining()
panda.run_replay(recording_name)
