#!/usr/bin/env python3

# Print a trace of a program's execution

from sys import argv
from os import path
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

bin_dir = "../tests/taint"
bin_name = "taint"
cmd = path.join(path.split(bin_dir)[-1], bin_name)

assert(path.isfile(path.join(bin_dir, bin_name))), "Missing executable {}".format(path.join(bin_dir, bin_name))
# Take a recording of toy running in the guest if necessary
recording_name = (bin_dir+"_"+bin_name).replace("/","_").replace("..","~")
print(recording_name)

@blocking
def take_recording():
    panda.record_cmd(cmd, copy_directory=bin_dir, recording_name=recording_name)
    panda.stop_run()

if not path.isfile(recording_name +"-rr-snp"):
    panda.queue_async(take_recording)
    panda.run()

mappings = {}

# Read symbols from bin into mappings
with open(path.join(bin_dir, bin_name), 'rb') as f:
    our_elf = ELFFile(f)
    for section in our_elf.iter_sections():
        if not isinstance(section, SymbolTableSection): continue
        for symbol in section.iter_symbols():
            if len(symbol.name): # Sometimes empty
                mappings[symbol['st_value']] = symbol.name

@panda.cb_after_block_exec(procname=bin_name) # After we've executed the block applying taint, make sure everything is tainted as expected
def abe(cpu, tb, exit):
    if tb.pc in mappings:
        print(hex(tb.pc),mappings[tb.pc])

panda.disable_tb_chaining()
panda.run_replay(recording_name)
