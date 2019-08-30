#!/usr/bin/env python3

from pypanda import *
from panda_x86_helper import * # for register names -> offset mapping
from sys import argv, exit

import capstone

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
insn_cache = {} # address -> disassembly string
executed_pcs = [] # List of addresses we executed

# Run a command in the guest
@blocking
def my_runcmd():
    panda.revert_sync('root')
    panda.copy_to_guest("toy")
    progress(panda.run_serial_cmd("toy/toy toy/testsmall.bin"))
    panda.run_monitor_cmd("quit") # XXX: need a better way to return control to main thread


def generate_insns(env, tb):
    # Disassemble each basic block and store in insn_cache
    if tb.pc in insn_cache: return

    code_buf = ffi.new("char[]", tb.size)
    panda.virtual_memory_read(env, tb.pc, code_buf, tb.size)
    code = ffi.unpack(code_buf, tb.size)

    insn_cache[tb.pc] = ""
    for i in md.disasm(code, tb.pc):
        insn_cache[tb.pc] += ("0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str))

@panda.cb_after_block_exec(name="after_exec", procname="toy")
def after_block_exec(env, tb):
    # Before we translate each block in find cache its disassembly
    generate_insns(env, tb)
    return 0

panda.queue_async(my_runcmd)
panda.run()


progress ("%d pcs in executed_pcs" % (len(executed_pcs)))
for pc in executed_pcs: print(insn_cache[pc])
