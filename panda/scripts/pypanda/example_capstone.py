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

# Run a command in the guest
@blocking
def my_runcmd():
    panda.revert_sync('root')
    panda.run_serial_cmd("find . /proc/self")

    # By quitting here main thread can continue executing after panda.run
    # XXX: Need a better way to transfer control back to main thread - maybe via main_loop_wait callbacks?
    panda.run_monitor_cmd("quit")

@panda.cb_after_block_translate(name="before")
def before_block_trans(env, tb):
    '''
    Disassemble each basic block as we translate. Store in insn_cache
    '''
    code_buf = ffi.new("char[]", tb.size)
    panda.virtual_memory_read(env, tb.pc, code_buf, tb.size)
    code = ffi.unpack(code_buf, tb.size)

    assert (tb.pc not in insn_cache)
    insn_cache[tb.pc] = ""
    for i in md.disasm(code, tb.pc):
        insn_cache[tb.pc] += ("0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str))
    return 0

@panda.cb_before_block_exec(name="exec")
def before_block_exec(env, tb):
    '''
    At each BB's execution, print from the cache
    '''
    pc = panda.current_pc(env)
    assert(pc in insn_cache)
    print(insn_cache[pc])
    return 0


panda.queue_async(my_runcmd)



panda.run()
