#!/usr/bin/env python3
# Test of tainted_branch

import os
import time
import keystone
import capstone
from panda import Panda, ffi
from panda.x86.helper import dump_regs, registers

CODE = b"""
mov eax, 0x123;
jmp .break_block

.break_block:
cmp eax, 0x456; # Compare (tainted) 0x123 to 0x456
je .true_branch
jmp .end

.true_branch:
inc ebx;

.end:
inc ecx
"""

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
encoding, count = ks.asm(CODE)
ADDRESS = 0x1000
stop_addr = ADDRESS + len(encoding)

# Create a machine of type 'configurable' but with just a CPU specified (no peripherals or memory maps)
panda = Panda("i386", extra_args=["-M", "configurable", "-nographic",
                    "-d", "taint_ops,llvm_ir"
                    ],
                    raw_monitor=True)
panda.load_plugin("taint2")


@panda.cb_after_machine_init
def setup(cpu):
    # After our CPU has been created, allocate memory and set starting state
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, bytes(encoding))

    # Set starting registers
    cpu.env_ptr.regs[registers["EAX"]] = 0x1
    cpu.env_ptr.eip = ADDRESS

    # Taint EAX
    panda.taint_label_reg(registers["EAX"], 10)

# Before every instruction, disassemble it with capstone
panda.cb_insn_translate(lambda x,y: True)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

@panda.cb_insn_exec
def on_insn(cpu, pc):
    # Disassemble each insn. When we reach stop_addr, shutdown
    if pc == stop_addr:
        #dump_regs(panda, cpu)
        os._exit(0) # TODO: we need a better way to stop here

    code = panda.virtual_memory_read(cpu, pc, 12)
    for i in md.disasm(code, pc):
        try:
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        except Exception:
            time.sleep(1)
        break
    return 0

# CFFI can't typedef structures with unions, like addrs, so this is a hack to fix it
ffi.cdef("""
        typedef struct {
            AddrType typ;
            uint64_t addr_val;
            uint16_t off;
            AddrFlag flag;
        } FakeAddr;
""")
ffi.cdef('typedef void (*on_branch2_t) (FakeAddr, uint64_t);', override=True)
ffi.cdef('void ppp_add_cb_on_branch2(on_branch2_t);')

@panda.ppp("taint2", "on_branch2")
def tainted_branch(addr, size):

    tainted = []
    for offset in range(0, size):
        if panda.taint_check_laddr(addr.addr_val, offset):
            print("TAINTED BRANCH")
            tq = panda.taint_get_laddr(addr.addr_val, offset)
            taint_labels = tq.get_labels()
            print(taint_labels)
            print("\n")

            #cpu = panda.get_cpu()
            #pc = panda.current_pc(cpu)
            #print(f"TAINTED BRANCH at 0x{pc:x}, labels: {taint_labels}\n")

panda.enable_precise_pc()

# Start PANDA running. Callback functions will be called as necessary
panda.run()
