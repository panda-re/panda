#!/usr/bin/env python3
# Test of tainted_branch

import os
import time
import keystone
import capstone
from panda import Panda, ffi
from panda.x86.helper import dump_regs, registers

CODE = b"""
jmp .start

.start:
mov bx, [ebx]
cmp ebx, eax
je .true

jmp .false

.true:
    mov edx, 3333
    jmp .end

.false:
    mov edx, 4444

.end:
nop
"""

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
ADDRESS = 0x1000
encoding, count = ks.asm(CODE, ADDRESS)
stop_addr = ADDRESS + len(encoding)
#print([hex(x) for x in encoding])

# Create a machine of type 'configurable' but with just a CPU specified (no peripherals or memory maps)
panda = Panda("i386", extra_args=["-M", "configurable", "-nographic",
                    #"-d", "llvm_ir"
                    #"-d", "in_asm"
                    ],
                    raw_monitor=True)
panda.load_plugin("taint2")


@panda.cb_after_machine_init
def setup(cpu):
    # After our CPU has been created, allocate memory and set starting state

    # Setup a region of memory
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)
    # Write code into memory
    panda.physical_memory_write(ADDRESS, bytes(encoding))

    # Set starting registers
    cpu.env_ptr.eip = ADDRESS
    cpu.env_ptr.regs[registers["EAX"]] = 0x11
    cpu.env_ptr.regs[registers["EBX"]] = ADDRESS

    # Taint register(s)
    panda.taint_label_reg(registers["EAX"], 10)
    #panda.taint_label_reg(registers["EBX"], 11)

# Before every instruction, disassemble it with capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

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

# After the tainted compare block - shutdown
@panda.cb_after_block_exec
def after(cpu, tb, rc):
    pc = panda.current_pc(cpu)
    if pc > 0x1005: # Ran 2 blocks: now stop
        print("\nSTOP\n")
        dump_regs(panda, cpu)
        os._exit(0) # TODO: we need a better way to stop here

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

panda.enable_precise_pc()

# Start PANDA running. Callback functions will be called as necessary
panda.run()
