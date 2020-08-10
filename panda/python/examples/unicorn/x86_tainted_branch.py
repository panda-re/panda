#!/usr/bin/env python3
# Test of tainted_branch

import os
import time
import keystone
import capstone
import z3

from panda import Panda, ffi
from panda.x86.helper import dump_regs, registers, all_registers

CODE = b"""
jmp .start

.start:
#mov ebx, [ebx]
add ebx, 8
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
panda = Panda("i386", extra_args=["-M", "configurable", "-nographic"])

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
    print("EIP:", cpu.env_ptr.eip)
    cpu.env_ptr.regs[registers["EAX"]] = 11
    cpu.env_ptr.regs[registers["EBX"]] = 29
    #cpu.env_ptr.regs[registers["EBX"]] = ADDRESS

    # Taint register(s)
    panda.taint_label_reg(registers["EAX"], 10)
    #panda.taint_label_reg(registers["EDX"], 11)

# After the tainted compare block - shutdown
@panda.cb_after_block_exec
def after(cpu, tb, rc):
    pc = panda.current_pc(cpu)
    if pc > 0x1005: # Ran 2 blocks: now stop
        print("\nSTOP\n")
        dump_regs(panda, cpu)
        os._exit(0) # TODO: we need a better way to stop here

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

@panda.ppp("taint2", "on_branch2")
def tainted_branch(addr, size):
    tainted = []
    for offset in range(0, size):
        if panda.taint_check_laddr(addr.addr_val, offset):
            print("TAINTED BRANCH")

            # At the time of the branch we need to determine CONCRETE values for non-tainted
            # registers. As such, let's generate vars for each of them:

            tq = panda.taint_get_laddr(addr.addr_val, offset)
            taint_labels = tq.get_labels()
            print(taint_labels)
            print("\n")

ffi.cdef('typedef void (*on_branch2_constraints_t) (char*);')
ffi.cdef('void ppp_add_cb_on_branch2_constraints(on_branch2_constraints_t);')

@panda.ppp("taint2", "on_branch2_constraints")
def taint_cmp(s):
    if s == ffi.NULL:
        print("ERR")
        return

    cpu = panda.get_cpu()

    data = ffi.string(s)

    # For each register we need to create a base value
    # tainted values should be bitvecs. non-tainted values should be
    # constants

    regs = {}

    # For each register, create concrete (BitVecVal) or symbolic (BitVec)
    # depending on taint
    for name, (qemu_idx, typ, size) in all_registers.items():
        name = name.lower()
        if typ == 0:
            # Normal registers
            if panda.taint_check_reg(qemu_idx):
                regs[name+"_v"] = z3.BitVec(name, size)
            else:
                val = cpu.env_ptr.regs[qemu_idx]
                regs[name+"_v"] = z3.BitVecVal(val, size)
        elif typ == 1:
            pass
        elif typ == 2:
            # Segment registers
            # Assign bitvecs
            regs[name+"_base_v"]  = z3.BitVecVal(cpu.env_ptr.segs[qemu_idx].base,  size)
            regs[name+"_flags_v"] = z3.BitVecVal(cpu.env_ptr.segs[qemu_idx].flags, size)
            regs[name+"_limit_v"] = z3.BitVecVal(cpu.env_ptr.segs[qemu_idx].flags, size)

    def Extract(size, start, val):
        end = start+size-1
        return z3.Extract(end, start, val)

    def load(endian, is_store, bit_sz, signed, addr):
        # TODO: actually use endianness
        assert(not is_store), "NYI"

        # assumes it's not tainted
        conc_data = panda.virtual_memory_read(cpu, addr, bit_sz*8, fmt='int') # TODO
        return z3.BitVecVal(conc_data, bit_sz*8)

    # XXX: this uses evals!!!

    print(f"\nTainted comparison at: 0x{panda.current_pc(cpu)} {data.decode()}")

    s_true = z3.Solver()
    eval(f"s_true.add({data.decode()})")
    if s_true.check():
        print("Solution found for TRUE branch:")
        print(s_true.model())
    else:
        print("TRUE branch UNSAT")

    s_false = z3.Solver()
    eval(f"s_false.add(z3.Not({data.decode()}))")
    if s_false.check():
        print("Solution found for FALSE branch:")
        print(s_false.model())
    else:
        print("FALSE branch UNSAT")


panda.enable_precise_pc()

# Start PANDA running. Callback functions will be called as necessary
panda.run()
