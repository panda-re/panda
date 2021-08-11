#!/usr/bin/env python3
import os
import time
import keystone
import capstone

from pandare import Panda
CODE = b"""
jmp .start

.start:
    MOV DX, word ptr [R13]
    MOV CX, word ptr [R13 + 0x2]
    ADD DX, CX
    CMP DX, 0x41
    JE .b
.b:
    MOV word ptr [R12], DX

jmp .end

.end:
nop
"""

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
ADDRESS = 0x1000
encoding, count = ks.asm(CODE, ADDRESS)
stop_addr = ADDRESS + len(encoding)

buf = b"ABCD"
buf_src = ADDRESS+200
buf_dest = ADDRESS+100

# Create a machine of type 'configurable' but with just a CPU specified (no peripherals or memory maps)
panda = Panda("x86_64", extra_args=["-M", "configurable", "-nographic", "-d", "in_asm"])

panda.load_plugin("taint2")
panda.load_plugin("tainted_branch")

@panda.cb_after_machine_init
def setup(cpu):
    # After our CPU has been created, allocate memory and set starting state

    # Setup a region of memory
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, bytes(encoding))

    # Copy from buffer at R13 into buffer at R12

    # R13 points to buffer in memory
    panda.arch.set_reg(cpu, "R13", buf_src)
    panda.physical_memory_write(buf_src, buf)

    # R12 points to empty memory
    panda.arch.set_reg(cpu, "R12", buf_dest)

    # RBP contains length of buffer
    panda.arch.set_reg(cpu, "RBP", len(buf))

    # Set starting pc
    panda.arch.set_pc(cpu, ADDRESS)

    # Taint buffer using PHYSICAL addresses
    for idx in range(len(buf)):
        panda.taint_label_ram(buf_src+idx, idx)
        panda.taint_sym_label_ram(buf_src+idx, idx)

# After the tainted compare block - shutdown
@panda.cb_after_block_exec
def after(cpu, tb, rc):
    pc = panda.arch.get_pc(cpu)
    if pc >= stop_addr - 6: # Stop just before .end
        print("\nSTOP", hex(stop_addr), "\n")
        panda.arch.dump_regs(cpu)

        # DEST BUFFER:
        dest_data = panda.physical_memory_read(buf_dest, len(buf))
        print("DEST:", dest_data)

        for idx in range(2):
            addr = buf_dest + idx
            assert(panda.taint_check_ram(addr)), f"Dest[{idx}] is not tainted"
            tq = panda.taint_get_ram(addr)
            taint_labels = tq.get_labels()
            print("Taint", hex(addr), taint_labels)
            # Get DEST memory symbol
            expr = panda.taint_sym_query_ram(addr)
            assert expr != None
            print(f"Memory[{hex(addr)}] => {type(expr)}: {expr}")

        # Get the RDX symbol 
        reg_num = panda.arch.registers['RDX']
        expr = panda.taint_sym_query_reg(reg_num)
        assert expr != None
        print("RDX symbolic value =>", expr)

        # Get Path Constrains
        pcs = panda.taint_sym_path_constraints()
        metas = panda.taint_sym_branch_meta()
        assert len(pcs) > 0
        assert len(pcs) == len(metas)
        [print('PC', hex(meta),'\t', pc) for pc, meta in zip(pcs, metas)]
        os._exit(0) # TODO: we need a better way to stop here

# Before every instruction, disassemble it with capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

panda.cb_insn_translate(lambda x,y: True)

@panda.cb_insn_exec
def on_insn(cpu, pc):
    code = panda.virtual_memory_read(cpu, pc, 12)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

panda.enable_precise_pc()
# Start PANDA running. Callback functions will be called as necessary
panda.run()
