# from idautils import *
# from idc import *
import struct
from llvm import *
from llvm.core import *
from bitstring import BitArray
from pwn import *


MAX_BITSET  = 2048

f = open("slice_report.bin")
outfile = open("slice_addrs", "w")

mod = Module.from_bitcode(file("llvm-mod.bc"))

marked = {}
while True:
    b = f.read(4)
    if not b:
        print "No more to read"
        break

    name_size = struct.unpack("<I", b)[0]
    name = f.read(name_size)
    print "name", name
    func = mod.get_function_named(name)
    if func not in marked:
        marked[func] = {}
    
    bb_idx = struct.unpack("<I", f.read(4))[0]
    markbytes = f.read(MAX_BITSET/8)
    bits = BitArray(bytes=markbytes)
    marked[func][bb_idx] = bits

for func in marked:
    base_addr = int(func.name.split("-")[4], 16)
    targetAsm = ""
    bb_idx = 0
    for bb in func.basic_blocks:
        if bb_idx >= len(marked[func]):
            break
        
        j = 0
        targetAsmSeen, targetAsmMarked = False, False
        for inst in bb.instructions:
            if marked[func][bb_idx][j]:
                targetAsmMarked = True

            md = inst.get_metadata("targetAsm")
            if md is not None:
                if targetAsm:
                    c = "*" if targetAsmMarked else " "
                    print c, disasm(targetAsm, vma = base_addr)
                    outfile.write(format(base_addr, 'x') + "\n")
                    base_addr += len(targetAsm) 

                targetAsm = md.getOperand(0).getName().decode("hex")

                targetAsmMarked = False


            j+=1
    
        if targetAsm:
            c = "*" if targetAsmMarked else " "
            print c, disasm(targetAsm, vma = base_addr)
        bb_idx+=1
        
    



