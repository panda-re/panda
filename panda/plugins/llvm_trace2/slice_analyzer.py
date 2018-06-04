# from idautils import *
# from idc import *
import struct
from llvm import *
from llvm.core import *
from pwn import *


MAX_BITSET  = 2048

f = open("slice_report.bin")
outfile = open("slice_addrs", "w")

mod = Module.from_bitcode(file("llvm-mod.bc"))

# Read marked functions from slice_report.bin
marked = {}
while True:
    b = f.read(4)
    if not b:
        print "No more to read"
        break

    name_size = struct.unpack("<I", b)[0]
    
    name = f.read(name_size)
    func = mod.get_function_named(name)
    if func not in marked:
        marked[func] = {}

    bb_idx = struct.unpack("<I", f.read(4))[0]
    markbytes = f.read(MAX_BITSET/8)
    
    # COnvert bytes to bits, then reverse each byte
    bits = "".join([format(ord(i), '08b')[::-1] for i in markbytes])
    marked[func][bb_idx] = bits

# Iterate marked functions 
for func in marked:
    print "*** Func %s***\n" % ( func.name)
    if len(func.name.split("-")) != 5:
        # If this function is not a guest TB of the format  tcg-llvm-tb-361-b7f58e50
        continue

    base_addr = int(func.name.split("-")[4], 16)
    targetAsm = ""
    bb_idx = 0
    for bb in func.basic_blocks:
        if bb_idx not in marked[func]:
            # If this bb_idx is not marked, increment bb_idx and continue
            bb_idx += 1
            continue
        print ">>> Block %d" % bb_idx
        
        j = 0
        targetAsmSeen, targetAsmMarked = False, False
        for inst in bb.instructions:
            if marked[func][bb_idx][j] == "1":
                targetAsmMarked = True

            md = inst.get_metadata("targetAsm")

            if md is not None:
                if targetAsm:
                    c = "*" if targetAsmMarked else " "
                    if targetAsmMarked:
                        outfile.write(format(base_addr, 'x') + "\n")
                    print c, disasm(targetAsm, vma = base_addr)
                    base_addr += len(targetAsm) 

                targetAsm = md.getOperand(0).getName().decode("hex")

                targetAsmMarked = False


            j+=1
    
        if targetAsm:
            c = "*" if targetAsmMarked else " "
            print c, disasm(targetAsm, vma = base_addr)
        bb_idx+=1
        
    



