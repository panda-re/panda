from plog import *
from llvm import *
from llvm.core import *
from google.protobuf.json_format import MessageToJson
import sys
import os
from os.path import dirname, join, realpath
import zlib
import struct
import argparse
import re
from enum import Enum, IntEnum
try_path(panda_dir, 'build')
try_path(panda_dir)
try_path(dirname(panda_dir), 'opt-panda')
try_path(dirname(panda_dir), 'debug-panda')
import plog_pb2
import IPython

class SliceVarType(Enum):
    TGT = "TGT"
    LLVM = "LLVM"
    MEM = "MEM"
    
regs = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "EIP"]
cpuStateAddr = 0

uses = set()
defs = set()
worklist = set()

class SliceVal():
    def __init__(self, typ, val):
        self.type = typ
        self.val = val
        
    def __eq__(self, other):
        return self.type == other.type and self.val == other.val
    
    def __hash__(self):
        return hash((self.type, self.val))
    
    def __repr__(self):
        val = self.val
        if self.type == SliceVarType.TGT:
            val = regs[(val - cpuStateAddr)/4]
            
        return "{}_{}".format(self.type.name, val)
    
class TraceEntry():
    def __init__(self):
        self.inst = None
        self.ple = None 
        self.bb_num = -1
        self.inst_index = -1

    def __repr__(self):
        # return "TraceEntry:[ inst: {}\n\tple: {}]".format(str(self.inst), str(self.ple))
        return "TraceEntry:[ inst_index: {}]".format(self.inst_index)
    
    
parser = argparse.ArgumentParser(description='Dynamic slicer')

def infer_offset(reg_str):
    return regs.index(reg_str.upper())

def VarFromCriteria(crit):
    sliceVarType = None
    if crit.startswith("TGT"):
        sliceval = cpuStateAddr + infer_offset(crit[4:])*4
        sliceval = SliceVal(SliceVarType.TGT, sliceval)
        return sliceval

def parse_criteria(fname):
    f = open(fname, "r").readlines()
    vmas = f[0][4:].strip().split(",")
    
    
    for line in f[1:]:
        addrs = line.split("rr:")[1].strip()
        target = line.split(" at ")[0]

        start_rr_instr_count, end_rr_instr_count = int(addrs.split("-")[0]), int(addrs.split("-")[1])

        target = VarFromCriteria(target)
        print target
        worklist.add(target)
        return vmas, start_rr_instr_count, end_rr_instr_count    

def getBlockIndex(func, blockname):
    # print "blockname", blockname
    # basic_block_names = [bb.name for bb in func.basic_blocks]
    # print "basic_block_names", basic_block_names
    # return basic_block_names.index(blockname)
    return 0

# @profile
def align_function(aligned_block, llvm_func, ple_vec, cursor_idx):
    
    entryblock = llvm_func.get_entry_basic_block()
    nextblock = entryblock
    
    has_successor = True
    # print "ple_vec", ple_vec
    
    while has_successor:
        has_successor = False
        inst_index = 0 
        bb_num = getBlockIndex(llvm_func, nextblock)
        
        for inst in nextblock.instructions:
            t = TraceEntry()
            t.bb_num = bb_num
            t.inst_index = inst_index
            inst_index += 1
            
            # Print target asm 
            md = inst.get_metadata("targetAsm")
            if md is not None:
                targetAsm = md.getOperand(0).getName().decode("hex")
                # disasm(targetAsm)
            
            #TODO: Check if in exception 
            
            # May not need this
            if cursor_idx >= len(ple_vec):
                ple = None
            else: 
                ple = ple_vec[cursor_idx]

            # print "aligned_block", aligned_block
            # print "inst", inst
            # print "cursor_idx", cursor_idx
            
            op_name = inst.opcode_name
            if op_name == "load":
                assert(ple and ple.llvmEntry.type == FunctionCode.FUNC_CODE_INST_LOAD)
                t.ple = ple 
                t.inst = inst 
            
                cursor_idx += 1
                aligned_block.append(t)
                
            elif op_name == "store":
                # print ple
                # Check if store is volatile
                if inst.is_volatile:
                    # cursor_idx += 1
                    continue
                
                assert(ple and ple.llvmEntry.type == FunctionCode.FUNC_CODE_INST_STORE)
                t.ple = ple
                t.inst = inst 
            
                cursor_idx += 1
                aligned_block.append(t)
                
            elif op_name == "br":
                assert(ple and ple.llvmEntry.type == FunctionCode.FUNC_CODE_INST_BR)
                t.inst = inst

                # Get next branch 
                has_successor = True 
                # If operands == 1, this is an unconditional branch
                # print "branch operands", inst.operands
                if len(inst.operands) == 1:
                    nextblock = inst.operands[0]
                    # print "nextblock", nextblock
                else:
                    # Check condition 
                    # if condition is true, go to first bb operand, else go to 2nd
                    nextblock = inst.operands[2] if ple.llvmEntry.condition else inst.operands[1]
                
                aligned_block.append(t)
                
                # check next logentry is a BB 
                assert(ple_vec[cursor_idx+1].llvmEntry.type == FunctionCode.BB)
                cursor_idx += 2
            
            elif op_name == "switch":
                assert(ple and ple.llvmEntry.type == FunctionCode.FUNC_CODE_INST_SWITCH)
                
                t.inst = inst
                
                aligned_block.append(t)
                
                has_successor = True 
                # Set next block
                operands = inst.operands
                default = inst.operands[1]
                cond = ple.llvmEntry.condition
                # print "cond", cond

                for i in range((len(inst.operands)-2)/2):
                    switch_case_cond = inst.operands[2+i*2].extract_element(Constant.int(Type.int(), 0)).extract_element(Constant.int(Type.int(), 0)).z_ext_value
                    
                    if cond == switch_case_cond:
                        nextblock = inst.operands[3+i*2]
                        # print "nextblock", nextblock
                        break
                
                # check next logentry is a BB 
                assert(ple_vec[cursor_idx+1].llvmEntry.type == FunctionCode.BB)
                cursor_idx += 2

            elif op_name == "phi":
                # We don't actually have a dynamic log entry here, but for
                # convenience we do want to know which basic block we just
                # came from. So we peek at the previous non-PHI thing in
                # our trace, which should be the predecessor basic block
                # to this PHI
                
                new_t = plog_pb2.LogEntry()
                
                incoming_blocks = [inst.get_incoming_block(i).name for i in range(inst.incoming_count)]
                for idx in reversed(range(len(aligned_block))):
                    te = aligned_block[idx]
                    if te.inst.opcode_name != 'phi':
                        # print "phi basic block", te.inst.basic_block.name
                        new_t.llvmEntry.phi_index = incoming_blocks.index(te.inst.basic_block.name)
                        # print "phi index", new_t.llvmEntry.phi_index
                        break
                
                t.ple = new_t
                t.inst = inst
                aligned_block.append(t)
            
            elif op_name == "select":
                assert(ple and ple.llvmEntry.type == FunctionCode.FUNC_CODE_INST_SELECT)
                t.ple = ple
                t.inst = inst
                
                aligned_block.append(t)
                cursor_idx += 1
            
            elif op_name == "ret":
                # print ple
                assert(ple and ple.llvmEntry.type == FunctionCode.FUNC_CODE_INST_RET)

                cursor_idx += 1
            
            elif op_name == "call":
                called_func = inst.called_function
                called_func_name = called_func.name

                if called_func_name.startswith("record"):
                    continue
                elif re.match("helper_[lb]e_ld.*_mmu_panda", called_func_name): 
                    assert(ple and ple.llvmEntry.type == FunctionCode.FUNC_CODE_INST_LOAD)
                    t.ple = ple 
                    t.inst = inst 
                    aligned_block.append(t)
                    cursor_idx += 1

                elif re.match("helper_[lb]e_st.*_mmu_panda", called_func_name):
                    assert(ple and ple.llvmEntry.type == FunctionCode.FUNC_CODE_INST_STORE)
                    t.ple = ple 
                    t.inst = inst 
                    aligned_block.append(t)
                    cursor_idx += 1

                elif called_func_name.startswith("llvm.memset"):
                    assert(ple and ple.llvmEntry.type == FunctionCode.FUNC_CODE_INST_STORE)
                    t.ple = ple 
                    t.inst = inst 
                    aligned_block.append(t)
                    cursor_idx += 1

                elif called_func_name.startswith("llvm.memcpy"):
                    assert(ple and ple.llvmEntry.type == FunctionCode.FUNC_CODE_INST_LOAD)
                    storePle = ple_vec[cursor_idx+1]
                    assert(storePle.llvmEntry.type == FunctionCode.FUNC_CODE_INST_STORE)
                    
                    t.ple = ple 
                    t.ple2 = storePle
                    t.inst = inst 
                    aligned_block.append(t)
                    cursor_idx += 2

                elif called_func.is_declaration or called_func.intrinsic_id:
                    t.inst = inst
                    t.ple = plog_pb2.LogEntry()
                    aligned_block.append(t)

                else:
                    # descend into function 
                    assert(ple and ple.llvmEntry.type == FunctionCode.BB)
                    
                    print "descending into function {}, cursor_idx {}".format(called_func_name, cursor_idx+1)
                    # print ple_vec[cursor_idx+1:]

                    cursor_idx = align_function(aligned_block, called_func, ple_vec, cursor_idx+1)

                    print "returned from descend, cursor_idx", cursor_idx
                    
                    callPle = ple_vec[cursor_idx]
                    assert(callPle and callPle.llvmEntry.type == FunctionCode.FUNC_CODE_INST_CALL)
                    
                    t.ple = callPle
                    t.inst = inst
                    aligned_block.append(t)
                    cursor_idx += 1                    
            else:
                # default 
                t.inst = inst 
                aligned_block.append(t)
                
    return cursor_idx

# def slice_trace():
    

def main():
    mod = Module.from_bitcode(file("llvm-mod.bc"))

    cpuStateAddr = mod.get_global_variable_named("CPUStateAddr").initializer.z_ext_value
    
    # open criteria file 
    vmas, start_rr_instr_count, end_rr_instr_count = parse_criteria("criteria")
    
    # POpulate TB map 
    tb_addr_map = {}
    for func in mod.functions:
        if func.name.startswith("tcg-llvm-tb"):
            split = func.name.split("-")
            addr = int(split[4], 16)
            tb_num = int(split[3])
            tb_addr_map[addr] = tb_num 
    
    # Seek to end of log
    # Seek to end of file and begin reading data there 
    log = PandaLog("extlib_reduced_log", "BWD")
    log.seek(-1)
    
    ple_vec = []
    aligned_block = []
    print start_rr_instr_count, end_rr_instr_count
    while True:        
        ple = log.read_entry()
        
        if ple is None:
            break
            
        # Check if in range of instrs

        if ple.instr > end_rr_instr_count or ple.instr < start_rr_instr_count:
            continue
        
        ple_vec.append(ple)
        
        if ple.llvmEntry.type == FunctionCode.LLVM_FN:
            cursor_idx = 0
            
            if ple.llvmEntry.tb_num == 0:
                # we reached beginning of log
                break
            
            funcname = "tcg-llvm-tb-{}-{:02x}".format(ple.llvmEntry.tb_num, ple.pc)
            llvm_func = mod.get_function_named(funcname)
            assert(llvm_func != None)
            
            if ple_vec[0].llvmEntry.type != FunctionCode.FUNC_CODE_INST_RET:
                print "WARNING: BB CUT SHORT BY EXCEPTION!"
                ple_vec = []
                aligned_block = []
                continue
            
            # Check flag for interrupt, exception
            if ple.llvmEntry.flags & 1:
                ple_vec = []
                aligned_block = []
                continue
            
            # Check if vma in list of vmas of interest
            if ple.llvmEntry.vma_name not in vmas:
                ple_vec = []
                aligned_block = []
                continue
            
            ple_vec = ple_vec[::-1]
            print "***************** {} ***************".format(funcname)
            
            assert(ple_vec[0].llvmEntry.type == FunctionCode.LLVM_FN and ple_vec[1].llvmEntry.type == FunctionCode.BB)
            
            # delete first two logentries
            del ple_vec[:2]
            # if ple.pc == 0xb7edd81d:
            cursor_idx = align_function(aligned_block, llvm_func, ple_vec, cursor_idx)
            print "cursor_idx", cursor_idx
#             slice_trace(aligned_block)
            
            ple_vec = []
            aligned_block = []

main()