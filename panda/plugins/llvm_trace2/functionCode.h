#ifndef FUNCCODE_H
#define FUNCCODE_H

#include <set>
#include <string>
#include <map>

// The function body block (FUNCTION_BLOCK_ID) describes function bodies.  It
// can contain a constant block (CONSTANTS_BLOCK_ID).
typedef enum {
    FUNC_CODE_DECLAREBLOCKS    =  1, // DECLAREBLOCKS: [n]

    FUNC_CODE_INST_BINOP       =  2, // BINOP:      [opcode, ty, opval, opval]
    FUNC_CODE_INST_CAST        =  3, // CAST:       [opcode, ty, opty, opval]
    FUNC_CODE_INST_GEP         =  4, // GEP:        [n x operands]
    FUNC_CODE_INST_SELECT      =  5, // SELECT:     [ty, opval, opval, opval]
    FUNC_CODE_INST_EXTRACTELT  =  6, // EXTRACTELT: [opty, opval, opval]
    FUNC_CODE_INST_INSERTELT   =  7, // INSERTELT:  [ty, opval, opval, opval]
    FUNC_CODE_INST_SHUFFLEVEC  =  8, // SHUFFLEVEC: [ty, opval, opval, opval]
    FUNC_CODE_INST_CMP         =  9, // CMP:        [opty, opval, opval, pred]

    FUNC_CODE_INST_RET         = 10, // RET:        [opty,opval<both optional>]
    FUNC_CODE_INST_BR          = 11, // BR:         [bb#, bb#, cond] or [bb#]
    FUNC_CODE_INST_SWITCH      = 12, // SWITCH:     [opty, op0, op1, ...]
    FUNC_CODE_INST_INVOKE      = 13, // INVOKE:     [attr, fnty, op0,op1, ...]
    // 14 is unused.
    FUNC_CODE_INST_UNREACHABLE = 15, // UNREACHABLE

    FUNC_CODE_INST_PHI         = 16, // PHI:        [ty, val0,bb0, ...]
    // 17 is unused.
    // 18 is unused.
    FUNC_CODE_INST_ALLOCA      = 19, // ALLOCA:     [instty, op, align]
    FUNC_CODE_INST_LOAD        = 20, // LOAD:       [opty, op, align, vol]
    // 21 is unused.
    // 22 is unused.
    FUNC_CODE_INST_VAARG       = 23, // VAARG:      [valistty, valist, instty]
    // This store code encodes the pointer type, rather than the value type
    // this is so information only available in the pointer type (e.g. address
    // spaces) is retained.
    FUNC_CODE_INST_STORE       = 24, // STORE:      [ptrty,ptr,val, align, vol]
    // 25 is unused.
    FUNC_CODE_INST_EXTRACTVAL  = 26, // EXTRACTVAL: [n x operands]
    FUNC_CODE_INST_INSERTVAL   = 27, // INSERTVAL:  [n x operands]
    // fcmp/icmp returning Int1TY or vector of Int1Ty. Same as CMP, exists to
    // support legacy vicmp/vfcmp instructions.
    FUNC_CODE_INST_CMP2        = 28, // CMP2:       [opty, opval, opval, pred]
    // new select on i1 or [N x i1]
    FUNC_CODE_INST_VSELECT     = 29, // VSELECT:    [ty,opval,opval,predty,pred]
    FUNC_CODE_INST_INBOUNDS_GEP= 30, // INBOUNDS_GEP: [n x operands]
    FUNC_CODE_INST_INDIRECTBR  = 31, // INDIRECTBR: [opty, op0, op1, ...]
    // 32 is unused.
    FUNC_CODE_DEBUG_LOC_AGAIN  = 33, // DEBUG_LOC_AGAIN

    FUNC_CODE_INST_CALL        = 34, // CALL:       [attr, fnty, fnid, args...]

    FUNC_CODE_DEBUG_LOC        = 35, // DEBUG_LOC:  [Line,Col,ScopeVal, IAVal]
    FUNC_CODE_INST_FENCE       = 36, // FENCE: [ordering, synchscope]
    FUNC_CODE_INST_CMPXCHG     = 37, // CMPXCHG: [ptrty,ptr,cmp,new, align, vol,
                                     //           ordering, synchscope]
    FUNC_CODE_INST_ATOMICRMW   = 38, // ATOMICRMW: [ptrty,ptr,val, operation,
                                     //             align, vol,
                                     //             ordering, synchscope]
    FUNC_CODE_INST_RESUME      = 39, // RESUME:     [opval]
    FUNC_CODE_INST_LANDINGPAD  = 40, // LANDINGPAD: [ty,val,val,num,id0,val0...]
    FUNC_CODE_INST_LOADATOMIC  = 41, // LOAD: [opty, op, align, vol,
                                     //        ordering, synchscope]
    FUNC_CODE_INST_STOREATOMIC = 42,  // STORE: [ptrty,ptr,val, align, vol
                                 //         ordering, synchscope]
    BB = 43,
    LLVM_FN = 44,
    LLVM_EXCEPTION = 45
} FunctionCode;


enum SliceVarType {
    IGNORE = 0, // from some part of CPU state we don't care about?
    LLVM = 1, // LLVM value
    MEM = 2, // memory
    HOST = 3, // host
    TGT = 4, //guest register, or a field on CPU state 
	SPEC = 5, //special register, like floating point
	FRET = 6, //XXX: handle LLVM function return values?
};

// copied from helper_runtime.cpp
const static std::set<std::string> external_helper_funcs {
    "helper_le_ldq_mmu_panda", "helper_le_ldul_mmu_panda", "helper_le_lduw_mmu_panda",
    "helper_le_ldub_mmu_panda", "helper_le_ldsl_mmu_panda", "helper_le_ldsw_mmu_panda",
    "helper_le_ldsb_mmu_panda",
    "helper_le_stq_mmu_panda", "helper_le_stl_mmu_panda", "helper_le_stw_mmu_panda",
    "helper_le_stb_mmu_panda",
    "helper_be_ldq_mmu_panda", "helper_be_ldul_mmu_panda", "helper_be_lduw_mmu_panda",
    "helper_be_ldub_mmu_panda", "helper_be_ldsl_mmu_panda", "helper_be_ldsw_mmu_panda",
    "helper_be_ldsb_mmu_panda",
    "helper_be_stq_mmu_panda", "helper_be_stl_mmu_panda", "helper_be_stw_mmu_panda",
    "helper_be_stb_mmu_panda",
    "helper_ret_ldq_mmu_panda", "helper_ret_ldul_mmu_panda", "helper_ret_lduw_mmu_panda",
    "helper_ret_ldub_mmu_panda", "helper_ret_ldsl_mmu_panda", "helper_ret_ldsw_mmu_panda",
    "helper_ret_ldsb_mmu_panda",
    "helper_ret_stq_mmu_panda", "helper_ret_stl_mmu_panda", "helper_ret_stw_mmu_panda",
    "helper_ret_stb_mmu_panda",
    "helper_inb", "helper_inw", "helper_inl", "helper_inq",
    "helper_outb", "helper_outw", "helper_outl", "helper_outq", 
};

#endif