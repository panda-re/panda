
/* PANDABEGINCOMMENT
 *
 * Header file for llvm trace. 
 * 
 *
PANDAENDCOMMENT */

#ifndef __LLVM_TRACE2_H__
#define __LLVM_TRACE2_H__

#include <llvm/InstVisitor.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Pass.h>

extern "C" {

#include "panda/plog.h"
bool init_plugin(void *self);
void uninit_plugin(void *self);
}


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
	BB = 43
} FunctionCode;

namespace llvm {

class PandaLLVMTraceVisitor: public InstVisitor<PandaLLVMTraceVisitor>{

public:
	// Default constructor
	PandaLLVMTraceVisitor(){};

	PandaLLVMTraceVisitor(Module *M):
		module(M){};
				
	//Default Destructor	
    ~PandaLLVMTraceVisitor() {};

    Function *log_dynvalF;
    Function *recordBBF;
	Function *recordStartBBF;
    Function *recordStoreF;
    Function *recordLoadF;
    Function *recordCallF;
    Function *recordReturnF;
	Module *module;

      // Overrides.
    void visitLoadInst(LoadInst &I);
    void visitStoreInst(StoreInst &I);
    void visitInstruction(Instruction &I);
    //void visitFunction(Function& F);
    //void visitBasicBlock(BasicBlock &BB);

    //void visitInvokeInst(InvokeInst &I);
    //void visitUnreachableInst(UnreachableInst &I);
    //void visitAllocaInst(AllocaInst &I);
    //void visitGetElementPtrInst(GetElementPtrInst &I);
	void visitCallInst(CallInst &I);
    //void visitSelectInst(SelectInst &I);
    //void visitExtractValueInst(ExtractValueInst &I);
    //void visitInsertValueInst(InsertValueInst &I);
    //void visitInsertElementInst(InsertElementInst &I);
    //void visitShuffleVectorInst(ShuffleVectorInst &I);

    //void visitReturnInst(ReturnInst &I);
    //void visitBinaryOperator(BinaryOperator &I);
    //void visitPHINode(PHINode &I);

    //void visitBranchInst(BranchInst &I);
    //void visitIndirectBrInst(IndirectBrInst &I);
    //void visitSwitchInst(SwitchInst &I);
    //void visitTerminatorInst(TerminatorInst &I);
    //void visitCastInst(CastInst &I);
    //void visitCmpInst(CmpInst &I);
    //void visitMemCpyInst(MemTransferInst &I);
    //void visitMemMoveInst(MemTransferInst &I);
    //void visitMemSetInst(MemSetInst &I);
};


class PandaLLVMTracePass: public BasicBlockPass {
public:
	static char ID;
	PandaLLVMTraceVisitor *PLTV;	

	PandaLLVMTracePass(): BasicBlockPass(ID), PLTV(new PandaLLVMTraceVisitor()){}

	PandaLLVMTracePass(Module *M) : 
		BasicBlockPass(ID), PLTV(new PandaLLVMTraceVisitor(M)){}

    ~PandaLLVMTracePass() {};

	bool runOnBasicBlock(BasicBlock &F);

	/*bool doInitialization(Module &module);*/
	//bool doInitialization(Function &module);
  virtual bool doInitialization(Module &M);
 virtual bool doFinalization(Module &M) { return false; }
 virtual bool doInitialization(Function &F) { return false; }
	virtual bool doFinalization(Function &F) { return false; }
};


} //namespace llvm    

#endif
