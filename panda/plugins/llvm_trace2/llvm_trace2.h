
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
#include "functionCode.h"

extern "C" {

#include "panda/plog.h"
#include "panda/plugin.h"
bool init_plugin(void *self);
void uninit_plugin(void *self);
int before_block_exec(CPUState *env, TranslationBlock *tb);
}

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
    Function *recordSelectF;
    Function *recordBranchF;
    Function *recordSwitchF;
    Function *recordPhiF;
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
	void visitSelectInst(SelectInst &I);
    //void visitExtractValueInst(ExtractValueInst &I);
    //void visitInsertValueInst(InsertValueInst &I);
    //void visitInsertElementInst(InsertElementInst &I);
    //void visitShuffleVectorInst(ShuffleVectorInst &I);

    //void visitReturnInst(ReturnInst &I);
    //void visitBinaryOperator(BinaryOperator &I);
	//void visitPHINode(PHINode &I);

	//void visitBranchInst(BranchInst &I);
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
