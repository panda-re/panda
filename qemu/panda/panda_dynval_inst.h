#ifndef PANDA_DYNVAL_INST_H
#define PANDA_DYNVAL_INST_H

#include "llvm/LLVMContext.h"
#include "llvm/Pass.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/IRBuilder.h"

extern "C" {
#include "panda_memlog.h"
}

namespace llvm {

/* PandaInstrumentVisitor class
 * This class takes care of instrumenting instructions we are interested in for
 * logging dynamic values.
 */
class PandaInstrumentVisitor : public InstVisitor<PandaInstrumentVisitor> {
    IRBuilder<> IRB;
    Module *mod;
    IntegerType *wordType;
    IntegerType *intType;
    IntegerType *ptrType;
    DynValBuffer *dynval_buffer;
public:
    PandaInstrumentVisitor() : IRB(getGlobalContext()) {}

    PandaInstrumentVisitor(Module *M) :
        IRB(getGlobalContext()),
        mod(M),
        wordType(IntegerType::get(getGlobalContext(), sizeof(size_t)*8)),
        intType(IntegerType::get(getGlobalContext(), sizeof(int)*8)),
        ptrType(IntegerType::get(getGlobalContext(), sizeof(uintptr_t)*8)),
        dynval_buffer(create_dynval_buffer(1048576)) // Default 1MB
        {}

    ~PandaInstrumentVisitor();

    DynValBuffer *getDynvalBuffer();

    void visitLoadInst(LoadInst &I);
    void visitStoreInst(StoreInst &I);
    void visitBranchInst(BranchInst &I);
    void visitSelectInst(SelectInst &I);
    void visitCallInst(CallInst &I);
    void visitSwitchInst(SwitchInst &I);
};

/* PandaInstrFunctionPass
 * This class is our function pass that instruments code to insert calls to
 * logging functions so we can log dynamic values.
 */
class PandaInstrFunctionPass : public FunctionPass {

public:
    static char ID;
    PandaInstrumentVisitor *PIV;

    PandaInstrFunctionPass() : FunctionPass(ID),
        PIV(new PandaInstrumentVisitor()) {}

    PandaInstrFunctionPass(Module *M) :
        FunctionPass(ID), PIV(new PandaInstrumentVisitor(M)) {}

    ~PandaInstrFunctionPass();

    // runOnFunction - Our custom function pass implementation
    bool runOnFunction(Function &F);

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesCFG();
    }
};

FunctionPass *createPandaInstrFunctionPass(Module *M);

} // End LLVM namespace

#endif

