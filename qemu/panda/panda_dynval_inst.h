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

/* LaredoInstrumentVisitor class
 * This class takes care of instrumenting instructions we are interested in for
 * logging dynamic values.
 */
class LaredoInstrumentVisitor : public InstVisitor<LaredoInstrumentVisitor> {
    IRBuilder<> IRB;
    Module *mod;
    IntegerType *wordType;
    IntegerType *intType;
    IntegerType *ptrType;
    DynValBuffer *dynval_buffer;
public:
    LaredoInstrumentVisitor() : IRB(getGlobalContext()) {}

    LaredoInstrumentVisitor(Module *M) :
        IRB(getGlobalContext()),
        mod(M),
        wordType(IntegerType::get(getGlobalContext(), sizeof(size_t)*8)),
        intType(IntegerType::get(getGlobalContext(), sizeof(int)*8)),
        ptrType(IntegerType::get(getGlobalContext(), sizeof(uintptr_t)*8)),
        dynval_buffer(create_dynval_buffer(1048576)) // Default 1MB
        {}

    ~LaredoInstrumentVisitor();

    DynValBuffer *getDynvalBuffer();

    void visitLoadInst(LoadInst &I);
    void visitStoreInst(StoreInst &I);
    void visitBranchInst(BranchInst &I);
    void visitSelectInst(SelectInst &I);
    void visitCallInst(CallInst &I);
};

/* LaredoInstrFunctionPass
 * This class is our function pass that instruments code to insert calls to
 * logging functions so we can log dynamic values.
 */
class LaredoInstrFunctionPass : public FunctionPass {

public:
    static char ID;
    LaredoInstrumentVisitor *LIV;

    LaredoInstrFunctionPass() : FunctionPass(ID),
        LIV(new LaredoInstrumentVisitor()) {}

    LaredoInstrFunctionPass(Module *M) :
        FunctionPass(ID), LIV(new LaredoInstrumentVisitor(M)) {}

    ~LaredoInstrFunctionPass();

    // runOnFunction - Our custom function pass implementation
    bool runOnFunction(Function &F);

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesCFG();
    }
};

FunctionPass *createLaredoInstrFunctionPass(Module *M);

} // End LLVM namespace

#endif

