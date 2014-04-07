/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

#ifndef PANDA_DYNVAL_INST_H
#define PANDA_DYNVAL_INST_H

#include "llvm/IR/LLVMContext.h"
#include "llvm/Pass.h"
#include "llvm/InstVisitor.h"
#include "llvm/IR/IRBuilder.h"
#include "panda_memlog.h"

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
    void visitMemSetInst(MemSetInst &I);
    void visitMemCpyInst(MemCpyInst &I);
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

