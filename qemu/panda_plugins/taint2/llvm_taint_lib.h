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

#ifndef LLVM_TAINT_LIB_H
#define LLVM_TAINT_LIB_H

#include "stdio.h"
#include <map>
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Pass.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/InstVisitor.h"
#include "llvm/IR/IRBuilder.h"
#include "taint_ops.h"
#include "panda_memlog.h"

typedef struct shad_struct Shad;

namespace llvm {

/* PandaSlotTracker class
 * This is modeled after SlotTracker in lib/VMCore/AsmWriter.cpp which keeps
 * track of unnamed instructions, allowing them to be printed out like %2 = ...
 * We need a similar mechanism to keep track of unnamed instructions so we can
 * propagate taint between temporaries within LLVM functions.
 */
class PandaSlotTracker {
public:
    /// ValueMap - A mapping of Values to slot numbers.
    typedef DenseMap<const Value*, unsigned> ValueMap;

private:
    Function* TheFunction;
    bool FunctionProcessed;
    ValueMap fMap;
    unsigned fNext;
    void CreateFunctionSlot(const Value *V);
    //void CreateMetadataSlot(const MDNode *N);
    void processFunction();

public:
    PandaSlotTracker(Function *F) : TheFunction(F),
        FunctionProcessed(false), fNext(0) {}
    int getLocalSlot(const Value *V);
    void initialize();
};

PandaSlotTracker *createPandaSlotTracker(Function *F);

/* PandaTaintVisitor class
 * This class implements our taint propagation policies for each LLVM
 * instruction.  Generally, it emits taint operations into the taint buffer to
 * be cached, and eventually processed by the taint processor.
 */
class PandaTaintVisitor : public InstVisitor<PandaTaintVisitor> {
private:
    PandaSlotTracker *PST;
    Shad *shad; // no ownership. weak ptr.
    taint2_memlog *memlog; // same.

public:
    DataLayout *dataLayout = NULL;

    Function *deleteF;
    Function *mixF;
    Function *mixCompF;
    Function *parallelCompF;
    Function *copyF;
    Function *sextF;
    Function *selectF;
    Function *pushFrameF;
    Function *popFrameF;

    Constant *memlogConst;
    Function *memlogPopF;

    Constant *llvConst;
    Constant *memConst;
    Constant *grvConst;
    Constant *gsvConst;
    Constant *retConst;

    Constant *prevBbConst;

    PandaTaintVisitor(Shad *shad, taint2_memlog *memlog)
        : PST(NULL), shad(shad), memlog(memlog) {}

    ~PandaTaintVisitor() {}

    // Define most visitor functions
    #define HANDLE_INST(N, OPCODE, CLASS) void visit##OPCODE##Inst(CLASS&);
    #include "llvm/IR/Instruction.def"

    // We missed some...
    void visitReturnInst(ReturnInst &I);
    void visitBranchInst(BranchInst &I);
    void visitBinaryOperator(BinaryOperator &I);
    void visitPHINode(PHINode &I);
    void visitInstruction(Instruction &I);

    // Helpers
    int getValueSize(Value *V);
};

/* PandaTaintFunctionPass class
 * This is our implementation of a function pass, inheriting from the generic
 * LLVM FunctionPass.  This expects a taint op buffer to be filled, and
 * eventually cached and processed.  The PandaTaintVisitor actually does the
 * taint op calculations and population of taint op buffers.
 */
class PandaTaintFunctionPass : public FunctionPass {
public:
    static char ID;
    PandaTaintVisitor PTV; // Our LLVM instruction visitor

    PandaTaintFunctionPass(Shad *shad, taint2_memlog *memlog)
        : FunctionPass(ID), PTV(shad, memlog) {}

    ~PandaTaintFunctionPass() { }

    bool doInitialization(Module &M);

    // runOnFunction - Our custom function pass implementation
    bool runOnFunction(Function &F);

    // debug print all taint ops for a function
    void debugTaintOps();

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesAll();
    }
};

FunctionPass *createPandaTaintFunctionPass();

} // End llvm namespace

#endif

