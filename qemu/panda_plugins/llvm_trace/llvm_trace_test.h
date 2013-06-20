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

#ifndef LLVM_TRACE_TEST_H
#define LLVM_TRACE_TEST_H

#include "llvm/IR/BasicBlock.h"
#include "llvm/Pass.h"
#include "llvm/InstVisitor.h"

using namespace llvm;

class TestFunctionPass;

/* TestInstVisitor class
 * This class visits instructions for the TestFunctionPass.
 */
class TestInstVisitor : public InstVisitor<TestInstVisitor> {
    //BasicBlock *next_bb; // Taken branch for BB that needs to be processed next
    TestFunctionPass *TFP;
public:
    //TestInstVisitor() : next_bb(0)*/ {}
    TestInstVisitor(TestFunctionPass *FP) : TFP(FP) {}
    ~TestInstVisitor(){}

    void visitLoadInst(LoadInst &I);
    void visitStoreInst(StoreInst &I);
    void visitBranchInst(BranchInst &I);
    void visitReturnInst(ReturnInst &I);
    void visitUnreachable(UnreachableInst &I);
    void visitSelectInst(SelectInst &I);
    void visitCallInst(CallInst &I);
    void visitSwitchInst(SwitchInst &I);
};

/* TestFunctionPass
 * This class is a test function pass responsible for analyzing an LLVM trace to
 * make sure the dynamic log lines up.
 */
class TestFunctionPass : public FunctionPass {
    TestInstVisitor *TIV;
    BasicBlock *next_bb; // Taken branch for BB that needs to be processed next
    bool retFlag;        // Return flag
public:
    static char ID;

    TestFunctionPass() : FunctionPass(ID), TIV(new TestInstVisitor(this)) {}
    
    ~TestFunctionPass(){
        delete TIV;
    }

    void setNextBB(BasicBlock *bb);
    BasicBlock *getNextBB();
    void setRetFlag(bool flag);
    bool getRetFlag();

    bool runOnFunction(Function &F);

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesAll();
    }
};

#endif

