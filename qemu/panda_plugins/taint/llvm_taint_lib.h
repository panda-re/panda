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
#include "taint_processor.h"
#include "panda_stats.h"
#include "panda_memlog.h"

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

class PandaTaintFunctionPass;

/* PandaTaintVisitor class
 * This class implements our taint propagation policies for each LLVM
 * instruction.  Generally, it emits taint operations into the taint buffer to
 * be cached, and eventually processed by the taint processor.
 */
class PandaTaintVisitor : public InstVisitor<PandaTaintVisitor> {
    PandaTaintFunctionPass *PTFP; // PTFP that this visitor is a member of
    TaintOpBuffer *tbuf; // global tbuf from PandaTaintFunctionPass
public:
    PandaSlotTracker *PST;

    PandaTaintVisitor() : PST(NULL) {}

    PandaTaintVisitor(PandaTaintFunctionPass *PTFP);

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
    void simpleDeleteTaintAtDest(int llvmReg);
    void simpleTaintCopy(int source, int dest, int bytes);
    void simpleTaintCompute(int source0, AddrType source0ty, int source1,
        AddrType source1ty, int dest, int bytes);
    void intPtrHelper(Instruction &I, int sourcesize, int destsize);
    void addSubHelper(Value *arg0, Value *arg1, Value *dst);
    void mulHelper(BinaryOperator &I);
    void shiftHelper(BinaryOperator &I);
    void approxArithHelper(Value *op0, Value *op1, Value *dest);
    void simpleArithHelper(BinaryOperator &I);
    void bswapHelper(CallInst &I);
    void memcpyHelper(CallInst &I);
    void memsetHelper(CallInst &I);
    void ctlzHelper(CallInst &I);
    void loadHelper(Value *src, Value *dst, int len, int is_mmu);
    void storeHelper(Value *src, Value *dst, int len, int is_mmu);
    void portLoadHelper(Value *src, Value *dst, int len);
    void portStoreHelper(Value *src, Value *dst, int len);
    void floatHelper(CallInst &I);
};

/* PandaTaintFunctionPass class
 * This is our implementation of a function pass, inheriting from the generic
 * LLVM FunctionPass.  This expects a taint op buffer to be filled, and
 * eventually cached and processed.  The PandaTaintVisitor actually does the
 * taint op calculations and population of taint op buffers.
 */
class PandaTaintFunctionPass : public FunctionPass {
    size_t tbuf_size; // global tbuf size
    TaintOpBuffer *tbuf; // global tbuf
    // taint cache for generated code and helper functions
    std::map<std::string, TaintTB*> *ttbCache;
    bool createdTtbCache;
public:
    static char ID;
    PandaTaintVisitor *PTV; // Our LLVM instruction visitor
    TaintTB *ttb; // Taint translation block to be processed; either fetched
                  // from the cache, or generated

    PandaTaintFunctionPass() : FunctionPass(ID),
        PTV(new PandaTaintVisitor()) {}

    PandaTaintFunctionPass(size_t tob_size,
            std::map<std::string, TaintTB*> *existingTtbCache) :
        FunctionPass(ID), tbuf_size(tob_size), tbuf(tob_new(tbuf_size)),
        createdTtbCache(false), PTV(new PandaTaintVisitor(this)){

        /*
         * We either create the ttbCache, or simply populate the one that was
         * passed in.
         */
        if (existingTtbCache == NULL){
            ttbCache = new std::map<std::string, TaintTB*>();
            createdTtbCache = true;
        }
        else {
            ttbCache = existingTtbCache;
        }
    }

    ~PandaTaintFunctionPass() {
        // If we created this ttbCache, we delete it
        if (createdTtbCache){
            std::map<std::string, TaintTB*>::iterator it;
            for (it = ttbCache->begin(); it != ttbCache->end(); it++){
                taint_tb_cleanup(it->second);
                ttbCache->erase(it);
            }
            delete ttbCache;
        }
        delete PTV;
        tob_delete(tbuf);
        cleanup_taint_stats();
    }

    TaintOpBuffer *getTaintOpBuffer();

    std::map<std::string, TaintTB*> *getTaintTBCache();

    // runOnFunction - Our custom function pass implementation
    bool runOnFunction(Function &F);

    // debug print all taint ops for a function
    void debugTaintOps();

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesAll();
    }

    // Functions for reading/writing persistent taint cache for use with helper
    // functions
    //void readTaintCache();
    //void writeTaintCache();
};

FunctionPass *createPandaTaintFunctionPass(size_t tob_size,
    std::map<std::string, TaintTB*> *existingTtbCache);

} // End llvm namespace

#endif

