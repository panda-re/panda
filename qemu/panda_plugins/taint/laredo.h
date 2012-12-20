
#ifndef LLVM_LAREDOPASS_H
#define LLVM_LAREDOPASS_H

#include "llvm/DerivedTypes.h"
#include "llvm/Function.h"
#include "llvm/Intrinsics.h"
#include "llvm/LLVMContext.h"
#include "llvm/Pass.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Assembly/Writer.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

#include <stdio.h>

extern "C" {
#include "taint_processor.h"
#include "laredo_instrumentation.h"
#include "panda_memlog.h"
}

namespace llvm {

/* LaredoSlotTracker class
 * This is modeled after SlotTracker in lib/VMCore/AsmWriter.cpp which keeps
 * track of unnamed instructions, allowing them to be printed out like %2 = ...
 * We need a similar mechanism to keep track of unnamed instructions so we can
 * propagate taint between temporaries within LLVM functions.
 */
class LaredoSlotTracker {
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
    LaredoSlotTracker(Function *F) : TheFunction(F),
        FunctionProcessed(false), fNext(0) {}
    int getLocalSlot(const Value *V);
    void initialize();
};

LaredoSlotTracker *createLaredoSlotTracker(Function *F);

/* LaredoTaintVisitor class
 * This class implements our taint propagation policies for each LLVM
 * instruction.  Generally, it emits taint operations into the taint buffer to
 * be cached, and eventually processed by the taint processor.
 */
class LaredoTaintVisitor : public InstVisitor<LaredoTaintVisitor> {
    Shad *shad;
    FILE *dlog; // file containing dynamic values
    TaintOpBuffer *tbuf; // global tbuf
    // taint cache for generated code and helper functions
    std::map<std::string, TaintTB*> *ttbCache;
public:
    LaredoSlotTracker *LST;

    LaredoTaintVisitor() : LST(NULL) {}
    LaredoTaintVisitor(Shad *shadmem, FILE *log, TaintOpBuffer *taintbuf,
            std::map<std::string, TaintTB*> *ttbc) :
        shad(shadmem), dlog(log), tbuf(taintbuf), ttbCache(ttbc), LST(NULL) {}

    inline ~LaredoTaintVisitor() {}

    // Define most visitor functions
    #define HANDLE_INST(N, OPCODE, CLASS) void visit##OPCODE##Inst(CLASS&);
    #include "llvm/Instruction.def"
    
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
    void approxArithHelper(BinaryOperator &I);
    void simpleArithHelper(BinaryOperator &I);
    void bswapHelper(CallInst &I);
    void loadHelper(Value *src, Value *dst, int len);
    void storeHelper(Value *src, Value *dst, int len);
};

/* LaredoTaintFunctionPass class
 * This is our implementation of a function pass, inheriting from the generic
 * LLVM FunctionPass.  This expects a taint op buffer to be filled, and
 * eventually cached and processed.  The LaredoTaintVisitor actually does the
 * taint op calculations and population of taint op buffers.
 */
class LaredoTaintFunctionPass : public FunctionPass {
    TaintOpBuffer *tbuf; // global tbuf
    // taint cache for generated code and helper functions
    std::map<std::string, TaintTB*> *ttbCache;
    FILE *taintCache; // persistent taint cache file for helpers
public:
    static char ID;
    LaredoTaintVisitor *LTV;
    FILE *dlog; // file containing dynamic values
    Shad *shad; // global shad
    TaintTB *ttb; // global ttb

    LaredoTaintFunctionPass() : FunctionPass(ID),
        LTV(new LaredoTaintVisitor()) {}

    LaredoTaintFunctionPass(FILE *log, Shad *shadmem,
            TaintOpBuffer *taintbuf, TaintTB *tainttb, FILE *tc) :
        FunctionPass(ID), tbuf(taintbuf),
        ttbCache(new std::map<std::string, TaintTB*>()), taintCache(tc),
        LTV(new LaredoTaintVisitor(shadmem, log, tbuf, ttbCache)), dlog(log), 
        shad(shadmem), ttb(tainttb) {}

    inline ~LaredoTaintFunctionPass() {
        std::map<std::string, TaintTB*>::iterator it;
        for (it = ttbCache->begin(); it != ttbCache->end(); it++){
            taint_tb_cleanup(it->second);
            ttbCache->erase(it);
        }
        if (dlog){
            fclose(dlog);
        }
        delete ttbCache;
        delete LTV;
        cleanup_taint_stats();
    }

    // runOnFunction - Our custom function pass implementation
    bool runOnFunction(Function &F);

    // debug print all taint ops for a function
    void debugTaintOps();

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesAll();
    }
    
    // Functions for reading/writing persistent taint cache for use with helper
    // functions
    void readTaintCache();
    void writeTaintCache();
};

FunctionPass *createLaredoTaintFunctionPass(FILE *log, Shad *shad,
                                        TaintOpBuffer *tbuf, TaintTB *ttb,
                                        FILE *tc);


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
public:
    LaredoInstrumentVisitor() : IRB(getGlobalContext()) {}
    
    LaredoInstrumentVisitor(Module *M) : IRB(getGlobalContext()), mod(M),
        wordType(IntegerType::get(getGlobalContext(), sizeof(size_t)*8)),
        intType(IntegerType::get(getGlobalContext(), sizeof(int)*8)),
        ptrType(IntegerType::get(getGlobalContext(), sizeof(uintptr_t)*8)) {}

    inline ~LaredoInstrumentVisitor() {
    }

    void visitLoadInst(LoadInst &I);
    void visitStoreInst(StoreInst &I);
    void visitBranchInst(BranchInst &I);
    void visitSelectInst(SelectInst &I);
    void visitCallInst(CallInst &I);
};

/* Laredo InstrFunctionPass
 * This class is our function pass that instruments code to insert calls to
 * logging functions so we can log dynamic values, specifically for QEMU helper
 * functions.
 */
class LaredoInstrFunctionPass : public FunctionPass {

public:
    static char ID;
    LaredoInstrumentVisitor *LIV;

    LaredoInstrFunctionPass() : FunctionPass(ID),
        LIV(new LaredoInstrumentVisitor()) {}

    LaredoInstrFunctionPass(Module *M) : FunctionPass(ID),
        LIV(new LaredoInstrumentVisitor(M)) {}

    inline ~LaredoInstrFunctionPass() {
        delete LIV;
    }

    // runOnFunction - Our custom function pass implementation
    bool runOnFunction(Function &F);

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesCFG();
    }
};

FunctionPass *createLaredoInstrFunctionPass(Module *M);

} // End llvm namespace

#endif

