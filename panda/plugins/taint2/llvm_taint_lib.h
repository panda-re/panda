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

#include <map>
#include <cstdio>
#include <vector>
#include <set>

#include <llvm/ADT/DenseMap.h>
#include <llvm/InstVisitor.h>

typedef struct taint2_memlog taint2_memlog;
typedef struct shad_struct Shad;
typedef struct addr_struct Addr;

using std::vector;
using std::pair;

namespace llvm {

class Function;
class Value;
class Constant;
class DataLayout;

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
    unsigned getMaxSlot();
};

class ReturnInst;
class BranchInst;
class BinaryOperator;
class PHINode;
class Instruction;

/* PandaTaintVisitor class
 * This class implements our taint propagation policies for each LLVM
 * instruction.  Generally, it emits taint operations into the taint buffer to
 * be cached, and eventually processed by the taint processor.
 */
class PandaTaintVisitor : public InstVisitor<PandaTaintVisitor> {
private:
    std::unique_ptr<PandaSlotTracker> PST;
    Shad *shad; // no ownership. weak ptr.
    taint2_memlog *taint_memlog; // same.

    Constant *constSlot(LLVMContext &ctx, Value *value);
    Constant *constWeakSlot(LLVMContext &ctx, Value *value);
    Constant *constInstr(LLVMContext &ctx, Instruction *I);
    int intValue(Value *value);
    unsigned getValueSize(Value *V);
    bool getAddr(Value *addrVal, Addr& addrOut);
    bool isCPUStateAdd(BinaryOperator *AI);
    bool isIrrelevantAdd(BinaryOperator *AI);
    bool isEnvPtr(Value *loadVal);
    void inlineCall(CallInst *CI);
    void inlineCallAfter(Instruction &I, Function *F, vector<Value *> &args);
    void inlineCallBefore(Instruction &I, Function *F, vector<Value *> &args);
    CallInst *insertLogPop(Instruction &after);
    void insertTaintMove(Instruction &I,
            Constant *shad_dest, Value *dest, Constant *shad_src, Value *src,
            uint64_t size);
    void insertTaintCopy(Instruction &I,
            Constant *shad_dest, Value *dest, Constant *shad_src, Value *src,
            uint64_t size);
    void insertTaintBulk(Instruction &I,
            Constant *shad_dest, Value *dest, Constant *shad_src, Value *src,
            uint64_t size, Function *func);
    void insertTaintPointer(Instruction &I, Value *ptr, Value *val, bool is_store);
    void insertTaintMix(Instruction &I, Value *src);
    void insertTaintMix(Instruction &I, Value *dest, Value *src);
    void insertTaintCompute(Instruction &I,
            Value *src1, Value *src2, bool is_mixed);
    void insertTaintCompute(Instruction &I, Value *dest,
            Value *src1, Value *src2, bool is_mixed);
    void insertTaintSext(Instruction &I, Value *src);
    void insertTaintSelect(Instruction &after, Value *dest,
            Value *selector, vector<pair<Value *, Value *>> &selections);
    void insertTaintDelete(Instruction &I,
            Constant *shad, Value *dest, Value *size);
    void insertTaintBranch(Instruction &I, Value *cond);
    void insertStateOp(Instruction &I);

public:
    DataLayout *dataLayout = NULL;

    Function *deleteF;
    Function *mixF;
    Function *pointerF;
    Function *mixCompF;
    Function *parallelCompF;
    Function *copyF;
    Function *moveF;
    Function *setF;
    Function *sextF;
    Function *selectF;
    Function *hostCopyF;
    Function *hostMemcpyF;
    Function *hostDeleteF;

    Function *pushFrameF;
    Function *popFrameF;
    Function *resetFrameF;
    Function *breadcrumbF;
    Function *branchF;

    Constant *memlogConst;
    Function *memlogPopF;

    Constant *llvConst;
    Constant *memConst;
    Constant *grvConst;
    Constant *gsvConst;
    Constant *retConst;

    Constant *prevBbConst;

    Type *instrT;

    PandaTaintVisitor(Shad *shad, taint2_memlog *taint_memlog)
        : shad(shad), taint_memlog(taint_memlog) {}

    ~PandaTaintVisitor() {}

    // Overrides.
    void visitFunction(Function& F);
    void visitBasicBlock(BasicBlock &BB);

    void visitInvokeInst(InvokeInst &I);
    void visitUnreachableInst(UnreachableInst &I);
    void visitAllocaInst(AllocaInst &I);
    void visitLoadInst(LoadInst &I);
    void visitStoreInst(StoreInst &I);
    void visitGetElementPtrInst(GetElementPtrInst &I);
    void visitCallInst(CallInst &I);
    void visitSelectInst(SelectInst &I);
    void visitExtractValueInst(ExtractValueInst &I);
    void visitInsertValueInst(InsertValueInst &I);

    void visitReturnInst(ReturnInst &I);
    void visitBinaryOperator(BinaryOperator &I);
    void visitPHINode(PHINode &I);
    void visitInstruction(Instruction &I);

    void visitBranchInst(BranchInst &I);
    void visitIndirectBrInst(IndirectBrInst &I);
    void visitSwitchInst(SwitchInst &I);
    void visitTerminatorInst(TerminatorInst &I);
    void visitCastInst(CastInst &I);
    void visitCmpInst(CmpInst &I);
    void visitMemCpyInst(MemTransferInst &I);
    void visitMemMoveInst(MemTransferInst &I);
    void visitMemSetInst(MemSetInst &I);
};

/* PandaTaintFunctionPass class
 * This is our implementation of a function pass, inheriting from the generic
 * LLVM FunctionPass.  This expects a taint op buffer to be filled, and
 * eventually cached and processed.  The PandaTaintVisitor actually does the
 * taint op calculations and population of taint op buffers.
 */
class PandaTaintFunctionPass : public FunctionPass {
private:
    Shad *shad;
    taint2_memlog *taint_memlog;

public:
    static char ID;
    PandaTaintVisitor PTV; // Our LLVM instruction visitor

    PandaTaintFunctionPass(Shad *shad, taint2_memlog *taint_memlog)
        : FunctionPass(ID), shad(shad), taint_memlog(taint_memlog), PTV(shad, taint_memlog) {}

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

} // End llvm namespace

#endif

