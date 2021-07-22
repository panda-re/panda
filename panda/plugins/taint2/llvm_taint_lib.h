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
//
// Change Log:
// 14-FEB-2019:  ensure LLVM frames cleared before they are reused

#ifndef LLVM_TAINT_LIB_H
#define LLVM_TAINT_LIB_H

#include <map>
#include <cstdio>
#include <vector>
#include <set>

#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/Pass.h>

typedef struct taint2_memlog taint2_memlog;
typedef struct addr_struct Addr;

struct ShadowState;

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
    //void CreateMetadataSlot(const MDNode *N);
    void processFunction();

public:
    PandaSlotTracker(Function *F) : TheFunction(F),
        FunctionProcessed(false), fNext(0) {}
    unsigned CreateFunctionSlot(const Value *V);
    int getLocalSlot(const Value *V);
    void initialize();
    unsigned getMaxSlot();
};

class TaintOpsFunction {
public:
    TaintOpsFunction() {
    }

    TaintOpsFunction(const TaintOpsFunction &p) {
        name = p.name;
        argTys = p.argTys;
        retTy = p.retTy;
        varArgs = p.varArgs;
    }

    TaintOpsFunction(const char *name, void *addr, vector<Type *> &argTys,
            Type *retTy, bool varArgs, orc::ExecutionSession &ES,
            orc::SymbolMap &symbols) :
        name(name), argTys(argTys), retTy(retTy), varArgs(varArgs) {

        symbols[ES.intern(name)] = *new JITEvaluatedSymbol(
            pointerToJITTargetAddress(addr), JITSymbolFlags::Exported);
    }

    const char *getName() const {
        return name;
    }

    Type *getRetTy() const {
        return retTy;
    }

    vector<Type *>getArgTys() const {
        return argTys;
    }

    bool hasVarArgs() const {
        return varArgs;
    }

private:
    const char *name = nullptr;
    vector<Type *> argTys;
    Type *retTy = nullptr;
    bool varArgs = false;
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
    ShadowState *shad; // no ownership. weak ptr.
    taint2_memlog *taint_memlog; // same.

    // for counting up slots used by called subroutines
    std::unique_ptr<PandaSlotTracker> subframePST;

    ConstantInt *const_uint64_ptr(void *ptr);
    Constant *constSlot(Value *value);
    Constant *constWeakSlot(Value *value);
    Constant *constNull(void);
    int intValue(Value *value);
    unsigned getValueSize(const Value *V);
    ConstantInt *valueSizeValue(const Value *V);
    bool getAddr(Value *addrVal, Addr& addrOut);
    bool isEnvPtr(Value *V);
    bool isCPUStateAdd(BinaryOperator *AI);
    bool isIrrelevantAdd(BinaryOperator *AI);
    uint64_t ICmpPredicate(Instruction &I);
    void addInstructionDetailsToArgumentList(vector<Value *> &args,
        Instruction &I, Instruction *before);
    void inlineCall(CallInst *CI);
    Value *ptrToInt(Value *ptr, Instruction &I);
    Function *getFunction(Module *m, TaintOpsFunction &func);
    CallInst *insertCall(Instruction &I, TaintOpsFunction &func,
        vector<Value *> &args, bool before, bool tryInline);
    void insertCallAfter(Instruction &I, TaintOpsFunction &func,
        vector<Value *> &args);
    void insertCallBefore(Instruction &I, TaintOpsFunction &func,
        vector<Value *> &args);
    CallInst *insertLogPop(Instruction &after);
    void insertTaintCopy(Instruction &I, Constant *shad_dest, Value *dest,
        Constant *shad_src, Value *src, uint64_t size);
    void insertTaintBulk(Instruction &I, Constant *shad_dest, Value *dest,
        Constant *shad_src, Value *src, uint64_t size);
    void insertAfterTaintLd(Instruction &I, Value *val, Value *addr, uint64_t size);
    void insertTaintCopyOrDelete(Instruction &I, Constant *shad_dest,
        Value *dest, Constant *shad_src, Value *src, uint64_t size);
    void insertTaintPointer(Instruction &I, Value *ptr, Value *val,
        bool is_store);
    void insertTaintMix(Instruction &I, Value *src);
    void insertTaintMix(Instruction &I, Value *dest, Value *src);
    void insertTaintCompute(Instruction &I,
        Value *src1, Value *src2, bool is_mixed);
    void insertTaintCompute(Instruction &I, Value *dest,
        Value *src1, Value *src2, bool is_mixed);
    void insertTaintMul(Instruction &I, Value *dest,
        Value *src1, Value *src2);
    void insertTaintSext(Instruction &I, Value *src);
    void insertTaintSelect(Instruction &after, Value *dest,
        Value *selector, vector<pair<Value *, Value *>> &selections);
    void insertTaintDelete(Instruction &I, Constant *shad, Value *dest,
        Value *size);
    void insertTaintBranch(Instruction &I, Value *cond);
    void insertTaintQueryNonConstPc(Instruction &I, Value *cond);
    void insertStateOp(Instruction &I);
    uint64_t getInstructionFlags(Instruction &I);
    Instruction *getResult(Instruction *I);

public:
    LLVMContext *ctx;
    DataLayout *dataLayout = NULL;

    TaintOpsFunction breadcrumbF;
    TaintOpsFunction mixF;
    TaintOpsFunction pointerF;
    TaintOpsFunction mix_computeF;
    TaintOpsFunction parallel_computeF;
    TaintOpsFunction mul_computeF;
    TaintOpsFunction copyF;
    TaintOpsFunction sextF;
    TaintOpsFunction selectF;
    TaintOpsFunction host_copyF;
    TaintOpsFunction host_memcpyF;
    TaintOpsFunction host_deleteF;
    TaintOpsFunction push_frameF;
    TaintOpsFunction pop_frameF;
    TaintOpsFunction reset_frameF;
    TaintOpsFunction memlog_popF;
    TaintOpsFunction deleteF;
    TaintOpsFunction branch_runF;
    TaintOpsFunction copyRegToPc_runF;
    TaintOpsFunction afterLdF;

    Constant *llvConst;
    Constant *memConst;
    Constant *grvConst;
    Constant *gsvConst;
    Constant *retConst;
    Constant *prevBbConst;
    Constant *memlogConst;

    ConstantInt *zeroConst;
    ConstantInt *oneConst;
    ConstantInt *maxConst; // == "ones" in taint_ops.cpp

    // needed for creating LSHR Instructions on 128 bit value
    ConstantInt *i64Of128Const;

    Type *shadP;
    Type *memlogP;
    Type *voidT;
    IntegerType *int1T;
    IntegerType *int64T;
    IntegerType *int128T;
    PointerType *int64P;

    PandaTaintVisitor(ShadowState *shad, taint2_memlog *taint_memlog)
        : shad(shad), taint_memlog(taint_memlog) {}

    ~PandaTaintVisitor() {}

    ConstantInt *const_uint64(uint64_t val);
    Constant *const_i64p(void *ptr);
    Constant *const_struct_ptr(Type *ptrT, void *ptr);

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
    void visitInsertElementInst(InsertElementInst &I);
    void visitShuffleVectorInst(ShuffleVectorInst &I);
    void visitFreezeInst(FreezeInst &I);

    void visitReturnInst(ReturnInst &I);
    void visitBinaryOperator(BinaryOperator &I);
    void visitUnaryOperator(UnaryOperator &I);
    void visitPHINode(PHINode &I);
    void visitInstruction(Instruction &I);

    void visitBranchInst(BranchInst &I);
    void visitIndirectBrInst(IndirectBrInst &I);
    void visitSwitchInst(SwitchInst &I);
    void visitTerminator(Instruction &I);
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
    ShadowState *shad;
    taint2_memlog *taint_memlog;
    bool processing_helper;

public:
    static char ID;
    PandaTaintVisitor *PTV; // Our LLVM instruction visitor

    PandaTaintFunctionPass(ShadowState *shad, taint2_memlog *taint_memlog)
        : FunctionPass(ID), shad(shad), taint_memlog(taint_memlog),
		  processing_helper(false),
		  PTV(new PandaTaintVisitor(shad, taint_memlog)) {}

    ~PandaTaintFunctionPass() { }

    bool doInitialization(Module &M);

    // runOnFunction - Our custom function pass implementation
    bool runOnFunction(Function &F);

    // debug print all taint ops for a function
    void debugTaintOps();

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesAll();
    }

    // the processing_helper flag is used to tweak some taint op arguments based
    // on whether or not instrumenting a helper function
    void setProcessingHelper() {
    	processing_helper = true;
    }

    void clearProcessingHelper() {
    	processing_helper = false;
    }

    bool processingHelper() {
    	return processing_helper;
    }
};

} // End llvm namespace

#endif

