/* PANDABEGINCOMMENT
 * Function *resetFrameF;
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
/*
 * Change Log:
 * 2018-MAY-15   Use copy to propagate taint instead of mix if doing an LLVM
 *               SHL instruction but with a shift of 0 bits (which does nothing)
 */

#include <iostream>
#include <vector>

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Linker.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Pass.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/IR/Instruction.h>

#include "panda/rr/rr_log.h"
#include "panda/addr.h"
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/tcg-llvm.h"

#include "shad.h"
#include "llvm_taint_lib.h"
#include "taint_ops.h"
#include "taint2.h"

extern "C" {
#include "libgen.h"

extern bool tainted_pointer;

PPP_PROT_REG_CB(on_branch2);
PPP_CB_BOILERPLATE(on_branch2);

PPP_PROT_REG_CB(on_indirect_jump);
PPP_CB_BOILERPLATE(on_indirect_jump);

PPP_PROT_REG_CB(on_ptr_load);
PPP_CB_BOILERPLATE(on_ptr_load);

PPP_PROT_REG_CB(on_ptr_store);
PPP_CB_BOILERPLATE(on_ptr_store);

}

extern const char *qemu_file;

// Helper methods for doing structure computations.
#define cpu_off(member) (uint64_t)(&((CPUArchState *)0)->member)
#define cpu_size(member) sizeof(((CPUArchState *)0)->member)
#define cpu_endoff(member) (cpu_off(member) + cpu_size(member))

#define contains_offset(member) ((signed)cpu_off(member) <= (offset) && (unsigned)(offset) < cpu_endoff(member))

using namespace llvm;
using std::vector;
using std::pair;

/***
 *** PandaTaintFunctionPass
 ***/

char PandaTaintFunctionPass::ID = 0;
//static RegisterPass<PandaTaintFunctionPass>
//X("PandaTaint", "Analyze each instruction in a function for taint operations");

static inline ConstantInt *const_uint64(LLVMContext &C, uint64_t val) {
    return ConstantInt::get(llvm::Type::getInt64Ty(C), val);
}

static inline ConstantInt *const_uint64_ptr(LLVMContext &C, void *ptr) {
    return ConstantInt::get(llvm::Type::getInt64Ty(C), (uint64_t)ptr);
}

static inline Constant *const_i64p(LLVMContext &C, void *ptr) {
    return ConstantExpr::getIntToPtr(const_uint64_ptr(C, ptr),
            llvm::Type::getInt64PtrTy(C));
}

static inline Constant *const_struct_ptr(LLVMContext &C, llvm::Type *ptrT, void *ptr) {
    return ConstantExpr::getIntToPtr(const_uint64_ptr(C, ptr), ptrT);
}

static void taint_branch_run(Shad *shad, uint64_t src, uint64_t size)
{
    // this arg should be the register number
    Addr a = make_laddr(src / MAXREGSIZE, 0);
    PPP_RUN_CB(on_branch2, a, size);
}

void taint_pointer_run(uint64_t src, uint64_t ptr, uint64_t dest, bool is_store, uint64_t size) {
    // I think this has to be an LLVM register
    Addr ptr_addr = make_laddr(ptr / MAXREGSIZE, 0);
    if (is_store) {
        PPP_RUN_CB(on_ptr_store, ptr_addr, dest, size);    
    }
    else {
        PPP_RUN_CB(on_ptr_load, ptr_addr, src, size);
    }
}

static void taint_copyRegToPc_run(Shad *shad, uint64_t src, uint64_t size)
{
    // this arg should be the register number
    Addr a = make_laddr(src / MAXREGSIZE, 0);
    PPP_RUN_CB(on_indirect_jump, a, size);
}

extern "C" { extern TCGLLVMContext *tcg_llvm_ctx; }
bool PandaTaintFunctionPass::doInitialization(Module &M) {
    // Add taint functions to module
    char *exe = strdup(qemu_file);
    std::string bitcode(dirname(exe));
    free(exe);
    bitcode.append("/panda/plugins/panda_taint2_ops.bc");
    std::cout << "taint2: Linking taint ops from " << bitcode << std::endl;

    LLVMContext &ctx = M.getContext();
    SMDiagnostic Err;
    Module *taintopmod(ParseIRFile(bitcode, Err, ctx));
    if (!taintopmod) {
        Err.print("qemu", llvm::errs());
        return false;
    }

    MDNode *md = MDNode::get(ctx, ArrayRef<Value *>());
    for (auto it = taintopmod->begin(); it != taintopmod->end(); it++) {
        if (it->size() == 0) continue;
        if (it->front().size() == 0) continue;
        it->front().front().setMetadata("tainted", md);
    }

    std::string err;
    Linker::LinkModules(&M, taintopmod, Linker::DestroySource, &err);
    if (!err.empty()) {
        std::cerr << err << std::endl;
        return false;
    }
    verifyModule(M, llvm::AbortProcessAction, &err);
    if (!err.empty()) {
        std::cerr << err << std::endl;
        return true;
    }

    PTV.deleteF = M.getFunction("taint_delete"),
    PTV.mixF = M.getFunction("taint_mix"),
    PTV.pointerF = M.getFunction("taint_pointer"),
    PTV.mixCompF = M.getFunction("taint_mix_compute"),
    PTV.parallelCompF = M.getFunction("taint_parallel_compute"),
    PTV.copyF = M.getFunction("taint_copy");
    PTV.sextF = M.getFunction("taint_sext");
    PTV.selectF = M.getFunction("taint_select");
    PTV.hostCopyF = M.getFunction("taint_host_copy");
    PTV.hostMemcpyF = M.getFunction("taint_host_memcpy");
    PTV.hostDeleteF = M.getFunction("taint_host_delete");

    PTV.pushFrameF = M.getFunction("taint_push_frame");
    PTV.popFrameF = M.getFunction("taint_pop_frame");
    PTV.resetFrameF = M.getFunction("taint_reset_frame");
    PTV.breadcrumbF = M.getFunction("taint_breadcrumb");

    llvm::Type *shadT = M.getTypeByName("class.Shad");
    assert(shadT);
    llvm::Type *shadP = PointerType::getUnqual(shadT);

    llvm::Type *instrT = M.getTypeByName("class.llvm::Instruction");
    assert(instrT);
    PTV.instrT = PointerType::getUnqual(instrT);

    PTV.llvConst = const_struct_ptr(ctx, shadP, &shad->llv);
    PTV.memConst = const_struct_ptr(ctx, shadP, &shad->ram);
    PTV.grvConst = const_struct_ptr(ctx, shadP, &shad->grv);
    PTV.gsvConst = const_struct_ptr(ctx, shadP, &shad->gsv);
    PTV.retConst = const_struct_ptr(ctx, shadP, &shad->ret);

    PTV.dataLayout = new DataLayout(&M);

    llvm::Type *memlogT = M.getTypeByName("struct.taint2_memlog");
    assert(memlogT);
    llvm::Type *memlogP = PointerType::getUnqual(memlogT);

    PTV.memlogPopF = M.getFunction("taint_memlog_pop");
    PTV.memlogConst = const_struct_ptr(ctx, memlogP, taint_memlog);

    PTV.prevBbConst = const_i64p(ctx, &shad->prev_bb);

    ExecutionEngine *EE = tcg_llvm_ctx->getExecutionEngine();
    vector<llvm::Type *> argTs{
        shadP, llvm::Type::getInt64Ty(ctx), llvm::Type::getInt64Ty(ctx)
    };
    PTV.branchF = M.getFunction("taint_branch");
    if (!PTV.branchF) { // insert
        PTV.branchF = Function::Create(
            FunctionType::get(llvm::Type::getVoidTy(ctx), argTs, false /*isVarArg*/),
            GlobalVariable::ExternalLinkage, "taint_branch", &M);
    }
    assert(PTV.branchF);
    EE->addGlobalMapping(PTV.branchF, (void *)taint_branch_run);

    PTV.copyRegToPcF = M.getFunction("taint_copyRegToPc");
    if (!PTV.copyRegToPcF) { // insert
        PTV.copyRegToPcF = Function::Create(
            FunctionType::get(llvm::Type::getVoidTy(ctx), argTs, false /*isVarArg*/),
            GlobalVariable::ExternalLinkage, "taint_copyRegToPc", &M);
    }
    assert(PTV.copyRegToPcF);
    EE->addGlobalMapping(PTV.copyRegToPcF, (void *)taint_copyRegToPc_run);
#define ADD_MAPPING(func) \
    EE->addGlobalMapping(M.getFunction(#func), (void *)(func));\
    M.getFunction(#func)->deleteBody();
    ADD_MAPPING(taint_delete);
    ADD_MAPPING(taint_mix);
    ADD_MAPPING(taint_pointer);
    ADD_MAPPING(taint_mix_compute);
    ADD_MAPPING(taint_parallel_compute);
    ADD_MAPPING(taint_copy);
    ADD_MAPPING(taint_sext);
    ADD_MAPPING(taint_select);
    ADD_MAPPING(taint_host_copy);
    ADD_MAPPING(taint_host_memcpy);
    ADD_MAPPING(taint_host_delete);

    ADD_MAPPING(taint_push_frame);
    ADD_MAPPING(taint_pop_frame);
    ADD_MAPPING(taint_reset_frame);
    ADD_MAPPING(taint_breadcrumb);

    ADD_MAPPING(taint_memlog_pop);

    //ADD_MAPPING(label_set_union);
    //ADD_MAPPING(label_set_singleton);
#undef ADD_MAPPING

    std::cout << "taint2: Done initializing taint transformation." << std::endl;

    return true;
}

bool PandaTaintFunctionPass::runOnFunction(Function &F) {
#ifdef TAINT2_DEBUG
    //printf("\n\n%s\n", F.getName().str().c_str());
#endif
    if (F.front().front().getMetadata("tainted") ||
            F.getName().startswith("taint")) { // already processed!!
        return false;
    }
    //printf("Processing entry BB...\n");
    PTV.visitFunction(F);
    for (BasicBlock &BB : F) {
        vector<Instruction *> insts;
        for (Instruction &I : BB) insts.push_back(&I);
        PTV.visitBasicBlock(BB);
        for (Instruction *I : insts) {
            PTV.visit(I);
        }
    }
#ifdef TAINT2_DEBUG
    //F.dump();
    /*std::string err;
    if (F.getName().startswith("tcg-llvm-tb-")) {
        std::cerr << "Verifying " << F.getName().str() << std::endl;
        verifyModule(*F.getParent(), llvm::AbortProcessAction, &err);
    }
    if (!err.empty()) std::cerr << err << std::endl;*/
#endif

    return true;
}

/***
 *** PandaSlotTracker
 ***/

void PandaSlotTracker::initialize() {
    if (TheFunction && !FunctionProcessed) {
        processFunction();
    }
}

void PandaSlotTracker::processFunction() {
    // Add arguments without names
    // We make sure that arguments have
    for(Function::arg_iterator AI = TheFunction->arg_begin(),
        AE = TheFunction->arg_end(); AI != AE; ++AI) {
        if (!AI->hasName()) {
            CreateFunctionSlot(AI);
        }
        else {
            AI->setName("");
            CreateFunctionSlot(AI);
        }
    }
    // Add all of the basic blocks and instructions with no names.
    for (Function::iterator BB = TheFunction->begin(),
            E = TheFunction->end(); BB != E; ++BB) {
        CreateFunctionSlot(BB);
        for (BasicBlock::iterator I = BB->begin(), E = BB->end(); I != E;
            ++I) {
            if (I->getType() != llvm::Type::getVoidTy(TheFunction->getContext())) {
                CreateFunctionSlot(I);
            }
        }
    }
    FunctionProcessed = true;
}

void PandaSlotTracker::CreateFunctionSlot(const Value *V) {
    unsigned DestSlot = fNext++;
    fMap[V] = DestSlot;
}

unsigned PandaSlotTracker::getMaxSlot() {
    return fNext;
}

//void PandaSlotTracker::CreateMetadataSlot(const MDNode *N) {
    // don't currently need this, but we will if we start using metadata
//}

int PandaSlotTracker::getLocalSlot(const Value *V) {
    ValueMap::iterator FI = fMap.find(V);
    return FI == fMap.end() ? -1 : (int)FI->second;
}

/***
 *** PandaTaintVisitor
 ***/

/*
 * Returns size in bytes of a generic LLVM value (could be operand or
 * instruction).
 */
unsigned PandaTaintVisitor::getValueSize(const Value *V) {
    uint64_t size = dataLayout->getTypeSizeInBits(V->getType());
    return (size < 8) ? 1 : size / 8;
}

ConstantInt *PandaTaintVisitor::valueSizeValue(const Value *V) {
    return const_uint64(V->getContext(), getValueSize(V));
}

bool inline_taint = false;
void PandaTaintVisitor::inlineCall(CallInst *CI) {
    assert(CI);
        if (inline_taint) {
        InlineFunctionInfo IFI;
        if (!InlineFunction(CI, IFI)) {
            printf("Inlining failed!\n");
        }
    }
}

void PandaTaintVisitor::inlineCallAfter(Instruction &I, Function *F, vector<Value *> &args) {
    assert(F);
    CallInst *CI = CallInst::Create(F, args);
    if (!CI) {
        printf("Couldn't create call inst!!\n");
    }
    CI->insertAfter(&I);

    if (F->size() == 1) { // no control flow
        inlineCall(CI);
    }
}

void PandaTaintVisitor::inlineCallBefore(Instruction &I, Function *F, vector<Value *> &args) {
    assert(F);
    CallInst *CI = CallInst::Create(F, args);
    if (!CI) {
        printf("Couldn't create call inst!!\n");
    }
    CI->insertBefore(&I);

    if (F->size() == 1) { // no control flow
        inlineCall(CI);
    }
}

Constant *PandaTaintVisitor::constInstr(Instruction *I) {
    assert(I);
    return const_struct_ptr(I->getContext(), instrT, I);
}

Constant *PandaTaintVisitor::constNull(LLVMContext &C) {
    return const_struct_ptr(C, instrT, nullptr);
}

Constant *PandaTaintVisitor::constSlot(Value *value) {
    assert(value && !isa<Constant>(value));
    LLVMContext &ctx = value->getContext();
    int slot = PST->getLocalSlot(value);
    assert(slot >= 0);
    return const_uint64(ctx, MAXREGSIZE * slot);
}

Constant *PandaTaintVisitor::constWeakSlot(Value *value) {
    assert(value);
    LLVMContext &ctx = value->getContext();
    int slot = PST->getLocalSlot(value);
    assert(isa<Constant>(value) || slot >= 0);
    return const_uint64(ctx, slot < 0 ? ~0UL : MAXREGSIZE * slot);
}

int PandaTaintVisitor::intValue(Value *value) {
    ConstantInt *CI;
    if ((CI = dyn_cast<ConstantInt>(value))) {
        return CI->getZExtValue();
    } else return -1;
}

void PandaTaintVisitor::visitFunction(Function& F) {
    // create slot tracker to keep track of LLVM values
    PST.reset(new PandaSlotTracker(&F));
    PST->initialize();
}

void PandaTaintVisitor::visitBasicBlock(BasicBlock &BB) {
    LLVMContext &ctx = BB.getContext();
    Function *F = BB.getParent();
    assert(F);
    if (&F->front() == &BB && F->getName().startswith("tcg-llvm-tb-")) {
        // Entry block.
        // This is a single guest BB, so callstack should be empty.
        // Insert call to reset llvm frame.
        vector<Value *> args{ llvConst };
        assert(BB.getFirstNonPHI());
        inlineCallBefore(*BB.getFirstNonPHI(), resetFrameF, args);

        // Insert call to clear llvm shadow mem.
        vector<Value *> args2{
            llvConst, const_uint64(ctx, 0),
            const_uint64(ctx, MAXREGSIZE * PST->getMaxSlot())
        };
        inlineCallBefore(*BB.getFirstNonPHI(), deleteF, args2);

        // Two things: Insert "tainted" metadata.
        MDNode *md = MDNode::get(ctx, ArrayRef<Value *>());

        BB.front().setMetadata("tainted", md);
    } else {
        // At end of BB, log where we just were.
        // But only if this isn't the first block of a TB.
        vector<Value *> args{
            const_i64p(ctx, &shad->prev_bb), constSlot(&BB)
        };
        assert(BB.getTerminator() != NULL);
        inlineCallBefore(*BB.getTerminator(), breadcrumbF, args);
    }
}

// Insert a log pop after this instruction.
CallInst *PandaTaintVisitor::insertLogPop(Instruction &after) {
    vector<Value *> args{ memlogConst };
    CallInst *CI = CallInst::Create(memlogPopF, args);
    if (!CI) {
        printf("Couldn't create call inst!!\n");
    }
    CI->insertAfter(&after);
    return CI;
}

void PandaTaintVisitor::insertTaintCopy(Instruction &I,
        Constant *shad_dest, Value *dest, Constant *shad_src, Value *src,
        uint64_t size) {
    // If these are llvm regs we have to interpret them as slots.
    if (shad_dest == llvConst && !isa<Constant>(dest))
        dest = constSlot(dest);
    if (shad_src == llvConst && !isa<Constant>(src))
        src = constSlot(src);

    insertTaintBulk(I, shad_dest, dest, shad_src, src, size, copyF);
}

void PandaTaintVisitor::insertTaintBulk(Instruction &I,
        Constant *shad_dest, Value *dest, Constant *shad_src, Value *src,
        uint64_t size, Function *func) {
    LLVMContext &ctx = I.getContext();
    CallInst *srcCI = NULL, *destCI = NULL;
    if (!src) { // grab from memlog. Src will be below dest.
        assert(shad_src == memConst);
        src = (srcCI = insertLogPop(I));
    }
    if (!dest) { // grab from memlog. Dest will be on top of stack.
        assert(shad_dest == memConst);
        dest = (destCI = insertLogPop(I));
    }

    vector<Value *> args{
        shad_dest, dest,
        shad_src, src,
        const_uint64(ctx, size), constInstr(&I)
    };
    Instruction *after = srcCI ? srcCI : (destCI ? destCI : &I);
    inlineCallAfter(*after, func, args);

    if (srcCI) inlineCall(srcCI);
    if (destCI) inlineCall(destCI);
}

// Make sure slot integers are slot integers! Will not fix for you.
void PandaTaintVisitor::insertTaintCopyOrDelete(Instruction &I,
        Constant *shad_dest, Value *dest, Constant *shad_src, Value *src,
        uint64_t size) {
    LLVMContext &ctx = I.getContext();
    if (isa<Constant>(src)) {
        vector<Value *> args{ shad_dest, dest, const_uint64(ctx, size) };
        inlineCallAfter(I, deleteF, args);
    } else {
        insertTaintBulk(I, shad_dest, dest, shad_src, constSlot(src), size, copyF);
    }
}

void PandaTaintVisitor::insertTaintPointer(Instruction &I,
        Value *ptr, Value *val, bool is_store) {
    LLVMContext &ctx = I.getContext();
    CallInst *popCI = insertLogPop(I);
    Value *addr = popCI;

    Constant *shad_dest = is_store ? memConst : llvConst;
    Value *dest = is_store ? addr : constSlot(val);

    Constant *shad_src = is_store ? llvConst : memConst;
    // If we're storing a constant, still do a taint mix.
    Value *src = is_store ? constWeakSlot(val) : addr;
    vector<Value *> args{
        shad_dest, dest,
        llvConst, constSlot(ptr), const_uint64(ctx, getValueSize(ptr)),
            shad_src, src, const_uint64(ctx, getValueSize(val)),
            const_uint64(ctx, is_store)
            };
    inlineCallAfter(*popCI, pointerF, args);

    inlineCall(popCI);
}


void PandaTaintVisitor::insertTaintMix(Instruction &I, Value *src) {
    insertTaintMix(I, &I, src);
}
void PandaTaintVisitor::insertTaintMix(Instruction &I, Value *dest, Value *src) {
    LLVMContext &ctx = I.getContext();
    if (isa<Constant>(src)) return;

    if (!dest) dest = &I;
    Constant *dest_size = const_uint64(ctx, getValueSize(dest));
    Constant *src_size = const_uint64(ctx, getValueSize(src));

    vector<Value *> args{
        llvConst, constSlot(dest), dest_size,
        constSlot(src), src_size,
        constInstr(&I)
    };
    inlineCallAfter(I, mixF, args);
}

void PandaTaintVisitor::insertTaintCompute(Instruction &I, Value *src1, Value *src2, bool is_mixed) {
    insertTaintCompute(I, &I, src1, src2, is_mixed);
}

// Compute operations
void PandaTaintVisitor::insertTaintCompute(Instruction &I, Value *dest, Value *src1, Value *src2, bool is_mixed) {
    LLVMContext &ctx = I.getContext();
    if (!dest) dest = &I;

    if (isa<Constant>(src1) && isa<Constant>(src2)) {
        return; // do nothing.
    } else if (isa<Constant>(src1) || isa<Constant>(src2)) {
        Value *tainted = isa<Constant>(src1) ? src2 : src1;
        if (is_mixed) {
            insertTaintMix(I, tainted);
        } else {
            insertTaintCopy(I, llvConst, dest, llvConst, tainted, getValueSize(src2));
        }
        return;
    }

    if (!is_mixed) {
        assert(getValueSize(dest) == getValueSize(src1));
    }
    assert(getValueSize(src1) == getValueSize(src1));

    Constant *dest_size = const_uint64(ctx, getValueSize(dest));
    Constant *src_size = const_uint64(ctx, getValueSize(src1));

    vector<Value *> args{
        llvConst, constSlot(dest), dest_size,
        constSlot(src1), constSlot(src2), src_size,
        constInstr(&I)
    };
    inlineCallAfter(I, is_mixed ? mixCompF : parallelCompF, args);
}

void PandaTaintVisitor::insertTaintSext(Instruction &I, Value *src) {
    LLVMContext &ctx = I.getContext();
    Value *dest = &I;
    Constant *dest_size = const_uint64(ctx, getValueSize(dest));
    Constant *src_size = const_uint64(ctx, getValueSize(src));

    vector<Value *> args{
        llvConst, constSlot(dest), dest_size, constSlot(src), src_size
    };
    inlineCallAfter(I, sextF, args);
}

void PandaTaintVisitor::insertTaintSelect(Instruction &after, Value *dest,
        Value *selector, vector<pair<Value *, Value *>> &selections) {
    LLVMContext &ctx = after.getContext();
    Constant *dest_size = const_uint64(ctx, getValueSize(dest));

    vector<Value *> args{
        llvConst, constSlot(dest), dest_size, selector
    };
    for (auto &selection : selections) {
        args.push_back(selection.first);
        args.push_back(selection.second);
    }
    args.push_back(const_uint64(ctx, ~0UL));
    args.push_back(const_uint64(ctx, ~0UL));
    inlineCallAfter(after, selectF, args);
}

void PandaTaintVisitor::insertTaintDelete(Instruction &I,
        Constant *shad, Value *dest, Value *size) {
    CallInst *destCI = NULL;
    if (shad == llvConst) dest = constSlot(dest);
    if (shad == memConst && dest == NULL) {
        dest = (destCI = insertLogPop(I));
    }

    vector<Value *> args{ shad, dest, size };
    inlineCallAfter(destCI ? *destCI : I, deleteF, args);
}

void PandaTaintVisitor::insertTaintBranch(Instruction &I, Value *cond) {
    if (isa<Constant>(cond)) return;
    LLVMContext &ctx = I.getContext();

    // First block is just checking exit request. don't instrument!
    BasicBlock *BB = I.getParent();
    assert(BB);
    Function *F = BB->getParent();
    assert(F);
    if (BB == &F->front() && F->getName().startswith("tcg-llvm-tb")) return;

    vector<Value *> args{
        llvConst, constSlot(cond), const_uint64(ctx, getValueSize(cond))
    };
    inlineCallBefore(I, branchF, args);
}

void PandaTaintVisitor::insertTaintQueryNonConstPc(Instruction &I, Value *new_pc) {
    if (isa<Constant>(new_pc)) return;
    LLVMContext &ctx = I.getContext();

    vector<Value *> args{
        llvConst, constSlot(new_pc), const_uint64(ctx, getValueSize(new_pc))
    };
    inlineCallBefore(I, copyRegToPcF, args);
}

// Terminator instructions
void PandaTaintVisitor::visitReturnInst(ReturnInst &I) {
    Value *ret = I.getReturnValue();
    if (!ret) return;

    LLVMContext &ctx = I.getContext();
    if (isa<Constant>(ret)) {
        // delete return taint.
        vector<Value *> args{
            retConst, const_uint64(ctx, 0),
            const_uint64(ctx, MAXREGSIZE)
        };
        inlineCallBefore(I, deleteF, args);
    } else {
        vector<Value *> args{
            retConst, const_uint64(ctx, 0),
            llvConst, constSlot(ret),
            const_uint64(ctx, getValueSize(ret)), constNull(ctx)
        };
        inlineCallBefore(I, copyF, args);
    }

    visitTerminatorInst(I);
}

void PandaTaintVisitor::visitBranchInst(BranchInst &I) {
    if (I.isConditional()) {
        insertTaintBranch(I, I.getCondition());
    }
}
void PandaTaintVisitor::visitIndirectBrInst(IndirectBrInst &I) {
    insertTaintBranch(I, I.getAddress());
}
void PandaTaintVisitor::visitSwitchInst(SwitchInst &I) {
    insertTaintBranch(I, I.getCondition());
}

// On a branch we just have to log the previous BB.
void PandaTaintVisitor::visitTerminatorInst(TerminatorInst &I) {
    // BB logging is in the previous stuff.
}

void PandaTaintVisitor::visitInvokeInst(InvokeInst &I) {
    assert(false && "Can't handle invoke!!");
}

/*
 * Treat unreachable the same way as return.  This matters, for example, when
 * there is a call to cpu_loop_exit() in a helper function, followed by an
 * unreachable instruction.  Functions that end with unreachable return void, so
 * we don't have to worry about taint transfer.
 */
void PandaTaintVisitor::visitUnreachableInst(UnreachableInst &I) {}

// Check whether this instruction is just adding to an irrel. register
// Form would be add(load(i2p(add(env, x))), y)
// We can safely ignore those instrs.
bool PandaTaintVisitor::isIrrelevantAdd(BinaryOperator *AI) {
    if (!isa<ConstantInt>(AI->getOperand(1))) return false;

    LoadInst *LI = dyn_cast<LoadInst>(AI->getOperand(0));
    if (!LI) return false;

    Addr addr = Addr();
    if (getAddr(LI->getPointerOperand(), addr) && addr.flag == IRRELEVANT)
        return true;

    return false;
}

// Binary operators
void PandaTaintVisitor::visitBinaryOperator(BinaryOperator &I) {
    bool is_mixed = false;
    if (I.getMetadata("host")) return;
    switch (I.getOpcode()) {
        case Instruction::Shl:
        {
            // operand 1 is the number of bits to shift
            // if shifting 0 bits, then you're not really shifting at all, so
            // don't propagate the taint that may be in one byte to them all
            Value *op1 = I.getOperand(1);
            if (isa<Constant>(op1))
            {
                if (intValue(op1) != 0)
                {
                    is_mixed = true;
                }
            }
            else
            {
                is_mixed = true;
            }
        }
        break;
        
        case Instruction::Add:
            {
                BinaryOperator *AI = dyn_cast<BinaryOperator>(&I);
                assert(AI);
                if (isCPUStateAdd(AI)) return;
                else if (isIrrelevantAdd(AI)) return;
            } // fall through otherwise.
        case Instruction::Sub:
        case Instruction::Mul:
        case Instruction::UDiv:
        case Instruction::SDiv:
        case Instruction::FAdd:
        case Instruction::FSub:
        case Instruction::FMul:
        case Instruction::FDiv:
        case Instruction::URem:
        case Instruction::SRem:
        case Instruction::FRem:
        case Instruction::LShr:
        case Instruction::AShr:
            is_mixed = true;
            break;
            // mixed; i.e. operation is not bitwise, so taint transfers
            // between bytes in the word.

        case Instruction::And:
        case Instruction::Or:
        case Instruction::Xor:
            is_mixed = false;
            break;
            // parallel

        default:
            assert(false && "Bad BinaryOperator!!");
    }

    insertTaintCompute(I, &I, I.getOperand(0), I.getOperand(1), is_mixed);
}

// Memory operators

// Do nothing.
void PandaTaintVisitor::visitAllocaInst(AllocaInst &I) {}

bool PandaTaintVisitor::isEnvPtr(Value *V) {
    if (PST->getLocalSlot(V) == 0) return true;
    PtrToIntInst *P2II = dyn_cast<PtrToIntInst>(V);
    if (P2II == nullptr) return false;
    return PST->getLocalSlot(P2II->getOperand(0)) == 0;
}

bool PandaTaintVisitor::isCPUStateAdd(BinaryOperator *AI) {
    assert(AI->getOpcode() == Instruction::Add);
    return isEnvPtr(AI->getOperand(0));
}

// Find address and constant given a load/store (i.e. host vmem) address.
// Argument should be the value from a load/store inst.
// Returns true if addrOut has been changed.
// This function is our main venue for avoiding taint-tracking on host data
// structures.
bool PandaTaintVisitor::getAddr(Value *addrVal, Addr& addrOut) {
    IntToPtrInst *I2PI;
    GetElementPtrInst *GEPI;
    addrOut.flag = (AddrFlag)0;
    int offset = -1;

    Instruction *I = dyn_cast<Instruction>(addrVal);
    if (I && I->getMetadata("host")) {
        addrOut.flag = IRRELEVANT;
        return true;
    }

    // Structure produced by code gen should always be inttoptr(add(env_v, off)).
    // Helper functions are GEP's.
    if ((I2PI = dyn_cast<IntToPtrInst>(addrVal)) != NULL) {
        assert(I2PI->getOperand(0));
        BinaryOperator *AI = dyn_cast<BinaryOperator>(I2PI->getOperand(0));
        if (AI && AI->getOpcode() == Instruction::Add) {
            if (!isCPUStateAdd(AI)) return false;
            offset = intValue(AI->getOperand(1));
        } else if (isEnvPtr(I2PI->getOperand(0))) {
            offset = 0;
        }
    } else if ((GEPI = dyn_cast<GetElementPtrInst>(addrVal)) != NULL) {
        // unsupported as of yet.
        // this happens in helper functions.
        return false;
    } else {
        return false;
    }

    int64_t archStateOffset = (uintptr_t)first_cpu->env_ptr
        - (uintptr_t)ENV_GET_CPU((CPUArchState*)first_cpu->env_ptr);
    if (offset == offsetof(CPUState, tcg_exit_req) - archStateOffset) {
        assert((uintptr_t)first_cpu->env_ptr + offset == (uintptr_t)&first_cpu->tcg_exit_req);
        addrOut.flag = IRRELEVANT;
        return true;
    }

    if (offset < 0 || (size_t)offset >= sizeof(CPUArchState)) return false;
    if (is_irrelevant(offset)) {
        addrOut.flag = IRRELEVANT;
        return true;
    }

#if defined (TARGET_PPC) 
    if (contains_offset(gpr)) {
        addrOut.typ = GREG;
        addrOut.val.gr = (offset - cpu_off(gpr)) / cpu_size(gpr[0]);
        addrOut.off = (offset - cpu_off(gpr)) % cpu_size(gpr[0]);
        return true;
    }
#else
    if (contains_offset(regs)) {
        addrOut.typ = GREG;
        addrOut.val.gr = (offset - cpu_off(regs)) / cpu_size(regs[0]);
        addrOut.off = (offset - cpu_off(regs)) % cpu_size(regs[0]);
        return true;
    }
#endif
    addrOut.typ = GSPEC;
    addrOut.val.gs = offset;
    addrOut.off = 0;
    return true;
}

static Value *ptrToInt(Value *ptr, Instruction &I) {
    assert(ptr);
    LLVMContext &ctx = ptr->getContext();

    IntToPtrInst *I2PI = dyn_cast<IntToPtrInst>(ptr);
    if (I2PI) {
        Value *orig = I2PI->getOperand(0);
        assert(orig->getType() == llvm::Type::getInt64Ty(ctx));
        return orig;
    } else {
        return new PtrToIntInst(ptr, llvm::Type::getInt64Ty(ctx), "", &I);
    }
}

void PandaTaintVisitor::insertStateOp(Instruction &I) {
    // These are loads/stores from CPUState etc.
    LLVMContext &ctx = I.getContext();
    Addr addr = Addr();

    bool isStore = isa<StoreInst>(I);
    Value *ptr = I.getOperand(isStore ? 1 : 0);
    Value *val = isStore ? I.getOperand(0) : &I;
    uint64_t size = getValueSize(val);
    if (getAddr(ptr, addr)) {
        if (addr.flag == IRRELEVANT) return;
        // Successfully statically found offset.
        Constant *ptrConst;
        uint64_t ptrAddr;
        if (addr.typ == GREG) {
            ptrConst = grvConst;
            ptrAddr = addr.val.gr * sizeof(target_ulong) + addr.off;
        } else {
            ptrConst = gsvConst;
            ptrAddr = addr.val.gs;
        }

#if defined(TARGET_ARM)
        if (ptrAddr == cpu_off(regs[15]) && isStore) {
#elif defined(TARGET_I386)
        if (ptrAddr == cpu_off(eip) && isStore) {
#elif defined(TARGET_PPC)
        if (ptrAddr == cpu_off(nip) && isStore) {
#else
#error "unsupported architecture"
#endif
             // we are storing to pc
             // insert instrumentation before for querying taint
             // on LLVM register `val` being stored
            insertTaintQueryNonConstPc(I, val);
        }

        Constant *destConst = isStore ? ptrConst : llvConst;
        Constant *srcConst = isStore ? llvConst : ptrConst;
        Value *dest = isStore ? const_uint64(ctx, ptrAddr) : val;
        Value *src = isStore ? val : const_uint64(ctx, ptrAddr);
        if (isStore && isa<Constant>(val)) {
            insertTaintDelete(I, destConst, dest, const_uint64(ctx, size));
        } else {
            insertTaintCopy(I, destConst, dest, srcConst, src, size);
        }
    } else if (isa<Constant>(val) && isStore) {
        vector<Value *> args{
            const_uint64_ptr(ctx, first_cpu->env_ptr), ptrToInt(ptr, I),
            grvConst, gsvConst, const_uint64(ctx, size), const_uint64(ctx, sizeof(target_ulong))
        };
        inlineCallAfter(I, hostDeleteF, args);
    } else if (isa<AllocaInst>(ptr) && isStore) {
        if (isa<Constant>(val)) {
            insertTaintDelete(I, llvConst, ptr, const_uint64(ctx, size));
        } else {
            insertTaintCopy(I, llvConst, ptr, llvConst, val, size);
        }
    } else {
        vector<Value *> args{
            const_uint64_ptr(ctx, first_cpu->env_ptr), ptrToInt(ptr, I),
            llvConst, constSlot(val), grvConst, gsvConst,
            const_uint64(ctx, size), const_uint64(ctx, sizeof(target_ulong)),
            ConstantInt::get(llvm::Type::getInt1Ty(ctx), isStore)
        };
        inlineCallAfter(I, hostCopyF, args);
    }
}

void PandaTaintVisitor::visitLoadInst(LoadInst &I) {
    if (I.getMetadata("host")) {
        return;
    }

    insertStateOp(I);
}

/*
 * We should only care about non-volatile stores, the volatile stores are
 * irrelevant to guest execution.  Volatile stores come in pairs for each guest
 * instruction, so we can gather statistics looking at every other volatile
 * store.
 */
void PandaTaintVisitor::visitStoreInst(StoreInst &I) {
    if (I.getMetadata("host")) {
        return;
    }

    insertStateOp(I);
}

/*
 * In TCG->LLVM translation, it seems like this instruction is only used to get
 * the pointer to the CPU state.  Because of this, we will just delete taint at
 * the destination LLVM register.
 */
void PandaTaintVisitor::visitGetElementPtrInst(GetElementPtrInst &I) {
    insertTaintMix(I, I.getOperand(0));
}

// Cast operators
void PandaTaintVisitor::visitCastInst(CastInst &I) {
    Value *src = I.getOperand(0);

    if (I.getMetadata("host")) return;

    unsigned srcSize = getValueSize(src), destSize = getValueSize(&I);
    switch (I.getOpcode()) {
        // Mixed cases
        case Instruction::FPExt:
        case Instruction::FPToSI:
        case Instruction::FPTrunc:
        case Instruction::SIToFP:
        case Instruction::UIToFP:
            insertTaintMix(I, &I, src);
            return;

        case Instruction::IntToPtr:
            {
                BinaryOperator *AI = dyn_cast<BinaryOperator>(src);
                if ((AI && isCPUStateAdd(AI)) || isEnvPtr(src)) {
                    // do nothing.
                    return;
                } else break;
            }

        case Instruction::SExt:
            if (destSize > srcSize) {
                // Generate a sext.
                insertTaintSext(I, src);
                return;
            }
            // Else fall through to a copy.
        // Parallel cases. Assume little-endian...
        // Both involve a simple copy.
        case Instruction::BitCast:
        case Instruction::PtrToInt:
        case Instruction::Trunc:
        case Instruction::ZExt:
           break;
        default:
           // BROKEN
           assert(false && "Bad CastInst!!");
    }
    insertTaintCopy(I, llvConst, &I,
            llvConst, src,
            std::min(srcSize, destSize));
}

// Other operators

/*
 * If both operands are LLVM registers, then the result will be a one bit (byte)
 * compute taint.  If only one operand is a register, then the result will be a
 * compute, but only propagating taint from the register source.  If both are
 * constants, then it will be a delete.  Since this is usually used for a branch
 * condition, this could let us see if we can
 * potentially affect control flow.
 */
void PandaTaintVisitor::visitCmpInst(CmpInst &I) {
    LoadInst *LI = dyn_cast<LoadInst>(I.getOperand(0));
    if (LI) {
        IntToPtrInst *I2PI = dyn_cast<IntToPtrInst>(LI->getOperand(0));
        if (I2PI) {
            BinaryOperator *AI = dyn_cast<BinaryOperator>(I2PI->getOperand(0));
            if (AI && AI->getOpcode() == Instruction::Add
                    && isEnvPtr(AI->getOperand(0))
                    && intValue(AI->getOperand(1)) < 0) {
                // Don't instrument tcg_exit_req / other control data compares.
                return;
            }
        }
    }
    insertTaintCompute(I, &I, I.getOperand(0), I.getOperand(1), true);
}

void PandaTaintVisitor::visitPHINode(PHINode &I) {
    LoadInst *LI = new LoadInst(prevBbConst);
    assert(LI != NULL);
    assert(I.getParent()->getFirstNonPHI() != NULL);

    LI->insertBefore(I.getParent()->getFirstNonPHI());
    vector<pair<Value *,Value *>> selections;
    for (unsigned i = 0; i < I.getNumIncomingValues(); ++i) {
        Constant *value = constWeakSlot(I.getIncomingValue(i));
        Constant *select = constSlot(I.getIncomingBlock(i));
        selections.push_back(std::make_pair(value, select));
    }
    insertTaintSelect(*LI, &I, LI, selections);
}

void PandaTaintVisitor::visitMemCpyInst(MemTransferInst &I) {
    LLVMContext &ctx = I.getContext();
    Value *dest = I.getDest();
    Value *src = I.getSource();
    Value *size = I.getLength();
    PtrToIntInst *destP2II = new PtrToIntInst(dest, llvm::Type::getInt64Ty(ctx), "", &I);
    PtrToIntInst *srcP2II = new PtrToIntInst(src, llvm::Type::getInt64Ty(ctx), "", &I);
    assert(destP2II && srcP2II);
    vector<Value *> args{
        const_uint64_ptr(ctx, first_cpu->env_ptr), destP2II, srcP2II,
        grvConst, gsvConst, size, const_uint64(ctx, sizeof(target_ulong))
    };
    inlineCallAfter(I, hostMemcpyF, args);
}

void PandaTaintVisitor::visitMemMoveInst(MemTransferInst &I) {
    assert(false && "MemMove unhandled!");
}

void PandaTaintVisitor::visitMemSetInst(MemSetInst &I) {
    LLVMContext &ctx = I.getContext();

    Value *dest = I.getDest();
    Value *size = I.getLength();
    assert(isa<Constant>(I.getValue()));

    PtrToIntInst *P2II = new PtrToIntInst(dest, llvm::Type::getInt64Ty(ctx), "", &I);
    assert(P2II);

    vector<Value *> args{
        const_uint64_ptr(ctx, first_cpu->env_ptr), P2II,
        grvConst, gsvConst, size, const_uint64(ctx, sizeof(target_ulong))
    };
    inlineCallAfter(I, hostDeleteF, args);
}

const static std::set<std::string> ldFuncs{
    "helper_le_ldq_mmu_panda", "helper_le_ldul_mmu_panda", "helper_le_lduw_mmu_panda",
    "helper_le_ldub_mmu_panda", "helper_le_ldsl_mmu_panda", "helper_le_ldsw_mmu_panda",
    "helper_le_ldsb_mmu_panda",
    "helper_be_ldq_mmu_panda", "helper_be_ldul_mmu_panda", "helper_be_lduw_mmu_panda",
    "helper_be_ldub_mmu_panda", "helper_be_ldsl_mmu_panda", "helper_be_ldsw_mmu_panda",
    "helper_be_ldsb_mmu_panda",
    "helper_ret_ldq_mmu_panda", "helper_ret_ldul_mmu_panda", "helper_ret_lduw_mmu_panda",
    "helper_ret_ldub_mmu_panda", "helper_ret_ldsl_mmu_panda", "helper_ret_ldsw_mmu_panda",
    "helper_ret_ldsb_mmu_panda"
};
const static std::set<std::string> stFuncs{
    "helper_le_stq_mmu_panda", "helper_le_stl_mmu_panda", "helper_le_stw_mmu_panda",
    "helper_le_stb_mmu_panda",
    "helper_be_stq_mmu_panda", "helper_be_stl_mmu_panda", "helper_be_stw_mmu_panda",
    "helper_be_stb_mmu_panda",
    "helper_ret_stq_mmu_panda", "helper_ret_stl_mmu_panda", "helper_ret_stw_mmu_panda",
    "helper_ret_stb_mmu_panda"
};
const static std::set<std::string> inoutFuncs{
    "helper_inb", "helper_inw", "helper_inl", "helper_inq",
    "helper_outb", "helper_outw", "helper_outl", "helper_outq"
};
const static std::set<std::string> unaryMathFuncs{
    "sin", "cos", "tan", "log", "__isinf", "__isnan", "rint", "floor", "abs",
    "fabs", "ceil", "exp2"
};
void PandaTaintVisitor::visitCallInst(CallInst &I) {
    LLVMContext &ctx = I.getContext();
    Function *calledF = I.getCalledFunction();
    Value *calledV = I.getCalledValue();
    assert(calledV);

    llvm::Type *valueType = calledV->getType();
    FunctionType *callType;
    // If not a function type, it's a function pointer.
    if (!(callType = dyn_cast<FunctionType>(valueType))) {
        PointerType *pointerType = dyn_cast<PointerType>(valueType);
        assert(pointerType && pointerType->getElementType()->isFunctionTy());
        callType = dyn_cast<FunctionType>(pointerType->getElementType());
    }
    assert(callType && callType->isFunctionTy());

    if (calledF) {
        std::string calledName = calledF->getName().str();

        switch (calledF->getIntrinsicID()) {
            case Intrinsic::uadd_with_overflow:
                insertTaintCompute(I, I.getArgOperand(0), I.getArgOperand(1), 1);
                return;
            case Intrinsic::bswap:
            case Intrinsic::ctlz:
            case Intrinsic::cttz:
                insertTaintMix(I, I.getArgOperand(0));
                return;
            case Intrinsic::dbg_declare:
            case Intrinsic::dbg_value:
            case Intrinsic::lifetime_start:
            case Intrinsic::lifetime_end:
            case Intrinsic::returnaddress:
                // This needs to be eliminated before we can generate code!
                //assert(false && "Have to eliminate debug statements!");
                return;
            case Intrinsic::not_intrinsic:
                break;
            default:
                printf("taint2: Note: unsupported intrinsic %s in %s.\n",
                    calledF->getName().str().c_str(),
                    I.getParent()->getParent()->getName().str().c_str());
                return;
        }

        assert(!calledF->isIntrinsic());
        if (calledF->getName().startswith("taint")) {
            return;
        } else if (calledName == "cpu_loop_exit") {
            return;
        } else if (ldFuncs.count(calledName) > 0) {
            Value *ptr = I.getArgOperand(1);
            if (tainted_pointer && !isa<Constant>(ptr)) {
                insertTaintPointer(I, ptr, &I, false);
            } else {
                insertTaintCopy(I, llvConst, &I, memConst, NULL, getValueSize(&I));
            }
            return;
        } else if (stFuncs.count(calledName) > 0) {
            Value *ptr = I.getArgOperand(1);
            Value *val = I.getArgOperand(2);
            if (tainted_pointer && !isa<Constant>(ptr)) {
                insertTaintPointer(I, ptr, val, true /* is_store */ );
            } else if (isa<Constant>(val)) {
                insertTaintDelete(I, memConst, NULL, const_uint64(ctx, getValueSize(val)));
            } else {
                insertTaintCopy(I, memConst, NULL, llvConst, val, getValueSize(val));
            }
            return;
        } else if (unaryMathFuncs.count(calledName) > 0) {
            insertTaintMix(I, I.getArgOperand(0));
            return;
        } else if (calledName == "ldexp" || calledName == "atan2") {
            insertTaintCompute(I, I.getArgOperand(0), I.getArgOperand(1), true);
            return;
        } else if (inoutFuncs.count(calledName) > 0) {
            return;
        }
        // Else fall through to named case.
    }

    // This is a call that we aren't going to model, so we need to process
    // it instruction by instruction.
    // First, we need to set up a new stack frame and copy argument taint.
    vector<Value *> fargs{ llvConst };
    int numArgs = I.getNumArgOperands();
    for (int i = 0; i < numArgs; i++) {
        Value *arg = I.getArgOperand(i);
        int argBytes = getValueSize(arg);
        assert(argBytes > 0);

        auto arg_dest = const_uint64(ctx, (shad->num_vals + i) * MAXREGSIZE);
        auto arg_bytes = const_uint64(ctx, argBytes);
        // if arg is constant then delete taint
        if (!isa<Constant>(arg)) {
            vector<Value *> copyargs{
                llvConst, arg_dest,
                llvConst, constSlot(arg), arg_bytes,
                constNull(ctx)
            };
            inlineCallBefore(I, copyF, copyargs);
        } else {
            vector<Value *> args { llvConst, arg_dest, arg_bytes };
            inlineCallBefore(I, deleteF, args);
        }
    }
    if (!callType->getReturnType()->isVoidTy()) { // Copy from return slot.
        vector<Value *> retargs{
            llvConst, constSlot(&I), retConst,
            const_uint64(ctx, 0), const_uint64(ctx, MAXREGSIZE),
            constNull(ctx)
        };
        inlineCallAfter(I, copyF, retargs);
    }
    inlineCallBefore(I, pushFrameF, fargs);
    inlineCallAfter(I, popFrameF, fargs);
}
/*
// For now delete dest taint.
void PandaTaintVisitor::portLoadHelper(Value *srcval, Value *dstval, int len) {

}

// this is essentially a copy of storeHelper without the tainted pointer code
void PandaTaintVisitor::portStoreHelper(Value *srcval, Value *dstval, int len) {
    // can't propagate taint from a constant
    bool srcConstant = isa<Constant>(srcval);

    struct addr_struct src = {};
    struct addr_struct dst = {};
    struct taint_op_struct op = {};
    char name[6] = "store";

    // write instruction boundary op
    op.typ = INSNSTARTOP;
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = len;
    op.val.insn_start.flag = INSNREADLOG;
    tob_op_write(tbuf, &op);

    if (srcConstant) {
        op.typ = DELETEOP;
        dst.typ = UNK;
        dst.val.ua = 0;
        dst.flag = READLOG;
        for (int i = 0; i < len; i++) {
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, &op);
        }
    }
    else {
        op.typ = COPYOP;
        dst.typ = UNK;
        dst.flag = READLOG;
        dst.val.ua = 0;
        src.typ = LADDR;
        src.val.la = PST->getLocalSlot(srcval);
        for (int i = 0; i < len; i++) {
            src.off = i;
            dst.off = i;
            op.val.copy.a = src;
            op.val.copy.b = dst;
            tob_op_write(tbuf, &op);
        }
    }
}
*/

void PandaTaintVisitor::visitSelectInst(SelectInst &I) {
    LLVMContext &ctx = I.getContext();
    Value *cond = I.getCondition();
    ZExtInst *ZEI = new ZExtInst(cond, Type::getInt64Ty(ctx), "", &I);
    assert(ZEI);

    vector<pair<Value *, Value *>> selections;
    selections.push_back(std::make_pair(
                constWeakSlot(I.getTrueValue()),
                ConstantInt::get(ctx, APInt(64, 1))));
    selections.push_back(std::make_pair(
                constWeakSlot(I.getFalseValue()),
                ConstantInt::get(ctx, APInt(64, 0))));
    insertTaintSelect(I, &I, ZEI, selections);
}

void PandaTaintVisitor::visitExtractValueInst(ExtractValueInst &I) {
    LLVMContext &ctx = I.getContext();
    assert(I.getNumIndices() == 1);

    Value *aggregate = I.getAggregateOperand();
    assert(aggregate && aggregate->getType()->isStructTy());
    StructType *typ = dyn_cast<StructType>(aggregate->getType());
    const StructLayout *structLayout = dataLayout->getStructLayout(typ);

    assert(I.idx_begin() != I.idx_end());
    unsigned offset = structLayout->getElementOffset(*I.idx_begin());
    uint64_t src = MAXREGSIZE * PST->getLocalSlot(aggregate) + offset;

    insertTaintCopy(I,
            llvConst, constSlot(&I),
            llvConst, const_uint64(ctx, src),
            getValueSize(&I));
}

void PandaTaintVisitor::visitInsertValueInst(InsertValueInst &I) {
    LLVMContext &ctx = I.getContext();
    assert(I.getNumIndices() == 1);

    Value *aggregate = I.getAggregateOperand();
    assert(aggregate && aggregate->getType()->isStructTy());
    StructType *typ = dyn_cast<StructType>(aggregate->getType());
    const StructLayout *structLayout = dataLayout->getStructLayout(typ);

    Value *inserted = I.getInsertedValueOperand();

    assert(I.idx_begin() != I.idx_end());
    unsigned offset = structLayout->getElementOffset(*I.idx_begin());
    uint64_t dest = MAXREGSIZE * PST->getLocalSlot(&I);

    // First copy the aggregate value, then copy the inserted taint over
    // it. NB: inserting instructions must be swapped since we insert
    // them both after I.
    insertTaintCopyOrDelete(I,
            llvConst, const_uint64(ctx, dest + offset),
            llvConst, inserted,
            getValueSize(inserted));
    insertTaintCopyOrDelete(I,
            llvConst, constSlot(&I),
            llvConst, aggregate,
            getValueSize(aggregate));
}

void PandaTaintVisitor::visitInsertElementInst(InsertElementInst &I) {
    LLVMContext &ctx = I.getContext();

    Value *base = I.getOperand(0);
    Value *element = I.getOperand(1);
    Value *indexVal = I.getOperand(2);
    ConstantInt *CI = dyn_cast<ConstantInt>(indexVal);
    assert(CI);
    uint64_t index = CI->getZExtValue();
    uint64_t elementWidth = getValueSize(element);

    uint64_t dest = MAXREGSIZE * PST->getLocalSlot(&I);
    uint64_t offset = index * elementWidth;

    // First copy the aggregate value, then copy the inserted taint over
    // it. NB: inserting instructions must be swapped since we insert
    // them both after I.
    insertTaintCopyOrDelete(I,
            llvConst, const_uint64(ctx, dest + offset),
            llvConst, element,
            getValueSize(element));
    insertTaintCopyOrDelete(I,
            llvConst, constSlot(&I),
            llvConst, base,
            getValueSize(base));
}

void PandaTaintVisitor::visitShuffleVectorInst(ShuffleVectorInst &I) {
    assert(I.getType()->getBitWidth() <= 8 * MAXREGSIZE);
    insertTaintCompute(I, I.getOperand(0), I.getOperand(1), true);
}

// Unhandled
void PandaTaintVisitor::visitInstruction(Instruction &I) {
    I.dump();
    printf("Error: Unhandled instruction\n");
    assert(1==0);
}
