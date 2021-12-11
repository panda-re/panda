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
//
// Change Log:
// Added taint propagation truncation for mul X 0, mul X 1, lshr 0 , ashr 0
//  sub, sdiv, udiv, fsub, fdiv (x,x) == no taint op
//
// 15-FEB-2019:  ensure LLVM frames cleared before they are reused

#include <iostream>
#include <vector>

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/JITSymbol.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Linker/Linker.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Pass.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/IR/Instruction.h>

#include "panda/rr/rr_log.h"
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/tcg-llvm.h"

#include "addr.h"
#define SHAD_LLVM
#include "shad.h"
#include "llvm_taint_lib.h"
#include "taint_ops.h"
#include "taint2.h"
#define CONC_LVL CONC_LVL_OFF
#include "concolic.h"
#include "taint_sym_api.h"
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

PPP_PROT_REG_CB(on_after_load);
PPP_CB_BOILERPLATE(on_after_load);

PPP_PROT_REG_CB(on_after_store);
PPP_CB_BOILERPLATE(on_after_store);

}

extern bool symexEnabled;

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
static PandaTaintFunctionPass *ptfp;
extern TCGLLVMTranslator *tcg_llvm_translator;

//static RegisterPass<PandaTaintFunctionPass>
//X("PandaTaint", "Analyze each instruction in a function for taint operations");

ConstantInt *PandaTaintVisitor::const_uint64(uint64_t val) {
    switch(val) {
        case 0:
            return zeroConst;
        case 1:
            return oneConst;
        case UINT64_C(~0):
            return maxConst;
        default:
            return ConstantInt::get(int64T, val);
    }
}

ConstantInt *PandaTaintVisitor::const_uint64_ptr(void *ptr) {
    return ConstantInt::get(int64T, (uint64_t)ptr);
}

Constant *PandaTaintVisitor::const_i64p(void *ptr) {
    return ConstantExpr::getIntToPtr(const_uint64_ptr(ptr), int64P);
}

Constant *PandaTaintVisitor::const_struct_ptr(Type *ptrT, void *ptr) {
    return ConstantExpr::getIntToPtr(const_uint64_ptr(ptr), ptrT);
}

uint64_t PandaTaintVisitor::getInstructionFlags(Instruction &I)
{
    uint64_t flags = 0;

    switch(I.getOpcode()) {
        case Instruction::GetElementPtr:
            if((dyn_cast<GetElementPtrInst>(&I))->
                    hasAllConstantIndices()) {
                flags = INSTRUCTION_FLAG_GEP_HAS_CONSTANT_INDICES;
            }
            break;
        default:
            break;
    }

    return flags;
}

void taint_branch_run(Shad *shad, uint64_t src, uint64_t size, uint64_t concrete, 
        uint64_t opcode, bool from_helper)
{
    // this arg should be the register number
    Addr a = make_laddr(src / MAXREGSIZE, 0);
    bool tainted = false;
    PPP_RUN_CB(on_branch2, a, size, from_helper, &tainted);
    // if (!I) return;
    if (tainted && symexEnabled) {
        if (opcode == llvm::Instruction::Br) {
            // CINFO(llvm::errs() << "Tainted branch: " << *I << "\n");
            CINFO(std::cerr << "Concrete condition: " << concrete << "\n");
            if (shad->query_full(src)->sym &&
                shad->query_full(src)->sym->expr) {
                z3::expr expr(*shad->query_full(src)->sym->expr);
                CINFO(std::cerr << expr << "\n");
                reg_branch_pc(expr, concrete);
            }
            else {
                CINFO(std::cerr << "Tainted branch has no symbolic info\n");
            }
        }
        else if (opcode == llvm::Instruction::Switch) {
            // Switch probably extinct during tcg llvm translation
            CINFO(llvm::errs() << "Tainted switch: " << *I << "\n");
            CINFO(std::cerr << "Tracking for switch inst not implemented\n");
            assert(false);
        }
        else {
            CINFO(llvm::errs() << "Unknown opcode: " << opcode << "\n");
            assert(false);
        }

    }
}

void taint_pointer_run(uint64_t src, uint64_t ptr, uint64_t dest, bool is_store,
        uint64_t size) {

    // I think this has to be an LLVM register
    Addr ptr_addr = make_laddr(ptr / MAXREGSIZE, 0);
    if (is_store) {
        PPP_RUN_CB(on_ptr_store, ptr_addr, dest, size);
    } else {
        PPP_RUN_CB(on_ptr_load, ptr_addr, src, size);
    }
}

void taint_after_ld_run(uint64_t rega, uint64_t addr, uint64_t size) {
    Addr reg = make_laddr(rega / MAXREGSIZE, 0);
    PPP_RUN_CB(on_after_load, reg, addr, size);    
}

void taint_copyRegToPc_run(Shad *shad, uint64_t src, uint64_t size,
		bool from_helper) {
    // this arg should be the register number
    Addr a = make_laddr(src / MAXREGSIZE, 0);
    bool tainted = false;
    PPP_RUN_CB(on_indirect_jump, a, size, from_helper, &tainted);
}

static void llvmTaintLibNewModuleCallback(Module *module,
        legacy::FunctionPassManager *functionPassManager) {
    functionPassManager->add(ptfp);
}

bool PandaTaintFunctionPass::doInitialization(Module &M) {
    std::cout << "taint2: Initializing taint ops" << std::endl;

    ptfp = this;
    tcg_llvm_translator->addNewModuleCallback(
        &llvmTaintLibNewModuleCallback);
    auto &ES = tcg_llvm_translator->getExecutionSession();
    PTV->ctx = tcg_llvm_translator->getContext();

    Type *shadT = StructType::create(*PTV->ctx, "class.Shad");
    assert(shadT && "Can't resolve class.Shad");
    PTV->shadP = PointerType::getUnqual(shadT);

    Type *memlogT = StructType::create(*PTV->ctx, "struct.taint2_memlog");
    assert(memlogT && "Can't resolve struct.taint2_memlog");
    PTV->memlogP = PointerType::getUnqual(memlogT);

    PTV->int1T = Type::getInt1Ty(*PTV->ctx);
    PTV->int64T = Type::getInt64Ty(*PTV->ctx);
    PTV->int128T = Type::getInt128Ty(*PTV->ctx);
    PTV->int64P = Type::getInt64PtrTy(*PTV->ctx);
    PTV->voidT = Type::getVoidTy(*PTV->ctx);

    PTV->llvConst = PTV->const_struct_ptr(PTV->shadP, &shad->llv);
    PTV->memConst = PTV->const_struct_ptr(PTV->shadP, &shad->ram);
    PTV->grvConst = PTV->const_struct_ptr(PTV->shadP, &shad->grv);
    PTV->gsvConst = PTV->const_struct_ptr(PTV->shadP, &shad->gsv);
    PTV->retConst = PTV->const_struct_ptr(PTV->shadP, &shad->ret);
    PTV->prevBbConst = PTV->const_i64p(&shad->prev_bb);
    PTV->memlogConst = PTV->const_struct_ptr(PTV->memlogP, taint_memlog);
    PTV->zeroConst = ConstantInt::get(PTV->int64T, 0);
    PTV->oneConst = ConstantInt::get(PTV->int64T, 1);
    PTV->maxConst = ConstantInt::get(PTV->int64T, UINT64_C(~0));
    PTV->i64Of128Const = ConstantInt::get(PTV->int128T, 64);

    PTV->dataLayout = tcg_llvm_translator->getDataLayout();

    orc::SymbolMap symbols;

    vector<Type *> argTys { PTV->int64P, PTV->int64T };

    PTV->breadcrumbF = TaintOpsFunction("taint_breadcrumb",
        (void *) &taint_breadcrumb, argTys, PTV->voidT, false, ES, symbols);

    argTys = { PTV->shadP, PTV->int64T, PTV->int64T, PTV->int64T,
        PTV->int64T, PTV->int64T, PTV->int64T, PTV->int64T,
        PTV->int64T, PTV->int64T };

    PTV->mixF = TaintOpsFunction("taint_mix", (void *) &taint_mix,
        argTys, PTV->voidT, true, ES, symbols);

    argTys = { PTV->shadP, PTV->int64T, PTV->shadP, PTV->int64T,
        PTV->int64T, PTV->shadP, PTV->int64T, PTV->int64T, PTV->int64T };

    PTV->pointerF = TaintOpsFunction("taint_pointer",
        (void *) &taint_pointer, argTys, PTV->voidT, false, ES, symbols);

    argTys = { PTV->shadP, PTV->int64T, PTV->int64T, PTV->int64T,
        PTV->int64T, PTV->int64T, PTV->int64T, PTV->int64T,
        PTV->int64T, PTV->int64T, PTV->int64T };

    PTV->mix_computeF = TaintOpsFunction("taint_mix_compute",
        (void *) &taint_mix_compute, argTys, PTV->voidT, false, ES,
        symbols);

    PTV->parallel_computeF = TaintOpsFunction("taint_parallel_compute",
        (void *) &taint_parallel_compute, argTys, PTV->voidT, false, ES,
        symbols);

    argTys = { PTV->shadP, PTV->int64T, PTV->int64T, PTV->int64T,
        PTV->int64T, PTV->int64T, PTV->int64T, PTV->int64T,
        PTV->int64T, PTV->int64T, PTV->int64T, PTV->int64T };

    PTV->mul_computeF = TaintOpsFunction("taint_mul_compute",
        (void *) &taint_mul_compute, argTys, PTV->voidT, false, ES,
        symbols);

    argTys = { PTV->shadP, PTV->int64T, PTV->shadP, PTV->int64T,
        PTV->int64T, PTV->int64T, PTV->int64T, PTV->int64T };

    PTV->copyF = TaintOpsFunction("taint_copy", (void *) &taint_copy,
        argTys, PTV->voidT, true, ES, symbols);

    argTys = { PTV->shadP, PTV->int64T, PTV->int64T, PTV->int64T,
        PTV->int64T, PTV->int64T };

    PTV->sextF = TaintOpsFunction("taint_sext", (void *) &taint_sext,
        argTys, PTV->voidT, false, ES, symbols);

    argTys = { PTV->shadP, PTV->int64T, PTV->int64T, PTV->int64T };

    PTV->selectF = TaintOpsFunction("taint_select", (void *) &taint_select,
        argTys, PTV->voidT, true, ES, symbols);

    argTys = { PTV->int64T, PTV->int64T, PTV->shadP, PTV->int64T,
        PTV->shadP, PTV->shadP, PTV->shadP, PTV->int64T, PTV->int64T,
        PTV->int1T };

    PTV->host_copyF = TaintOpsFunction("taint_host_copy",
        (void *) &taint_host_copy, argTys, PTV->voidT, false, ES, symbols);

    argTys = { PTV->int64T, PTV->int64T, PTV->int64T, PTV->shadP,
        PTV->shadP, PTV->int64T, PTV->int64T };

    PTV->host_memcpyF = TaintOpsFunction("taint_host_memcpy",
        (void *) &taint_host_memcpy, argTys, PTV->voidT, false, ES,
        symbols);

    argTys = { PTV->int64T, PTV->int64T, PTV->shadP, PTV->shadP,
        PTV->int64T, PTV->int64T };

    PTV->host_deleteF = TaintOpsFunction("taint_host_delete",
        (void *) &taint_host_delete, argTys, PTV->voidT, false, ES,
        symbols);

    argTys = { PTV->shadP };

    PTV->push_frameF = TaintOpsFunction("taint_push_frame",
        (void *) &taint_push_frame, argTys, PTV->voidT, false, ES, symbols);

    PTV->pop_frameF = TaintOpsFunction("taint_pop_frame",
        (void *) &taint_pop_frame, argTys, PTV->voidT, false, ES, symbols);

    PTV->reset_frameF = TaintOpsFunction("taint_reset_frame",
        (void *) &taint_reset_frame, argTys, PTV->voidT, false, ES,
        symbols);

    argTys = { PTV->memlogP };

    PTV->memlog_popF = TaintOpsFunction("taint_memlog_pop",
        (void *) &taint_memlog_pop, argTys, PTV->int64T, false, ES,
        symbols);

    argTys = { PTV->shadP, PTV->int64T, PTV->int64T };

    PTV->deleteF = TaintOpsFunction("taint_delete",
        (void *) &taint_delete, argTys, PTV->voidT, false, ES, symbols);
        
    argTys = { PTV->shadP, PTV->int64T, PTV->int64T, PTV->int64T,
                PTV->int64T, PTV->int1T };

    PTV->branch_runF = TaintOpsFunction("taint_branch_run",
        (void *) &taint_branch_run, argTys, PTV->voidT, false, ES, symbols);

    argTys = { PTV->shadP, PTV->int64T, PTV->int64T, PTV->int1T };

    PTV->copyRegToPc_runF = TaintOpsFunction("taint_copyRegToPc_run",
        (void *) &taint_copyRegToPc_run, argTys, PTV->voidT, false, ES,
        symbols);
    
    argTys = { PTV->int64T, PTV->int64T, PTV->int64T };

    PTV->afterLdF = TaintOpsFunction("taint_after_ld_run",
        (void *) &taint_after_ld_run, argTys, PTV->voidT, false, ES, symbols);

    if(tcg_llvm_translator->getJit()->getMainJITDylib().define(
            orc::absoluteSymbols(std::move(symbols)))) {
        assert(false && "Cannot add symbols to JITDylib");
    }

    std::cout << "taint2: Done initializing taint transformation." <<
        std::endl;

    return true;
}

bool PandaTaintFunctionPass::runOnFunction(Function &F) {

#ifdef TAINT2_DEBUG
    //printf("\n\n%s\n", F.getName().str().c_str());
#endif

    if (F.getName().startswith("taint") ||
            F.front().front().getMetadata("tainted")) { // already processed!!
        return false;
    }

    // Avoid Instrumentation in helper functions
    if (F.getName().startswith("helper_panda_")) {
        return false;
    }

    //printf("Processing entry BB...\n");
    PTV->visitFunction(F);
    for (BasicBlock &BB : F) {
        vector<Instruction *> insts;
        for (Instruction &I : BB) {
            insts.push_back(&I);
        }
        PTV->visitBasicBlock(BB);
        for (Instruction *I : insts) {
            PTV->visit(I);
        }
    }

#ifdef TAINT2_DEBUG
    //F.dump();
    /*std::string err;
    if (F.getName().startswith("tcg-llvm-tb-")) {
        std::cerr << "Verifying " << F.getName().str() << std::endl;
        verifyModule(*F.getParent(), AbortProcessAction, &err);
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
        } else {
            AI->setName("");
            CreateFunctionSlot(AI);
        }
    }

    // Add all of the basic blocks and instructions with no names.
    for (BasicBlock &BB : *TheFunction) {
        CreateFunctionSlot(&BB);
        for (Instruction &I : BB) {
            if (!I.getType()->isVoidTy()) {
                CreateFunctionSlot(&I);
            }
        }
    }
    FunctionProcessed = true;
}

unsigned PandaSlotTracker::CreateFunctionSlot(const Value *V) {
    unsigned DestSlot = fNext++;
    fMap[V] = DestSlot;
    return DestSlot;
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
    return const_uint64(getValueSize(V));
}

bool inline_taint = false;

void PandaTaintVisitor::inlineCall(CallInst *CI) {
    assert(CI && "CallInst can't be null");
    if (inline_taint) {
        InlineFunctionInfo IFI;
        if (!InlineFunction(*CI, IFI).isSuccess()) {
            printf("Inlining failed!\n");
        }
    }
}

Function *PandaTaintVisitor::getFunction(Module *m,
        TaintOpsFunction &func) {

    Function *F=m->getFunction(func.getName());

    if(!F) {
        FunctionType *functionT = FunctionType::get(
            func.getRetTy(), func.getArgTys(), func.hasVarArgs());

        F = Function::Create(functionT, Function::ExternalLinkage,
            func.getName(), m);
    }

    return F;
}

CallInst *PandaTaintVisitor::insertCall(Instruction &I,
        TaintOpsFunction &func, vector<Value *> &args, bool before,
        bool tryInline) {

    Module *m=I.getModule();
    Function *F=getFunction(m, func);

    CallInst *CI = CallInst::Create(F, args);
    assert(CI && "Couldn't create call inst!!");

    if(before) {
        CI->insertBefore(&I);
    } else {
        CI->insertAfter(&I);
    }

    if (tryInline && (F->size() == 1)) { // no control flow
        inlineCall(CI);
    }

    return CI;
}

void PandaTaintVisitor::insertCallAfter(Instruction &I,
        TaintOpsFunction &func, vector<Value *> &args) {
    insertCall(I, func, args, false, true);
}

void PandaTaintVisitor::insertCallBefore(Instruction &I,
        TaintOpsFunction &func, vector<Value *> &args) {
    insertCall(I, func, args, true, true);
}

Constant *PandaTaintVisitor::constSlot(Value *value) {
    assert(value && !isa<Constant>(value));
    int slot = PST->getLocalSlot(value);
    assert(slot >= 0);
    return const_uint64(MAXREGSIZE * slot);
}

Constant *PandaTaintVisitor::constWeakSlot(Value *value) {
    assert(value);
    int slot = PST->getLocalSlot(value);
    assert(isa<Constant>(value) || slot >= 0);
    return const_uint64(slot < 0 ? UINT64_C(~0) : MAXREGSIZE * slot);
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
    Function *F = BB.getParent();
    assert(F);

    if (&F->front() == &BB && F->getName().startswith("tcg-llvm-tb-")) {
        // Entry block.
        // This is a single guest BB, so callstack should be empty.
        // Insert call to reset llvm frame and clear it for use
        // N.B.  As inserting both calls BEFORE the node, need to insert the
        // reset second so it gets executed first (or will end up clearing an
        // abandoned frame instead of one about to use).

        // Insert call to clear llvm shadow mem.
        vector<Value *> args { llvConst, zeroConst,
            const_uint64(MAXREGSIZE * PST->getMaxSlot()) };

        insertCallBefore(*BB.getFirstNonPHI(), deleteF, args);

        // Insert call to reset the frame before clearing the llvm shadow mem
        args = { llvConst };
        assert(BB.getFirstNonPHI());
        insertCallBefore(*BB.getFirstNonPHI(), reset_frameF, args);

        // Two things: Insert "tainted" metadata.
        MDNode *md = MDNode::get(*ctx, ArrayRef<Metadata *>());

        BB.front().setMetadata("tainted", md);
    } else {
        // At end of BB, log where we just were.
        // But only if this isn't the first block of a TB.
        vector<Value *> args {
            prevBbConst, constSlot(&BB)
        };
        assert(BB.getTerminator() != NULL);
        insertCallBefore(*BB.getTerminator(), breadcrumbF, args);
    }
}

// Insert a log pop after this instruction.
CallInst *PandaTaintVisitor::insertLogPop(Instruction &after) {

    vector<Value *> args { memlogConst };
    return insertCall(after, memlog_popF, args, false, false);
}

void PandaTaintVisitor::insertTaintCopy(Instruction &I, Constant *shad_dest,
        Value *dest, Constant *shad_src, Value *src, uint64_t size) {

    // If these are llvm regs we have to interpret them as slots.
    if (shad_dest == llvConst && !isa<Constant>(dest)) {
        dest = constSlot(dest);
    }
    if (shad_src == llvConst && !isa<Constant>(src)) {
        src = constSlot(src);
    }

    insertTaintBulk(I, shad_dest, dest, shad_src, src, size);
}

// load llreg from addr
// or store llreg to addr 
// both logically after taint transfer has occurred
// NB: val is llvm register that is dest of store or that is source of load
void PandaTaintVisitor::insertAfterTaintLd(Instruction &I,
       Value *val, Value *ptr, uint64_t size) {
    Instruction *cast = CastInst::CreateZExtOrBitCast(ptr, int64T, "", &I);
    vector<Value *> args { constSlot(val), cast, const_uint64(size) };
    insertCallAfter(I, afterLdF, args);    
}

uint64_t PandaTaintVisitor::ICmpPredicate(Instruction &I) {
    if (I.getOpcode() == llvm::Instruction::ICmp) {;
        auto *CI = llvm::dyn_cast<llvm::ICmpInst>(&I);
        return CI->getPredicate();
    }
    return -1;
}

void PandaTaintVisitor::addInstructionDetailsToArgumentList(
    vector<Value *> &args, Instruction &I, Instruction *before) {

    auto opc = I.getOpcode();

    // taint_copy()/update_cb() (taint_ops.cpp) assumes that there are 
    // no valid llvm instructions with an opcode of zero
    assert(opc != 0);

    Constant *opcode = const_uint64(opc);
    Constant *instruction_flags = const_uint64(getInstructionFlags(I));

    args.push_back(opcode);
    args.push_back(instruction_flags);

    switch(opc) {
        
        case llvm::Instruction::Call: {
            Function *calledF = dyn_cast<CallInst>(&I)->getCalledFunction();
            if (!calledF) {
                args.push_back(zeroConst);
                return;
            }
            switch (calledF->getIntrinsicID()) {
                case Intrinsic::bswap:
                // case Intrinsic::ceil:
                // case Intrinsic::ctlz:
                // case Intrinsic::cttz:
                // case Intrinsic::fabs:
                // case Intrinsic::floor:
                // case Intrinsic::rint:
                    args.push_back(const_uint64(I.getNumOperands()));
                    break;
                default:
                    args.push_back(zeroConst);
                    return;
            }
            break;  // outter switch
        }  
        // If taint_ops aren't going to act on the operands, don't bother
        // passing them to the taint_ops function.
        case llvm::Instruction::Trunc:
        case llvm::Instruction::ZExt:
        case llvm::Instruction::IntToPtr:
        case llvm::Instruction::PtrToInt:
        case llvm::Instruction::BitCast:
        case llvm::Instruction::SExt:
        case llvm::Instruction::Store:
        case llvm::Instruction::Load:
        case llvm::Instruction::ExtractValue:
        case llvm::Instruction::InsertValue:
        case llvm::Instruction::FAdd:
        case llvm::Instruction::FSub:
        case llvm::Instruction::FMul:
        case llvm::Instruction::FDiv:
        case llvm::Instruction::FRem:
        // case llvm::Instruction::ICmp:
        case llvm::Instruction::FCmp:
            args.push_back(zeroConst);
            return;
        default:
            args.push_back(const_uint64(I.getNumOperands()));
            break;
    }

    for(auto it = I.value_op_begin(); it != I.value_op_end(); it++) {
        // do not pass non-constant Instruction operands this way, or
        // the taint operations won't be able to distinguish between LLVM
        // constants and non-constants (fortunately, the taint operations
        // don't really need the values of the non-constant operands, they just
        // need to know where they are)
        if (isa<Constant>(*it)) {
            Instruction *lshr;
            unsigned size_in_bits = it->getType()->getScalarSizeInBits();
            args.push_back(const_uint64(size_in_bits));
            switch(size_in_bits) {
                case 128:
                    args.push_back(new TruncInst(*it, int64T, "", before));
                    // operands to LSHR must be same size (128 bits in this case)
                    lshr = BinaryOperator::CreateLShr(*it, i64Of128Const);
                    lshr->insertBefore(before);
                    args.push_back(new TruncInst(lshr, int64T, "", before));
                    break;
                case 0:
                    // assert(false && "Operand has no size?");
                    args.push_back(zeroConst);
                    break;
                default:
                    args.push_back(*it);
                    break;
            }
        } else {
            args.push_back(zeroConst);
        }
    }
}

void PandaTaintVisitor::insertTaintBulk(Instruction &I,
        Constant *shad_dest, Value *dest, Constant *shad_src, Value *src,
        uint64_t size) {

    CallInst *srcCI = NULL;
    CallInst *destCI = NULL;

    if (!src) { // grab from memlog. Src will be below dest.
        assert(shad_src == memConst);
        src = (srcCI = insertLogPop(I));
    }

    if (!dest) { // grab from memlog. Dest will be on top of stack.
        assert(shad_dest == memConst);
        dest = (destCI = insertLogPop(I));
    }

    Instruction *after = srcCI ? srcCI : (destCI ? destCI : &I);
    Instruction *next = after->getNextNode();

    vector<Value *> args { shad_dest, dest, shad_src, src,
        const_uint64(size) };

    addInstructionDetailsToArgumentList(args, I, next);

    insertCallBefore(*next, copyF, args);

    if (srcCI) {
        inlineCall(srcCI);
    }

    if (destCI) {
        inlineCall(destCI);
    }
}

// Make sure slot integers are slot integers! Will not fix for you.
void PandaTaintVisitor::insertTaintCopyOrDelete(Instruction &I,
        Constant *shad_dest, Value *dest, Constant *shad_src, Value *src,
        uint64_t size) {

    if (isa<Constant>(src)) {
        vector<Value *> args { shad_dest, dest, const_uint64(size) };
        insertCallAfter(I, deleteF, args);
    } else {
        insertTaintBulk(I, shad_dest, dest, shad_src, constSlot(src), size);
    }
}

void PandaTaintVisitor::insertTaintPointer(Instruction &I,
        Value *ptr, Value *val, bool is_store) {
    CallInst *popCI = insertLogPop(I);
    Value *addr = popCI;

    Constant *shad_dest = is_store ? memConst : llvConst;
    Value *dest = is_store ? addr : constSlot(val);

    Constant *shad_src = is_store ? llvConst : memConst;
    // If we're storing a constant, still do a taint mix.
    Value *src = is_store ? constWeakSlot(val) : addr;
    vector<Value *> args { shad_dest, dest, llvConst, constSlot(ptr),
        const_uint64(getValueSize(ptr)), shad_src, src,
        const_uint64(getValueSize(val)), const_uint64(is_store) };

    insertCallAfter(*popCI, pointerF, args);

    inlineCall(popCI);
}


void PandaTaintVisitor::insertTaintMix(Instruction &I, Value *src) {
    insertTaintMix(I, &I, src);
}

void PandaTaintVisitor::insertTaintMix(Instruction &I, Value *dest,
        Value *src) {
    if (isa<Constant>(src)) return;

    if (!dest) dest = &I;
    Constant *dest_size = const_uint64(getValueSize(dest));
    Constant *src_size = const_uint64(getValueSize(src));

    /* Provide concrete value if possible */
    Value *val = const_uint64(0);
    if (isa<CmpInst>(&I)) {
        if (src->getType()->isIntegerTy())
            val = CastInst::CreateIntegerCast(src, Type::getInt64Ty(*ctx), false, "", &I);
        else if (src->getType()->isPointerTy())
            val = CastInst::CreatePointerCast(src, Type::getInt64Ty(*ctx), "", &I);
    }

    vector<Value *> args { llvConst, constSlot(dest), dest_size,
        constSlot(src), src_size,
        val, const_uint64(ICmpPredicate(I)) };

    Instruction *next = I.getNextNode();

    addInstructionDetailsToArgumentList(args, I, next);
    
    insertCallBefore(*next, mixF, args);
}

void PandaTaintVisitor::insertTaintCompute(Instruction &I, Value *src1,
        Value *src2, bool is_mixed) {
    insertTaintCompute(I, &I, src1, src2, is_mixed);
}

// This function is used to guarantee that the JIT optimizer doesn't optimize
// away I.  If the result of I is only consumed by another LLVM instruction,
// the optimizer may combine those two instructions.  This instruction
// combination hasn't been investigated fully to ensure it doesn't adversely
// affect taint propagation.  By passing the instruction result to a taint ops
// function, the optimizer won't optimize away I.  Ultimately the taint ops
// function ignores the instruction result (see taint_mix_compute
// as an example.)
Instruction *PandaTaintVisitor::getResult(Instruction *I) {

    Instruction *iResult = I;
    Instruction *next = iResult->getNextNode();

    // Extract result (or an element of the result for vector operations)
    // and pass to taint ops function to prevent JIT optimizer from
    // optimizing out I
    if(iResult->getType()->isVectorTy()) {
        iResult = ExtractElementInst::Create(iResult, const_uint64(0), "",
            next);
    }

    if(iResult->getType()->isAggregateType()) {
        iResult = ExtractValueInst::Create(iResult, ArrayRef<unsigned>(0), "", next);
    }

    if(iResult->getType()->isFloatingPointTy()) {
        iResult = new FPToSIInst(iResult, int64T, "", next);
    } else if(!iResult->getType()->isIntegerTy(64)) {
        iResult = CastInst::CreateIntegerCast(iResult, int64T, false, "", next);
    }

    return iResult;
}

// Compute operations
void PandaTaintVisitor::insertTaintCompute(Instruction &I, Value *dest,
        Value *src1, Value *src2, bool is_mixed) {

    if (!dest) dest = &I;

    if (isa<Constant>(src1) && isa<Constant>(src2)) {
        return; // do nothing.
    } else if (isa<Constant>(src1) || isa<Constant>(src2)) {
        Value *tainted = isa<Constant>(src1) ? src2 : src1;
        if (is_mixed) {
            insertTaintMix(I, tainted);
        } else {
            insertTaintCopy(I, llvConst, dest, llvConst, tainted,
                getValueSize(src2));
        }
        return;
    }

    TaintOpsFunction &func = is_mixed ? mix_computeF : parallel_computeF;

    Instruction *iResult = getResult(&I);

    if (!is_mixed) {
        assert(getValueSize(dest) == getValueSize(src1));
    }
    assert(getValueSize(src1) == getValueSize(src2));

    Constant *dest_size = const_uint64(getValueSize(dest));
    Constant *src_size = const_uint64(getValueSize(src1));
    Constant *opcode = const_uint64(I.getOpcode());

    unsigned src1BitWidth = src1->getType()->getPrimitiveSizeInBits();
    unsigned src2BitWidth = src2->getType()->getPrimitiveSizeInBits();
    Instruction *val1, *val2;
    // The argument could be pointers too
    if (src1->getType()->isPointerTy())
        val1 = llvm::CastInst::CreatePointerCast(src1,
            llvm::Type::getInt64Ty(*ctx), "", &I);

    else if (src1BitWidth <= 64)
        val1 = llvm::CastInst::CreateZExtOrBitCast(src1,
            llvm::Type::getInt64Ty(*ctx), "", &I);
    else
        val1 = llvm::CastInst::CreateTruncOrBitCast(src1,
            llvm::Type::getInt64Ty(*ctx), "", &I);

    if (src2->getType()->isPointerTy())
        val2 = llvm::CastInst::CreatePointerCast(src2,
            llvm::Type::getInt64Ty(*ctx), "", &I);
    else if (src2BitWidth <= 64)
        val2 = llvm::CastInst::CreateZExtOrBitCast(src2,
            llvm::Type::getInt64Ty(*ctx), "", &I);
    else
        val2 = llvm::CastInst::CreateTruncOrBitCast(src2,
            llvm::Type::getInt64Ty(*ctx), "", &I);

    vector<Value *> args { llvConst, constSlot(dest), dest_size,
        constSlot(src1), constSlot(src2), src_size,
        opcode, iResult, val1, val2, const_uint64(ICmpPredicate(I)) };

    insertCallAfter(*iResult, func, args);
}

// if we multiply tainted_val * 0, and 0 is untainted,
// the result is no longer controlable, so do not propagate taint
// if tainted_val * 1, do a parallel compute
void PandaTaintVisitor::insertTaintMul(Instruction &I, Value *dest,
        Value *src1, Value *src2) {

    if (!dest) dest = &I;

    const uint64_t maxBitWidth = 128;
    unsigned src1BitWidth = src1->getType()->getPrimitiveSizeInBits();
    unsigned src2BitWidth = src1->getType()->getPrimitiveSizeInBits();
    if ((src1BitWidth > maxBitWidth) || (src2BitWidth > maxBitWidth)) {
        printf("warning: encountered a value greater than %lu bits - not "
               "attempting to propagate taint through mul instruction\n",
               maxBitWidth);
        return;
    }

    if (isa<Constant>(src1) && isa<Constant>(src2)) {
        return; // do nothing, should not happen in optimized code
    } else if (isa<Constant>(src1)) {
        //one oper is const (necessarily not tainted), so do a static check
        if (ConstantInt* CI = dyn_cast<ConstantInt>(src1)){
            if (CI->isZero()) return;
        } else if (ConstantFP* CFP = dyn_cast<ConstantFP>(src1)){
            if (CFP->isZero()) return;
        }
        insertTaintMix(I, src2);
        return;
    } else if (isa<Constant>(src2)) {
        if (ConstantInt* CI = dyn_cast<ConstantInt>(src2)){
            if (CI->isZero()) return;
        } else if (ConstantFP* CFP = dyn_cast<ConstantFP>(src2)){
            if (CFP->isZero()) return;
        }
        insertTaintMix(I, src1);
        return;
    }
    //neither are constants, but one can be a dynamic untainted zero
    assert(getValueSize(src1) == getValueSize(src2));
    Constant *dest_size = const_uint64(getValueSize(dest));
    Constant *src_size = const_uint64(getValueSize(src1));

    IRBuilder<> b(*ctx);
    Instruction *nextI = I.getNextNode();
    b.SetInsertPoint(nextI);
    Value *src1slot = constSlot(src1);
    Value *src2slot = constSlot(src2);
    Value *dslot = constSlot(dest);

    Value *arg1_lo = NULL;
    Value *arg1_hi = NULL;
    if (64 < src1BitWidth) {
        arg1_lo = b.CreateTrunc(src1, int64T);
        arg1_hi = b.CreateTrunc(b.CreateLShr(src1, 64), int64T);
    } else {
        arg1_lo = b.CreateSExtOrBitCast(src1, int64T);
        Value *tmp = b.CreateTrunc(b.CreateLShr(arg1_lo, 63), int1T);
        arg1_hi = b.CreateSelect(tmp, maxConst, zeroConst);
    }

    Value *arg2_lo = NULL;
    Value *arg2_hi = NULL;
    if (64 < src1BitWidth) {
        arg2_lo = b.CreateTrunc(src2, int64T);
        arg2_hi = b.CreateTrunc(b.CreateLShr(src2, 64), int64T);
    } else {
        arg2_lo = b.CreateSExtOrBitCast(src2, int64T);
        Value *tmp = b.CreateTrunc(b.CreateLShr(arg2_lo, 63), int1T);
        arg2_hi = b.CreateSelect(tmp, maxConst, zeroConst);
    }

    Value *iResult = getResult(&I);

    vector<Value *> args { llvConst, dslot, dest_size, src1slot, src2slot,
        src_size, arg1_lo, arg1_hi, arg2_lo, arg2_hi,
        const_uint64(I.getOpcode()), iResult };

    Function *mulCompF = getFunction(I.getModule(), mul_computeF);

    b.CreateCall(mulCompF, args);
}

void PandaTaintVisitor::insertTaintSext(Instruction &I, Value *src) {

    Value *dest = &I;
    Constant *dest_size = const_uint64(getValueSize(dest));
    Constant *src_size = const_uint64(getValueSize(src));

    vector<Value *> args { llvConst,
        constSlot(dest), dest_size, constSlot(src), src_size, const_uint64(I.getOpcode()) };

    insertCallAfter(I, sextF, args);
}

void PandaTaintVisitor::insertTaintSelect(Instruction &after, Value *dest,
        Value *selector, vector<pair<Value *, Value *>> &selections) {

    // Needs implementation
    Constant *dest_size = const_uint64(getValueSize(dest));

    vector<Value *> args { llvConst, constSlot(dest), dest_size, selector };

    for (auto &selection : selections) {
        args.push_back(selection.first);
        args.push_back(selection.second);
    }
    args.push_back(maxConst);
    args.push_back(maxConst);
    insertCallAfter(after, selectF, args);
}

void PandaTaintVisitor::insertTaintDelete(Instruction &I, Constant *shad,
        Value *dest, Value *size) {

    CallInst *destCI = NULL;

    if (shad == llvConst) {
        dest = constSlot(dest);
    }
    if (shad == memConst && dest == NULL) {
        dest = (destCI = insertLogPop(I));
    }

    vector<Value *> args{ shad, dest, size };

    insertCallAfter(destCI ? *destCI : I, deleteF, args);
}

void PandaTaintVisitor::insertTaintBranch(Instruction &I, Value *cond) {
    if (isa<Constant>(cond)) {
        return;
    }

    // First block is just checking exit request. don't instrument!
    BasicBlock *BB = I.getParent();
    assert(BB);
    Function *F = BB->getParent();
    assert(F);
    if (BB == &F->front() && F->getName().startswith("tcg-llvm-tb")) {
        return;
    }

    Instruction *Cast = llvm::CastInst::CreateZExtOrBitCast(cond, 
            llvm::Type::getInt64Ty(*ctx), "", &I);
    vector<Value *> args { llvConst,
        constSlot(cond), const_uint64(getValueSize(cond)), Cast,
		const_uint64(I.getOpcode()),
        ConstantInt::get(int1T, ptfp->processingHelper()) };

    insertCallBefore(I, branch_runF, args);
}

void PandaTaintVisitor::insertTaintQueryNonConstPc(Instruction &I,
        Value *new_pc) {

    if (isa<Constant>(new_pc)) {
        return;
    }

    vector<Value *> args { llvConst,
        constSlot(new_pc), const_uint64(getValueSize(new_pc)),
		ConstantInt::get(int1T, ptfp->processingHelper())
    };

    insertCallBefore(I, copyRegToPc_runF, args);
}

// Terminator instructions
void PandaTaintVisitor::visitReturnInst(ReturnInst &I) {

    Value *retV = I.getReturnValue();

    if (!retV) {
        return;
    }

    if (isa<Constant>(retV)) {
        // delete return taint.
        vector<Value *> args { retConst, zeroConst,
            const_uint64(MAXREGSIZE) };
        insertCallBefore(I, deleteF, args);
    } else {
        vector<Value *> args { retConst, zeroConst,
            llvConst, constSlot(retV), const_uint64(getValueSize(retV)),
            zeroConst, zeroConst, zeroConst };
        insertCallBefore(I, copyF, args);
    }

    visitTerminator(I);
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
void PandaTaintVisitor::visitTerminator(Instruction &I) {
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
    if (!isa<ConstantInt>(AI->getOperand(1))) {
        return false;
    }

    LoadInst *LI = dyn_cast<LoadInst>(AI->getOperand(0));
    if (!LI) {
        return false;
    }

    Addr addr = Addr();
    if (getAddr(LI->getPointerOperand(), addr) && addr.flag == IRRELEVANT) {
        return true;
    }

    return false;
}

// Binary operators
void PandaTaintVisitor::visitBinaryOperator(BinaryOperator &I) {

    bool is_mixed = false;

    if (I.getMetadata("host")) {
        return;
    }

    switch (I.getOpcode()) {
        case Instruction::LShr:
        case Instruction::AShr:
        case Instruction::Shl:
            {
                // operand 1 is the number of bits to shift
                // if shifting 0 bits, then you're not really shifting at all, so
                // don't propagate the taint that may be in one byte to them all
                Value *op1 = I.getOperand(1);
                if (isa<Constant>(op1)) {
                    if (intValue(op1) != 0) {
                        is_mixed = true;
                    }
                } else {
                    is_mixed = true;
                }
            }
            break;

        case Instruction::Mul:
        case Instruction::FMul:
            insertTaintMul(I, &I, I.getOperand(0), I.getOperand(1));
            return;
        case Instruction::Add:
            {
                BinaryOperator *AI = dyn_cast<BinaryOperator>(&I);
                assert(AI);
                if (isCPUStateAdd(AI)) {
                    return;
                } else if (isIrrelevantAdd(AI)) {
                    return;
                }
            }
            is_mixed = true;
            break;
        case Instruction::Sub:
        case Instruction::UDiv:
        case Instruction::SDiv:
        case Instruction::FDiv:
        case Instruction::FSub:
            // these operations have exactly 1 result if operand is repeated, no need to taint
            if (I.getOperand(0) == I.getOperand(1)) {
                return;
            }
            is_mixed = true;
            break;
        case Instruction::FAdd:
        case Instruction::URem:
        case Instruction::SRem:
        case Instruction::FRem:
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
    if (PST->getLocalSlot(V) == 0) {
        return true;
    }
    PtrToIntInst *P2II = dyn_cast<PtrToIntInst>(V);
    if (P2II == nullptr) {
        return false;
    }
    return PST->getLocalSlot(P2II->getOperand(0)) == 0;
}

bool PandaTaintVisitor::isCPUStateAdd(BinaryOperator *AI) {
    return (AI->getOpcode() == Instruction::Add) && isEnvPtr(AI->getOperand(0));
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
#elif defined (TARGET_MIPS)
    if (contains_offset(active_tc.gpr)){
        addrOut.typ = GREG;
        addrOut.val.gr = (offset - cpu_off(active_tc.gpr)) / cpu_size(active_tc.gpr[0]);
        addrOut.off = (offset - cpu_off(active_tc.gpr)) % cpu_size(active_tc.gpr[0]);
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

Value *PandaTaintVisitor::ptrToInt(Value *ptr, Instruction &I) {
    assert(ptr);

    IntToPtrInst *I2PI = dyn_cast<IntToPtrInst>(ptr);
    if (I2PI) {
        Value *orig = I2PI->getOperand(0);
        assert(orig->getType() == int64T);
        return orig;
    } else {
        return new PtrToIntInst(ptr, int64T, "", &I);
    }
}

void PandaTaintVisitor::insertStateOp(Instruction &I) {
    // These are loads/stores from CPUState etc.
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
#elif defined(TARGET_MIPS)
        if (ptrAddr == cpu_off(active_tc.PC) && isStore) {
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
        Value *dest = isStore ? const_uint64(ptrAddr) : val;
        Value *src = isStore ? val : const_uint64(ptrAddr);
        if (isStore && isa<Constant>(val)) {
            insertTaintDelete(I, destConst, dest, const_uint64(size));
        } else {
            insertTaintCopy(I, destConst, dest, srcConst, src, size);
        }
    } else if (isa<Constant>(val) && isStore) {
        vector<Value *> args { const_uint64_ptr(first_cpu->env_ptr),
            ptrToInt(ptr, I), grvConst,
            gsvConst, const_uint64(size),
            const_uint64(sizeof(target_ulong))
        };

        insertCallAfter(I, host_deleteF, args);
    } else if (isa<AllocaInst>(ptr) && isStore) {
        if (isa<Constant>(val)) {
            insertTaintDelete(I, llvConst, ptr, const_uint64(size));
        } else {
            insertTaintCopy(I, llvConst, ptr, llvConst, val, size);
        }
    } else if (isa<AllocaInst>(ptr)) {
        insertTaintCopy(I, llvConst, val, llvConst, ptr, size);
    } else {
        vector<Value *> args { const_uint64_ptr(first_cpu->env_ptr),
            ptrToInt(ptr, I), llvConst,
            constSlot(val), grvConst,
            gsvConst,
            memConst,
            const_uint64(size), const_uint64(sizeof(target_ulong)),
            ConstantInt::get(int1T, isStore) };

        insertCallAfter(I, host_copyF, args);
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
 * the pointer to the CPU state.  Because of this, we will just delete taint in
 * later ops at the destination LLVM register.
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
    insertTaintCopy(I, llvConst, &I, llvConst, src,
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
    assert(I.getParent()->getFirstNonPHI() != NULL);

    LoadInst *LI = new LoadInst(int64T, prevBbConst, "",
        I.getParent()->getFirstNonPHI());

    vector<pair<Value *,Value *>> selections;
    for (unsigned i = 0; i < I.getNumIncomingValues(); ++i) {
        Constant *value = constWeakSlot(I.getIncomingValue(i));
        Constant *select = constSlot(I.getIncomingBlock(i));
        selections.push_back(std::make_pair(value, select));
    }
    insertTaintSelect(*LI, &I, LI, selections);
}

void PandaTaintVisitor::visitMemCpyInst(MemTransferInst &I) {
    Value *dest = I.getDest();
    Value *src = I.getSource();
    Value *size = I.getLength();
    PtrToIntInst *destP2II = new PtrToIntInst(dest, int64T, "", &I);
    PtrToIntInst *srcP2II = new PtrToIntInst(src, int64T, "", &I);
    assert(destP2II && srcP2II);

    vector<Value *> args {
        const_uint64_ptr(first_cpu->env_ptr), destP2II, srcP2II,
        grvConst,
        gsvConst, size,
        const_uint64(sizeof(target_ulong)) };

    insertCallAfter(I, host_memcpyF, args);
}

void PandaTaintVisitor::visitMemMoveInst(MemTransferInst &I) {
    printf("taint2: Warning: MemMove unhandled!  Taint may be lost!\n");
}

void PandaTaintVisitor::visitMemSetInst(MemSetInst &I) {

    Value *dest = I.getDest();
    Value *size = I.getLength();
    if (isa<Constant>(I.getValue())) {
        PtrToIntInst *P2II = new PtrToIntInst(dest, int64T, "", &I);
        assert(P2II);

        vector<Value *> args { const_uint64_ptr(first_cpu->env_ptr), P2II,
            grvConst, gsvConst, size, const_uint64(sizeof(target_ulong)) };

        insertCallAfter(I, host_deleteF, args);
    } else {
        printf("taint2: Warning: MemSet with non-constant fill unhandled!  "
                "Taint may be lost!\n");
    }
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

void PandaTaintVisitor::visitCallInst(CallInst &I) {
    Function *calledF = I.getCalledFunction();
    Value *calledV = I.getCalledOperand();
    assert(calledV);

    Type *valueType = calledV->getType();
    FunctionType *callType;
    // If not a function type, it's a function pointer.
    if (!(callType = dyn_cast<FunctionType>(valueType))) {
        PointerType *pointerType = dyn_cast<PointerType>(valueType);
        assert(pointerType && pointerType->getElementType()->isFunctionTy());
        callType = dyn_cast<FunctionType>(pointerType->getElementType());
        if (!calledF) {
            return;
            //printf("calledF = %d\n", (bool)calledF);
        }
    }
    assert(callType && callType->isFunctionTy());

    if (calledF) {
        std::string calledName = calledF->getName().str();

        switch (calledF->getIntrinsicID()) {
            case Intrinsic::uadd_with_overflow:
            case Intrinsic::uadd_sat:
            case Intrinsic::sadd_sat:
            case Intrinsic::ssub_sat:
            case Intrinsic::usub_sat:
                insertTaintCompute(I, I.getArgOperand(0), I.getArgOperand(1), true);
                return;
            case Intrinsic::bswap:
            case Intrinsic::ceil:
            case Intrinsic::ctlz:
            case Intrinsic::cttz:
            case Intrinsic::fabs:
            case Intrinsic::floor:
            case Intrinsic::rint:
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
        if (calledF->getName().startswith("helper_panda_")) {
            return;
        } else if (calledF->getName().startswith("taint")) {
            return;
        } else if (calledName == "cpu_loop_exit") {
            return;
        } else if (ldFuncs.count(calledName) > 0) {
            Value *ptr = I.getArgOperand(1);
            // insertAfterTaintLd mainly used for tainted_mmio
            //   where we could expect ptr to be non-constant 
            if (!isa<Constant>(ptr)) {
                insertAfterTaintLd(I, &I, ptr, getValueSize(&I));
            }
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
                insertTaintDelete(I, memConst, NULL, const_uint64(getValueSize(val)));
            } else {
                insertTaintCopy(I, memConst, NULL, llvConst, val, getValueSize(val));
            }
            return;
#ifdef TARGET_I386
        } else if (calledName == "helper_outb") {

            // Call taint_copy to copy taint from LLVM to the EAX register. We
            // have to copy taint here to ensure that EAX becomes tainted.
            vector<Value *> args { grvConst, const_uint64(R_EAX), llvConst,
                constWeakSlot(I.getArgOperand(2)), oneConst };

            addInstructionDetailsToArgumentList(args, I, &I);

            insertCall(I, copyF, args, true, false);
            // For output, we have to propagate taint before the helper function
            // is executed because the helper would likely have some side effect
            // on the device.
        } else if (calledName == "helper_inb") {
            // Call taint_copy to copy taint from EAX to LLVM. The helper's
            // return value is the value on the IO port and so the taint data
            // (if any) will be associated with the return value.
            vector<Value *> args { llvConst, constSlot(&I), grvConst,
                const_uint64(R_EAX), oneConst };

            Instruction *next = I.getNextNode();
            addInstructionDetailsToArgumentList(args, I, next);

            insertCall(*next, copyF, args, false, false);
            // For input, we have to propagate taint after the helper function
            // is executed since the value on the port isn't available until
            // after the helper returns.
#endif
        } else if (inoutFuncs.count(calledName) > 0) {
            return;
        }
        // Else fall through to named case.
    }

    // This is a call that we aren't going to model, so we need to process
    // it instruction by instruction.
    // First, we need to set up a new stack frame and copy argument taint.

    // As the frame may have been used before, first clear it out
    // note that shad->num_vals is MAXFRAMESIZE
    // if function called doesn't have a name, or has no instructions yet,
    // then have to assume worst case of maximum frame size as can't calculate
    // using PandaSlotTracker
    uint64_t clrBytes = MAXREGSIZE * (shad->num_vals);
    if (calledF && (calledF->getInstructionCount() > 0)) {
        subframePST.reset(new PandaSlotTracker(calledF));
        subframePST->initialize();
        clrBytes = MAXREGSIZE * (subframePST->getMaxSlot());
    }
    Constant *clrDestC = const_uint64((shad->num_vals)*MAXREGSIZE);
    Constant *clrBytesC = const_uint64(clrBytes);

    vector<Value *> args { llvConst, clrDestC, clrBytesC };

    insertCallBefore(I, deleteF, args);

    // And now copy taint for the arguments into the new frame
    int numArgs = I.getNumArgOperands();
    for (int i = 0; i < numArgs; i++) {
        Value *arg = I.getArgOperand(i);
        int argBytes = getValueSize(arg);
        assert(argBytes > 0);

        auto arg_dest = const_uint64((shad->num_vals + i) * MAXREGSIZE);
        auto arg_bytes = const_uint64(argBytes);
        // if arg is constant then delete taint
        if (!isa<Constant>(arg)) {
            vector<Value *> args { llvConst, arg_dest, llvConst,
                constSlot(arg), arg_bytes, zeroConst, zeroConst,
                zeroConst };

            insertCallBefore(I, copyF, args);
        }
        // no need to insert a taint_delete for constant arguments, as we've
        // already cleared the subframe
    }

    if (!callType->getReturnType()->isVoidTy()) { // Copy from return slot.
        vector<Value *> args { llvConst, constSlot(&I), retConst,
            zeroConst, const_uint64(MAXREGSIZE), zeroConst, zeroConst,
            zeroConst } ;

        insertCallAfter(I, copyF, args);
    }

    args = { llvConst };

    insertCallBefore(I, push_frameF, args);
    insertCallAfter(I, pop_frameF, args);
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
    Value *cond = I.getCondition();

    if(cond->getType()->isVectorTy()) {
        printf("Ignoring select instruction with vector arguments\n");
    } else {
        ZExtInst *ZEI = new ZExtInst(cond, int64T, "", &I);

        vector<pair<Value *, Value *>> selections;
        selections.push_back(std::make_pair(
            constWeakSlot(I.getTrueValue()), oneConst));
        selections.push_back(std::make_pair(
            constWeakSlot(I.getFalseValue()), zeroConst));
        insertTaintSelect(I, &I, ZEI, selections);
    }
}

void PandaTaintVisitor::visitExtractValueInst(ExtractValueInst &I) {
    assert(I.getNumIndices() == 1);

    Value *aggregate = I.getAggregateOperand();
    assert(aggregate && aggregate->getType()->isStructTy());
    StructType *typ = dyn_cast<StructType>(aggregate->getType());
    const StructLayout *structLayout = dataLayout->getStructLayout(typ);

    assert(I.idx_begin() != I.idx_end());
    unsigned offset = structLayout->getElementOffset(*I.idx_begin());
    uint64_t src = MAXREGSIZE * PST->getLocalSlot(aggregate) + offset;

    insertTaintCopy(I, llvConst, constSlot(&I), llvConst,
        const_uint64(src), getValueSize(&I));
}

void PandaTaintVisitor::visitInsertValueInst(InsertValueInst &I) {
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
            llvConst, const_uint64(dest + offset),
            llvConst, inserted,
            getValueSize(inserted));
    insertTaintCopyOrDelete(I,
            llvConst, constSlot(&I),
            llvConst, aggregate,
            getValueSize(aggregate));
}

void PandaTaintVisitor::visitInsertElementInst(InsertElementInst &I) {

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
            llvConst, const_uint64(dest + offset),
            llvConst, element,
            getValueSize(element));
    insertTaintCopyOrDelete(I,
            llvConst, constSlot(&I),
            llvConst, base,
            getValueSize(base));
}

void PandaTaintVisitor::visitShuffleVectorInst(ShuffleVectorInst &I) {
    assert(I.getType()->getIntegerBitWidth() <= 8 * MAXREGSIZE);
    insertTaintCompute(I, I.getOperand(0), I.getOperand(1), true);
}

void PandaTaintVisitor::visitUnaryOperator(UnaryOperator &I) {
    insertTaintMix(I, I.getOperand(0));
}


void PandaTaintVisitor::visitFreezeInst(FreezeInst &I) {
    // TODO:  if the input to freeze is undef or poison, result is constant (so
    // need to delete taint)
    // otherwise, the output is what started out with (so need to copy taint)
    // but pointers, aggregates and vectors are special (see LLVM doc)
    printf("taint2: Warning: Freeze unhandled!  Taint may be lost!\n");
}

// Unhandled
void PandaTaintVisitor::visitInstruction(Instruction &I) {
    //dump only available if LLVM compiled with dump enabled
    printf("Error: Unhandled instruction:\n");
    //TODO: need a way to turn on/off calls to dump - would be ideal if we
    // could determine during compile if dump was available - maybe add a
    // test to the configure script since there doesn't seem to be a way
    // to interogate llvm-config to determine if dump is available
    //I.dump();
    // meanwhile...
    printf("%s (%d)\n", I.getOpcodeName(), I.getOpcode());
    assert(false);
}
