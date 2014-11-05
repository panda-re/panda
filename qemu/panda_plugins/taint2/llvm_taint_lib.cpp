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

#include "llvm_taint_lib.h"
#include "guestarch.h"
#include "my_mem.h"

extern char *qemu_loc;

using namespace llvm;

/***
 *** PandaTaintFunctionPass
 ***/

char PandaTaintFunctionPass::ID = 0;
static RegisterPass<PandaTaintFunctionPass>
X("PandaTaint", "Analyze each instruction in a function for taint operations");

FunctionPass *llvm::createPandaTaintFunctionPass(Shad *) {
    return new PandaTaintFunctionPass();
}

static inline ConstantInt *const_uint64(LLVMContext &C, uint64_t val) {
    return ConstantInt::get(IntegerType::get(C, 64), val);
}

static inline ConstantInt *const_uint64_ptr(LLVMContext &C, void *ptr) {
    return ConstantInt::get(IntegerType::get(C, 64), (uint64_t)ptr);
}

bool PandaTaintFunctionPass::doInitialization(Module &M) {
    // Add taint functions to module
    char *exe = strdup(qemu_loc);
    std::string bitcode(dirname(exe));
    free(exe);
    bitcode.append("/panda_plugins/taint_ops.bc");
    std::cerr << "Linking taint ops from " << bitcode << std::endl;

    LLVMContext &ctx = M.getContext();
    SMDiagnostic Err;
    Module *taintopmod(ParseIRFile(bitcode, Err, ctx));
    if (!taintopmod) {
        Err.print("qemu", llvm::errs());
        return false;
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
    PTV.mixCompF = M.getFunction("taint_mix_compute"),
    PTV.parallelCompF = M.getFunction("taint_parallel_compute"),
    PTV.copyF = M.getFunction("taint_copy");
    PTV.sextF = M.getFunction("taint_sext");
    PTV.pushFrameF = M.getFunction("taint_push_frame");
    PTV.popFrameF = M.getFunction("taint_pop_frame");

    PTV.llvConst = const_uint64_ptr(ctx, shad->llv);
    PTV.memConst = const_uint64_ptr(ctx, shad->ram);
    PTV.grvConst = const_uint64_ptr(ctx, shad->grv);
    PTV.gsvConst = const_uint64_ptr(ctx, shad->gsv);
    PTV.retConst = const_uint64_ptr(ctx, shad->ret);

    PTV.dataLayout = M.getDataLayout();

    PTV.memlogPopF = M.getFunction("memlog_pop");
    PTV.memlogConst = const_uint64_ptr(ctx, taint2_memlog);

    // FIXME: implement.
    PTV.prevBbConst = const_uint64_ptr(ctx, shad->prev_bb);
}

bool PandaTaintFunctionPass::runOnFunction(Function &F) {
#ifdef TAINTDEBUG
    printf("\n\n%s\n", F.getName().str().c_str());
#endif
    // create slot tracker to keep track of LLVM values
    PTV->PST = createPandaSlotTracker(&F);
    PTV->PST->initialize();

    //printf("Processing entry BB...\n");
    PTV->visit(F);

    // delete slot tracker
    delete PTV->PST;

    return false; // no modifications made to function
}

/***
 *** PandaSlotTracker
 ***/

PandaSlotTracker *llvm::createPandaSlotTracker(Function *F) {
    return new PandaSlotTracker(F);
}

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
        if (!BB->hasName()) {
            CreateFunctionSlot(BB);
        }
        else {
            // the naming of the 'entry' BB happens by default, so leave it
            if (strcmp(BB->getName().str().c_str(), "entry")) {
                BB->setName("");
                CreateFunctionSlot(BB);
            }
        }
        for (BasicBlock::iterator I = BB->begin(), E = BB->end(); I != E;
            ++I) {
            if (I->getType() != Type::getVoidTy(TheFunction->getContext()) &&
                !I->hasName()) {
                CreateFunctionSlot(I);
            }
            else if (I->getType() != Type::getVoidTy(TheFunction->getContext())
                && I->hasName()) {
                I->setName("");
                CreateFunctionSlot(I);
            }

            // We currently are assuming no metadata, but we will need this if
            // we start using metadata
            /*for (unsigned i = 0, e = I->getNumOperands(); i != e; ++i) {
                if (MDNode *N = dyn_cast_or_null<MDNode>(I->getOperand(i))) {
                    CreateMetadataSlot(N);
                }
            }*/
        }
    }
    FunctionProcessed = true;
}

void PandaSlotTracker::CreateFunctionSlot(const Value *V) {
    assert(V->getType() != Type::getVoidTy(TheFunction->getContext()) &&
        !V->hasName() && "Doesn't need a slot!");
    unsigned DestSlot = fNext++;
    fMap[V] = DestSlot;
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
unsigned PandaTaintVisitor::getValueSize(Value *V) {
    return dataLayout.getTypeSizeInBits(V->getType()) / 8;
}

void PandaTaintVisitor::inlineCallAfter(Instruction &I, Function *F, vector<Value *> &args) {
    CallInst *CI = CallInst::Create(copyF, args);
    if (!CI) {
        printf("Couldn't create call inst!!\n");
    }
    CI.insertAfter(I);

    // Inline.
    if (!InlineFunction(CI, InlineFunctionInfo())) {
        printf("Inlining failed!\n");
    }
}

void PandaTaintVisitor::inlineCallBefore(Instruction &I, Function *F, vector<Value *> &args) {
    CallInst *CI = CallInst::Create(copyF, args);
    if (!CI) {
        printf("Couldn't create call inst!!\n");
    }
    CI.insertBefore(I);

    // Inline.
    if (!InlineFunction(CI, InlineFunctionInfo())) {
        printf("Inlining failed!\n");
    }
}

inline void PandaTaintVisitor::constSlot(LLVMContext &ctx, Value *value) {
    assert(value && !isa<Constant>(value));
    return const_uint64(ctx, MAXREGSIZE * PST->getLocalSlot(value));
}

inline int PandaTaintVisitor::intValue(Value *value) {
    if ((ConstantInt *CI = dyn_cast<ConstantInt>(value))) {
        return CI->getZExtValue();
    } else return -1;
}

void PandaTaintVisitor::visitFunction(Function& F) {
    LLVMContext &ctx = F.getContext();
    // Two things: Insert "tainted" metadata.
    // Use the terminator inst because it's least likely to change with future
    // optimizations.
    MDString *md = MDString::get(ctx, "tainted");
    assert(F.getTerminator() != NULL);
    if (F.getTerminator()->getMetadata("tainted")) { // already processed!!
        return;
    }
    F.getTerminator()->setMetadata("tainted", md);

    // Insert call to clear llvm shadow mem.
    vector<Value *> args{
        llvConst, const_uint64(ctx, 0),
        const_uint64(ctx, MAXREGSIZE * shad->num_vals)
    };
    assert(F.getFirstNonPHI() != NULL);
    inlineCallAfter(*F.getFirstNonPHI(), deleteF, args);
}

void PandaTaintVisitor::visitBasicBlock(BasicBlock &BB) {
    // At end of BB, log where we just were.
    LLVMContext &ctx = BB.getContext();
    vector<Value *> args{
        const_uint64_ptr(ctx, &shad->prev_bb), constSlot(ctx, &BB)
    };
    assert(BB.getTerminator() != NULL);
    inlineCallBefore(*BB.getTerminator(), breadcrumbF, args);
}

// Insert a log pop after this instruction.
Instruction *PandaTaintVisitor::insertLogPop(Instruction &after) {
    vector<Value *> args{ memlogConst };
    CI = CallInst::Create(memlogPopF, args);
    if (!CI) {
        printf("Couldn't create call inst!!\n");
    }
    CI.insertAfter(after);
    return CI;
}

// Copy taint from LLVM source to dest byte by byte
void PandaTaintVisitor::insertTaintCopy(Instruction &I,
        Constant *shad_dest, uint64_t dest, Constant *shad_src, uint64_t src,
        uint64_t size) {
    LLVMContext &ctx = I.getContext();
    insertTaintCopy(I, shad_dest, const_uint64(ctx, dest),
            shad_src, const_uint64(ctx, dest), size);
}

void PandaTaintVisitor::insertTaintMove(Instruction &I,
        Constant *shad_dest, Value *dest, Constant *shad_src, Value *src,
        uint64_t size) {
    insertTaintBulk(I, shad_dest, dest, shad_src, src, size, moveF);
}

void PandaTaintVisitor::insertTaintCopy(Instruction &I,
        Constant *shad_dest, Value *dest, Constant *shad_src, Value *src,
        uint64_t size) {
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
    // If these are llvm regs we have to interpret them as slots.
    if (shad_dest == llvConst) dest = constSlot(ctx, dest);
    if (shad_src == llvConst) src = constSlot(ctx, src);

    vector<Value *> args{ shad_dest, dest, shad_src, src, const_uint64(ctx, size) };
    Instruction *after = srcCI ? srcCI : (destCI ? destCI : &I);
    inlineCallAfter(I, func, args);

    InlineFunctionInfo IFI;
    if (destCI && !InlineFunction(destCI, IFI)) {
        printf("Inlining failed!\n");
    }
    if (srcCI && !InlineFunction(srcCI, IFI)) {
        printf("Inlining failed!\n");
    }
}

void PandaTaintVisitor::insertTaintMix(Instruction &I, Value *dest = NULL, Value *src) {
    LLVMContext &ctx = I.getContext();
    if (!dest) dest = &I;
    Constant *dest_size = const_uint64(ctx, getValueSize(dest));
    Constant *src_size = const_uint64(ctx, getValueSize(src));

    vector<Value *> args{
        llvConst, constSlot(ctx, dest), dest_size, constSlot(ctx, src), src_size
    };
    inlineCallAfter(I, mixF, args);
}

// Compute operations
void PandaTaintVisitor::insertTaintCompute(Instruction &I, Value *dest = NULL, Value *src1, Value *src2, bool is_mixed) {
    LLVMContext &ctx = I.getContext();
    if (!dest) dest = &I;
    if (!is_mixed) assert(getValueSize(dest) == getValueSize(src1));
    assert(getValueSize(src1) == getValueSize(src1));

    Constant *dest_size = const_uint64(ctx, getValueSize(dest));
    Constant *src_size = const_uint64(ctx, getValueSize(src));

    vector<Value *> args{
        llvConst, constSlot(ctx, dest), dest_size
        constSlot(ctx, src1), constSlot(ctx, src2), src_size
    };
    inlineCallAfter(I, is_mixed ? mixCompF : parallelCompF, args);
}

void PandaTaintVisitor::insertTaintSext(Instruction &I, Value *src) {
    LLVMConstext &ctx = I.getContext();
    Value *dest = &I;
    Constant *dest_size = const_uint64(ctx, getValueSize(dest));
    Constant *src_size = const_uint64(ctx, getValueSize(src));

    vector<Value *> args{
        llvConst, constSlot(ctx, dest), dest_size, constSlot(ctx, src), src_size
    };
    inlineCallAfter(I, sextF, args);
}

void PandaTaintVisitor::insertTaintSelect(Instruction &after, Value *dest,
        Value *selector, vector<pair<Value *, Value *>> &selections) {
    LLVMContext &ctx = after.getContext();
    Constant *dest_size = const_uint64(ctx, getValueSize(dest));

    vector<Value *> args{
        llvConst, constSlot(ctx, dest), dest_size, selector
    };
    for (auto &selection : selections) {
        args.push_back(selection.first);
        args.push_back(selection.second);
    }
    args.push_back(const_uint64(ctx, 0));
    inlineCallAfter(after, selectF, args);
}

void PandaTaintVisitor::insertTaintDelete(Instruction &I,
        Constant *shad, Value *dest, Value *size) {
    LLVMContext &ctx = I.getContext();
    vector<Value *> args{ shad, dest, size };
    inlineCallAfter(I, deleteF, args);
}

// Terminator instructions
void PandaTaintVisitor::visitReturnInst(ReturnInst &I) {
    Value *ret = I.getReturnValue();
    if (!ret) return;

    LLVMContext &ctx = I.getContext();
    vector<Value *> args{
        retConst, const_uint64(ctx, 0),
        llvConst, const_uint64(PST->getLocalSlot(ret)),
        const_uint64(getValueSize(ret))
    };
    inlineCallBefore(I, copyF, args);

    visitTerminatorInst(I);
}

// On a branch we just have to log the previous BB.
void PandaTaintVisitor::visitTerminatorInst(TerminatorInst &I) {
    // FIXME: Insert BB logging.
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

// Binary operators
void PandaTaintVisitor::visitBinaryOperator(BinaryOperator &I) {
    bool isMixed;
    switch (I.getOpcode()) {
        case Instruction::Add:
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
        case Instruction::Shl:
        case Instruction::LShr:
        case Instruction::AShr:
            isMixed = true;
            break;
            // mixed

        case Instruction::And:
        case Instruction::Or:
        case Instruction::Xor:
            isMixed = false
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

void PandaTaintVisitor::visitLoadInst(LoadInst &I) {
    // These are loads from CPUState etc.
}

/*
 * We should only care about non-volatile stores, the volatile stores are
 * irrelevant to guest execution.  Volatile stores come in pairs for each guest
 * instruction, so we can gather statistics looking at every other volatile
 * store.
 */
void PandaTaintVisitor::visitStoreInst(StoreInst &I) {
    // look for magic taint pc update info
    MDNode *md = I.getMetadata("pcupdate.md");
    if (md != NULL) {
        // found store instruction that contains PC.  
    }

    if (I.isVolatile()) {
        return;
    }

    
}

void PandaTaintVisitor::visitFenceInst(FenceInst &I) {}
void PandaTaintVisitor::visitAtomicCmpXchgInst(AtomicCmpXchgInst &I) {}
void PandaTaintVisitor::visitAtomicRMWInst(AtomicRMWInst &I) {}

/*
 * In TCG->LLVM translation, it seems like this instruction is only used to get
 * the pointer to the CPU state.  Because of this, we will just delete taint at
 * the destination LLVM register.
 */
void PandaTaintVisitor::visitGetElementPtrInst(GetElementPtrInst &I) {
}

// Cast operators
void PandaTaintVisitor::visitCastInst(CastInst &I) {
    LLVMContext &ctx = I.getContext();
    Value *src = I.getOperand(0);

    unsigned srcSize = getValueSize(src), destSize = getValueSize(&I);
    switch (I.getOpcode()) {
        // Mixed cases
        case Instruction::FPExtInst:
        case Instruction::FPToSIInst:
        case Instruction::FPTruncInst:
        case Instruction::SIToFPInst:
        case Instruction::UIToFPInst:
            insertTaintMix(I, &I, src);
            break;

        case Instruction::SExtInst:
            if (destSize > srcSize) {
                // Generate a sext.
                insertTaintSext(I, src);
                break;
            }
            // Else fall through to a copy.
        // Parallel cases. Assume little-endian...
        // Both involve a simple copy.
        case Instruction::BitCastInst:
        case Instruction::IntToPtrInst:
        case Instruction::PtrToIntInst:
        case Instruction::TruncInst:
        case Instruction::ZExtInst:
           insertTaintCopy(I, llvConst, PST->getLocalSlot(&I),
                   llvConst, PST->getLocalSlot(src),
                   min(srcSize, destSize));
           break;
        default:
           // BROKEN
           assert(false && "Bad CastInst!!");
    }
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
    insertTaintCompute(I, &I, I.getOperand(0), I.getOperand(1), true);
}

void PandaTaintVisitor::visitPHINode(PHINode &I) {
    LLVMContext &ctx = I.getContext();
    LoadInst *LI = new LoadInst(prevBbConst);
    LI.insertBefore(I.getParent().getFirstNonPHI());
    vector<pair<Value *,Value *>> selections;
    for (unsigned i = 0; i < getNumIncomingValues(); ++i) {
        Constant *select = const_uint64_ptr(ctx, I.getIncomingBlock(i));
        Constant *value = constSlot(I.getIncomingValue(i));
        selections.push_back(std::makepair(select, value));
    }
    insertTaintSelect(LI, &I, LI, selections);
}

void PandaTaintVisitor::visitMemCpyInst(MemTransferInst &I) {
    int size = intValue(I.getLength());
    assert(size >= 0);

    insertTaintCopy(I, memConst, NULL, memConst, NULL, size);
}

void PandaTaintVisitor::visitMemMoveInst(MemTransferInst &I) {
    int size = intValue(I.getLength());
    assert(size >= 0);

    insertTaintMove(I, memConst, NULL, memConst, NULL, size);
}

void PandaTaintVisitor::visitMemSetInst(MemSetInst &I) {
    LLVMContext &ctx = I.getContext();

    CallInst *destCI = insertLogPop(I);
    if (!CI) { printf("Couldn't create call inst!\n"); }

    Value *size = I.getLength();
    Value *writeval = I.getValue();
    if (isa<Constant>(writeval)) {
        insertTaintDelete(I, memConst, destCI, size);
    } else {
        assert(size->getType()->isIntegerTy());
        assert(getValueSize(size) <= 8);
        if (getValueSize(size) < 8) {
            // insert ZExtInst before I.
            size = new ZExtInst(size, IntegerType::get(ctx, 64), I);
        }
        vector<Value *> args{
            memConst, destCI, size, llvConst, constSlot(ctx, writeval)
        };
        inlineCallAfter(*destCI, setF, args);
    }
    if (!InlineFunction(*destCI, InlineFunctionInfo())) {
        printf("Couldn't inline!!\n");
    }
}

void PandaTaintVisitor::visitCallInst(CallInst &I) {
    Function *called = I.getCalledFunction();
    if (!called) {
        //assert(1==0);
        //return; // doesn't have name, we can't process it
        // Might be ok for now, but we might need to revisit.
        printf("Note: skipping taint analysis of statically unknowable call in %s.\n",
            I.getParent()->getParent()->getName().str().c_str());
        return;
    }
    std::string calledName = called->getName().str();

    switch (I.getCalledFunction()->getIntrinsicID()) {
        case Intrinsic::uadd_with_overflow:
            insertTaintCompute(I, I.getArgOperand(0), I.getArgOperand(1), 1);
            return;
        case Intrinsic::bswap:
        case Intrinsic::ctlz:
            insertTaintMix(I, I.getArgOperand(0));
            return;
        case Intrinsic::not_intrinsic:
            break;
        default:
            printf("Note: unsupported intrinsic %s in %s.\n",
                I.getCalledFunction()->getName().str().c_str(),
                I.getParent()->getParent()->getName().str().c_str());
            return;
    }

    assert(!I.getCalledFunction()->isIntrinsic());
    if (!calledName.compare("__ldb_mmu_panda")
            || !calledName.compare("__ldw_mmu_panda")
            || !calledName.compare("__ldl_mmu_panda")
            || !calledName.compare("__ldq_mmu_panda")) {
        insertTaintCopy(I, llvConst, &I, memConst, NULL, getValueSize(&I));
        return;
    }
    else if (!calledName.compare("__stb_mmu_panda")
            || !calledName.compare("__stw_mmu_panda")
            || !calledName.compare("__stl_mmu_panda")
            || !calledName.compare("__stq_mmu_panda")) {
        Value *src = I.getArgOperand(1);
        insertTaintCopy(I, memConst, NULL, llvConst, src, getValueSize(src));
        return;
    }
    else if (!calledName.compare("sin")
            || !calledName.compare("cos")
            || !calledName.compare("tan")
            || !calledName.compare("log")
            || !calledName.compare("__isinf")
            || !calledName.compare("__isnan")
            || !calledName.compare("rint")
            || !calledName.compare("floor")
            || !calledName.compare("abs")
            || !calledName.compare("ceil")
            || !calledName.compare("exp2")) {
        insertTaintMix(I, I.getArgOperand(0));
        return;
    }
    else if (!calledName.compare("ldexp")
            || !calledName.compare("atan2")) {
        insertTaintCompute(I, I.getArgOperand(0), I.getArgOperand(1), true);
        return;
    }
    else if (!calledName.compare(0, 9, "helper_in") && calledName.size() == 10) {
        /*
         * The last character of the instruction name determines the size of data transfer
         * b = single byte
         * w = 2 bytes
         * l - 4 bytes
         */
        char type = *calledName.rbegin();
        int len;
        if (type == 'b') {
            len = 1;
        } else if (type == 'w') {
            len = 2;
        } else if (type == 'l') {
            len = 4;
        }

        /* helper_in instructions will be modeled as loads with various lengths */
        // For now do nothing.
        return;
    }
    else if (!calledName.compare(0, 10, "helper_out") && calledName.size() == 11) {
        /*
         * The last character of the instruction name determines the size of data transfer
         * b = single byte
         * w = 2 bytes
         * l - 4 bytes
         */
        char type = *calledName.rbegin();
        int len;
        if (type == 'b') {
            len = 1;
        } else if (type == 'w') {
            len = 2;
        } else {
            len = 4;
        }

        /* helper_out instructions will be modeled as stores with various lengths */
        // For now do nothing.
        //portStoreHelper(I.getArgOperand(1), I.getArgOperand(0), len);
        return;
    } else {
        // This is a call that we aren't going to model, so we need to process
        // it instruction by instruction.
        // First, we need to set up a new stack frame and copy argument taint.
        vector<Value *> fargs{ llvConst };
        int numArgs = I.getNumArgOperands();
        for (int i = 0; i < numArgs; i++) {
            Value *arg = I.getArgOperand(i);
            argBytes = getValueSize(arg);

            // if arg is constant then do nothing
            if (!isa<Constant>(arg)) {
                vector<Value *> copyargs{
                    llvConst, const_uint64(ctx, (shad->num_vals + i) * MAXREGSIZE),
                    llvConst, constSlot(ctx, arg), MAXREGSIZE
                };
                inlineCallBefore(I, copyF, copyargs);
            }
        }
        if (!called->getType()->isVoidTy()) { // Copy from return slot.
            vector<Value *> retargs{
                llvConst, &I, retConst, const_uint64(ctx, 0), maxregsize
            };
            inlineCallAfter(I, copyF, retargs);
        }
        inlineCallBefore(I, pushFrameF, fargs);
        inlineCallAfter(I, popFrameF, fargs);
    }
}

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

/*
 * This may need to become more complex for more complex cases of this
 * instruction. Currently we are just treating it like a branch, but with values
 * filled in instead of branch targets.
 */
void PandaTaintVisitor::visitSelectInst(SelectInst &I) {}

void PandaTaintVisitor::visitVAArgInst(VAArgInst &I) {}
void PandaTaintVisitor::visitExtractElementInst(ExtractElementInst &I) {}
void PandaTaintVisitor::visitInsertElementInst(InsertElementInst &I) {}
void PandaTaintVisitor::visitShuffleVectorInst(ShuffleVectorInst &I) {}

/*
 * This may need to become more complex for more complex cases of this
 * instruction.
 */
void PandaTaintVisitor::visitExtractValueInst(ExtractValueInst &I) {
}

void PandaTaintVisitor::visitInsertValueInst(InsertValueInst &I) {
}

void PandaTaintVisitor::visitLandingPadInst(LandingPadInst &I) {}

// Unhandled
void PandaTaintVisitor::visitInstruction(Instruction &I) {
    printf("Error: Unhandled instruction\n");
    assert(1==0);
}
