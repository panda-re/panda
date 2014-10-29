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

/*
 * Most of the time, existingTtbCache should be just passed as NULL so one is
 * created in the constructor.  Otherwise, pass in an existing one that was
 * created previously.
 */
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

    PTV.setTaintFuncs(
            M.getFunction("taint_delete"),
            M.getFunction("taint_mix"),
            M.getFunction("taint_parallel"),
            M.getFunction("taint_copy"));

    PTV.llvConst = const_uint64_ptr(ctx, shad->llv);
    PTV.memConst = const_uint64_ptr(ctx, shad->ram);
    PTV.grvConst = const_uint64_ptr(ctx, shad->grv);
    PTV.gsvConst = const_uint64_ptr(ctx, shad->gsv);
    PTV.retConst = const_uint64_ptr(ctx, shad->ret);
}

bool PandaTaintFunctionPass::runOnFunction(Function &F) {

#ifdef TAINTDEBUG
    printf("\n\n%s\n", F.getName().str().c_str());
#endif
    // create slot tracker to keep track of LLVM values
    PTV->PST = createPandaSlotTracker(&F);
    PTV->PST->initialize();

    // process taint starting with the entry BB
    Function::iterator bb = F.begin();
    //printf("Processing entry BB...\n");
    PTV->visit(bb);

    // delete slot tracker
    delete PTV->PST;

    return true; // no modifications made to function
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
int PandaTaintVisitor::getValueSize(Value *V) {
    if (V->getType()->isIntegerTy()) {
        return (int)ceil(V->getType()->getScalarSizeInBits() / 8.0);
    }
    else if (V->getType()->isPointerTy()) {
        return (int)ceil(static_cast<SequentialType*>(V->getType())->
            getElementType()->getScalarSizeInBits() / 8.0);
    }
    else if (V->getType()->isFloatingPointTy()) {
        return (int)ceil(V->getType()->getScalarSizeInBits() / 8.0);
    }
    else if (V->getType()->isStructTy()) {
        StructType *S = cast<StructType>(V->getType());
        int size = 0;
        for (int i = 0, elements = S->getNumElements(); i < elements; i++) {
            //TODO: Handle the case where getElementType returns a derived type
            size += (int)ceil(S->getElementType(i)->getScalarSizeInBits() / 8.0);
        }
        return size;
    }
    else {
        // those are all that's supported for now
        //assert(1==0);
        printf("Error in getValueSize() for type %i\n", V->getType()->getTypeID());
        //    V->getParent()->getParent()->getName().str().c_str());
        return -1;
    }
}

static void PandaTaintVisitor::inlineCallAfter(Instruction &I, Function *F, vector<Value *> &args) {
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

// Copy taint from LLVM source to dest byte by byte
void PandaTaintVisitor::insertTaintCopyFor(Instruction &I,
        Constant *shad_dest, uint64_t dest, Constant *shad_src, uint64_t src,
        uint64_t bytes) {
    LLVMContext &ctx = I.getContext();
    vector<Value *> args{
        shad_dest, const_uint64(ctx, dest),
        shad_src, const_uint64(ctx, src),
        const_uint64(ctx, bytes)
    };
    inlineCallAfter(I, copyF, args);
}

// Compute operations
void PandaTaintVisitor::insertTaintCompute(Instruction &I, uint64_t dest, uint64_t src1, uint64_t src2, uint64_t size, bool is_mixed) {
    LLVMContext &ctx = I.getContext();
    vector<Value *> args{
        llvConst, const_uint64(ctx, dest),
        const_uint64(ctx, src1), const_uint64(ctx, src2),
        const_uint64(ctx, size)
    };
    if (is_mixed)
        inlineCallAfter(I, mixF, args);
    else
        inlineCallAfter(I, parallelF, args);
}

// Terminator instructions
void PandaTaintVisitor::visitReturnInst(ReturnInst &I) {
}

void PandaTaintVisitor::visitBranchInst(BranchInst &I) {
}

void PandaTaintVisitor::visitSwitchInst(SwitchInst &I) {
}

void PandaTaintVisitor::visitIndirectBrInst(IndirectBrInst &I) {
void PandaTaintVisitor::visitInvokeInst(InvokeInst &I) {
void PandaTaintVisitor::visitResumeInst(ResumeInst &I) {

/*
 * Treat unreachable the same way as return.  This matters, for example, when
 * there is a call to cpu_loop_exit() in a helper function, followed by an
 * unreachable instruction.  Functions that end with unreachable return void, so
 * we don't have to worry about taint transfer, we just have to tell the taint
 * processor we are returning.
 */
void PandaTaintVisitor::visitUnreachableInst(UnreachableInst &I) {
}

// Binary operators
void PandaTaintVisitor::visitBinaryOperator(BinaryOperator &I) {
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
            // mixed

        case Instruction::And:
        case Instruction::Or:
        case Instruction::Xor:
            // parallel

        default:
            printf("Unknown binary operator\n");
            exit(1);
    }
}

// Memory operators

// Delete taint at destination register
void PandaTaintVisitor::visitAllocaInst(AllocaInst &I) {
    simpleDeleteTaintAtDest(PST->getLocalSlot(&I));
}

void PandaTaintVisitor::loadHelper(Value *srcval, Value *dstval, int len, int is_mmu) {
}

void PandaTaintVisitor::visitLoadInst(LoadInst &I) {
}

void PandaTaintVisitor::storeHelper(Value *srcval, Value *dstval, int len, int is_mmu) {
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
#ifdef TAINTSTATS
        static bool evenStore = false;
        evenStore = !evenStore;
        if (evenStore) {
            assert(shadow);
        }
#endif
        return;
    }
}

void PandaTaintVisitor::visitFenceInst(FenceInst &I) {
void PandaTaintVisitor::visitAtomicCmpXchgInst(AtomicCmpXchgInst &I) {
void PandaTaintVisitor::visitAtomicRMWInst(AtomicRMWInst &I) {

/*
 * In TCG->LLVM translation, it seems like this instruction is only used to get
 * the pointer to the CPU state.  Because of this, we will just delete taint at
 * the destination LLVM register.
 */
void PandaTaintVisitor::visitGetElementPtrInst(GetElementPtrInst &I) {
}

// Cast operators

void PandaTaintVisitor::visitTruncInst(TruncInst &I) { }
void PandaTaintVisitor::visitZExtInst(ZExtInst &I) { }
void PandaTaintVisitor::visitSExtInst(SExtInst &I) { }
void PandaTaintVisitor::visitFPToUIInst(FPToUIInst &I) { }

void PandaTaintVisitor::visitFPToSIInst(FPToSIInst &I) { }

void PandaTaintVisitor::visitUIToFPInst(UIToFPInst &I) {}
void PandaTaintVisitor::visitSIToFPInst(SIToFPInst &I) {}
void PandaTaintVisitor::visitFPTruncInst(FPTruncInst &I) {}
void PandaTaintVisitor::visitFPExtInst(FPExtInst &I) {}

void PandaTaintVisitor::visitPtrToIntInst(PtrToIntInst &I) { }

void PandaTaintVisitor::visitIntToPtrInst(IntToPtrInst &I) { }

/*
 * Haven't actually seen bitcast in generated code, we've only seen it in helper
 * functions for pointer operations in QEMU address space.  We treat it the same
 * way as getelementptr, and delete taint.  This may need to change if it is
 * used in other ways.
 */
void PandaTaintVisitor::visitBitCastInst(BitCastInst &I) {
    simpleDeleteTaintAtDest(PST->getLocalSlot(&I));
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
void PandaTaintVisitor::visitICmpInst(ICmpInst &I) {
}
void PandaTaintVisitor::visitFCmpInst(FCmpInst &I) {
}

void PandaTaintVisitor::visitPHINode(PHINode &I) {
}

/*
 * Taint model for LLVM bswap intrinsic.
 */
void PandaTaintVisitor::bswapHelper(CallInst &I) {
}

/*
 * Taint model for LLVM memcpy intrinsic.
 */
void PandaTaintVisitor::memcpyHelper(CallInst &I) {
}

/*
 * Taint model for LLVM memset intrinsic.
 */
void PandaTaintVisitor::memsetHelper(CallInst &I) {
}

/*
 * Taint model for LLVM ctlz intrinsic.
 */
void PandaTaintVisitor::ctlzHelper(CallInst &I) {
}

/*
 * Taint model for floating point math functions like sin(), cos(), etc.  Very
 * similar to approxArithHelper(), except it takes only one operand.
 */
void PandaTaintVisitor::floatHelper(CallInst &I) {
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

    // Check to see if it's a supported intrinsic
    if (I.getCalledFunction()->getIntrinsicID()
            == Intrinsic::uadd_with_overflow) {
        addSubHelper(I.getArgOperand(0), I.getArgOperand(1), &I);
        return;
    }
    else if (I.getCalledFunction()->getIntrinsicID() == Intrinsic::bswap) {
        bswapHelper(I);
        return;
    }
    else if (I.getCalledFunction()->getIntrinsicID() == Intrinsic::memcpy) {
         memcpyHelper(I);
         return;
    }
    else if (I.getCalledFunction()->getIntrinsicID() == Intrinsic::memset) {
         memsetHelper(I);
         return;
    }
    else if (I.getCalledFunction()->getIntrinsicID() == Intrinsic::ctlz) {
         ctlzHelper(I);
         return;
    }
    else if (I.getCalledFunction()->getIntrinsicID()
            != Intrinsic::not_intrinsic) {
        printf("Note: unsupported intrinsic %s in %s.\n",
            I.getCalledFunction()->getName().str().c_str(),
            I.getParent()->getParent()->getName().str().c_str());
        //assert(1==0);
    }
    else if (!calledName.compare("__ldb_mmu_panda")
            || !calledName.compare("__ldw_mmu_panda")
            || !calledName.compare("__ldl_mmu_panda")
            || !calledName.compare("__ldq_mmu_panda")) {

        // guest load in whole-system mode
        int len = getValueSize(&I);
        loadHelper(I.getArgOperand(0), &I, len, 1);
        return;
    }
    else if (!calledName.compare("__stb_mmu_panda")
            || !calledName.compare("__stw_mmu_panda")
            || !calledName.compare("__stl_mmu_panda")
            || !calledName.compare("__stq_mmu_panda")) {

        // guest store in whole-system mode
        int len = getValueSize(I.getArgOperand(1));

	/*
	printf ("calling storeHelper.  mmu = 1.\n");

	// printf an instruction
	std::string line;   
	raw_string_ostream line2(line);
	I.print(line2); 
	printf("%s\n", line.c_str());  
                                                                                                                
	printf ("arg1\n");
	I.getArgOperand(1)->dump();
	printf ("\n");
	printf ("arg0\n");
	I.getArgOperand(0)->dump();
	printf ("\n");
	*/

	

	//	printf ("arg1 = [%s]\n", ((I.getArgOperand(1))));
	storeHelper(/*src=*/ I.getArgOperand(1), /*dest=*/I.getArgOperand(0), len, 1);
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

        floatHelper(I);
        return;
    }
    else if (!calledName.compare("ldexp")
            || !calledName.compare("atan2")) {

        approxArithHelper(I.getArgOperand(0), I.getArgOperand(1), &I);
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
        } else {
            len = 4;
        }

        /* helper_in instructions will be modeled as loads with various lengths */
        portLoadHelper(I.getArgOperand(0), &I, len);
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
        portStoreHelper(I.getArgOperand(1), I.getArgOperand(0), len);
        return;
    }

    std::map<std::string, TaintTB*> *ttbCache = PTFP->getTaintTBCache();
    std::map<std::string, TaintTB*>::iterator it = ttbCache->find(calledName);

    /*
     * If it's not currently in the cache and it's something that should be in
     * the cache (per the if statement), then we need to create a new function
     * pass and put it in the cache.
     */
    if (it == ttbCache->end() && I.getCalledFunction()
        && !I.getCalledFunction()->isDeclaration()
        && !I.getCalledFunction()->isIntrinsic()) {

        FunctionPass *newPTFP =
            createPandaTaintFunctionPass(10*1048576, ttbCache);

        newPTFP->runOnFunction(*I.getCalledFunction());
        it = ttbCache->find(calledName);
        delete newPTFP;
        assert(it != ttbCache->end());
    }

    if (it != ttbCache->end()) {
#ifdef TAINTDEBUG
        printf("found %s in cache\n", it->first.c_str());
#endif
        /*** Process call taint here ***/

        struct taint_op_struct op = {};
        struct addr_struct src = {};
        struct addr_struct dst = {};
        src.typ = LADDR;
        dst.typ = LADDR;
        dst.flag = FUNCARG; // copy taint to new frame
        int argBytes;

        // if there are args then copy their taint to new frame
        int numArgs = I.getNumArgOperands();
        for (int i = 0; i < numArgs; i++) {
            Value *arg = I.getArgOperand(i);
            argBytes = getValueSize(arg);

            // if arg is constant then delete taint in arg reg
            if (isa<Constant>(arg)) {
                op.typ = DELETEOP;
                dst.val.la = i;
                for (int j = 0; j < argBytes; j++) {
                    dst.off = j;
                    op.val.deletel.a = dst;
                    tob_op_write(tbuf, &op);
                }
            }
            else {
                op.typ = COPYOP;
                src.val.la = PST->getLocalSlot(arg);
                dst.val.la = i;
                for (int j = 0; j < argBytes; j++) {
                    src.off = j;
                    dst.off = j;
                    op.val.copy.a = src;
                    op.val.copy.b = dst;
                    tob_op_write(tbuf, &op);
                }
            }
        }

        // call op (function name, pointer to taint buf, increment frame level)
        op.typ = CALLOP;
        strncpy(op.val.call.name, it->first.c_str(), FUNCNAMELENGTH);
        op.val.call.ttb = it->second;
        tob_op_write(tbuf, &op);

        // copy return reg to value in this frame, if applicable
        int slot = PST->getLocalSlot(&I);
        if (slot > -1) {
            op.typ = COPYOP;
            memset(&src, 0, sizeof(src));
            memset(&dst, 0, sizeof(dst));
            src.typ = RET;
            dst.typ = LADDR;
            dst.val.la = slot;
            for (int i = 0; i < getValueSize(&I); i++) {
                src.off = i;
                dst.off = i;
                op.val.copy.a = src;
                op.val.copy.b = dst;
                tob_op_write(tbuf, &op);
            }
        }
    }
    else {
#ifdef TAINTDEBUG
        printf("didn't find %s in cache\n", calledName.c_str());
#endif
        // if it's not in the cache, ignore taint operations
        return;
    }
}

// this is essentially a copy of loadHelper without the tainted pointer code
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
void PandaTaintVisitor::visitSelectInst(SelectInst &I) {
}

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
