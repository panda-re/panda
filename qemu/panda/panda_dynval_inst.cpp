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

#include <stdio.h>
#include "panda_dynval_inst.h"
#include "panda_memlog.h"
extern "C" {
#include "config.h"
}

using namespace llvm;



/***
 *** PandaInstrFunctionPass
 ***/



char PandaInstrFunctionPass::ID = 0;
static RegisterPass<PandaInstrFunctionPass>
Y("PandaInstr", "Instrument instructions that produce dynamic values");

PandaInstrFunctionPass::~PandaInstrFunctionPass(){
    delete PIV;
}

FunctionPass *llvm::createPandaInstrFunctionPass(Module *M) {
    return new PandaInstrFunctionPass(M);
}

bool PandaInstrFunctionPass::runOnFunction(Function &F){
    PIV->visit(F);
    return true;
}



/***
 *** PandaInstrumentVisitor
 ***/



PandaInstrumentVisitor::~PandaInstrumentVisitor(){
    delete_dynval_buffer(dynval_buffer);
}

/*
 * Return pointer to DynValBuffer
 */
DynValBuffer *PandaInstrumentVisitor::getDynvalBuffer(){
    return dynval_buffer;
}

/*
 * Call the logging function, logging the address of the load.  If it's loading
 * the root of a global value (likely CPUState), then we can ignore it.
 */
void PandaInstrumentVisitor::visitLoadInst(LoadInst &I){
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    // We used to ignore global values, but I think we will keep it now since
    // global QEMU values may be referenced in helper functions
    //if (!(isa<GlobalValue>(I.getPointerOperand()))){
        if (isa<GetElementPtrInst>(I.getPointerOperand())){
            // Result from a getelementptr instruction
            CallInst *CI;
            PtrToIntInst *PTII;
            std::vector<Value*> argValues;
            PTII = static_cast<PtrToIntInst*>(
                IRB.CreatePtrToInt(I.getPointerOperand(), ptrType));
            argValues.push_back(ConstantInt::get(ptrType,
                (uintptr_t)dynval_buffer));
            argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
            argValues.push_back(ConstantInt::get(intType, LOAD));
            argValues.push_back(static_cast<Value*>(PTII));
            //argValues.push_back(static_cast<Value*>(I.getPointerOperand()));
            CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
            CI->insertBefore(static_cast<Instruction*>(&I));
            PTII->insertBefore(static_cast<Instruction*>(CI));
        }
        else if (
            // GetElementPtr ConstantExpr
            (isa<ConstantExpr>(I.getPointerOperand()) &&
                static_cast<ConstantExpr*>(I.getPointerOperand())->getOpcode()
                == Instruction::GetElementPtr)
            // IntToPtr ConstantExpr
            || (isa<ConstantExpr>(I.getPointerOperand()) &&
                static_cast<ConstantExpr*>(I.getPointerOperand())->getOpcode()
                == Instruction::IntToPtr)
            // env, or some other global variable
            || (isa<GlobalVariable>(I.getPointerOperand()))
            ){
            CallInst *CI;
            PtrToIntInst *PTII;
            std::vector<Value*> argValues;
            PTII = static_cast<PtrToIntInst*>(
                IRB.CreatePtrToInt(I.getPointerOperand(), ptrType));
            argValues.push_back(ConstantInt::get(ptrType,
                (uintptr_t)dynval_buffer));
            argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
            argValues.push_back(ConstantInt::get(intType, LOAD));
            argValues.push_back(static_cast<Value*>(PTII));
            CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
            CI->insertBefore(static_cast<Instruction*>(&I));
        }
        else {
            PtrToIntInst *PTII;
            CallInst *CI;
            std::vector<Value*> argValues;
            PTII = static_cast<PtrToIntInst*>(IRB.CreatePtrToInt(
                I.getPointerOperand(), wordType));
            argValues.push_back(ConstantInt::get(ptrType,
                (uintptr_t)dynval_buffer));
            argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
            argValues.push_back(ConstantInt::get(intType, LOAD));
            argValues.push_back(static_cast<Value*>(PTII));
            CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
            CI->insertBefore(static_cast<Instruction*>(&I));
            PTII->insertBefore(static_cast<Instruction*>(CI));
        }
    //}
}

// Call the logging function, logging the address of the store
void PandaInstrumentVisitor::visitStoreInst(StoreInst &I){
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    if (I.isVolatile()){
        // Stores to LLVM runtime that we don't care about
        return;
    }
    else if (isa<ConstantExpr>(I.getPointerOperand()) &&
                isa<Constant>(static_cast<Instruction*>(
                I.getPointerOperand())->getOperand(0))){
        /*
         * Storing to a constant looks something like this:
         * store i32 %29, i32* inttoptr (i64 135186980 to i32*),
         * sort of like an inttoptr instruction as an operand.  This is how we
         * deal with logging that weirdness.
         */
        CallInst *CI;
        std::vector<Value*> argValues;
        uint64_t constaddr = static_cast<ConstantInt*>(
            static_cast<Instruction*>(
                I.getPointerOperand())->getOperand(0))->getZExtValue();
        argValues.push_back(ConstantInt::get(ptrType,
            (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
        argValues.push_back(ConstantInt::get(intType, STORE));
        argValues.push_back(ConstantInt::get(wordType, constaddr));
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
    }
    else if (isa<GlobalVariable>(I.getPointerOperand())){
    //else if (isa<GlobalValue>(I.getPointerOperand())){
        // env, or some other global variable
        CallInst *CI;
        PtrToIntInst *PTII;
        std::vector<Value*> argValues;
        PTII = static_cast<PtrToIntInst*>(
            IRB.CreatePtrToInt(I.getPointerOperand(), ptrType));
        argValues.push_back(ConstantInt::get(ptrType,
            (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
        argValues.push_back(ConstantInt::get(intType, STORE));
        argValues.push_back(static_cast<Value*>(PTII));
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
    }
    else {
        PtrToIntInst *PTII;
        CallInst *CI;
        std::vector<Value*> argValues;
        PTII = static_cast<PtrToIntInst*>(IRB.CreatePtrToInt(
            I.getPointerOperand(), wordType));
        argValues.push_back(ConstantInt::get(ptrType,
            (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
        argValues.push_back(ConstantInt::get(intType, STORE));
        argValues.push_back(static_cast<Value*>(PTII));
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
        PTII->insertBefore(static_cast<Instruction*>(CI));
    }
}

/*
 * Call the logging function, logging the branch target.  Target[0] is the true
 * branch, and target[1] is the false branch.  So when logging, we NOT the
 * condition to actually log the target taken.  We are also logging and
 * processing unconditional branches for the time being.
 */
void PandaInstrumentVisitor::visitBranchInst(BranchInst &I){
    BinaryOperator *BO;
    ZExtInst *ZEI;
    CallInst *CI;
    std::vector<Value*> argValues;
    Value *condition;
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    if (I.isConditional()){
        condition = I.getCondition();
        if(isa<UndefValue>(condition)){
            BO = static_cast<BinaryOperator*>(IRB.CreateNot(condition));
            ZEI = static_cast<ZExtInst*>(IRB.CreateZExt(BO, wordType));
            argValues.push_back(ConstantInt::get(ptrType,
                (uintptr_t)dynval_buffer));
            argValues.push_back(ConstantInt::get(intType, BRANCHENTRY));
            argValues.push_back(ConstantInt::get(intType, BRANCHOP));
            argValues.push_back(static_cast<Value*>(ZEI));
            CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
            CI->insertBefore(static_cast<Instruction*>(&I));
        }
        else if (isa<Constant>(condition)){
            CallInst *CI;
            std::vector<Value*> argValues;
            uint64_t constcond = static_cast<ConstantInt*>(
                I.getCondition())->getZExtValue();
            argValues.push_back(ConstantInt::get(ptrType,
                (uintptr_t)dynval_buffer));
            argValues.push_back(ConstantInt::get(intType, BRANCHENTRY));
            argValues.push_back(ConstantInt::get(intType, BRANCHOP));
            argValues.push_back(ConstantInt::get(wordType, !constcond));
            CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
            CI->insertBefore(static_cast<Instruction*>(&I));
        }
        else {
            BO = static_cast<BinaryOperator*>(IRB.CreateNot(condition));
            ZEI = static_cast<ZExtInst*>(IRB.CreateZExt(BO, wordType));
            argValues.push_back(ConstantInt::get(ptrType,
                (uintptr_t)dynval_buffer));
            argValues.push_back(ConstantInt::get(intType, BRANCHENTRY));
            argValues.push_back(ConstantInt::get(intType, BRANCHOP));
            argValues.push_back(static_cast<Value*>(ZEI));
            CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
            CI->insertBefore(static_cast<Instruction*>(&I));
            ZEI->insertBefore(static_cast<Instruction*>(CI));
            BO->insertBefore(static_cast<Instruction*>(ZEI));
        }
    }
    else {
        argValues.push_back(ConstantInt::get(ptrType,
            (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, BRANCHENTRY));
        argValues.push_back(ConstantInt::get(intType, BRANCHOP));
        argValues.push_back(ConstantInt::get(wordType, 0));
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
    }
}

/*
 * Instrument select instructions similar to how we instrument branches.
 */
void PandaInstrumentVisitor::visitSelectInst(SelectInst &I){
    BinaryOperator *BO;
    ZExtInst *ZEI;
    CallInst *CI;
    std::vector<Value*> argValues;
    Value *condition;
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    condition = I.getCondition();
    BO = static_cast<BinaryOperator*>(IRB.CreateNot(condition));
    ZEI = static_cast<ZExtInst*>(IRB.CreateZExt(BO, wordType));
    argValues.push_back(ConstantInt::get(ptrType,
        (uintptr_t)dynval_buffer));
    argValues.push_back(ConstantInt::get(intType, SELECTENTRY));
    argValues.push_back(ConstantInt::get(intType, SELECT));
    argValues.push_back(static_cast<Value*>(ZEI));
    CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
    CI->insertBefore(static_cast<Instruction*>(&I));
    ZEI->insertBefore(static_cast<Instruction*>(CI));
    BO->insertBefore(static_cast<Instruction*>(ZEI));
}

void PandaInstrumentVisitor::visitCallInst(CallInst &I){
/* Currently, we only need to instrument helper_in*() and helper_out*() for x86
 * 32 and 64 bit
 */
#if defined(TARGET_I386)
    CallInst *CI;
    ZExtInst *ZEI;
    std::vector<Value*> argValues;
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    if (!I.getCalledFunction() || !I.getCalledFunction()->hasName()){
        return;
    }
    std::string fnName = I.getCalledFunction()->getName().str();
    if (!fnName.compare("helper_inb")
        || !fnName.compare("helper_inw")
        || !fnName.compare("helper_inl")){
        // looks like %tmp1_v7 = call i64 @helper_inb(i32 146)
        // arg is port number. we'll treat it as a load from the port into the
        // LLVM register

        ZEI = static_cast<ZExtInst*>
            (IRB.CreateZExt(I.getArgOperand(0), ptrType));
        argValues.push_back(ConstantInt::get(ptrType,
            (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, PADDRENTRY));
        argValues.push_back(ConstantInt::get(intType, PLOAD));
        // Zero-extend because the arg is a uint32_t
        argValues.push_back(ZEI);
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
        if (!isa<Constant>(I.getArgOperand(0))){
            ZEI->insertBefore(CI);
        }
    }
    else if (!fnName.compare("helper_outb")
        || !fnName.compare("helper_outw")
        || !fnName.compare("helper_outl")){
        // looks like call void @helper_outb(i32 146, i32 %tmp7_v)
        // args are port number, data.  we'll treat it as a store from the
        // temporary to the port.

        ZEI = static_cast<ZExtInst*>
            (IRB.CreateZExt(I.getArgOperand(0), ptrType));
        argValues.push_back(ConstantInt::get(ptrType,
            (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, PADDRENTRY));
        argValues.push_back(ConstantInt::get(intType, PSTORE));
        // Zero-extend because the arg is a uint32_t
        argValues.push_back(ZEI);
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
        if (!isa<Constant>(I.getArgOperand(0))){
            ZEI->insertBefore(CI);
        }
    }
#endif //TARGET_I386
}

/*
 * Instrument switch instructions to log the index of the taken branch.
 */
void PandaInstrumentVisitor::visitSwitchInst(SwitchInst &I){
    SExtInst *SEI;
    CallInst *CI;
    std::vector<Value*> argValues;
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    if (I.getCondition()->getType() != wordType){
        SEI = static_cast<SExtInst*>(IRB.CreateSExt(I.getCondition(), wordType));
        argValues.push_back(ConstantInt::get(ptrType, (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, SWITCHENTRY));
        argValues.push_back(ConstantInt::get(intType, SWITCH));
        argValues.push_back(static_cast<Value*>(SEI));
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
        SEI->insertBefore(static_cast<Instruction*>(CI));
    }
    else {
        argValues.push_back(ConstantInt::get(ptrType, (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, SWITCHENTRY));
        argValues.push_back(ConstantInt::get(intType, SWITCH));
        argValues.push_back(static_cast<Value*>(I.getCondition()));
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
    }
}

void PandaInstrumentVisitor::visitMemSetInst(MemSetInst &I){
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }

    int bytes = 0;
    Value *length = I.getLength();
    if (ConstantInt* CI = dyn_cast<ConstantInt>(length)) {
        if (CI->getBitWidth() <= 64) {
            bytes = CI->getSExtValue();
        }
    }

    if (bytes > 100) {
        //This mostly happens in cpu state reset
        printf("Note: dyn log ignoring memset greater than 100 bytes\n");
        return;
    }

    PtrToIntInst *PTII;
    CallInst *CI;
    std::vector<Value*> argValues;
    PTII = static_cast<PtrToIntInst*>(IRB.CreatePtrToInt(
        I.getOperand(0), wordType));
    argValues.push_back(ConstantInt::get(ptrType,
        (uintptr_t)dynval_buffer));
    argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
    argValues.push_back(ConstantInt::get(intType, STORE));
    argValues.push_back(static_cast<Value*>(PTII));
    CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
    CI->insertBefore(static_cast<Instruction*>(&I));
    PTII->insertBefore(static_cast<Instruction*>(CI));
}

void PandaInstrumentVisitor::visitMemCpyInst(MemCpyInst &I){
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    PtrToIntInst *PTII_SRC;
    PtrToIntInst *PTII_DST;
    CallInst *CI_SRC;
    CallInst *CI_DST;
    std::vector<Value*> argValues_src;
    std::vector<Value*> argValues_dst;

    PTII_DST = static_cast<PtrToIntInst*>(IRB.CreatePtrToInt(
        I.getOperand(0), wordType));
    argValues_dst.push_back(ConstantInt::get(ptrType,
        (uintptr_t)dynval_buffer));
    argValues_dst.push_back(ConstantInt::get(intType, ADDRENTRY));
    argValues_dst.push_back(ConstantInt::get(intType, STORE));
    argValues_dst.push_back(static_cast<Value*>(PTII_DST));

    PTII_SRC = static_cast<PtrToIntInst*>(IRB.CreatePtrToInt(
        I.getOperand(1), wordType));
    argValues_src.push_back(ConstantInt::get(ptrType,
        (uintptr_t)dynval_buffer));
    argValues_src.push_back(ConstantInt::get(intType, ADDRENTRY));
    argValues_src.push_back(ConstantInt::get(intType, LOAD));
    argValues_src.push_back(static_cast<Value*>(PTII_SRC));

    //The load must come first in the dynamic log
    CI_SRC = IRB.CreateCall(F, ArrayRef<Value*>(argValues_src));
    CI_SRC->insertBefore(static_cast<Instruction*>(&I));
    PTII_SRC->insertBefore(static_cast<Instruction*>(CI_SRC));

    //The store must come second in the dynamic log
    CI_DST = IRB.CreateCall(F, ArrayRef<Value*>(argValues_dst));
    CI_DST->insertBefore(static_cast<Instruction*>(&I));
    PTII_DST->insertBefore(static_cast<Instruction*>(CI_DST));
}
