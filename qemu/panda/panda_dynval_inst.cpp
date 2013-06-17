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

#include "stdio.h"

#include "panda_dynval_inst.h"

extern "C" {
#include "panda_memlog.h"
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

/*
 * Just print out name so we can see which helpers are being called.
 */
void PandaInstrumentVisitor::visitCallInst(CallInst &I){
    /*assert(I.getCalledFunction()->hasName());
    std::string fnName = I.getCalledFunction()->getName().str();
    printf("HELPER %s\n", fnName.c_str());
    fflush(stdout);*/
}

/*
 * Instrument switch instructions to log the index of the taken branch.
 */
void PandaInstrumentVisitor::visitSwitchInst(SwitchInst &I){
    ZExtInst *ZEI;
    CallInst *CI;
    std::vector<Value*> argValues;
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    if (I.getCondition()->getType() != wordType){
        ZEI = static_cast<ZExtInst*>(IRB.CreateZExt(I.getCondition(), wordType));
        argValues.push_back(ConstantInt::get(ptrType, (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, SWITCHENTRY));
        argValues.push_back(ConstantInt::get(intType, SWITCH));
        argValues.push_back(static_cast<Value*>(ZEI));
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
        ZEI->insertBefore(static_cast<Instruction*>(CI));
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

