
/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Ray Wang        raywang@mit.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */


/*
 * This plugin creates an LLVM trace from a panda replay
 * With dynamic values inlined into the trace. 
 *
 * The C struct is defined in llvm_trace2.proto
 *
 */

#include <vector>
#include <set>
#include <string>

#include "llvm_trace2.h"
#include "Extras.h"

extern "C" {
#include "panda/plugin.h"
#include "panda/tcg-llvm.h"
#include "panda/plugin_plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
}

#include <iostream>

#include <llvm/IR/Metadata.h>
#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instruction.h>

#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Regex.h"

extern PandaLog globalLog;
extern int llvmtrace_flags;
bool do_record = true;
bool record_int = false;

namespace llvm {

    MDNode *LLVMTraceMD;

    PandaLLVMTracePass *PLTP; 
  // Integer types
  // Removed const modifier since method signatures have changed
  Type *Int8Type;
  Type *Int32Type;
  Type *Int64Type;
  Type *VoidType;
  Type *VoidPtrType;

//*************************************************************
// Record Functions
//************************************************************

//void PandaLLVMTraceVisitor::visitPhiInst(){

//}
void recordStartBB(uint64_t fp, uint64_t tb_num){
    
    //giri doesn't write to log, instead pushes onto a bb stack. 

    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_type(FunctionCode::BB);
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);


        if (tb_num > 0){
            ple->mutable_llvmentry()->set_tb_num(tb_num);
        }
        
        globalLog.write_entry(std::move(ple));
    }
}

void recordCall(uint64_t fp){

    Function* calledFunc = (Function*)fp;
    //printf("Called fp name: %s\n", calledFunc->getName().str().c_str());
    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_CALL);
        ple->mutable_llvmentry()->set_address(fp);
        
        globalLog.write_entry(std::move(ple));
    }

    if (calledFunc->getName().startswith("helper_iret")){
        printf("FOUND AN IRET IN RECORDCALL\n");
        llvmtrace_flags &= ~1;

        //turn on record!
        do_record = true;
        printf("TURNED ON RECORD\n");
    }

}

//TODO: Can I get rid of this?
void recordBB(uint64_t fp, unsigned lastBB){
    
    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
        ple->mutable_llvmentry()->set_type(FunctionCode::BB);

        globalLog.write_entry(std::move(ple));
    }
}

void recordLoad(uint64_t address){
    //printf("recording load at address %" PRIx64 "\n", address);

    //printf("recording load from   address %lx\n", address);

    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_LOAD);

        uint64_t x86state = (uint64_t)cpus.tqh_first->env_ptr;
		
        //printf("Address: %lx, firstcpu: %lx - %lx\n", address, (uint64_t)first_cpu, (uint64_t)first_cpu + sizeof(CPUState));
		/*printf("Address: %lx, cpux86state: %lx - %lx\n", address, x86state, x86state + sizeof(CPUState));*/
        //printf("Value %lu\n", value);
        if ((address >= x86state) && (address < x86state + sizeof(CPUState))){
            uint32_t reg_offset = (address - x86state)/4;
			/*printf("%u\n", reg_offset);*/
			//printf("%s\n", infer_register(reg_offset));
            ple->mutable_llvmentry()->set_addr_type(TGT); // Something in CPU state, may not necessarily be a register
            ple->mutable_llvmentry()->set_cpustate_offset(reg_offset); // Something in CPU state, may not necessarily be a register
            //TODO: Fix this and store
        } else {
            ple->mutable_llvmentry()->set_addr_type(MEM); 
        }

        ple->mutable_llvmentry()->set_address(address);
        ple->mutable_llvmentry()->set_num_bytes(4);

        globalLog.write_entry(std::move(ple));
    }
}

void recordStore(uint64_t address, uint64_t value){

    //printf("recording store to address %lx\n", address);
    
    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_STORE);
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);

        //TODO: THIS REALLY NEEDS TO BE LOOKED AT 
        uint64_t x86state = (uint64_t)cpus.tqh_first->env_ptr;
        
        /*printf("Address: %lx, firstcpu: %lx - %lx\n", address, (uint64_t)first_cpu, (uint64_t)first_cpu + sizeof(CPUState));*/
		/*printf("Address: %lx, cpux86state: %lx - %lx\n", address, x86state, x86state + sizeof(CPUState));*/
        /*printf("Value %lu\n", value);*/
        if ((address >= x86state) && (address < x86state + sizeof(CPUState))){
            uint32_t reg_offset = (address - x86state)/4;
			/*printf("%u\n", reg_offset);*/
			/*printf("%s\n", infer_register(reg_offset));*/
            ple->mutable_llvmentry()->set_addr_type(TGT); // Something in CPU state, may not necessarily be a register
            ple->mutable_llvmentry()->set_cpustate_offset(reg_offset); // Something in CPU state, may not necessarily be a register
            //TODO: Fix this and store
        } else {
            ple->mutable_llvmentry()->set_addr_type(MEM); 
        }

        ple->mutable_llvmentry()->set_address(address);
        ple->mutable_llvmentry()->set_num_bytes(4);
        ple->mutable_llvmentry()->set_value(value);

        globalLog.write_entry(std::move(ple));
    }
}

void recordReturn(uint64_t retVal){
    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_RET);
        ple->mutable_llvmentry()->set_value(retVal);
        globalLog.write_entry(std::move(ple));
    }
}

void recordSelect(uint8_t condition){
    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_SELECT);
        ple->mutable_llvmentry()->set_condition(condition);

        globalLog.write_entry(std::move(ple));
    }

}

void recordSwitch(uint32_t condition){
    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_SWITCH);
        ple->mutable_llvmentry()->set_condition(condition);

        globalLog.write_entry(std::move(ple));
    }

}

void recordBranch(uint8_t condition){
    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_BR);
        ple->mutable_llvmentry()->set_condition(condition);

        globalLog.write_entry(std::move(ple));
    }
}


//********************************************************
// Visit functions
// ********************************************************

void PandaLLVMTraceVisitor::visitInstruction(Instruction &I) {
    //I.dump();
    //printf("Error: Unhandled instruction\n");
    /*assert(1==0);*/
}

//TODO: Do i need to check metadata to see if host instruction?


void PandaLLVMTraceVisitor::visitReturnInst(ReturnInst &I){

    // Record the return value
    // Should not be NULL
    //Value *retVal = I.getReturnValue();
    //retVal = castTo(retVal, Int64Type, "", &I);
    //std::vector<Value*> args = make_vector(retVal, 0);

    CallInst *CI = CallInst::Create(recordReturnF);
    
    //insert call into function
    CI->insertBefore(static_cast<Instruction*>(&I));
    CI->setMetadata("host", LLVMTraceMD);
}


void PandaLLVMTraceVisitor::visitSelectInst(SelectInst &I){

    // Get the condition and record it
    Value *cond = I.getCondition();
    cond = castTo(cond, Int8Type, cond->getName(), &I);
    std::vector<Value*> args = make_vector(cond, 0);

    CallInst *CI = CallInst::Create(recordSelectF, args);
    
    //insert call into function
    CI->insertAfter(static_cast<Instruction*>(&I));
    CI->setMetadata("host", LLVMTraceMD);
}

void PandaLLVMTraceVisitor::visitSwitchInst(SwitchInst &I){

    // Get the condition and record it
    Value *cond = I.getCondition();
    cond = castTo(cond, Int64Type, cond->getName(), &I);

    std::vector<Value*> args = make_vector(cond, 0);

    CallInst *CI = CallInst::Create(recordSwitchF, args);
    
    //insert call into function
    CI->insertBefore(static_cast<Instruction*>(&I));
    CI->setMetadata("host", LLVMTraceMD);
}

void PandaLLVMTraceVisitor::visitBranchInst(BranchInst &I){

    // Get the condition and record it
    Value *cond;
    if (I.isConditional()){
        cond = I.getCondition();
        cond = castTo(cond, Int8Type, cond->getName(), &I);
    }
    else {
        cond = ConstantInt::get(Int8Type, 111);
    }
    std::vector<Value*> args = make_vector(cond, 0);

    CallInst *CI = CallInst::Create(recordBranchF, args);
    
    //insert call into function
    CI->insertBefore(static_cast<Instruction*>(&I));
    CI->setMetadata("host", LLVMTraceMD);

    /*I.dump();*/
}

void PandaLLVMTraceVisitor::visitLoadInst(LoadInst &I){

    //Get the address we're loading from 
    // and cast to void ptr type
    Value *ptr = I.getPointerOperand();
    ptr = castTo(ptr, VoidPtrType, ptr->getName(), &I);
   
    std::vector<Value*> args = make_vector(ptr, 0);

    CallInst *CI = CallInst::Create(recordLoadF, args);
    
    //insert call into function
    CI->insertAfter(static_cast<Instruction*>(&I));
    CI->setMetadata("host", LLVMTraceMD);
    
    /*I.dump();*/
}

void PandaLLVMTraceVisitor::visitStoreInst(StoreInst &I){
    if (I.isVolatile()){
        // Stores to LLVM runtime that we don't care about
        return;
    }

    Value *address = castTo(I.getPointerOperand(), VoidPtrType, I.getPointerOperand()->getName(), &I);    
    Value *val = I.getValueOperand();
    /*val->dumpa);*/
    if (val->getType()->isPointerTy()){
        printf("Val is a ptr TYPE?\n");
        /*val->getType()->dump();*/
        /*printf("\n");*/
        //val = ConstantInt::get(Int64Type, 111);
        //XXX Fix this later
        val = ConstantInt::get(Int64Type, 111);
    } else{
        val = castTo(val, Int64Type, I.getValueOperand()->getName(), &I);    
    }

    std::vector<Value*> args = make_vector(address, val, 0);

    CallInst *CI = CallInst::Create(recordStoreF, args);

    CI->insertAfter(static_cast<Instruction*>(&I));
    CI->setMetadata("host", LLVMTraceMD);

    //handle cases where dynamic values are being used. 
}


/**
 * This function handles intrinsics like llvm.memset and llvm.memcpy. 
 * llvm.memset is recorded as a Store, and llvm.memcpy is recorded as first a Load from src and second a Store to dest
 */
void PandaLLVMTraceVisitor::handleVisitSpecialCall(CallInst &I){
    
    Function *calledFunc = I.getCalledFunction();

    std::string name = calledFunc->getName().str();
    printf("func name %s\n", name.c_str());

    if (name.substr(0,12) == "llvm.memset.") {
        // Record store
        
        Value *dest = I.getOperand(0);
        dest = castTo(dest, VoidPtrType, dest->getName(), &I);

        Value *value = I.getOperand(1);
        value = castTo(value, Int64Type, "", &I);
        
        Value* numBytes = I.getOperand(2);

        int bytes = 0;
        if (ConstantInt* CI = dyn_cast<ConstantInt>(numBytes)) {
            if (CI->getBitWidth() <= 64) {
                bytes = CI->getSExtValue();
            }
        }

        if (bytes > 100) {
            //This mostly happens in cpu state reset
            printf("Note: dyn log ignoring memset greater than 100 bytes\n");
            return;
        }

        /*std::vector<Value*> args = make_vector(dest, numBytes, 0);*/
        std::vector<Value*> args = make_vector(dest, value, 0);
        CallInst *CI = CallInst::Create(recordStoreF, args);
        
        //insert call into function
        CI->insertAfter(static_cast<Instruction*>(&I));
        CI->setMetadata("host", LLVMTraceMD);

    } else if (name.substr(0,12) == "llvm.memcpy." ||
             name.substr(0,13) == "llvm.memmove.")  {

        Value *dest = I.getOperand(0);
        Value *src = I.getOperand(1);

        /*Value *numBytes = I.getOperand(2);*/
        dest = castTo(dest, VoidPtrType, dest->getName(), &I);
        src = castTo(src, VoidPtrType, src->getName(), &I);
        /*std::vector<Value*> args = make_vector(src, numBytes, 0);*/
        std::vector<Value*> args;
        CallInst *CI;
        
        Value* value = ConstantInt::get(Int64Type, 111);
        args = make_vector(dest, value, 0);
        CI = CallInst::Create(recordStoreF, args);
        CI->insertAfter(static_cast<Instruction*>(&I));
        CI->setMetadata("host", LLVMTraceMD);
        
        // insert load after memcpy, pushing back store
        args = make_vector(src, 0);
        CI = CallInst::Create(recordLoadF, args);
        CI->insertAfter(static_cast<Instruction*>(&I));
        CI->setMetadata("host", LLVMTraceMD);

        
    } 
    //else {
        //printf("Unhandled special call\n");
    //}
}

void PandaLLVMTraceVisitor::handleExternalHelperCall(CallInst &I) {
    Function *calledFunc = I.getCalledFunction();

    std::string name = calledFunc->getName().str();

    std::vector<Value*> args;
    if (Regex("helper_[lb]e_ld.*_mmu_panda").match(name)) {
        // Helper load, record load

        // THis should be address
       Value *dest = I.getArgOperand(1);

        dest = CastInst::Create(Instruction::IntToPtr, dest, VoidPtrType, dest->getName(), &I);

       /*dest = castTo(dest, VoidPtrType, dest->getName(), &I);*/
        args = make_vector(dest, 0);
        CallInst *CI = CallInst::Create(recordLoadF, args);
        CI->insertBefore(static_cast<Instruction*>(&I));
    } else if (Regex("helper_[lb]e_st.*_mmu_panda").match(name)) {
        // THis should be address

       Value *dest = I.getArgOperand(1);
       Value *storeVal = I.getArgOperand(2);

       //dest = castTo(dest, VoidPtrType, dest->getName(), &I);
        dest = CastInst::Create(Instruction::IntToPtr, dest, VoidPtrType, dest->getName(), &I);
       storeVal = castTo(storeVal, Int64Type, storeVal->getName(), &I);
        //ITPI2 = IRB.CreateIntToPtr(storeVal, VoidPtrType);
        //storeVal = CastInst::Create(Instruction::IntToPtr, storeVal, VoidPtrType, storeVal->getName(), &I);

        args = make_vector(dest, storeVal, 0);
        CallInst *CI = CallInst::Create(recordStoreF, args);
        CI->insertBefore(static_cast<Instruction*>(&I));
    } else {
        printf("Unhandled external helper call\n");
    }

}

void PandaLLVMTraceVisitor::visitCallInst(CallInst &I){
    Function *calledFunc = I.getCalledFunction();
    //llvm::Module *mod = tcg_llvm_ctx->getModule();

    if (!calledFunc || !calledFunc->hasName()) { return; }
     
    StringRef name = calledFunc->getName();

    Value *fp;
    if (name.startswith("record")) {
        return;
    }

    if (calledFunc->isIntrinsic()){
        //this is like a memset or memcpy
        handleVisitSpecialCall(I);
        return;
    } else if (external_helper_funcs.count(name)) {
        // model the MMU load/store functions with regular loads/stores from dmemory
       handleExternalHelperCall(I);
        return;
    } else if (calledFunc->isDeclaration()) {
        return;
    }

    printf("call to helper %s\n", name.str().c_str());

    //fp = castTo(I.getCalledFunction(), VoidPtrType, name, &I);   
    fp = ConstantInt::get(Int64Type, (uint64_t)I.getCalledFunction());
    //Clear llvmtrace interrupt flag if an iret
    if (name.startswith("helper_iret")){
        printf("HELPER IRET ENCOUNTERED\n");
        llvmtrace_flags &= ~1;
        fp->dump();
        printf("iret addr: %p\n", fp); 
    }

    //TODO: Should i do something about helper functions?? 

    std::vector<Value*> args = make_vector(fp, 0);

    CallInst *CI = CallInst::Create(recordCallF, args);

    CI->insertAfter(static_cast<Instruction*>(&I));
    CI->setMetadata("host", LLVMTraceMD);

    //record return of call inst
    //CallInst *returnInst = CallInst::Create(recordReturn, args, "", &I);
    //I.dump(); 

    //handle cases where dynamic values are being used. 
}

//*********************************************************
// LLVM Pass Initialization
// ********************************************************

extern "C" { extern TCGLLVMContext *tcg_llvm_ctx; }

static void llvm_init(){

    printf("LLVM_init\n");
    FunctionPassManager *passMngr = tcg_llvm_ctx->getFunctionPassManager();
    Module *mod = tcg_llvm_ctx->getModule();
    LLVMContext &ctx = mod->getContext();
    LLVMTraceMD = MDNode::get(ctx, MDString::get(ctx, "llvmtrace"));

    std::vector<Type*> argTypes;

    //TODO: Stick this somewhere
    // Add the taint analysis pass to our taint pass manager
    PLTP = new llvm::PandaLLVMTracePass(mod);
    passMngr->add(PLTP);

    passMngr->doInitialization();

	 printf("eip: %lu\n", offsetof(CPUX86State, eip)/4);
	 printf("cc_dst: %lu\n", offsetof(CPUX86State, cc_dst)/4);
	 printf("xmm_regs: %lu\n", offsetof(CPUX86State, xmm_regs)/4);
	 printf("segs: %lu\n", offsetof(CPUX86State, segs)/4);
	 printf("ldt : %lu\n", offsetof(CPUX86State, ldt)/4);
	 printf("tr : %lu\n", offsetof(CPUX86State, tr)/4);
	 printf("segs gdt: %lu\n", offsetof(CPUX86State, gdt)/4);
	 printf("segs idt: %lu\n", offsetof(CPUX86State, idt)/4);
	 printf("cr array: %lu\n", offsetof(CPUX86State, cr)/4);
	 printf("bnd_regs: %lu\n", offsetof(CPUX86State, bnd_regs)/4);
	 printf("fpregs: %lu\n", offsetof(CPUX86State, fpregs)/4);
	 printf("fpop: %lu\n", offsetof(CPUX86State, fpop)/4);


	 printf("exception_next_eip: %lu\n", offsetof(CPUX86State, exception_next_eip)/4);

}


void instrumentBasicBlock(BasicBlock &BB){
    Module *module = tcg_llvm_ctx->getModule();
    Value *FP = castTo(BB.getParent(), VoidPtrType, "", BB.getTerminator());
    Value *tb_num_val;
    if (BB.getParent()->getName().startswith("tcg-llvm-tb-")) {
        int tb_num; 
        sscanf(BB.getParent()->getName().str().c_str(), "tcg-llvm-tb-%d-%*d", &tb_num); 
        tb_num_val = ConstantInt::get(Int64Type, tb_num);
    } else {
        tb_num_val = ConstantInt::get(Int64Type, 0);
    }   

    //Function *recordBBF = module->getFunction("recordBB");
    Function *recordStartBBF = module->getFunction("recordStartBB");

    //Value *lastBB;
    //if (isa<ReturnInst>(BB.getTerminator()))
         //lastBB = ConstantInt::get(Int32Type, 1);
    //else
         //lastBB = ConstantInt::get(Int32Type, 0);
    
    //std::vector<Value*> args = make_vector<Value*>(FP, lastBB, 0);
    //CallInst::Create(recordBBF, args, "", BB.getTerminator());

    // Insert code at the beginning of the basic block to record that it started
    // execution.

    std::vector<Value*> args = make_vector<Value *>(FP, tb_num_val, 0);
    Instruction *F = BB.getFirstInsertionPt();
    CallInst::Create(recordStartBBF, args, "", F);
}

char PandaLLVMTracePass::ID = 0;
static RegisterPass<PandaLLVMTracePass>
Y("PandaLLVMTrace", "Instrument instructions that produce dynamic values");

bool PandaLLVMTracePass::runOnBasicBlock(BasicBlock &B){
    //TODO: Iterate over function instrs
    instrumentBasicBlock(B);
    PLTV->visit(B);
    return true; // modified program
};

//What initialization is necessary? 
bool PandaLLVMTracePass::doInitialization(Module &module){
    printf("Doing pandallvmtracepass initialization\n");
    ExecutionEngine *execEngine = tcg_llvm_ctx->getExecutionEngine();
      // Get references to the different types that we'll need.
  Int8Type  = IntegerType::getInt8Ty(module.getContext());
  Int32Type = IntegerType::getInt32Ty(module.getContext());
  Int64Type = IntegerType::getInt64Ty(module.getContext());
  VoidPtrType = PointerType::getUnqual(Int8Type);
  VoidType = Type::getVoidTy(module.getContext());

  // Insert code at the beginning of the basic block to record that it started
  // execution.
  //std::vector<Value*> args = make_vector<Value *>();
  //Instruction *F = BB.getFirstInsertionPt();
  //Instruction *S = CallInst::Create(recordStartBBF, args, "", F);

    //initialize all the other record/logging functions
    PLTV->recordLoadF = cast<Function>(module.getOrInsertFunction("recordLoad", VoidType, VoidPtrType, nullptr));
    PLTV->recordStoreF = cast<Function>(module.getOrInsertFunction("recordStore", VoidType, VoidPtrType, Int64Type, nullptr));
    PLTV->recordCallF = cast<Function>(module.getOrInsertFunction("recordCall", VoidType, Int64Type, nullptr));
    PLTV->recordSelectF = cast<Function>(module.getOrInsertFunction("recordSelect", VoidType, Int8Type, nullptr));
    PLTV->recordSwitchF = cast<Function>(module.getOrInsertFunction("recordSwitch", VoidType, Int64Type, nullptr));
    PLTV->recordBranchF = cast<Function>(module.getOrInsertFunction("recordBranch", VoidType, Int8Type, nullptr));
    // recordStartBB: 
    PLTV->recordStartBBF = cast<Function>(module.getOrInsertFunction("recordStartBB", VoidType, VoidPtrType, Int64Type, nullptr));
    PLTV->recordBBF = cast<Function>(module.getOrInsertFunction("recordBB", VoidType, VoidPtrType, Int32Type, nullptr));
    PLTV->recordReturnF = cast<Function>(module.getOrInsertFunction("recordReturn", VoidType, nullptr));

    //add external linkages
    
#define ADD_MAPPING(func) \
    execEngine->addGlobalMapping(module.getFunction(#func), (void *)(func));\
    module.getFunction(#func)->deleteBody();
    ADD_MAPPING(recordLoad);
    ADD_MAPPING(recordStore);
    ADD_MAPPING(recordCall);
    ADD_MAPPING(recordSelect);
    ADD_MAPPING(recordSwitch);
    ADD_MAPPING(recordBranch);
    ADD_MAPPING(recordStartBB);
    ADD_MAPPING(recordBB);
    ADD_MAPPING(recordReturn);
    return true; //modified program
};


} // namespace llvm
// I'll need a pass manager to traverse stuff. 

//*************************************************************************
// Helper functions
//*************************************************************************

const char* infer_register(uint32_t offset){
    switch (offset) {
    case 0:
        return "EAX";
    case 1:
        return "ECX";
    case 2:
        return "EDX";
    case 3:
        return "EBX";
    case 4:
        return "ESP ";
    case 5:
        return "EBP";
    case 6:
        return "ESI";
    case 7:
        return "EDI";
    case 8:
        return "EIP";
    case 9:
        return "EFLAGS";
    case 10:
        return "CC_DST";
    case 11:
        return "CC_SRC";
    case 12:
        return "CC_SRC2";
    case 13:
        return "CC_OP";
    case 14:
        return "DF";
    default:
        printf("NOT an x86 reg: %u\n", offset);
        return "";
	}
}

char* lookup_libname(target_ulong curpc, OsiModules* ms){
    for (int i = 0; i < ms->num; i++){
        if (curpc >= ms->module[i].base && curpc <= ms->module[i].base + ms->module[i].size){
            //we've found the module this belongs to
            //return name of module
            return ms->module[i].name;
        }
    }
    return NULL;
}


//*************************************************************************
// PANDA Plugin setup functions and callbacks
//*************************************************************************

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    // write LLVM FUNCTION to pandalog
    // Get dynamic libraries of current process
    OsiProc *current = get_current_process(env);
    OsiModules *ms = get_libraries(env, current);
        
    target_ulong curpc = panda_current_pc(env);

    //Look up mapping/library name
    const char* lib_name;
    if (ms == NULL){
        lib_name = "";
    } else {
        lib_name = lookup_libname(curpc, ms);
    }

    if (llvmtrace_flags&1 && !record_int){
        // this is an interrupt, and we don't want to record interrupts. turn off record
        printf("TURNING OFF RECORD\n");
        do_record = false;
    }
    printf("lib_name: %s\n", lib_name);
    
    if (pandalog && do_record) {
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_type(FunctionCode::LLVM_FN);

        if (tb->llvm_function->getName().startswith("tcg-llvm-tb-")) {
            int tb_num; 
            sscanf(tb->llvm_function->getName().str().c_str(), "tcg-llvm-tb-%d-%*d", &tb_num); 
            /*llvmentry->tb_num = tb_num;*/
            ple->mutable_llvmentry()->set_tb_num(tb_num);
        
            ple->mutable_llvmentry()->set_flags(llvmtrace_flags);
            
            if (lib_name != NULL){
                ple->mutable_llvmentry()->set_vma_name(lib_name);
            }
        }   
        
        globalLog.write_entry(std::move(ple));
    }

    return 0;
}

int cb_cpu_restore_state(CPUState *env, TranslationBlock *tb){
    printf("EXCEPTION - logging\n");
    
    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_type(FunctionCode::LLVM_EXCEPTION);

        globalLog.write_entry(std::move(ple));
    }
        
    return 0; 
}

bool init_plugin(void *self){
    printf("Initializing plugin llvm_trace2\n");

    panda_cb pcb;
    panda_enable_memcb();
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    
    // Initialize OS API
    if(!init_osi_api()) return false;
    
    //Parse args
    panda_arg_list *args = panda_get_args("llvm_trace2");
    if (args != NULL) {
        record_int = panda_parse_bool_opt(args, "int","set to 1 to record interrupts. 0 by default");
    }

    //Initialize pandalog
    if (!pandalog){
        printf("Must supply -pandalog logfile argument\n");
        exit(1);
    }
        
    // Initialize pass manager
    
    // I have to enable llvm to get the tcg_llvm_ctx
    if (!execute_llvm){
        panda_enable_llvm();
    }
    
    panda_enable_llvm_helpers();

    llvm::llvm_init();
  /*
     * Run instrumentation pass over all helper functions that are now in the
     * module, and verify module.
     */
    llvm::Module *module = tcg_llvm_ctx->getModule();

    // Populate module with helper function log ops 
    /*for (llvm::Function f : *mod){*/
        for (llvm::Module::iterator func = module->begin(), mod_end = module->end(); func != mod_end; ++func) {
            for (llvm::Function::iterator b = func->begin(), be = func->end(); b != be; ++b) {
                llvm::BasicBlock* bb = b;
                llvm::PLTP->runOnBasicBlock(*bb);
            }
        }

    return true;
}
void uninit_plugin(void *self){
    printf("Uninitializing plugin\n");
    llvm::Module *mod = tcg_llvm_ctx->getModule();

	llvm::Constant* cpustate = llvm::ConstantInt::get(llvm::Int64Type, (uint64_t)cpus.tqh_first->env_ptr);
	//Add a global variable of the CPUState address
	llvm::GlobalVariable* CPUStateAddr =  new llvm::GlobalVariable(/*Module=*/*mod, 
        /*Type=*/cpustate->getType(),
        /*isConstant=*/true,
        /*Linkage=*/llvm::GlobalValue::ExternalLinkage,
        /*Initializer=*/cpustate, // has initializer, specified below
        /*Name=*/"CPUStateAddr");
	
	CPUStateAddr->dump();
    
    //XXX: Make this be done somewhere else, in cleanup
    /*globalLog.close();*/

    tcg_llvm_write_module(tcg_llvm_ctx, "./llvm-mod.bc");
    
     llvm::PassRegistry *pr = llvm::PassRegistry::getPassRegistry();
    const llvm::PassInfo *pi =
        pr->getPassInfo(llvm::StringRef("PandaLLVMTrace"));
    if (!pi){
        printf("Unable to find 'PandaLLVMTrace' pass in pass registry\n");
    }
    else {
        pr->unregisterPass(*pi);
    }

    panda_disable_llvm_helpers();

    if (execute_llvm){
        panda_disable_llvm();
    }
    panda_disable_memcb();
}


