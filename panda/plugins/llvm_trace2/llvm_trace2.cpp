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
#define UNW_LOCAL_ONLY

#include <vector>
#include <set>
#include <string>
#include <libunwind.h>

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
#include <fstream>
#include <sstream>


#include <llvm/IR/Metadata.h>
#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instruction.h>

#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Regex.h"

extern PandaLog globalLog;
extern int llvmtrace_flags;
extern bool panda_exit_loop;

bool do_record = true;
bool record_int = false;
bool use_osi = false;

bool llvm_done = false;

uint64_t startpc = -1;
uint64_t startinstr = -1;
uint64_t endpc = UINT64_MAX;
uint64_t endinstr = UINT64_MAX;

#define cpu_off(member) (uint64_t)(&((CPUArchState *)0)->member)
#define cpu_size(member) sizeof(((CPUArchState *)0)->member)
#define cpu_endoff(member) (cpu_off(member) + cpu_size(member))
#define cpu_contains(member, offset) \
    (cpu_off(member) <= (size_t)(offset) && \
     (size_t)(offset) < cpu_endoff(member))

std::vector<std::string> registers = {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "EIP", "EFLAGS", "CC_DST", "CC_SRC", "CC_SRC2", "CC_OP", "DF"};

namespace llvm {

    MDNode *LLVMTraceMD;

    PandaLLVMTracePass *PLTP; 
  // Integer types
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

void replaceIndirectCall(uint64_t fp, uint64_t num_args, ...){

    va_list Args;
    va_start(Args, num_args);
    std::vector<uint64_t> Result;
    for (int i = 0; i < num_args; i++) {
        uint64_t Val = va_arg(Args, uint64_t);
        Result.push_back(Val);
    }
    va_end(Args);

    // Look up called function pointer
    Module *mod = tcg_llvm_ctx->getModule();
    ExecutionEngine *execEngine = tcg_llvm_ctx->getExecutionEngine();

    unw_cursor_t cursor;
    unw_context_t context;
    unw_word_t offset;

    // Initialize cursor to current frame for local unwinding.
    unw_getcontext(&context);
    unw_init_local(&cursor, &context);
    char func_name[64];

    // Set PC for unwind to function pointer
    unw_set_reg(&cursor, UNW_REG_IP, fp);
    if (unw_get_proc_name(&cursor, func_name, sizeof(func_name), &offset) == 0) {
        printf("Indirect call to unknown function");
        return;
    }

    printf("Indirectly calling func %s\n", func_name);
    Function* llvmNewFunc = mod->getFunction(StringRef(func_name));

    std::vector<GenericValue> args(llvmNewFunc->getFunctionType()->getNumParams());

    // Construct GenericValue arguments for Function
    for (int i = 0; i < llvmNewFunc->getFunctionType()->getNumParams(); i++) {
        if (llvmNewFunc->getFunctionType()->getParamType(i)->isPointerTy()){
            args[i].PointerVal = (void*) Result[i];        
        } else {
            args[i].IntVal = APInt(64, Result[i]);        
        }
    }

    // Call LLVM version of function with passed-in args
    GenericValue retval = execEngine->runFunction(llvmNewFunc, args);

    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_CALL);
        ple->mutable_llvmentry()->set_address(fp);

        ple->mutable_llvmentry()->set_called_func_name(func_name);
        
        globalLog.write_entry(std::move(ple));
    }
}

void recordCall(uint64_t fp){

    Function* calledFunc = (Function*)fp;

    StringRef calledFuncName = calledFunc->getName();
 
    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_CALL);
        ple->mutable_llvmentry()->set_address(fp);

        if (!calledFuncName.empty()) {
            ple->mutable_llvmentry()->set_called_func_name(calledFuncName.str().c_str());
        }
        
        globalLog.write_entry(std::move(ple));
    }

    // Handling this in seg_helper.c now...
    // if (calledFunc->getName().startswith("helper_iret")){
    //     llvmtrace_flags &= ~1;

    //     //turn on record!
    //     if (!do_record){
    //         do_record = true;
    //         printf("HELPER_IRET LLVM ENCOUNTERED, TURNED ON RECORD\n");
    //         // panda_enable_llvm();
    //     }
    // }
}

//TODO: Can I get rid of this?
// void recordBB(uint64_t fp, unsigned lastBB){
    
//     if (pandalog && do_record){
//         std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
//         ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
//         ple->mutable_llvmentry()->set_type(FunctionCode::BB);

//         globalLog.write_entry(std::move(ple));
//     }
// }

void recordLoad(uint64_t address, uint64_t resultval, uint64_t num_bytes){
    // printf("recording load from   address %lx, resultval %lx\n", address, resultval);

    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_LOAD);

        uint64_t x86state = (uint64_t)cpus.tqh_first->env_ptr;
		
        if ((address >= x86state) && (address < x86state + sizeof(CPUState))){
            uint32_t reg_offset = (address - x86state)/4;
            ple->mutable_llvmentry()->set_addr_type(TGT); // Something in CPU state, may not necessarily be a register
            ple->mutable_llvmentry()->set_cpustate_offset(reg_offset); // Something in CPU state, may not necessarily be a register
            //TODO: Fix this and store
        } else {
            ple->mutable_llvmentry()->set_addr_type(MEM); 
        }

        ple->mutable_llvmentry()->set_address(address);
        ple->mutable_llvmentry()->set_num_bytes(num_bytes);
        ple->mutable_llvmentry()->set_value(resultval);

        globalLog.write_entry(std::move(ple));
    }
}

void recordStore(uint64_t address, uint64_t value, uint64_t num_bytes){

    //printf("recording store to address %lx\n", address);
    
    if (pandalog && do_record){
        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_type(FunctionCode::FUNC_CODE_INST_STORE);
        ple->mutable_llvmentry()->set_pc(first_cpu->panda_guest_pc);

        //TODO: THIS REALLY NEEDS TO BE LOOKED AT 
        uint64_t x86state = (uint64_t)cpus.tqh_first->env_ptr;
        
        if ((address >= x86state) && (address < x86state + sizeof(CPUState))){
            uint32_t reg_offset = (address - x86state)/4;
            ple->mutable_llvmentry()->set_addr_type(TGT); // Something in CPU state, may not necessarily be a register
            ple->mutable_llvmentry()->set_cpustate_offset(reg_offset); // Something in CPU state, may not necessarily be a register
            //TODO: Fix this and store
        } else {
            ple->mutable_llvmentry()->set_addr_type(MEM); 
        }

        ple->mutable_llvmentry()->set_address(address);
        //XXX: Change to variable number of bytes
        ple->mutable_llvmentry()->set_num_bytes(num_bytes);
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

    if (llvmtrace_flags & 1 && !record_int){
        // this is an interrupt, and we don't want to record interrupts. turn off record
        if (do_record){
            printf("TURNING OFF RECORD at pc %lx, instr %lu\n", first_cpu->panda_guest_pc, rr_get_guest_instr_count());
            do_record = false;
        }
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
    // I.dump();
    Value *loadinst = castTo(&I, Int64Type, I.getName(), I.getNextNode());

    std::vector<Value*> args = make_vector(ptr, loadinst, ConstantInt::get(Int64Type, 4), 0);

    CallInst *CI = CallInst::Create(recordLoadF, args);
    
    //insert call into function
    CI->insertAfter(static_cast<Instruction*>(loadinst));
    CI->setMetadata("host", LLVMTraceMD);   
}

void PandaLLVMTraceVisitor::visitStoreInst(StoreInst &I){
    if (I.isVolatile()){
        // Stores to LLVM runtime that we don't care about
        return;
    }

    Value *address = castTo(I.getPointerOperand(), VoidPtrType, I.getPointerOperand()->getName(), &I);    

    Value *storeval = castTo(I.getValueOperand(), Int64Type, I.getValueOperand()->getName(), &I);        

    std::vector<Value*> args = make_vector(address, storeval, ConstantInt::get(Int64Type, 4), 0);

    CallInst *CI = CallInst::Create(recordStoreF, args);

    CI->insertAfter(static_cast<Instruction*>(&I));
    CI->setMetadata("host", LLVMTraceMD);

    //handle cases where dynamic values are being used. 
}


/**
 * This function handles intrinsics like llvm.memset and llvm.memcpy. 
 * llvm.memset is recorded as a Store, and llvm.memcpy is recorded as first a Load from src and second a Store to dest
 */
void PandaLLVMTraceVisitor::handleVisitIntrinsicCall(CallInst &I){
    
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

        std::vector<Value*> args = make_vector(dest, value, numBytes, 0);
        CallInst *CI = CallInst::Create(recordStoreF, args);
        
        //insert call into function
        CI->insertAfter(static_cast<Instruction*>(&I));
        CI->setMetadata("host", LLVMTraceMD);

    } else if (name.substr(0,12) == "llvm.memcpy." ||
             name.substr(0,13) == "llvm.memmove.")  {

        Value *dest = I.getOperand(0);
        Value *src = I.getOperand(1);

        // printf("memcpy src: \n");
        // I.getOperand(1)->dump();

        Value *numBytes = I.getOperand(2);

        dest = castTo(dest, VoidPtrType, dest->getName(), &I);
        src = castTo(src, VoidPtrType, src->getName(), &I);
        /*std::vector<Value*> args = make_vector(src, numBytes, 0);*/
        std::vector<Value*> args;
        CallInst *CI;
        
        //XXX: Record number of bytes and true values
        Value* value = ConstantInt::get(Int64Type, 111);
        args = make_vector(dest, value, numBytes, 0);
        CI = CallInst::Create(recordStoreF, args);
        CI->insertAfter(static_cast<Instruction*>(&I));
        CI->setMetadata("host", LLVMTraceMD);
        
        Value* loadvalue = ConstantInt::get(Int64Type, 111);
        // insert load after memcpy, pushing back store
        args = make_vector(src, loadvalue, numBytes, 0);
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
    SmallVector<StringRef, 3> *matches = new SmallVector<StringRef, 3>();

    if (Regex("helper_([lb]e|ret)_ld(.*)_mmu_panda").match(name, matches)) {
        // Helper load, record load
        int size = -1;
        StringRef sz_c = matches[0][2];
        // printf("sz_c %s", std::string(sz_c).c_str());
        if (sz_c.endswith("q")) size = 8;
        else if (sz_c.endswith("l")) size = 4;
        else if (sz_c.endswith("w")) size = 2;
        else if (sz_c.endswith("b")) size = 1;
        else assert(false && "Invalid size in call to load");
        // printf("Size: %d\n", size);

        // THis should be address
        Value *dest = I.getArgOperand(1);

        dest = CastInst::Create(Instruction::IntToPtr, dest, VoidPtrType, dest->getName(), &I);
        Value *loadresult = castTo(&I, Int64Type, I.getName(), I.getNextNode());

        args = make_vector(dest, loadresult, ConstantInt::get(Int64Type, size), 0);
        CallInst *CI = CallInst::Create(recordLoadF, args);
        CI->insertAfter(static_cast<Instruction*>(loadresult));
    } else if (Regex("helper_([lb]e|ret)_st(.*)_mmu_panda").match(name, matches)) {
        
        int size = -1;
        StringRef sz_c = matches[0][2];
        // printf("sz_c %s", std::string(sz_c).c_str());
        if (sz_c.endswith("q")) size = 8;
        else if (sz_c.endswith("l")) size = 4;
        else if (sz_c.endswith("w")) size = 2;
        else if (sz_c.endswith("b")) size = 1;
        else assert(false && "Invalid size in call to store");
        // printf("Size: %d\n", size);

        // THis should be address
        Value *dest = I.getArgOperand(1);
        Value *storeVal = I.getArgOperand(2);

        //dest = castTo(dest, VoidPtrType, dest->getName(), &I);
        dest = CastInst::Create(Instruction::IntToPtr, dest, VoidPtrType, dest->getName(), &I);
        storeVal = castTo(storeVal, Int64Type, storeVal->getName(), &I);
        //ITPI2 = IRB.CreateIntToPtr(storeVal, VoidPtrType);
        //storeVal = CastInst::Create(Instruction::IntToPtr, storeVal, VoidPtrType, storeVal->getName(), &I);

        args = make_vector(dest, storeVal, ConstantInt::get(Int64Type, size), 0);
        CallInst *CI = CallInst::Create(recordStoreF, args);
        CI->insertBefore(static_cast<Instruction*>(&I));
    } else {
        printf("Unhandled external helper call\n");
    }

}

void PandaLLVMTraceVisitor::visitCallInst(CallInst &I){
    
    Value *fp;  

    if (I.getCalledFunction()) { 
        // Check if value is called
        Function *calledFunc = I.getCalledFunction();

        StringRef name = calledFunc->getName();

        if (name.startswith("record")) {
            return;
        }

        if (calledFunc->isIntrinsic()){
            //this is like a memset or memcpy
            handleVisitIntrinsicCall(I);
            return;
        } else if (external_helper_funcs.count(name)) {
            // model the MMU load/store functions with regular loads/stores from dmemory
           handleExternalHelperCall(I);
            return;
        } else if (calledFunc->isDeclaration()) {
            return;
        }

        // printf("call to helper %s\n", name.str().c_str());

        //fp = castTo(I.getCalledFunction(), VoidPtrType, name, &I);   
        fp = ConstantInt::get(Int64Type, (uint64_t)calledFunc);

        //Clear llvmtrace interrupt flag if an iret
        // XXX: Fix this 
        // if (name.startswith("helper_iret")){
        //     printf("HELPER IRET ENCOUNTERED\n");
        //     llvmtrace_flags &= ~1;
        //     printf("iret addr: %p\n", fp); 
        // }

        std::vector<Value*> args = make_vector(fp, 0);

        CallInst *CI = CallInst::Create(recordCallF, args);

        CI->insertAfter(static_cast<Instruction*>(&I));
        CI->setMetadata("host", LLVMTraceMD);

    } else if (I.getCalledValue()){
        //Called function is not a constant function
        Value *calledVal = I.getCalledValue();

        printf("call to function value \n");

        fp = castTo(calledVal, Int64Type, "", &I);

        std::vector<Value*> args;
        args.push_back(fp);

        args.push_back(ConstantInt::get(Int64Type, I.getNumArgOperands()));

        for (int i = 0; i < I.getNumArgOperands(); i++){
            args.push_back(castTo(I.getArgOperand(i), Int64Type, "", &I));
        }

        //TODO: Fix for calls that return values
        // Only delete call if no uses 
        if (I.use_empty()){

            CallInst *NewCI = CallInst::Create(replaceIndirectCallF, args);

            NewCI->insertBefore(static_cast<Instruction*>(&I));
            NewCI->setMetadata("host", LLVMTraceMD);

            I.getParent()->getInstList().erase(&I);
        } else {
            printf("Indirect call has uses, not replacing with trampoline\n");
        }

    }

    //TODO: Should i do something about helper functions?? 
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
}


void instrumentBasicBlock(BasicBlock &BB){
    Module *module = tcg_llvm_ctx->getModule();
    Value *FP = castTo(BB.getParent(), VoidPtrType, "", BB.getFirstInsertionPt());
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
    CallInst::Create(recordStartBBF, args, "", BB.getFirstInsertionPt());
}

char PandaLLVMTracePass::ID = 0;
static RegisterPass<PandaLLVMTracePass> Y("PandaLLVMTrace", "Instrument instructions that produce dynamic values");

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
    PLTV->recordLoadF = cast<Function>(module.getOrInsertFunction("recordLoad", VoidType, VoidPtrType, Int64Type, Int64Type, nullptr));

    PLTV->recordStoreF = cast<Function>(module.getOrInsertFunction("recordStore", VoidType, VoidPtrType, Int64Type, Int64Type, nullptr));

    PLTV->recordCallF = cast<Function>(module.getOrInsertFunction("recordCall", VoidType, Int64Type, nullptr));

    SmallVector<Type *, 0> ArgTys;
    FunctionType* fType = FunctionType::get(VoidType, ArgTys, true);
    PLTV->replaceIndirectCallF = cast<Function>(module.getOrInsertFunction("replaceIndirectCall", fType));

    PLTV->recordSelectF = cast<Function>(module.getOrInsertFunction("recordSelect", VoidType, Int8Type, nullptr));

    PLTV->recordSwitchF = cast<Function>(module.getOrInsertFunction("recordSwitch", VoidType, Int64Type, nullptr));

    PLTV->recordBranchF = cast<Function>(module.getOrInsertFunction("recordBranch", VoidType, Int8Type, nullptr));

    // recordStartBB: 
    PLTV->recordStartBBF = cast<Function>(module.getOrInsertFunction("recordStartBB", VoidType, VoidPtrType, Int64Type, nullptr));

    PLTV->recordReturnF = cast<Function>(module.getOrInsertFunction("recordReturn", VoidType, nullptr));

    //add external linkages
    
#define ADD_MAPPING(func) \
    execEngine->addGlobalMapping(module.getFunction(#func), (void *)(func));\
    module.getFunction(#func)->deleteBody();
    ADD_MAPPING(recordLoad);
    ADD_MAPPING(recordStore);
    ADD_MAPPING(recordCall);
    ADD_MAPPING(replaceIndirectCall);
    ADD_MAPPING(recordSelect);
    ADD_MAPPING(recordSwitch);
    ADD_MAPPING(recordBranch);
    ADD_MAPPING(recordStartBB);
    // ADD_MAPPING(recordBB);
    ADD_MAPPING(recordReturn);

    return true; //modified program
};


} // end  namespace llvm


// I'll need a pass manager to traverse stuff. 

//*************************************************************************
// Helper functions
//*************************************************************************

OsiModule* lookup_libname(target_ulong curpc, GArray* ms){
    for (int i = 0; i < ms->len; i++){
        OsiModule *mod = &g_array_index(ms, OsiModule, i);

        if (curpc >= mod->base && curpc <= mod->base + mod->size){
            //we've found the module this belongs to
            //return name of module
            return mod;
        }
    }
    return NULL;
}



//*************************************************************************
// PANDA Plugin setup functions and callbacks
//*************************************************************************


void llvmtrace_enable_llvm(){
    // I have to enable llvm to get the tcg_llvm_ctx
    printf("TURNING ON LLVM\n");

    panda_enable_llvm();    
    panda_enable_llvm_helpers();

    llvm::llvm_init();

    /*
     * Run instrumentation pass over all helper functions that are now in the
     * module, and verify module.
     */
    llvm::Module *module = tcg_llvm_ctx->getModule();

    // // Populate module with helper function log ops 
    for (llvm::Module::iterator func = module->begin(), mod_end = module->end(); func != mod_end; ++func) {
        for (llvm::Function::iterator b = func->begin(), be = func->end(); b != be; ++b) {
            llvm::BasicBlock* bb = b;
            llvm::PLTP->runOnBasicBlock(*bb);
        }
    }
}

int llvmtrace_before_block_exec(CPUState *env, TranslationBlock *tb) {
    // write LLVM FUNCTION to pandalog
    // Get dynamic libraries of current process
    if (!execute_llvm) {
        return 0;
    }

    // if we are no longer in interrupt, flip do_record on
    if (!(llvmtrace_flags & 1) && !do_record) {
        printf("TURNING ON RECORD at pc " TARGET_FMT_lx ", instr %lu\n", panda_current_pc(env), rr_get_guest_instr_count());
        do_record = true;
    }
    
    if (pandalog && do_record) {
        //Look up mapping/library name

        std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
        ple->mutable_llvmentry()->set_type(FunctionCode::LLVM_FN);

        if (tb->llvm_function->getName().startswith("tcg-llvm-tb-")) {
            int tb_num; 
            sscanf(tb->llvm_function->getName().str().c_str(), "tcg-llvm-tb-%d-%*d", &tb_num); 
            /*llvmentry->tb_num = tb_num;*/
            ple->mutable_llvmentry()->set_tb_num(tb_num);
        
            ple->mutable_llvmentry()->set_flags(llvmtrace_flags);
            
            if (use_osi) {
                OsiModule* lib = NULL;
                OsiProc *current = get_current_process(env);
                // printf("proc name %s\n", current->name);
                GArray *ms = get_libraries(env, current);
                    
                target_ulong curpc = panda_current_pc(env);

                if (ms == NULL){
                    lib = NULL;
                } else {
                    lib = lookup_libname(curpc, ms);
                    if (lib != NULL) {
                        printf("lib_name %s\n", lib->name);
                        ple->mutable_llvmentry()->set_vma_name(lib->name);
                        ple->mutable_llvmentry()->set_vma_base(lib->base);
                    }
                }

                free_osiproc(current);
                g_array_free(ms, true);   
            }
        }   

        globalLog.write_entry(std::move(ple));

    }

    return 0;
}



int llvmtrace_before_block_translate(CPUState *env, target_ulong pc) {
    if (!execute_llvm){
        std::ofstream crit_file("criteria");
        if (!crit_file.is_open()){
            std::cout << "Error: llvmtrace_before_block_translate could not open crit_file!" << std::endl;
            exit(1);
        }

        if (startinstr != 0){
            uint64_t ins = rr_get_guest_instr_count();
            if (ins > startinstr) {
                llvmtrace_enable_llvm();
                printf (" enabled LLVM tracing @ ins  %" PRId64 "\n", ins);
                crit_file << "rr_start:" << ins << std::endl;
            }
        } else if (startpc != 0){
            if (startpc == pc){
                llvmtrace_enable_llvm();
                printf (" enabled LLVM tracing @ pc " TARGET_FMT_lx ", instr %lu\n", pc, rr_get_guest_instr_count());
                crit_file << "rr_start:" << rr_get_guest_instr_count() << std::endl;
            }
        } else {
            // neither option is set, enable LLVM at beginning
            llvmtrace_enable_llvm();
            printf (" enabled LLVM tracing @ beginning\n");   
        }
        if (crit_file.bad()) {
           std::cout << "Writing to file failed" << std::endl;
           exit(1);
        }
        crit_file.close();

    } 

    return 0; 
}

int llvmtrace_after_block_translate(CPUState *env, TranslationBlock *tb){
    if (execute_llvm){
        std::ofstream crit_file("criteria", std::ios::app);
        if (!crit_file.is_open()){
            std::cout << "Error: llvm_trace_after_block_translate could not open crit_file!" << std::endl;
            exit(1);
        }

        // execute LLVM is on. See if we should disable LLVM 
        if (endinstr != UINT64_MAX){
            uint64_t ins = rr_get_guest_instr_count();
            if (ins > endinstr){
                panda_end_replay();
                printf (" disabled LLVM tracing @ ins  %" PRId64 "\n", ins);
                crit_file << "rr_end:" << ins << std::endl;

            }
        } else if (endpc != UINT64_MAX){
            if (tb->pc <= endpc && endpc <= tb->pc + tb->size){
                panda_end_replay();
                printf (" disabled LLVM tracing @ pc " TARGET_FMT_lx ", instr %lu\n", tb->pc, rr_get_guest_instr_count());
                printf (" writing rr_end instr %lu\n", rr_get_guest_instr_count());
                crit_file << "rr_end:" << rr_get_guest_instr_count() << std::endl;
            }
        }
        if (crit_file.bad()) {
           std::cout << "Writing to file failed" << std::endl;
           exit(1);
        }
        crit_file.close();
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
    pcb.before_block_exec = llvmtrace_before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.before_block_translate = llvmtrace_before_block_translate;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
    pcb.after_block_translate = llvmtrace_after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    panda_arg_list *args = panda_get_args("llvm_trace2");

    if (args != NULL) {
        record_int = panda_parse_bool_opt(args, "int", "set to 1 to record interrupts. 0 by default");
        startpc = panda_parse_uint64_opt(args, "startpc", 0, "Start PC at which to begin LLVM tracing (in hex)");
        endpc = panda_parse_uint64_opt(args, "endpc", UINT64_MAX, "End PC at which to stop LLVM tracing (in hex)");
        startinstr = panda_parse_uint64_opt(args, "startinstr", 0, "Start rr instr count at which to begin LLVM tracing");
        endinstr = panda_parse_uint64_opt(args, "endinstr", UINT64_MAX, "End rr instr count at which to stop LLVM tracing");
    }

    use_osi = panda_parse_bool_opt(args, "use_osi", "use operating system introspection");

    //Initialize pandalog
    if (!pandalog){
        printf("Must supply -pandalog logfile argument\n");
        exit(1);
    }
        
    // Initialize OS API
    if(use_osi && !init_osi_api()) return false;

    // llvmtrace_enable_llvm();

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

    if (execute_llvm){
        panda_disable_llvm_helpers();
        panda_disable_llvm();
    }
}


