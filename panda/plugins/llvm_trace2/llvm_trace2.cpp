
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

#include "panda/plugin.h"
#include "panda/tcg-llvm.h"
#include "panda/plugin_plugin.h"
#include <iostream>

#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/Support/raw_ostream.h"


namespace llvm {


PandaLLVMTracePass *PLTP; 
  // Integer types
  // Removed const modifier since method signatures have changed
  Type *Int8Type;
  Type *Int32Type;
  Type *Int64Type;
  Type *VoidType;
  Type *VoidPtrType;

//void PandaLLVMTraceVisitor::visitPhiInst(){

//}
void recordStartBB(uint64_t fp, unsigned lastBB){
	
	//printf("recording start of BB\n");

    //giri doesn't write to log, instead pushes onto a bb stack. 

	//if (pandalog) {
		//Panda__LLVMEntry *ple = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
		//*ple = PANDA__LLVMENTRY__INIT;
		//ple->has_type = 1;
		//ple->type = FunctionCode::BB;
        //Panda__LogEntry logEntry = PANDA__LOG_ENTRY__INIT;
		//logEntry.llvmentry = ple;
		//pandalog_write_entry(&logEntry);
	//}
}

void recordCall(uint64_t fp){

	if (pandalog) {
		Panda__LLVMEntry *ple = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
		*ple = PANDA__LLVMENTRY__INIT;
		ple->has_type = 1;
		ple->type = FunctionCode::FUNC_CODE_INST_CALL;
		ple->has_address = 1;
		ple->address = fp;
        Panda__LogEntry logEntry = PANDA__LOG_ENTRY__INIT;
		logEntry.llvmentry = ple;
		pandalog_write_entry(&logEntry);
	}
}
void recordBB(uint64_t fp, unsigned lastBB){
	
	if (pandalog) {
		Panda__LLVMEntry *ple = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
	*ple = PANDA__LLVMENTRY__INIT;
		
		ple->has_type = 1;
		ple->type = FunctionCode::BB;
        Panda__LogEntry logEntry = PANDA__LOG_ENTRY__INIT;
		logEntry.llvmentry = ple;
		pandalog_write_entry(&logEntry);
	}
}

void recordLoad(uint64_t address){
	//printf("ecording load at address %" PRIx64 "\n", address);

	if (pandalog) {
		Panda__LLVMEntry *ple = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
		*ple = PANDA__LLVMENTRY__INIT;
		ple->has_type = 1;
		ple->type = FunctionCode::FUNC_CODE_INST_LOAD;
		ple->has_address = 1;
		ple->address = address;
        Panda__LogEntry logEntry = PANDA__LOG_ENTRY__INIT;
		logEntry.llvmentry = ple;
		pandalog_write_entry(&logEntry);
	}
}

void recordReturn(){
	if (pandalog) {
		Panda__LLVMEntry *ple = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
		*ple = PANDA__LLVMENTRY__INIT;
		ple->has_type = 1;
		ple->type = FunctionCode::FUNC_CODE_INST_RET;
        Panda__LogEntry logEntry = PANDA__LOG_ENTRY__INIT;
		logEntry.llvmentry = ple;
		pandalog_write_entry(&logEntry);
	}
}

void recordStore(uint64_t address){

	/*printf("recording store to address %08x", address);*/

	if (pandalog) {
		Panda__LLVMEntry *ple = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
		*ple = PANDA__LLVMENTRY__INIT;
		ple->has_type = 1;
		ple->type = FunctionCode::FUNC_CODE_INST_STORE;
		ple->has_address = 1;
		ple->address = address;
        Panda__LogEntry logEntry = PANDA__LOG_ENTRY__INIT;
		logEntry.llvmentry = ple;
		pandalog_write_entry(&logEntry);
	}
}


void write_trace_log(){
	printf("writing trace log\n");
}

//this function is inlined into LLVM assembly, writes dynamic values to trace log in protobuf format
void log_dynval(){
    write_trace_log();

}


extern "C" { extern TCGLLVMContext *tcg_llvm_ctx; }

static void llvm_init(){

	printf("LLVM_init\n");
	Function *logFunc;
    ExecutionEngine *execEngine = tcg_llvm_ctx->getExecutionEngine();
    FunctionPassManager *passMngr = tcg_llvm_ctx->getFunctionPassManager();
    Module *mod = tcg_llvm_ctx->getModule();
    LLVMContext &ctx = mod->getContext();
	
	std::vector<Type*> argTypes;

	//1st arg, LLVM Instr opcode
	argTypes.push_back(IntegerType::get(ctx, 8*sizeof(unsigned)));
	
	// 2nd arg, num_args
	argTypes.push_back(IntegerType::get(ctx, 8*sizeof(unsigned)));

	// 3rd arg, 
	//argTypes.push_back(Integer

	FunctionType *fType = FunctionType::get(Type::getVoidTy(ctx), argTypes, false);
	logFunc = Function::Create(
		fType, 
		Function::ExternalLinkage, "log_dynval", mod
	);

	execEngine->addGlobalMapping(logFunc, (void*) &log_dynval);

    // Create instrumentation pass and add to function pass manager
    /*llvm::FunctionPass *instfp = new PandaLLVMTracePass(mod);*/
    /*fpm->add(instfp);*/
    /*PIFP = static_cast<PandaInstrFunctionPass*>(instfp);*/

	//TODO: Stick this somewhere
    // Add the taint analysis pass to our taint pass manager
   	PLTP = new llvm::PandaLLVMTracePass(mod);
    passMngr->add(PLTP);

	printf("before passmngr initialization\n");
    passMngr->doInitialization();
	printf("after passmgr initialization\n");
}


void instrumentBasicBlock(BasicBlock &BB){
    Module *module = tcg_llvm_ctx->getModule();
	Value *FP = castTo(BB.getParent(), VoidPtrType, "", BB.getTerminator());
	
	Function *recordBBF = module->getFunction("recordBB");
	Function *recordStartBBF = module->getFunction("recordStartBB");

	Value *lastBB;
	if (isa<ReturnInst>(BB.getTerminator()))
		 lastBB = ConstantInt::get(Int32Type, 1);
	else
		 lastBB = ConstantInt::get(Int32Type, 0);
	
	std::vector<Value*> args = make_vector<Value*>(FP, lastBB, 0);
	CallInst::Create(recordBBF, args, "", BB.getTerminator());

  // Insert code at the beginning of the basic block to record that it started
  // execution.
  args = make_vector<Value *>(FP, 0);
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


	//initialize all the other record/logging functionsu
	//PLTV->log_dynvalF = module.getOrInsertFunction("log_dynval");
	PLTV->recordLoadF = cast<Function>(module.getOrInsertFunction("recordLoad", VoidType, VoidPtrType, nullptr));
	PLTV->recordStoreF = cast<Function>(module.getOrInsertFunction("recordStore", VoidType, VoidPtrType, nullptr));
	PLTV->recordCallF = cast<Function>(module.getOrInsertFunction("recordCall", VoidType, VoidPtrType, nullptr));
	// recordStartBB: 
	PLTV->recordStartBBF = cast<Function>(module.getOrInsertFunction("recordStartBB", VoidType, VoidPtrType, nullptr));
	// recordBB: VoidPtrType fp, Int64Type lastBB
	PLTV->recordBBF = cast<Function>(module.getOrInsertFunction("recordBB", VoidType, VoidPtrType, Int32Type, nullptr));
	PLTV->recordReturnF = cast<Function>(module.getOrInsertFunction("recordReturn", VoidType, VoidPtrType, nullptr));


	//add external linkages
	
#define ADD_MAPPING(func) \
    execEngine->addGlobalMapping(module.getFunction(#func), (void *)(func));\
    module.getFunction(#func)->deleteBody();
    ADD_MAPPING(recordLoad);
    ADD_MAPPING(recordStore);
    ADD_MAPPING(recordCall);
    ADD_MAPPING(recordStartBB);
    ADD_MAPPING(recordBB);
    ADD_MAPPING(recordReturn);
	return true; //modified program
};


// Unhandled
void PandaLLVMTraceVisitor::visitInstruction(Instruction &I) {
    //I.dump();
    //printf("Error: Unhandled instruction\n");
    /*assert(1==0);*/
}

//TODO: Do i need to check metadata to see if host instruction?

void PandaLLVMTraceVisitor::visitLoadInst(LoadInst &I){
	//Function *func = module->getFunction("log_dynval");

	//std::vector<GenericValue> noargs;

	//Get the address we're loading from 
	// and cast to void ptr type
	Value *ptr = I.getPointerOperand();
	ptr = castTo(ptr, VoidPtrType, ptr->getName(), &I);
	std::vector<Value*> args = make_vector(ptr, 0);

    CallInst *CI = CallInst::Create(recordLoadF, args);
	
	//insert call into function
	CI->insertAfter(static_cast<Instruction*>(&I));
	
	/*I.dump();*/
}


const static std::set<std::string> ignore_funcs{
    "recordStartBB", "recordBB"
};

void PandaLLVMTraceVisitor::visitCallInst(CallInst &I){
	//Function *func = module->getFunction("log_dynval");

	Function *calledFunc = I.getCalledFunction();

	// if it's an intrinsic function, record the ID that was called
	Value *fp;
	if (calledFunc->isIntrinsic()){
		//fp = ConstantInt::get(Type::getInt64Ty(module->getContext()), calledFunc->getIntrinsicID());
		//fp = castTo(fp, VoidPtrType, "", &I);
		//std::cout << "called intrinsic " <<  Intrinsic::getName(Intrinsic::ID(calledFunc->getIntrinsicID())) << "\n";
		printf("INTRINSIC FUNC\n");
		return;
        /*fp = Constant::getNullValue(VoidPtrType);*/
	}
	else if (ignore_funcs.count(calledFunc->getName())) {
		/*printf("IGNORING FUNC\n");*/
		return;
	} else {
		fp = castTo(I.getCalledValue(), VoidPtrType, "", &I);
		//fp = I.getCalledValue();
		//printf("TYPE %s", fp->getType()->print());
		//std::string type_str;
		//raw_string_ostream rso(type_str);
		//fp->getType()->print(rso);
		//std::cout<<rso.str()<<"\n";
	}

	//TODO: Should i do something about helper functions?? 

	std::vector<Value*> args = make_vector(fp, 0);

    CallInst *CI = CallInst::Create(recordCallF, args);

	CI->insertAfter(static_cast<Instruction*>(&I));

	//record return of call inst
	//CallInst *returnInst = CallInst::Create(recordReturn, args, "", &I);
	//I.dump();	

	//handle cases where dynamic values are being used. 
}

void PandaLLVMTraceVisitor::visitStoreInst(StoreInst &I){
	//Function *func = module->getFunction("log_dynval");

    if (I.isVolatile()){
        // Stores to LLVM runtime that we don't care about
        return;
    }

	Value *address = castTo(I.getPointerOperand(), VoidPtrType, "", &I);	

	std::vector<Value*> args = make_vector(address, 0);

    CallInst *CI = CallInst::Create(recordStoreF, args);

	CI->insertAfter(static_cast<Instruction*>(&I));
	//I.dump();	

	//handle cases where dynamic values are being used. 
}


} // namespace llvm
// I'll need a pass manager to traverse stuff. 

int before_block_exec(CPUState *env, TranslationBlock *tb) {
	// write LLVM FUNCTION to pandalog
	
	if (pandalog) {
		Panda__LLVMEntry *ple = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
		*ple = PANDA__LLVMENTRY__INIT;
		ple->has_type = 1;
		ple->type = FunctionCode::LLVM_FN;
		ple->has_address = 0;
        Panda__LogEntry logEntry = PANDA__LOG_ENTRY__INIT;
		logEntry.llvmentry = ple;
		pandalog_write_entry(&logEntry);
	}

	return 0;
}


bool init_plugin(void *self){
    printf("Initializing plugin llvm_trace2\n");

    panda_cb pcb;
    panda_enable_memcb();
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

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
    //llvm::Module *mod = tcg_llvm_ctx->getModule();

    // Populate module with helper function log ops 
    //for (auto i = mod->begin(); i != mod->end(); i++){
        //if (!i->isDeclaration()) llvm::PLTP->runOnBasicBlock(*i);
    //}

	return true;
}
void uninit_plugin(void *self){
    printf("Uninitializing plugin\n");

    /*char modpath[256];*/
    /*strcpy(modpath, basedir);*/
    /*strcat(modpath, "/llvm-mod.bc");*/
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
