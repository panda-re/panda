
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

#include <llvm_trace2.h>

#include "panda/plugin.h"
#include "panda/tcg-llvm.h"
#include "panda/plugin_plugin.h"

#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include "llvm/ExecutionEngine/GenericValue.h"



namespace llvm {

PandaLLVMTracePass *PLTP; 

// Unhandled
void PandaLLVMTraceVisitor::visitInstruction(Instruction &I) {
    //I.dump();
    printf("Error: Unhandled instruction\n");
    /*assert(1==0);*/
}

void PandaLLVMTraceVisitor::visitLoadInst(LoadInst &I){
	//Function *func = module->getFunction("log_dynval");

	//std::vector<GenericValue> noargs;
    CallInst *CI = CallInst::Create(log_dynvalF);
	//if (!func) {
		//printf("Instrumentation function not found\n");
		//assert(1==0);
	//}
	
	//insert call into function
	CI->insertAfter(static_cast<Instruction*>(&I));
	
	//I.dump();
}

//void PandaLLVMTraceVisitor::visitPhiInst(){

//}

void PandaLLVMTraceVisitor::visitStoreInst(StoreInst &I){
	//Function *func = module->getFunction("log_dynval");

	//if (!func){
		//printf("Instrumentation function not found\n");
		//assert(1==0);
	//}

	I.dump();	

	//handle cases where dynamic values are being used. 
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

    passMngr->doInitialization();
}

char PandaLLVMTracePass::ID = 0;
bool PandaLLVMTracePass::runOnFunction(Function &F){
	//TODO: Iterate over function instrs
	PLTV->visit(F);
	return true; // modified program
};

//What initialization is necessary? 
bool PandaLLVMTracePass::doInitialization(Module &module){

	PLTV->log_dynvalF = module.getFunction("log_dynval");
	return true; //modified program
};

} // namespace llvm
// I'll need a pass manager to traverse stuff. 

bool init_plugin(void *self){
    printf("Initializing plugin llvm_trace2\n");

    // Initialize pass manager
	
	// I have to enable llvm to get the tcg_llvm_ctx
	if (!execute_llvm){
        panda_enable_llvm();
    }
    
    llvm::llvm_init();
  /*
     * Run instrumentation pass over all helper functions that are now in the
     * module, and verify module.
     */
    llvm::Module *mod = tcg_llvm_ctx->getModule();

    // Populate module with helper function log ops 
    for (auto i = mod->begin(); i != mod->end(); i++){
        if (!i->isDeclaration()) llvm::PLTP->runOnFunction(*i);
    }

	return true;
}



