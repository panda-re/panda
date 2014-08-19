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

/*
 * This function pass can be used in a plugin for generated code to change LLVM
 * function calls and function names to the associated LLVM versions that we've
 * generated bitcode for.  It is assumed that this will only be used on LLVM
 * code generated from TCG.
 */

#include <stdio.h>

#include "llvm/Linker.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/IR/Module.h"
#include "llvm/PassManager.h"
#include "llvm/PassRegistry.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/raw_ostream.h"

extern "C" {
#include "config.h"
}
#include "tcg-llvm.h"
#include "panda_externals.h"
#include "panda_helper_call_morph.h"

namespace llvm {



/***
 *** PandaCallMorphFunctionPass
 ***/



char PandaCallMorphFunctionPass::ID = 0;
static RegisterPass<PandaCallMorphFunctionPass>
Y("PandaCallMorph", "Change helper function calls to the the LLVM version");

bool PandaCallMorphFunctionPass::runOnFunction(Function &F){
    functionChanged = false;
    PHCV->visit(F);
    return functionChanged;
}



/***
 *** PandaHelperCallVisitor
 ***/



void PandaHelperCallVisitor::visitCallInst(CallInst &I){
    assert(I.getCalledFunction());
    if (I.getCalledFunction()->isIntrinsic()
            || !I.getCalledFunction()->hasName()
            || I.getCalledFunction()->getName().equals("log_dynval")
            || I.getCalledFunction()->getName().equals("__ldb_mmu_panda")
            || I.getCalledFunction()->getName().equals("__ldl_mmu_panda")
            || I.getCalledFunction()->getName().equals("__ldw_mmu_panda")
            || I.getCalledFunction()->getName().equals("__ldq_mmu_panda")
            || I.getCalledFunction()->getName().equals("__stb_mmu_panda")
            || I.getCalledFunction()->getName().equals("__stl_mmu_panda")
            || I.getCalledFunction()->getName().equals("__stw_mmu_panda")
            || I.getCalledFunction()->getName().equals("__stq_mmu_panda")
            || I.getCalledFunction()->getName().equals("helper_inb")
            || I.getCalledFunction()->getName().equals("helper_inw")
            || I.getCalledFunction()->getName().equals("helper_inl")
            || I.getCalledFunction()->getName().equals("helper_outb")
            || I.getCalledFunction()->getName().equals("helper_outw")
            || I.getCalledFunction()->getName().equals("helper_outl")){
        return; // Ignore intrinsics, declarations, memory, and I/O  functions
    }

    // Call LLVM version of helper
    Module *m = I.getParent()->getParent()->getParent();
    assert(m);
    std::string origName = I.getCalledFunction()->getName();
    std::string newName = origName.append("_llvm");
    Function *newFunction = m->getFunction(newName);
    assert(newFunction);
    I.setCalledFunction(newFunction);

    // Fix up argument types to match LLVM function signature
    int j = 0;
    Function::arg_iterator i;
    for (i = I.getCalledFunction()->arg_begin();
            i != I.getCalledFunction()->arg_end(); i++, j++){
        if (I.getArgOperand(j)->getType() == i->getType()){
            return; // No cast required
        }
        if (CastInst::isCastable(I.getArgOperand(j)->getType(), i->getType())){
            // False arguments assume things are unsigned, and I'm pretty sure
            // this is a correct assumption, especially since LLVM integers
            // don't have a sign bit.  Signedness will be handled (if necessary)
            // inside of the helper function.
            Instruction::CastOps opc =
                CastInst::getCastOpcode(I.getArgOperand(j), false, i->getType(),
                false);
            CastInst *CI = CastInst::Create(opc, I.getArgOperand(j),
                i->getType(), "", &I);
            I.setArgOperand(j, CI); // Replace old operand with CastInst
        }
        else {
            printf("Attempting to perform invalid cast of LLVM call argument\n");
            exit(1);
        }
    }
    PCMFP->functionChanged = true;
}

} // namespace llvm

/*
 * Start the process of including the execution of QEMU helper functions in the
 * LLVM JIT.
 */
void init_llvm_helpers(){
    assert(tcg_llvm_ctx);
    llvm::ExecutionEngine *ee = tcg_llvm_ctx->getExecutionEngine();
    assert(ee);
    llvm::FunctionPassManager *fpm = tcg_llvm_ctx->getFunctionPassManager();
    assert(fpm);
    llvm::Module *mod = tcg_llvm_ctx->getModule();
    assert(mod);
    llvm::LLVMContext &ctx = mod->getContext();

    // Read helper module, link into JIT, verify
    // XXX: Assumes you are invoking QEMU from the root of the qemu/ directory
    std::string bitcode = TARGET_ARCH;
#if defined(CONFIG_SOFTMMU)
    bitcode.append("-softmmu");
#elif defined(CONFIG_LINUX_USER)
    bitcode.append("-linux-user");
#endif
    bitcode.append("/llvm-helpers.bc");
    llvm::SMDiagnostic Err;
    llvm::Module *helpermod = ParseIRFile(bitcode, Err, ctx);
    if (!helpermod) {
        Err.print("qemu", llvm::errs());
        exit(1);
    }
    std::string err;
    llvm::Linker::LinkModules(mod, helpermod, llvm::Linker::DestroySource, &err);
    if (!err.empty()){
        printf("%s\n", err.c_str());
        exit(1);
    }
    verifyModule(*mod, llvm::AbortProcessAction, &err);
    if (!err.empty()){
        printf("%s\n", err.c_str());
        exit(1);
    }

    // Tell the JIT where env is
    llvm::GlobalValue *gv = mod->getNamedValue("env");
    ee->updateGlobalMapping(gv, get_env());

    // Create call morph pass and add to function pass manager
    llvm::FunctionPass *fp = new llvm::PandaCallMorphFunctionPass();
    fpm->add(fp);
}

/*
 * Stop running QEMU helper functions in the JIT.
 */
void uninit_llvm_helpers(){
    /*
     * XXX: Here, we unload our pass from the PassRegistry.  This seems to work
     * fine, until we reload this plugin again into QEMU and we get an LLVM
     * assertion saying the pass is already registered.  This seems like a bug
     * with LLVM.  Switching between TCG and LLVM works fine when passes aren't
     * added to LLVM.
     */
    llvm::PassRegistry *pr = llvm::PassRegistry::getPassRegistry();
    const llvm::PassInfo *pi =
        //pr->getPassInfo(&llvm::PandaInstrFunctionPass::ID);
        pr->getPassInfo(llvm::StringRef("PandaCallMorph"));
    if (!pi){
        printf("Unable to find 'PandaCallMorph' pass in pass registry\n");
    }
    else {
        pr->unregisterPass(*pi);
    }
}

