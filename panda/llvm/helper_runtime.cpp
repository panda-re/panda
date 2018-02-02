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

#include <cstdio>
#include <system_error>
#include <sstream>
#include <set>
#include <string>
#include <iostream>

extern "C" {
#include <libgen.h>
}

#include "llvm/Linker.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/IR/Module.h"
#include "llvm/PassManager.h"
#include "llvm/PassRegistry.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/raw_ostream.h"

#include "panda/cheaders.h"
#include "panda/tcg-llvm.h"
#include "panda/helper_runtime.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

namespace llvm {

/***
 *** PandaCallMorphFunctionPass
 ***/

char PandaCallMorphFunctionPass::ID = 0;
static RegisterPass<PandaCallMorphFunctionPass>
Y("PandaCallMorph", "Change helper function calls to the the LLVM version");

bool PandaCallMorphFunctionPass::runOnFunction(Function &F) {
    functionChanged = false;
    PHCV->visit(F);
    return functionChanged;
}

/***
 *** PandaHelperCallVisitor
 ***/

const static std::set<std::string> append_panda_funcs{
    "helper_le_ldq_mmu", "helper_le_ldul_mmu", "helper_le_lduw_mmu",
    "helper_le_ldub_mmu", "helper_le_ldsl_mmu", "helper_le_ldsw_mmu",
    "helper_le_ldsb_mmu",
    "helper_le_stq_mmu", "helper_le_stl_mmu", "helper_le_stw_mmu",
    "helper_le_stb_mmu",
    "helper_be_ldq_mmu", "helper_be_ldul_mmu", "helper_be_lduw_mmu",
    "helper_be_ldub_mmu", "helper_be_ldsl_mmu", "helper_be_ldsw_mmu",
    "helper_be_ldsb_mmu",
    "helper_be_stq_mmu", "helper_be_stl_mmu", "helper_be_stw_mmu",
    "helper_be_stb_mmu",
    "helper_ret_ldq_mmu", "helper_ret_ldul_mmu", "helper_ret_lduw_mmu",
    "helper_ret_ldub_mmu", "helper_ret_ldsl_mmu", "helper_ret_ldsw_mmu",
    "helper_ret_ldsb_mmu",
    "helper_ret_stq_mmu", "helper_ret_stl_mmu", "helper_ret_stw_mmu",
    "helper_ret_stb_mmu"
};
const static std::set<std::string> ignore_funcs{
    "helper_le_ldq_mmu_panda", "helper_le_ldul_mmu_panda", "helper_le_lduw_mmu_panda",
    "helper_le_ldub_mmu_panda", "helper_le_ldsl_mmu_panda", "helper_le_ldsw_mmu_panda",
    "helper_le_ldsb_mmu_panda",
    "helper_le_stq_mmu_panda", "helper_le_stl_mmu_panda", "helper_le_stw_mmu_panda",
    "helper_le_stb_mmu_panda",
    "helper_be_ldq_mmu_panda", "helper_be_ldul_mmu_panda", "helper_be_lduw_mmu_panda",
    "helper_be_ldub_mmu_panda", "helper_be_ldsl_mmu_panda", "helper_be_ldsw_mmu_panda",
    "helper_be_ldsb_mmu_panda",
    "helper_be_stq_mmu_panda", "helper_be_stl_mmu_panda", "helper_be_stw_mmu_panda",
    "helper_be_stb_mmu_panda",
    "helper_ret_ldq_mmu_panda", "helper_ret_ldul_mmu_panda", "helper_ret_lduw_mmu_panda",
    "helper_ret_ldub_mmu_panda", "helper_ret_ldsl_mmu_panda", "helper_ret_ldsw_mmu_panda",
    "helper_ret_ldsb_mmu_panda",
    "helper_ret_stq_mmu_panda", "helper_ret_stl_mmu_panda", "helper_ret_stw_mmu_panda",
    "helper_ret_stb_mmu_panda",
    "helper_inb", "helper_inw", "helper_inl", "helper_inq",
    "helper_outb", "helper_outw", "helper_outl", "helper_outq"
};
void PandaHelperCallVisitor::visitCallInst(CallInst &I) {
    Function *f = I.getCalledFunction();
    assert(f);

    Module *m = I.getParent()->getParent()->getParent();
    assert(m);

    std::string name = f->getName();
    if (f->isIntrinsic() || !f->hasName()
            || ignore_funcs.count(name) > 0) {
        return; // Ignore intrinsics, declarations, memory, and I/O  functions
    } else if (append_panda_funcs.count(name) > 0) {
        std::cout << "modifying " << name << "\n";
        name.append("_panda");
    } else {
        // Call LLVM version of helper
        name.append("_llvm");
    }
    Function *newFunction = m->getFunction(name);
    assert(newFunction);
    I.setCalledFunction(newFunction);
    f = newFunction;

    // Fix up argument types to match LLVM function signature
    Function::arg_iterator func_arg = f->arg_begin();
    unsigned call_arg_idx = 0;
    for (; func_arg != f->arg_end(); func_arg++, call_arg_idx++) {
        assert (call_arg_idx != I.getNumArgOperands());
        Value *call_arg = I.getArgOperand(call_arg_idx);
        if (call_arg->getType() == func_arg->getType()) {
            continue; // No cast required
        }
        assert(CastInst::isCastable(call_arg->getType(), func_arg->getType()));
        // False arguments assume things are unsigned, and I'm pretty sure
        // this is a correct assumption, especially since LLVM integers
        // don't have a sign bit.  Signedness will be handled (if necessary)
        // inside of the helper function.
        Instruction::CastOps opc =
            CastInst::getCastOpcode(call_arg, false, func_arg->getType(), false);
        CastInst *CI = CastInst::Create(opc, call_arg, func_arg->getType(), "", &I);
        I.setArgOperand(call_arg_idx, CI); // Replace old operand with CastInst
    }
    PCMFP->functionChanged = true;
}

} // namespace llvm

// resolved full path to the current executable
extern const char *qemu_file;

/*
 * Start the process of including the execution of QEMU helper functions in the
 * LLVM JIT.
 */
static bool helpers_initialized = false;
void init_llvm_helpers() {
    if (helpers_initialized) return;

    assert(tcg_llvm_ctx);
    //llvm::ExecutionEngine *ee = tcg_llvm_ctx->getExecutionEngine();
    //assert(ee);
    llvm::FunctionPassManager *fpm = tcg_llvm_ctx->getFunctionPassManager();
    assert(fpm);
    llvm::Module *mod = tcg_llvm_ctx->getModule();
    assert(mod);
    llvm::LLVMContext &ctx = mod->getContext();

    // Read helper module, link into JIT, verify
    char *exe = strdup(qemu_file);
    std::string bitcode(dirname(exe));
    free(exe);
    bitcode.append("/llvm-helpers.bc");

    llvm::SMDiagnostic Err;
    llvm::Module *helpermod = ParseIRFile(bitcode, Err, ctx);
    if (!helpermod) {
        Err.print("qemu", llvm::errs());
        exit(1);
    }
    std::string err;
    llvm::Linker::LinkModules(mod, helpermod, llvm::Linker::DestroySource, &err);
    if (!err.empty()) {
        printf("%s\n", err.c_str());
        exit(1);
    }
    verifyModule(*mod, llvm::AbortProcessAction, &err);
    if (!err.empty()) {
        printf("%s\n", err.c_str());
        exit(1);
    }

    /*std::stringstream mod_file;
    mod_file << "/tmp/llvm-mod-" << getpid() << ".bc";
    tcg_llvm_ctx->writeModule(mod_file.str().c_str());*/

    // Create call morph pass and add to function pass manager
    llvm::FunctionPass *fp = new llvm::PandaCallMorphFunctionPass();
    fpm->add(fp);
    helpers_initialized = true;
}

/*
 * Stop running QEMU helper functions in the JIT.
 */
void uninit_llvm_helpers() {
    /*
     * XXX: Here, we unload our pass from the PassRegistry.  This seems to work
     * fine, until we reload this plugin again into QEMU and we get an LLVM
     * assertion saying the pass is already registered.  This seems like a bug
     * with LLVM.  Switching between TCG and LLVM works fine when passes aren't
     * added to LLVM.
     */
    llvm::PassRegistry *pr = llvm::PassRegistry::getPassRegistry();
    const llvm::PassInfo *pi =
        pr->getPassInfo("PandaCallMorph");
    if (!pi) {
        printf("Unable to find 'PandaCallMorph' pass in pass registry\n");
    } else {
        pr->unregisterPass(*pi);
    }
    helpers_initialized = false;
}

