/*
 * This plugin allows QEMU to run with LLVM, and any calls to helper functions
 * are replaced with calls to the LLVM versions that we compile during the QEMU
 * build.  Any plugins that want to dynamically analyze/instrument helper
 * functions should build on the functionality of this plugin.
 */

extern "C" {

#include "panda_plugin.h"
#include "panda_externals.h"

}

#include "llvm/Linker.h"
#include "llvm/Module.h"
#include "llvm/PassManager.h"
#include "llvm/PassRegistry.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/Support/IRReader.h"
#include "llvm/Support/raw_ostream.h"

#include "panda_helper_call_morph.h"
#include "tcg-llvm.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int llvm_init(void *exEngine, void *funPassMan, void *module);

}

namespace llvm {

int llvm_init(void *exEngine, void *funPassMan, void *module){
    ExecutionEngine *ee = (ExecutionEngine *)exEngine;
    FunctionPassManager *fpm = (FunctionPassManager *)funPassMan;
    Module *mod = (Module *)module;
    LLVMContext &ctx = mod->getContext();

    // Read helper module, link into JIT, verify
    // XXX: Assumes you are invoking QEMU from the root of the qemu/ directory
    std::string bitcode = TARGET_ARCH;
#if defined(CONFIG_SOFTMMU)
    bitcode.append("-softmmu");
#elif defined(CONFIG_LINUX_USER)
    bitcode.append("-linux-user");
#endif
    bitcode.append("/llvm-helpers.bc");
    SMDiagnostic Err;
    Module *helpermod = ParseIRFile(bitcode, Err, ctx);
    if (!helpermod) {
        Err.Print("qemu", errs());
        exit(1);
    }
    std::string err;
    Linker::LinkModules(mod, helpermod, Linker::DestroySource, &err);
    if (!err.empty()){
        printf("%s\n", err.c_str());
        exit(1);
    }
    verifyModule(*mod, AbortProcessAction, &err);
    if (!err.empty()){
        printf("%s\n", err.c_str());
        exit(1);
    }

    // Tell the JIT where env is
    GlobalValue *gv = mod->getNamedValue("env");
    ee->updateGlobalMapping(gv, get_env());

    // Create call morph pass and add to function pass manager
    llvm::FunctionPass *fp = new PandaCallMorphFunctionPass();
    fpm->add(fp);
    
    return 0;
}

} // namespace llvm

/*int before_block_exec(CPUState *env, TranslationBlock *tb){
    printf("%s\n", tcg_llvm_get_func_name(tb));
    return 0;
}*/

bool init_plugin(void *self) {
    printf("Initializing plugin llvm_helpers\n");
    panda_cb pcb;
    pcb.llvm_init = llvm::llvm_init;
    panda_register_callback(self, PANDA_CB_LLVM_INIT, pcb);
    //pcb.before_block_exec = before_block_exec;
    //panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    if (!execute_llvm){
        panda_enable_llvm();
    }
    
    return true;
}

void uninit_plugin(void *self) {

    //tcg_llvm_write_module(tcg_llvm_ctx);

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

    panda_disable_llvm();
}

