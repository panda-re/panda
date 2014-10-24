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
 * llvm_trace PANDA plugin
 * Ryan Whelan
 *
 * This plugin captures a trace in LLVM format and saves 3 files to /tmp.  The
 * first is llvm-mod.bc, which is the LLVM IR bitcode of each guest translation
 * block.  The others are llvm-functions.log and llvm-memlog.log.  The first
 * contains the order of LLVM functions executed, and the second contains every
 * memory (and CPUState) access, as well as every branch target in the bitcode.
 * llvm-functions.log also contains select information about system calls for
 * QEMU-user mode, and our callbacks for those are implemented here.  For
 * instrumented helper functions, use this with our helper function analyzer.
 * This assumes you are obtaining an entire trace, so LLVM will be disabled and
 * the bitcode module will be written at the end of execution.
 */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

extern "C" {
#include "panda_plugin.h"
#include "panda_common.h"
#include "tubtf.h"

#ifndef CONFIG_SOFTMMU
#include "syscall_defs.h"
#endif
}

#include "panda_memlog.h"
#include "llvm/PassManager.h"
#include "llvm/PassRegistry.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"

#include "panda_dynval_inst.h"
#include "tcg-llvm.h"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int before_block_exec(CPUState *env, TranslationBlock *tb);
int after_block_exec(CPUState *env, TranslationBlock *tb,
    TranslationBlock *next_tb);
int cb_cpu_restore_state(CPUState *env, TranslationBlock *tb);

#ifndef CONFIG_SOFTMMU
int user_after_syscall(void *cpu_env, bitmask_transtbl *fcntl_flags_tbl,
                       int num, abi_long arg1, abi_long arg2, abi_long arg3,
                       abi_long arg4, abi_long arg5, abi_long arg6, abi_long
                       arg7, abi_long arg8, void *p, abi_long ret);

#endif
int phys_mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf);
int phys_mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf);

const char *default_basedir = "/tmp";
const char *basedir = NULL;
FILE *funclog;
extern FILE *memlog;

}

int tubtf_on;

// Instrumentation function pass
llvm::PandaInstrFunctionPass *PIFP;

/*
 * These memory callbacks are only for whole-system mode.  User-mode memory
 * accesses are captured by IR instrumentation.
 */
int phys_mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
    log_dynval(dynval_buffer, ADDRENTRY, STORE, addr);
    return 0;
}

int phys_mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf){
    DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
    log_dynval(dynval_buffer, ADDRENTRY, LOAD, addr);
    return 0;
}

namespace llvm {

static void llvm_init(){
    ExecutionEngine *ee = tcg_llvm_ctx->getExecutionEngine();
    FunctionPassManager *fpm = tcg_llvm_ctx->getFunctionPassManager();
    Module *mod = tcg_llvm_ctx->getModule();
    LLVMContext &ctx = mod->getContext();

    // Link logging function in with JIT
    Function *logFunc;
    std::vector<Type*> argTypes;
    // DynValBuffer*
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(uintptr_t)));
    // DynValEntryType
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(DynValEntryType)));
    // LogOp
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(LogOp)));
    // Dynamic value
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(uintptr_t)));
    logFunc = Function::Create(
            FunctionType::get(Type::getVoidTy(ctx), argTypes, false),
            Function::ExternalLinkage, "log_dynval", mod);
    logFunc->addFnAttr(Attribute::AlwaysInline);
    ee->addGlobalMapping(logFunc, (void*) &log_dynval);

    // Create instrumentation pass and add to function pass manager
    llvm::FunctionPass *instfp = createPandaInstrFunctionPass(mod);
    fpm->add(instfp);
    PIFP = static_cast<PandaInstrFunctionPass*>(instfp);
}

} // namespace llvm



int before_block_exec(CPUState *env, TranslationBlock *tb){

  if (tubtf_on) {
    char *llvm_fn_name = (char *) tcg_llvm_get_func_name(tb);
    uint32_t pc, unk;
    sscanf(llvm_fn_name, "tcg-llvm-tb-%d-%x", &unk, &pc);
    env->panda_guest_pc = pc;
    tubtf_write_el_64(panda_current_asid(env), pc, TUBTFE_LLVM_FN, unk, 0, 0, 0);
  }
  else {
    fprintf(funclog, "%s\n", tcg_llvm_get_func_name(tb));
    DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
    if (dynval_buffer->cur_size > 0){
        // Buffer wasn't flushed before, have to flush it now
      fwrite(dynval_buffer->start, dynval_buffer->cur_size, 1, memlog);
    }
    clear_dynval_buffer(dynval_buffer);
  }
    return 0;
}

int after_block_exec(CPUState *env, TranslationBlock *tb,
        TranslationBlock *next_tb){
  if (tubtf_on == 0) {
    // flush dynlog to file
    assert(memlog);
    DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
    fwrite(dynval_buffer->start, dynval_buffer->cur_size, 1, memlog);
    clear_dynval_buffer(dynval_buffer);
  }
    return 0;
}

int cb_cpu_restore_state(CPUState *env, TranslationBlock *tb){
    printf("EXCEPTION - logging\n");
    DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
    log_exception(dynval_buffer);
    return 0;
}

#ifndef CONFIG_SOFTMMU

// Globals to keep track of file descriptors
int infd = -1;
int outfd = -1;

/*
 * Kind of a hacky way to see if the file being opened is something we're
 * interested in.  For now, we are working under the assumption that a program
 * will open/read one file of interest, and open/write the other file of
 * interest.  So we assume that files that are opened from /etc and /lib aren't
 * of interest. /proc and openssl.cnf also aren't interesting, from looking at
 * openssl.
 */
static int user_open(bitmask_transtbl *fcntl_flags_tbl, abi_long ret, void *p,
              abi_long flagarg){
    const char *file = path((const char*)p);
    unsigned int flags = target_to_host_bitmask(flagarg, fcntl_flags_tbl);
    if (ret > 0){
        if((strncmp(file, "/etc", 4) != 0)
                && (strncmp(file, "/lib", 4) != 0)
                && (strncmp(file, "/proc", 5) != 0)
                && (strncmp(file, "/dev", 4) != 0)
                && (strncmp(file, "/usr", 4) != 0)
                && (strstr(file, "openssl.cnf") == 0)
                && (strstr(file, "xpdfrc") == 0)){
            printf("open %s for ", file);
            if ((flags & (O_RDONLY | O_WRONLY)) == O_RDONLY){
                printf("read\n");
                infd = ret;
            }
            if (flags & O_WRONLY){
                printf("write\n");
                outfd = ret;
            }
        }
    }
    return 0;
}

static int user_creat(abi_long ret, void *p){
    const char *file = path((const char*)p);
    if (ret > 0){
        printf("open %s for write\n", file);
        outfd = ret;
    }
    return 0;
}

static int user_read(abi_long ret, abi_long fd, void *p){
  if (tubtf_on == 0) {
    if (ret > 0 && fd == infd){
        // log the address and size of a buffer to be tainted
        fprintf(funclog, "taint,read,%ld,%ld\n", (uintptr_t)p,
            (unsigned long)ret);
        printf("taint,read,%ld,%ld\n", (uintptr_t)p, (unsigned long)ret);
    }
  }
    return 0;
}

static int user_write(abi_long ret, abi_long fd, void *p){
  if (tubtf_on == 0) {
    if (ret > 0 && fd == outfd){
        // log the address and size of a buffer to be checked for taint
        fprintf(funclog, "taint,write,%ld,%ld\n", (uintptr_t)p,
            (unsigned long)ret);
        printf("taint,write,%ld,%ld\n", (uintptr_t)p, (unsigned long)ret);
    }
  }
    return 0;
}

int user_after_syscall(void *cpu_env, bitmask_transtbl *fcntl_flags_tbl,
                       int num, abi_long arg1, abi_long arg2, abi_long arg3,
                       abi_long arg4, abi_long arg5, abi_long arg6,
                       abi_long arg7, abi_long arg8, void *p, abi_long ret){
    switch (num){
        case TARGET_NR_read:
            user_read(ret, arg1, p);
            break;
        case TARGET_NR_write:
            user_write(ret, arg1, p);
            break;
        case TARGET_NR_open:
            user_open(fcntl_flags_tbl, ret, p, arg2);
            break;
        case TARGET_NR_openat:
            user_open(fcntl_flags_tbl, ret, p, arg3);
            break;
        case TARGET_NR_creat:
            user_creat(ret, p);
            break;
        default:
            break;
    }
    return 0;
}

#endif // CONFIG_SOFTMMU

bool init_plugin(void *self) {
    printf("Initializing plugin llvm_trace\n");

    panda_arg_list *args = panda_get_args("llvm_trace");
    basedir = panda_parse_string(args, "base", "/tmp");
    tubtf_on = panda_parse_bool(args, "tubtf");
    
    printf("llvm_trace using basedir=%s\n", basedir);

    if (tubtf_on) {
      printf("tubt is on\n");
      char tubtf_path[256];
      strcpy(tubtf_path, basedir);
      strcat(tubtf_path, "/tubtf.log");
      tubtf_open(tubtf_path, TUBTF_COLW_64);
      panda_enable_precise_pc();
    }
    else {
      // XXX: unsafe string manipulations
      char memlog_path[256];
      char funclog_path[256];
      strcpy(memlog_path, basedir);
      strcat(memlog_path, "/llvm-memlog.log");
      open_memlog(memlog_path);
      strcpy(funclog_path, basedir);
      strcat(funclog_path, "/llvm-functions.log");
      funclog = fopen(funclog_path, "w");
    }

    panda_cb pcb;
    panda_enable_memcb();
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.phys_mem_read = phys_mem_read_callback;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_READ, pcb);
    pcb.phys_mem_write = phys_mem_write_callback;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_WRITE, pcb);
    pcb.cb_cpu_restore_state = cb_cpu_restore_state;
    panda_register_callback(self, PANDA_CB_CPU_RESTORE_STATE, pcb);

#ifndef CONFIG_SOFTMMU
    pcb.user_after_syscall = user_after_syscall;
    panda_register_callback(self, PANDA_CB_USER_AFTER_SYSCALL, pcb);
#endif

    if (!execute_llvm){
        panda_enable_llvm();
    }
    llvm::llvm_init();
    panda_enable_llvm_helpers();

    /*
     * Run instrumentation pass over all helper functions that are now in the
     * module, and verify module.
     */
    llvm::Module *mod = tcg_llvm_ctx->getModule();
    for (llvm::Module::iterator i = mod->begin(); i != mod->end(); i++){
        if (i->isDeclaration()){
            continue;
        }
#if defined(TARGET_ARM)
        //TODO: Fix handling of ARM's cpu_reset() helper
        // Currently, we skip instrumenting it, because we generate invalid LLVM bitcode if we try
        std::string modname =  i->getName().str();
        if (modname == "cpu_reset_llvm"){
            printf("Skipping instrumentation of cpu_reset\n");
            continue;
        }
#endif
        PIFP->runOnFunction(*i);
    }
    std::string err;
    if(verifyModule(*mod, llvm::AbortProcessAction, &err)){
        printf("%s\n", err.c_str());
        exit(1);
    }

    return true;
}

void uninit_plugin(void *self) {
  if (tubtf_on) {
    tubtf_close();
  }
  else {
    DynValBuffer *dynval_buffer = PIFP->PIV->getDynvalBuffer();
    if (dynval_buffer->cur_size > 0){
        // Buffer wasn't flushed before, have to flush it now
        fwrite(dynval_buffer->start, dynval_buffer->cur_size, 1, memlog);
    }
  }

    // XXX: more unsafe string manipulation
    char modpath[256];
    strcpy(modpath, basedir);
    strcat(modpath, "/llvm-mod.bc");
    tcg_llvm_write_module(tcg_llvm_ctx, modpath);

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
        pr->getPassInfo(llvm::StringRef("PandaInstr"));
    if (!pi){
        printf("Unable to find 'PandaInstr' pass in pass registry\n");
    }
    else {
        pr->unregisterPass(*pi);
    }

    panda_disable_llvm_helpers();

    if (execute_llvm){
        panda_disable_llvm();
    }
    panda_disable_memcb();

    if (tubtf_on == 0) {
      fclose(funclog);
      close_memlog();
    }
}
