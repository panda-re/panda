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
#include "panda_memlog.h"

#ifndef CONFIG_SOFTMMU
#include "syscall_defs.h"
#endif

}

#include <stdio.h>
#include <stdlib.h>
#include <vector>

#include "llvm/PassManager.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"

#include "laredo.h"
#include "tcg-llvm.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
bool before_block_exec(CPUState *env, TranslationBlock *tb);
int llvm_init(void *exEngine, void *funPassMan, void *module);

#ifndef CONFIG_SOFTMMU
int user_after_syscall(void *cpu_env, bitmask_transtbl *fcntl_flags_tbl,
                       int num, abi_long arg1, abi_long arg2, abi_long arg3,
                       abi_long arg4, abi_long arg5, abi_long arg6, abi_long
                       arg7, abi_long arg8, void *p, abi_long ret);

#endif
//int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
//                       target_ulong size, void *buf);

FILE *funclog;
extern FILE *memlog;

}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return 0;
}

namespace llvm {

int llvm_init(void *exEngine, void *funPassMan, void *module){
    ExecutionEngine *ee = (ExecutionEngine *)exEngine;
    FunctionPassManager *fpm = (FunctionPassManager *)funPassMan;
    Module *mod = (Module *)module;
    LLVMContext &ctx = mod->getContext();

    // Link logging functions in with JIT
    Function* printFunc;
    Function* ramFunc;
    std::vector<Type*> argTypes;
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(uintptr_t)));
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(int)));
    printFunc = Function::Create(
            FunctionType::get(Type::getVoidTy(ctx), argTypes, false),
            Function::ExternalLinkage, "printdynval", mod);
    printFunc->addFnAttr(Attribute::AlwaysInline);
    ee->addGlobalMapping(printFunc, (void*) &printdynval);
    
    argTypes.clear();
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(uintptr_t)));
    argTypes.push_back(IntegerType::get(ctx, 8*sizeof(int)));
    ramFunc = Function::Create(
            FunctionType::get(Type::getVoidTy(ctx), argTypes, false),
            Function::PrivateLinkage, "printramaddr", mod);
    ramFunc->addFnAttr(Attribute::AlwaysInline);
    ee->addGlobalMapping(ramFunc, (void*) &printramaddr);

    // Add our IR instrumentation pass to the pass manager
    fpm->add(createLaredoInstrFunctionPass(mod));
    
    return 0;
}

} // namespace llvm

bool before_block_exec(CPUState *env, TranslationBlock *tb){
    fprintf(funclog, "%s\n", tcg_llvm_get_func_name(tb));
    return false; // don't retranslate
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
    if (ret > 0 && fd == infd){
        // log the address and size of a buffer to be tainted
        fprintf(funclog, "taint,read,%ld,%ld\n", (uintptr_t)p,
            (unsigned long)ret);
        printf("taint,read,%ld,%ld\n", (uintptr_t)p, (unsigned long)ret);
    }
    return 0;
}

static int user_write(abi_long ret, abi_long fd, void *p){
    if (ret > 0 && fd == outfd){
        // log the address and size of a buffer to be checked for taint
        fprintf(funclog, "taint,write,%ld,%ld\n", (uintptr_t)p,
            (unsigned long)ret);
        printf("taint,write,%ld,%ld\n", (uintptr_t)p, (unsigned long)ret);
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

    panda_cb pcb;

    //panda_enable_precise_pc();

    panda_enable_memcb();    
    //pcb.mem_write = mem_write_callback;
    pcb.llvm_init = llvm::llvm_init;
    panda_register_callback(self, PANDA_CB_LLVM_INIT, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    //panda_register_callback(self, PANDA_CB_MEM_WRITE, pcb);

#ifndef CONFIG_SOFTMMU
    pcb.user_after_syscall = user_after_syscall;
    panda_register_callback(self, PANDA_CB_USER_AFTER_SYSCALL, pcb);
#endif

    open_memlog();
    setbuf(memlog, NULL);
    funclog = fopen("/tmp/llvm-functions.log", "w");
    setbuf(funclog, NULL);

    if (!execute_llvm){
        panda_enable_llvm();
    }
    
    return true;
}

void uninit_plugin(void *self) {

    fclose(funclog);
    close_memlog();
    tcg_llvm_write_module(tcg_llvm_ctx);

    panda_disable_llvm();
}

