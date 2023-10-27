/* PANDABEGINCOMMENT
 * 
 * Authors:
 * Luke Craig luke.craig@ll.mit.eduß
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

/**
 * Logic for this plugin:
 *  On the first execve or execveat the system will transition to the kernel
 *  and back to userspace. We attempt to catch the very first block of the new
 *  program by looking for the first block where the stack pointer is in 
 *  userspace, paged in, and has a value that makes sense for the auxiliary
 *  vector (described below). Specifically, we check that the first argument,
 *  the argc value, is a reasonable number. We chose this reasonable number
 *  to be 0x200000, a common value for ARG_MAX on unix systems.
 * 
 *  Once we have established the location of the auxiliary vector we make a PPP
 *  callback and pass the values of the auxv to the callback.
 * 
 * Issues:
 *  Currently the plugin catches about 95% of the new programs across
 *  architectures. The remaining 5% are somewhat elusive. It may be that the
 *  kernel does something like immediately switching to a new program or memory
 *  is not paged in at the stage we might expect.
 */


#define __STDC_FORMAT_MACROS

#include <linux/auxvec.h>
#include <linux/elf.h>
#include <string>
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

using namespace std;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    #include "syscalls2/syscalls_ext_typedefs.h"
    #include "syscalls2/syscalls2_info.h"
    #include "syscalls2/syscalls2_ext.h"
    #include "proc_start_linux.h"
    #include "proc_start_linux_ppp.h"
    PPP_PROT_REG_CB(on_rec_auxv);
    PPP_CB_BOILERPLATE(on_rec_auxv);
}

// uncomment to look under the hood
// #define DEBUG

#ifdef DEBUG
#define log(...) printf(__VA_ARGS__)
#else
#define log(...)
#endif

template<class T>
void fixupendian(T& x) {
#if defined(TARGET_WORDS_BIGENDIAN)
    switch(sizeof(T)) {
       case 4:
           x=bswap32(x);
           break;
#if TARGET_LONG_BITS == 64
       case 8:
           x=bswap64(x);
           break;
#endif
       default:
           assert(false);
           break;
    }
#endif
}

void *self_ptr;
panda_cb pcb_sbe_execve, pcb_asid;

#define ARG_MAX 0x200000

#define FAIL_READ_ARGV -1
#define FAIL_READ_ENVP -2
#define FAIL_READ_AUXV -3

/*
 * AT_MINSIGSTKSZ isn't always defined for systems that run PANDA, but could be
 * provided by a guest kernel.
 * AT_MINSIGSTKSZ was defined as a uapi standard in v5.14 of the kernel:
 * https://git.kernel.org/tip/7cd60e43a6def40ecb75deb8decc677995970d0b
*/

#ifndef AT_MINSIGSTKSZ
#define AT_MINSIGSTKSZ  51
#endif

string read_str(CPUState* cpu, target_ulong ptr){
    string buf = "";
    char tmp;
    while (true){
        if (panda_virtual_memory_read(cpu, ptr, (uint8_t*)&tmp,1) == MEMTX_OK){
            buf += tmp;
            if (tmp == '\x00'){
                break;
            }
            ptr+=1;
        }else{
            break;
        }
    }
    return buf;
}

/**
 * 
 * The stack layout in the first block of a linux process looks like this:
 * 
 * |‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
 * |             Auxiliary vector           |
 * |________________________________________|
 * |                                        |
 * |                  environ               |
 * |________________________________________|
 * |‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
 * |                   argv                 |
 * |________________________________________|
 * |‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
 * |                   Stack                |
 * |________________________________________|
 * 
 * The Stack grows down.
 * 
 */ 

template<class T>
int read_aux_vals(CPUState *cpu, struct auxv_values *vals){
    T sp = panda_current_sp(cpu);
    log("read_aux_vals: sp=" TARGET_FMT_lx "\n", static_cast<target_ulong>(sp));
    
    // keep track of where on the stack we are
    int ptrlistpos = 1;
    T ptr;

    /**
     * Read the argv values to the program.
     */
    vals->argv_ptr_ptr = sp + (ptrlistpos * sizeof(T));
    int argc_num = 0;
    while (true){
        if (panda_virtual_memory_read(cpu, sp + (ptrlistpos * sizeof(T)), (uint8_t *)&ptr, sizeof(ptr)) != MEMTX_OK){
            return FAIL_READ_ARGV;
        }
        fixupendian(ptr);
        ptrlistpos++;
        if (ptr == 0){
            break;
        } else if (argc_num < MAX_NUM_ARGS){
            string arg = read_str(cpu, ptr);
            if (arg.length() > 0)
            {
                strncpy(vals->argv[argc_num], arg.c_str(), MAX_PATH_LEN);
                vals->arg_ptr[argc_num] = ptr;
                argc_num++;
            }
        }
    }
    vals->argc = argc_num;

    /**
     * Read the environ values from the stack
     */ 
    vals->env_ptr_ptr = sp + (ptrlistpos * sizeof(T));
    int envc_num = 0;
    while (true){
        if (panda_virtual_memory_read(cpu, sp + (ptrlistpos * sizeof(T)), (uint8_t *)&ptr, sizeof(ptr)) != MEMTX_OK){
            return FAIL_READ_ENVP;
        }
        fixupendian(ptr);
        ptrlistpos++;
        if (ptr == 0){
            break;
        } else if (envc_num < MAX_NUM_ENV){
            string arg = read_str(cpu, ptr);
            if (arg.length() > 0){
                strncpy(vals->envp[envc_num], arg.c_str(), MAX_PATH_LEN);
                vals->env_ptr[envc_num] = ptr;
                envc_num++;
            }
        }
    }
    vals->envc = envc_num;

    /**
     * Read the auxiliary vector
     */ 
    T entrynum, entryval;
    while (true){
        if (panda_virtual_memory_read(cpu, sp + (ptrlistpos * sizeof(T)), (uint8_t *)&entrynum, sizeof(entrynum)) != MEMTX_OK || panda_virtual_memory_read(cpu, sp + ((ptrlistpos + 1) * sizeof(T)), (uint8_t *)&entryval, sizeof(entryval))){
            return FAIL_READ_AUXV;
        }
        ptrlistpos += 2;
        fixupendian(entrynum);
        fixupendian(entryval);
        if (entrynum == AT_NULL){
            break;
        }else if (entrynum == AT_ENTRY){
            vals->entry = entryval;
        }else if (entrynum == AT_PHDR){
            vals->phdr = entryval;
            // every elf I've seen says that the PHDR
            // is immediately following the EHDR.
            // we can do a bunch to check this or we can just
            // take the value.
#if TARGET_LONG_BITS == 64
            if(sizeof(T) == 8) {
                vals->program_header = entryval - sizeof(Elf64_Ehdr);
            } else
#endif
                vals->program_header = entryval - sizeof(Elf32_Ehdr);
        }else if (entrynum == AT_EXECFN){
            vals->execfn_ptr = entryval;
            string execfn = read_str(cpu, entryval);
            execfn.copy(vals->execfn, MAX_PATH_LEN - 1, 0);
        }else if (entrynum == AT_SYSINFO_EHDR){
            vals->ehdr = entryval;
        }else if (entrynum == AT_HWCAP){
            vals->hwcap = entryval;
        }else if (entrynum == AT_HWCAP2){
            vals->hwcap2 = entryval;
        }else if (entrynum == AT_PAGESZ){
            vals->pagesz = entryval;
        }else if (entrynum == AT_CLKTCK){
            vals->clktck = entryval;
        }else if (entrynum == AT_PHENT){
            vals->phent = entryval;
        }else if (entrynum == AT_PHNUM){
            vals->phnum = entryval;
        }else if (entrynum == AT_BASE){
            vals->base = entryval;
        }else if (entrynum == AT_FLAGS){
            vals->flags = entryval;
        }else if (entrynum == AT_UID){
            vals->uid = entryval;
        }else if (entrynum == AT_EUID){
            vals->euid = entryval;
        }else if (entrynum == AT_GID){
            vals->gid = entryval;
        }else if (entrynum == AT_EGID){
            vals->egid = entryval;
        }else if (entrynum == AT_SECURE){
            vals->secure = entryval;
        }else if (entrynum == AT_RANDOM){
            vals->random = entryval;
        }else if (entrynum == AT_PLATFORM){
            vals->platform = entryval;
        }else if (entrynum == AT_MINSIGSTKSZ){
            vals->minsigstksz = entryval;
        }
    }
    return 0;
}

template<class T> 
bool try_run_auxv(CPUState *cpu, TranslationBlock *tb, T sp){

#ifdef TARGET_X86_64
    if(sizeof(T) == 8) {
        CPUArchState *env = static_cast<CPUArchState *>(cpu->env_ptr);
        if(((env->hflags & (1 << HF_LMA_SHIFT)) && 
                (env->hflags & (1 << HF_CS64_SHIFT))) == 0) {
            log("try_run_auxv: 32-bit app detected\n");
            return try_run_auxv(cpu, tb, static_cast<uint32_t>(sp));
        }
    }
#endif

    log("checking sp " TARGET_FMT_lx "\n", static_cast<target_ulong>(sp));
    T argc;
    if (panda_virtual_memory_read(cpu, sp, (uint8_t *)&argc, sizeof(argc)) != MEMTX_OK){
        log("got here and could not read stack " TARGET_FMT_lx "\n", static_cast<target_ulong>(sp));
        return false;
    }
    fixupendian(argc);
    log("sp " TARGET_FMT_lx "\n", static_cast<target_ulong>(sp));
    if (argc > ARG_MAX){
        log("argc is incorrect " TARGET_FMT_lx "\n", static_cast<target_ulong>(argc));
        return false;
    }
    struct auxv_values *vals = (struct auxv_values*)malloc(sizeof(struct auxv_values));
    memset(vals, 0, sizeof(struct auxv_values));
    int status = read_aux_vals<T>(cpu, vals);
    if (!status && vals->entry && vals->phdr) {
        PPP_RUN_CB(on_rec_auxv, cpu, tb, vals);
        free(vals);
        return true;
    }else if (status == FAIL_READ_ARGV){
        log("failed to read argv\n");
    }else if (status == FAIL_READ_ENVP){
        log("failed to read envp\n");
    }else if (status == FAIL_READ_AUXV){
        log("failed to read auxv\n");
    }else{
        log("read_aux_vals failed, status: %d",status);
        log(" vals->entry: " TARGET_FMT_lx ", vals->phdr: " TARGET_FMT_lx "\n", vals->entry, vals->phdr);
    }
    free(vals);
    return false;
}

void sbe(CPUState *cpu, TranslationBlock *tb){
    target_ulong sp = panda_current_sp(cpu);
    bool sp_in_kernel = address_in_kernel_code_linux(sp);
    bool pc_in_kernel = address_in_kernel_code_linux(tb->pc);
    if (!sp_in_kernel && !pc_in_kernel){ 
        if (!try_run_auxv(cpu, tb, sp)){
            log("Failed to read in this ASID. Try the next one\n");
            panda_enable_callback(self_ptr, PANDA_CB_ASID_CHANGED, pcb_asid);
        }
        panda_disable_callback(self_ptr,  PANDA_CB_START_BLOCK_EXEC, pcb_sbe_execve);
    }
}

bool asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    panda_enable_callback(self_ptr, PANDA_CB_START_BLOCK_EXEC, pcb_sbe_execve);
    panda_disable_callback(self_ptr, PANDA_CB_ASID_CHANGED, pcb_asid);
    return false;
}

void execve_cb(CPUState *cpu, target_ptr_t pc, target_ptr_t filename, target_ptr_t argv, target_ptr_t envp) {
    log("execve\n");
    panda_enable_callback(self_ptr, PANDA_CB_START_BLOCK_EXEC, pcb_sbe_execve);
}

void execveat_cb (CPUState* cpu, target_ptr_t pc, int dfd, target_ptr_t filename, target_ptr_t argv, target_ptr_t envp, int flags) {
    log("execveat\n");
    panda_enable_callback(self_ptr, PANDA_CB_START_BLOCK_EXEC, pcb_sbe_execve);
}

bool init_plugin(void *self) {
    self_ptr = self;
    #if defined(TARGET_AARCH64)
        fprintf(stderr, "[ERROR] proc_start_linux: aarch64 architecture not supported!\n");
        return false;
    #elif defined(TARGET_PPC)
        fprintf(stderr, "[ERROR] proc_start_linux: PPC architecture not supported by syscalls2!\n");
        return false;
    #else
        pcb_sbe_execve.start_block_exec = sbe;
        panda_register_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb_sbe_execve);
        panda_disable_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb_sbe_execve);
        pcb_asid.asid_changed = asid_changed;
        panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb_asid);
        panda_disable_callback(self, PANDA_CB_ASID_CHANGED, pcb_asid);

        // why? so we don't get 1000 messages telling us syscalls2 is already loaded
        void* syscalls2 = panda_get_plugin_by_name("syscalls2");
        if (syscalls2 == NULL){
            panda_require("syscalls2");
        }
        assert(init_syscalls2_api());
        PPP_REG_CB("syscalls2", on_sys_execve_enter, execve_cb);
        PPP_REG_CB("syscalls2", on_sys_execveat_enter, execveat_cb);
    #endif
    return true;
}

void uninit_plugin(void *self) {
#if defined(TARGET_PPC)
#else

    void* syscalls = panda_get_plugin_by_name("syscalls2");
    if (syscalls != NULL){
        PPP_REMOVE_CB("syscalls2", on_sys_execve_enter, execve_cb);
        PPP_REMOVE_CB("syscalls2", on_sys_execveat_enter, execveat_cb);
    }
#endif
}
