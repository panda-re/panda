/* PANDABEGINCOMMENT
 * 
 * Authors:
 * Luke Craig luke.craig@ll.mit.eduß
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
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



#if TARGET_LONG_BITS == 32
#define ELF(r) Elf32_ ## r
#else
#define ELF(r) Elf64_ ## r
#endif

void *self_ptr;
panda_cb pcb_btc_execve;

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

void btc_execve(CPUState *env, TranslationBlock *tb){
    if (unlikely(!panda_in_kernel(env))){
        target_ulong sp = panda_current_sp(env);
        target_ulong argc;
        if (panda_virtual_memory_read(env, sp, (uint8_t*) &argc, sizeof(argc))== MEMTX_OK){
            
            // the idea of this code is to fill this as best as we can
            struct auxv_values vals;
            memset(&vals, 0, sizeof(struct auxv_values));

            // we read argc, but just to check the stack is readable.
            // don't use it. just iterate and check for nulls.
            int ptrlistpos = 1;
            target_ulong ptr;
            
            // read the arguments from the argv
            vals.argv_ptr_ptr = sp+(ptrlistpos*sizeof(target_ulong));
            int argc_num = 0;
            while (true){
                if (panda_virtual_memory_read(env, sp+(ptrlistpos*sizeof(target_ulong)), (uint8_t*) &ptr, sizeof(ptr)) != MEMTX_OK){
                    printf("failed reading args\n");
                    panda_disable_callback(self_ptr, PANDA_CB_BEFORE_TCG_CODEGEN, pcb_btc_execve);
                    return;
                }
                ptrlistpos++;
                if (ptr == 0){
                    break;
                }else if (argc_num < MAX_NUM_ARGS){
                    string arg = read_str(env, ptr);
                    if (arg.length() > 0){
                        strncpy(vals.argv[argc_num], arg.c_str(), MAX_PATH_LEN);
                        vals.arg_ptr[argc_num] = ptr;
                        argc_num++;
                    }
                }
            }
            vals.argc = argc_num;

            // read the environment variable
            vals.env_ptr_ptr = sp+(ptrlistpos*sizeof(target_ulong));
            int envc_num = 0;
            while (true){
                if (panda_virtual_memory_read(env, sp+(ptrlistpos*sizeof(target_ulong)), (uint8_t*) &ptr, sizeof(ptr)) != MEMTX_OK){
                    printf("failed reading envp\n");
                    panda_disable_callback(self_ptr, PANDA_CB_BEFORE_TCG_CODEGEN, pcb_btc_execve);
                    return;
                }
                ptrlistpos++;
                if (ptr == 0){
                    break;
                }else if (envc_num < MAX_NUM_ENV){
                    string arg = read_str(env, ptr);
                    if (arg.length() > 0){
                        strncpy(vals.envp[envc_num], arg.c_str(), MAX_PATH_LEN);
                        vals.env_ptr[envc_num] = ptr;
                        envc_num++;
                    }
                }
            }
            vals.envc = envc_num;
            target_ulong entrynum, entryval;

            while (true){
                if (panda_virtual_memory_read(env, sp+(ptrlistpos*sizeof(target_ulong)), (uint8_t*) &entrynum, sizeof(entrynum)) != MEMTX_OK || panda_virtual_memory_read(env, sp+((ptrlistpos+1)*sizeof(target_ulong)), (uint8_t*) &entryval, sizeof(entryval))){
                    panda_disable_callback(self_ptr, PANDA_CB_BEFORE_TCG_CODEGEN, pcb_btc_execve);
                    return;
                }
                ptrlistpos+=2;
                if (entrynum == AT_NULL){
                    break;
                }else if (entrynum == AT_ENTRY){
                    vals.entry = entryval;
                }else if (entrynum == AT_PHDR){
                    vals.phdr = entryval;
                    // every elf I've seen says that the PHDR
                    // is immediately following the EHDR.
                    // we can do a bunch to check this or we can just
                    // take the value.
                    vals.program_header = entryval - sizeof(ELF(Ehdr));
                }else if (entrynum == AT_EXECFN){
                    vals.execfn_ptr = entryval;
                    string execfn = read_str(env, entryval);
                    execfn.copy(vals.execfn, MAX_PATH_LEN -1, 0);
                }else if (entrynum == AT_SYSINFO_EHDR){
                    vals.ehdr = entryval;
                }else if (entrynum == AT_HWCAP){
                    vals.hwcap = entryval;
                }else if (entrynum == AT_HWCAP2){
                    vals.hwcap2 = entryval;
                }else if (entrynum == AT_PAGESZ){
                    vals.pagesz = entryval;
                }else if (entrynum == AT_CLKTCK){
                    vals.clktck = entryval;
                }else if (entrynum == AT_PHENT){
                    vals.phent = entryval;
                }else if (entrynum == AT_PHNUM){
                    vals.phnum = entryval;
                }else if (entrynum == AT_BASE){
                    vals.base = entryval;
                }else if (entrynum == AT_FLAGS){
                    vals.flags = entryval;
                }else if (entrynum == AT_UID){
                    vals.uid = entryval;
                }else if (entrynum == AT_EUID){
                    vals.euid = entryval;
                }else if (entrynum == AT_GID){
                    vals.gid = entryval;
                }else if (entrynum == AT_EGID){
                    vals.egid = entryval;
                }else if (entrynum == AT_SECURE){
                    vals.secure = entryval;
                }else if (entrynum == AT_RANDOM){
                    vals.random = entryval;
                }else if (entrynum == AT_PLATFORM){
                    vals.platform = entryval;
                }
            }
            if (vals.entry && vals.phdr){
                PPP_RUN_CB(on_rec_auxv, env, tb, &vals);
            }else {
                return;
            }
        }else{
            // If we can't read from the stack this is an indication that
            // we aren't quite in a usable userspace just yet.
            return;
        }
        panda_disable_callback(self_ptr, PANDA_CB_BEFORE_TCG_CODEGEN, pcb_btc_execve);
    }
}

void run_btc_cb(){
    panda_do_flush_tb();
    panda_enable_callback(self_ptr, PANDA_CB_BEFORE_TCG_CODEGEN, pcb_btc_execve);
}

void execve_cb(CPUState *cpu, target_ptr_t pc, target_ptr_t filename, target_ptr_t argv, target_ptr_t envp) {
    run_btc_cb();
}

void execveat_cb (CPUState* cpu, target_ptr_t pc, int dfd, target_ptr_t filename, target_ptr_t argv, target_ptr_t envp, int flags) {
    run_btc_cb();
}

bool init_plugin(void *self) {
    self_ptr = self;

    #if defined(TARGET_MIPS64)
        fprintf(stderr, "[ERROR] proc_start_linux: mips64 architecture not supported!\n");
        return false;
    #elif defined(TARGET_PPC)
        fprintf(stderr, "[ERROR] proc_start_linux: PPC architecture not supported by syscalls2!\n");
        return false;
    #else
        pcb_btc_execve.before_tcg_codegen = btc_execve;
        panda_register_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, pcb_btc_execve);

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
#if defined(TARGET_PPC) or defined(TARGET_MIPS64)
#else
  void* syscalls = panda_get_plugin_by_name("syscalls2");
  if (syscalls != NULL){
    PPP_REMOVE_CB("syscalls2", on_sys_execve_enter, execve_cb);
    PPP_REMOVE_CB("syscalls2", on_sys_execveat_enter, execveat_cb);
  }
#endif
}
