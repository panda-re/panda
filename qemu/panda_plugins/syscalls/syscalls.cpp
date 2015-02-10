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

extern "C" {
#define __STDC_FORMAT_MACROS
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include <stdio.h>
#include <stdlib.h>
}

#include <cassert>
#include <functional>
#include <string>
#include <list>
#include <algorithm>
#include <memory>

#include "syscalls.hpp"

// the previous output file was /scratch/syscalls.txt
// this just writes syscalls.txt to the current working directory
#define DEFAULT_LOG_FILE "syscalls.txt"

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);

#include "gen_syscalls_ext_typedefs.h"
#include "gen_syscall_ppp_register.cpp"
void registerExecPreCallback(void (*callback)(CPUState*, target_ulong));
void appendReturnPoint(ReturnPoint&& rp);
}
#include "gen_syscall_ppp_boilerplate.cpp"

// This is where we'll write out the syscall data
FILE *plugin_log;
void* syscalls_plugin_self;

#include "gen_callbacks.hpp"
#include "gen_default_callbacks.cpp"

std::vector<target_asid> relevant_ASIDs;

std::vector<void (*)(CPUState*, target_ulong)> preExecCallbacks;

void registerExecPreCallback(void (*callback)(CPUState*, target_ulong)){
    preExecCallbacks.push_back(callback);
}

// ARM OABI has the syscall number embedded in the swi: swi #90xxxx
//#define CAPTURE_ARM_OABI 0

#ifdef TARGET_ARM
// ARM: stolen from target-arm/helper.c
static uint32_t arm_get_vaddr_table(CPUState *env, uint32_t address)
{
#if (TARGET_LONG_BITS == 64)
#error 64-bit ARM is not yet supported
#endif
    uint32_t table;

    if (address & env->cp15.c2_mask)
        table = env->cp15.c2_base1 & 0xffffc000;
    else

        table = env->cp15.c2_base0 & env->cp15.c2_base_mask;

    return table;
}
#endif

target_asid get_asid(CPUState *env, target_ulong addr) {
#if defined(TARGET_I386)
    return env->cr[3];
#elif defined(TARGET_ARM)
    return arm_get_vaddr_table(env, addr);
#else
    return 0;
#endif
}

// Check if the instruction is sysenter (0F 34)
bool translate_callback(CPUState *env, target_ulong pc) {
#if defined(TARGET_I386)
    unsigned char buf[2];
    panda_virtual_memory_rw(env, pc, buf, 2, 0);
    // Check if the instruction is syscall (0F 05)
    if (buf[0]== 0x0F && buf[1] == 0x05) {
        return true;
    }
    // Check if the instruction is sysenter (0F 34)
    else if (buf[0]== 0x0F && buf[1] == 0x34) {
        return true;
    }
    else {
        return false;
    }
#elif defined(TARGET_ARM)
    unsigned char buf[4];

    // Check for ARM mode syscall
    if(env->thumb == 0) {
        panda_virtual_memory_rw(env, pc, buf, 4, 0);
        // EABI
        if ( ((buf[3] & 0x0F) ==  0x0F)  && (buf[2] == 0) && (buf[1] == 0) && (buf[0] == 0) ) {
            return true;
        }
#if defined(CAPTURE_ARM_OABI)
        else if (((buf[3] & 0x0F) == 0x0F)  && (buf[2] == 0x90)) {  // old ABI
            return true;
        }
#endif
    }
    else {
        panda_virtual_memory_rw(env, pc, buf, 2, 0);
        // check for Thumb mode syscall
        if (buf[1] == 0xDF && buf[0] == 0){
            return true;
        }
    }
    return false;
#endif
}

static std::list<ReturnPoint> fork_returns;
static std::list<ReturnPoint> exec_returns;
static std::list<ReturnPoint> clone_returns;
static std::list<ReturnPoint> prctl_returns;
static std::list<ReturnPoint> mmap_returns;
// always return to same process
static std::list<ReturnPoint> other_returns;

void appendReturnPoint(ReturnPoint&& rp){
    other_returns.push_back(std::move(rp));
}

#if defined(TARGET_ARM)
static void vmi_fork_callback(CPUState *env, target_ulong pc){
    uint8_t offset = 0;
    if(env->thumb == 0){
        offset = 4;
    } else {
        offset = 2;
    }
    // pc + offset or env->regs[14] ?
    fork_returns.push_back(ReturnPoint(pc + offset, get_asid(env, pc)));
}

static void vmi_execve_callback(CPUState *env, target_ulong pc,
    syscalls::string filename,target_ulong argv,target_ulong envp)
{
    uint8_t offset = 0;
    if(env->thumb == 0){
        offset = 4;
    } else {
        offset = 2;
    }
    exec_returns.push_back(ReturnPoint(pc+offset,  get_asid(env, pc)));
    //exec_returns.push_back(std::make_pair(env->regs[14], get_asid(env, pc)));
}

static void vmi_clone_callback(CPUState* env,target_ulong pc,uint32_t clone_flags,uint32_t newsp,
                         target_ulong parent_tidptr,int32_t tls_val,
                         target_ulong child_tidptr,target_ulong regs)
{
    clone_returns.push_back(ReturnPoint(mask_retaddr_to_pc(env->regs[14]), get_asid(env, pc)));
}

static void vmi_sys_prctl_callback(CPUState *env, target_ulong pc,
    uint32_t option,uint32_t arg2,uint32_t arg3,uint32_t arg4,uint32_t arg5)
{
    prctl_returns.push_back(ReturnPoint(mask_retaddr_to_pc(env->regs[14]), get_asid(env, pc)));
}

static void vmi_do_mmap2_callback(CPUState *env, target_ulong pc,
    uint32_t addr,uint32_t len,uint32_t prot,uint32_t flags,uint32_t fd,uint32_t pgoff)
{
    mmap_returns.push_back(ReturnPoint(mask_retaddr_to_pc(env->regs[14]), get_asid(env, pc)));
}

#endif //TARGET_ARM

static inline bool in_kernelspace(CPUState *env) {
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
    return false;
#endif
}

static bool is_empty(ReturnPoint& pt){ 
    return (pt.retaddr == 0 && pt.process_id == 0);
}

static bool returned_check_callback(CPUState *env, TranslationBlock* tb){
    // First, check if any of the PANDA VMI callbacks needs to be triggered
#if defined(CONFIG_PANDA_VMI)
    panda_cb_list *plist;
    for(auto& retVal :fork_returns){
        if (retVal.retaddr == tb->pc && retVal.process_id == get_asid(env, tb->pc)){
           // we returned from fork
           for(plist = panda_cbs[PANDA_CB_VMI_AFTER_FORK]; plist != NULL; plist = panda_cb_list_next(plist)) {
                plist->entry.return_from_fork(env);
            }
           // set to 0,0 so we can remove after we finish iterating
           retVal.retaddr = retVal.process_id = 0;
        }
    }
    fork_returns.remove_if(is_empty);
    for(auto& retVal :exec_returns){
        if(retVal.process_id == get_asid(env, tb->pc) && !in_kernelspace(env)){
        //if (retVal.retaddr == tb->pc /*&& retVal.process_id == get_asid(env, tb->pc)*/){
           // we returned from fork
           for(plist = panda_cbs[PANDA_CB_VMI_AFTER_EXEC]; plist != NULL; plist = panda_cb_list_next(plist)) {
                plist->entry.return_from_exec(env);
            }
           // set to 0,0 so we can remove after we finish iterating
           retVal.retaddr = retVal.process_id = 0;
        }
    }
    exec_returns.remove_if(is_empty);
    for(auto& retVal :clone_returns){
        if (retVal.retaddr == tb->pc && retVal.process_id == get_asid(env, tb->pc)){
           // we returned from fork
           for(plist = panda_cbs[PANDA_CB_VMI_AFTER_CLONE]; plist != NULL; plist = panda_cb_list_next(plist)) {
                plist->entry.return_from_clone(env);
            }
           // set to 0,0 so we can remove after we finish iterating
           retVal.retaddr = retVal.process_id = 0;
        }
    }
    clone_returns.remove_if(is_empty);

#else
    fork_returns.clear();
    exec_returns.clear();
    clone_returns.clear();
#endif

    //check if any of the internally tracked syscalls has returned
    //only one should be at its return point for any given basic block
    bool invalidate = false;
    for(auto& retVal : other_returns){
        if(retVal.retaddr == tb->pc && retVal.process_id == get_asid(env, tb->pc)){
            Callback_RC rc = retVal.callback(retVal.opaque.get(), env, retVal.process_id);
            if(Callback_RC::INVALIDATE == rc){
                invalidate = true;
            } else if(Callback_RC::NORMAL == rc){
                retVal.retaddr = retVal.process_id = 0;
            } else if(Callback_RC::ERROR == rc){
                fprintf(stderr, "Syscalls caused an error\n");
                assert(0);
            } else {
                fprintf(stderr, "Unknown syscalls internal callback return value\n");
                assert(0);
            }
        }
    }
    other_returns.remove_if(is_empty);
    return invalidate;
}

//void record_syscall(const char* callname);
void finish_syscall(){}
//void log_string(target_ulong src, const char* argname);
//void log_pointer(target_ulong addr, const char* argname);
//void log_32(target_ulong value, const char* argname);
//void log64(target_ulong high, target_ulong low, const char* argname){}
std::function<void (const char*)> record_syscall;
std::function<syscalls::string  (target_ulong, const char*)> log_string;
std::function<target_ulong (target_ulong, const char*)> log_pointer;
std::function<uint32_t     (target_ulong, const char*)> log_32;
std::function<int32_t      (target_long, const char*)> log_s32;
std::function<uint64_t     (target_ulong, target_ulong, const char*)> log_64;

static inline bool is_watched(CPUState *env){
    target_ulong pc;
#if defined(TARGET_ARM)
    pc = env->regs[15];
#elif defined(TARGET_I386)
    pc = env->eip;
#endif
    if(relevant_ASIDs.empty())
        return true;
    for (auto asid : relevant_ASIDs){
        if (get_asid(env, pc) == asid)
            return true;
    }
    return false;
}

static void syscall_fprintf(CPUState* env, const char* __format, ...){
    if (is_watched(env)){
        va_list va;
        va_start(va,__format);
        vfprintf(plugin_log, __format,va);
        va_end(va);
    }
}

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
    // run any code we need to update our state
    for(const auto callback : preExecCallbacks){
        callback(env, pc);
    }
    
#if defined(TARGET_I386)
    // On Windows, the system call id is in EAX
    record_syscall = [&env, &pc](const char* callname){
      syscall_fprintf(env, "CALL=%s, PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx ", CR3=" TARGET_FMT_lx "\n", callname, pc, env->regs[R_EAX], env->cr[3]);
    };
#elif defined(TARGET_ARM)
#if defined(CAPTURE_ARM_OABI)
#if (1)
    if(env->thumb == 0){ //Old ABI not possible with Thumb
      // read 4 bytes, number may be in instruction.
      unsigned char buf[4];
      panda_virtual_memory_rw(env, pc, buf, 4, 0);
        if (buf[2] == 0x90) {
	fprintf(plugin_log, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx ", OLD ABI \n", pc, *(unsigned int*)&buf);
	return 0;
      }
    }
#else
    syscall_fprintf(env, "SKIPPING OABI\n");
#endif
#endif// OABI
    if (env->regs[7] == 0xf0){ //skip sys_futex
      return 0;
    }

    record_syscall = [&env, &pc](const char* callname){
      syscall_fprintf(env, "CALL=%s, PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx ", thumb=" TARGET_FMT_lx "\n", callname, pc, env->regs[7], env->thumb);
    };
#endif

    log_string = [&env, &pc](target_ulong src, const char* argname) -> syscalls::string{
      syscalls::string arg(env, pc, src);
      syscall_fprintf(env, "STRING, NAME=%s, VALUE=%s\n", argname, arg.value().c_str()); 
      return arg;
    };

    log_pointer = [&env, &pc](target_ulong addr, const char* argname) -> target_ulong {
      syscall_fprintf(env, "PTR, NAME=%s, VALUE=" TARGET_FMT_lx"\n",argname, addr);
      return addr;
    };

    log_32 = [&env,&pc](target_ulong value, const char* argname){
      syscall_fprintf(env, "U32, NAME=%s, VALUE=" TARGET_FMT_lx"\n", argname, value);
      return value;
    };

    log_s32 = [&env,&pc](target_long value, const char* argname){
      syscall_fprintf(env, "S32, NAME=%s, VALUE=" TARGET_FMT_lx"\n", argname, value);
      return value;
    };
    
    log_64 = [&env,&pc](target_ulong high, target_ulong low, const char* argname){
      syscall_fprintf(env, "I64, NAME=%s, VALUE=%llx\n", argname, ((unsigned long long)high << 32) | low );
      return ((unsigned long long)high << 32) | low;
    };


    // syscall is in R7
    //syscall_fprintf(env, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx ", thumb=" TARGET_FMT_lx "\n", pc, env->regs[7], env->thumb);

#include "gen_syscall_printer.cpp"
    return 0;
}



extern "C" {

panda_arg_list *args;

bool init_plugin(void *self) {

    int i;
    char *sclog_filename = NULL;
    args = panda_get_args("syscalls");
    if (args != NULL) {
        for (i = 0; i < args->nargs; i++) {
            // Format is syscall:file=<file>
            if (0 == strncmp(args->list[i].key, "file", 4)) {
                sclog_filename = args->list[i].value;
            }
        }
    }
    if (!sclog_filename) {
        fprintf(stderr, "warning: Plugin 'syscalls' uses argument: -panda-arg syscalls:file=<file>\nusing default log file %s\n", DEFAULT_LOG_FILE);
        char *scdef=new char[strlen(DEFAULT_LOG_FILE)+1];
        strcpy(scdef,DEFAULT_LOG_FILE);
        sclog_filename=scdef;
    }

    plugin_log = fopen(sclog_filename, "w");
    if(!plugin_log) {
        fprintf(stderr, "Couldn't open %s. Abort.\n",sclog_filename);
        return false;
    }

// Don't bother if we're not on a supported target
#if defined(TARGET_I386) || defined(TARGET_ARM)

    panda_cb pcb;

    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    pcb.before_block_exec_invalidate_opt = returned_check_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);

#else

    fwrite(stderr,"The syscalls plugin is not currently supported on this platform.\n");

    return false;

#endif

#if defined(TARGET_ARM)
    syscalls::register_call_fork(vmi_fork_callback);
    syscalls::register_call_execve(vmi_execve_callback);
    syscalls::register_call_do_mmap2(vmi_do_mmap2_callback);
    syscalls::register_call_sys_prctl(vmi_sys_prctl_callback);
    syscalls::register_call_clone(vmi_clone_callback);
#endif
    syscalls_plugin_self = self;
    return true;
}

void uninit_plugin(void *self) {
    fflush(plugin_log);
    fclose(plugin_log);
}

}
