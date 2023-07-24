#include "dynamic_symbols.h"
extern "C"{
    #include "syscalls2/syscalls_ext_typedefs.h"
    #include "syscalls2/syscalls2_info.h"
    #include "syscalls2/syscalls2_ext.h"
}

void (*dlsym_add_hook)(struct hook*);
panda_cb pcb_asid;

/**
 * Make a check every time the process changes.
 */

bool asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    enable_analysis(ANALYSIS_GENERIC);
    return false;
}

void task_change(CPUState *env){
    enable_analysis(ANALYSIS_GENERIC);
}

/**
 * This handles a check on every return.
 */

void sys_all_return(CPUState *cpu, target_ulong pc, target_ulong callno){
    enable_analysis(ANALYSIS_GENERIC);
}

/**
 * Handle MMAP calls. These have a fairly good chance of indicating a library 
 * change.
 * 
 * We have to change mmap, mmap2, old_mmap, mmap_pgoff, and mprotect
 */
#if TARGET_MIPS
void sys_mmap_return(CPUState* cpu, target_ulong pc, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e, unsigned int f)
#elif TARGET_AARCH64
void sys_mmap_return(CPUState* cpu, target_ulong pc, long unsigned int b, unsigned int c, int d, int e, int f, long unsigned int g)
#else
void sys_mmap_return(CPUState* cpu,target_ulong pc, target_ulong arg0,target_ulong arg1, target_ulong arg2, target_ulong arg3, target_ulong arg4,target_ulong arg5)
#endif
{
    enable_analysis(ANALYSIS_SPECIFIC);
}

void sys_old_mmap_return(CPUState *cpu, target_ulong pc, uint32_t arg0){
    enable_analysis(ANALYSIS_SPECIFIC);
}

#ifdef TARGET_MIPS
void sys_mmap2_return(CPUState* cpu, target_ulong pc, unsigned int b, unsigned int c, int d, int e, int f, unsigned int g)
#elif TARGET_AARCH64
void sys_mmap2_return(CPUState* cpu, target_ulong pc, unsigned int b, unsigned int c, int d, int e, int f, unsigned int g)
#else
void sys_mmap2_return()
#endif
{
    enable_analysis(ANALYSIS_SPECIFIC);
}

void sys_mprotect_return(CPUState *cpu, target_ulong pc, target_ulong arg0, uint32_t arg1, target_ulong arg2)
{
    enable_analysis(ANALYSIS_SPECIFIC);
}

/**
 * Check on sys_exit and sys_exit_group.
 */

void sys_exit_enter(CPUState *cpu, target_ulong pc, int exit_code){
    target_ulong asid = get_id(cpu);
    remove_asid_entries(asid);
}

/**
 * This set of info points checks when a program starts and on the entry point
 * of the program.
 */

void hook_program_start(CPUState *env, TranslationBlock* tb, struct hook* h){
    enable_analysis(ANALYSIS_SPECIFIC);
    h->enabled = false;
}

void recv_auxv(CPUState *env, TranslationBlock *tb, struct auxv_values *av){
    target_ulong asid = get_id(env);
    remove_asid_entries(asid);
    struct hook h;
    // printf("Received auxv entrypoint: " TARGET_FMT_lx " name: %s\n", av->entry, av->argv[0]);

#ifdef TARGET_ARM
    // If the entrypoint is in thumb mode, bit 0 will be set which results
    // in an update to the CSPR.T bit. The hook needs needs the bit to masked
    // out.
    h.addr = av->entry & ~0x1;
#else
    h.addr = av->entry;
#endif

    h.asid = asid;
    h.type = PANDA_CB_START_BLOCK_EXEC;
    h.cb.start_block_exec = hook_program_start;
    h.km = MODE_USER_ONLY;
    h.enabled = true;
    dlsym_add_hook(&h);
    enable_analysis(ANALYSIS_SPECIFIC);
}


#ifndef TARGET_PPC

bool initialize_process_infopoints(void* self){
    pcb_asid.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb_asid);

    PPP_REG_CB("syscalls2", on_sys_exit_enter, sys_exit_enter);
    PPP_REG_CB("syscalls2", on_sys_exit_group_enter, sys_exit_enter);
    PPP_REG_CB("syscalls2", on_all_sys_return, sys_all_return);
    #if defined(TARGET_X86_64)
        PPP_REG_CB("syscalls2", on_sys_mmap_return, sys_mmap_return);
    #elif defined(TARGET_ARM) && defined(TARGET_AARCH64)
        PPP_REG_CB("syscalls2", on_sys_mmap_return, sys_mmap_return);
    #elif defined(TARGET_I386)
        PPP_REG_CB("syscalls2", on_sys_mmap_pgoff_return, sys_mmap_return);
        PPP_REG_CB("syscalls2", on_sys_old_mmap_return, sys_old_mmap_return);
    #elif defined(TARGET_ARM)
        PPP_REG_CB("syscalls2", on_do_mmap2_return, sys_mmap_return);
    #elif defined(TARGET_MIPS) && !defined(TARGET_MIPS64)
        // XXX No mips64 support since we don't have these syscalls
        PPP_REG_CB("syscalls2", on_sys_mmap_return, sys_mmap_return);
        PPP_REG_CB("syscalls2", on_mmap2_return, sys_mmap2_return);
    #endif
    PPP_REG_CB("syscalls2", on_sys_mprotect_return, sys_mprotect_return);
    panda_require("proc_start_linux");
    PPP_REG_CB("proc_start_linux",on_rec_auxv, recv_auxv);

    // osi initialized in init_plugin
    PPP_REG_CB("osi", on_task_change, task_change);
    
    void* hooks = panda_get_plugin_by_name("hooks");
    if (hooks == NULL){
        panda_require("hooks");
        hooks = panda_get_plugin_by_name("hooks");
    }
    if (hooks != NULL){
        dlsym_add_hook = (void(*)(struct hook*)) dlsym(hooks, "add_hook");
        if ((void*)dlsym_add_hook == NULL) {
            printf("couldn't load add_hook from hooks\n");
            return false;
        }
    }
    return true;
}
#endif