#include "dynamic_symbols.h"
extern "C"{
    #include "syscalls2/syscalls_ext_typedefs.h"
    #include "syscalls2/syscalls2_info.h"
    #include "syscalls2/syscalls2_ext.h"
}

void (*dlsym_add_hook)(struct hook*);

/**
 * Make a check every time the ASID changes.
 */

bool asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    enable_analysis();
    return false;
}

/**
 * Handle the various mmap syscalls per architecture.
 */
void sys_mmap_return(
    CPUState* cpu,
    target_ulong pc,
    target_ulong arg0,
    target_ulong arg1,
    target_ulong arg2,
    target_ulong arg3,
    target_ulong arg4,
    target_ulong arg5)
{
    enable_analysis();
}

void sys_old_mmap_return(CPUState *cpu, target_ulong pc, uint32_t arg0){
    enable_analysis();
}

void sys_mmap2_return(CPUState* cpu, target_ulong pc, unsigned int b, unsigned int c, int d, int e, int f, unsigned int g){
    enable_analysis();
}

void sys_mmap_arm64_return(CPUState* cpu, target_ulong pc, long unsigned int b, unsigned int c, int d, int e, int f, long unsigned int g){
    enable_analysis();
}

void sys_mmap2_mips_return(CPUState* cpu, target_ulong pc, unsigned int b, unsigned int c, int d, int e, int f, unsigned int g){
    enable_analysis();
}
void sys_mmap_mips_return(CPUState* cpu, target_ulong pc, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e, unsigned int f){
    enable_analysis();
}

#ifdef TARGET_MIPS64
void sys_mprotect_return(CPUState *cpu, target_ulong pc, uint32_t arg0, uint32_t arg1, uint32_t arg2){
#else
void sys_mprotect_return(CPUState *cpu, target_ulong pc, target_ulong arg0, uint32_t arg1, target_ulong arg2){
#endif

    enable_analysis();
}

/**
 * Check on sys_exit and sys_exit_group.
 */

void sys_exit_enter(CPUState *cpu, target_ulong pc, int exit_code){
    target_ulong asid = get_id(cpu);
    remove_asid_entries(asid);
    enable_analysis();
}

/**
 * This set of info points checks when a program starts and on the entry point
 * of the program.
 */

void hook_program_start(CPUState *env, TranslationBlock* tb, struct hook* h){
    enable_analysis();
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
    enable_analysis();
}

#ifndef TARGET_PPC

bool initialize_process_infopoints(){
    PPP_REG_CB("syscalls2", on_sys_exit_enter, sys_exit_enter);
    PPP_REG_CB("syscalls2", on_sys_exit_group_enter, sys_exit_enter);
    #if defined(TARGET_X86_64)
        PPP_REG_CB("syscalls2", on_sys_mmap_return, sys_mmap_return);
    #elif defined(TARGET_ARM) && defined(TARGET_AARCH64)
        PPP_REG_CB("syscalls2", on_sys_mmap_return, sys_mmap_arm64_return);
    #elif defined(TARGET_I386)
        PPP_REG_CB("syscalls2", on_sys_mmap_pgoff_return, sys_mmap_return);
        PPP_REG_CB("syscalls2", on_sys_old_mmap_return, sys_old_mmap_return);
    #elif defined(TARGET_ARM)
        PPP_REG_CB("syscalls2", on_do_mmap2_return, sys_mmap_return);
    #elif defined(TARGET_MIPS)
        PPP_REG_CB("syscalls2", on_sys_mmap_return, sys_mmap_mips_return);
        PPP_REG_CB("syscalls2", on_mmap2_return, sys_mmap2_mips_return);
    #endif
    PPP_REG_CB("syscalls2", on_sys_mprotect_return, sys_mprotect_return);
    panda_require("proc_start_linux");
    PPP_REG_CB("proc_start_linux",on_rec_auxv, recv_auxv);
    
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