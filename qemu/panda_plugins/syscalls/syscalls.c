#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"

#include <stdio.h>
#include <stdlib.h>

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);

bool init_plugin(void *);
void uninit_plugin(void *);

// This is where we'll write out the syscall data
FILE *plugin_log;

// Check if the instruction is sysenter (0F 34)
bool translate_callback(CPUState *env, target_ulong pc) {
    unsigned char buf[2];
    panda_virtual_memory_rw(env, pc, buf, 2, 0);
    if (buf[0] == 0x0F && buf[1] == 0x34)
        return true;
    else
        return false;
}

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
#ifdef TARGET_I386
    // On Windows, the system call id is in EAX
    fprintf(plugin_log, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx "\n", pc, env->regs[R_EAX]);
#endif
    return 0;
}

bool init_plugin(void *self) {
// Don't bother if we're not on x86
#ifdef TARGET_I386
    panda_cb pcb;

    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
#endif

    plugin_log = fopen("syscalls.txt", "w");    
    if(!plugin_log) return false;
    else return true;
}

void uninit_plugin(void *self) {
    fflush(plugin_log);
    fclose(plugin_log);
}
