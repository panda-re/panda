#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"

#include <stdio.h>
#include <stdlib.h>

int guest_hypercall_callback(CPUState *env);
bool init_plugin(void);

FILE *plugin_log;

int guest_hypercall_callback(CPUState *env) {
    printf("Hypercall called!\n");
    return 1;
}

int before_block_callback(CPUState *env, TranslationBlock *tb) {
#ifdef TARGET_I386
    fprintf(plugin_log, "Next TB: %#lx, CR3=%#lx\n", tb->pc, env->cr[3]);
#endif
    return 1;
}

int after_block_callback(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb) {
#ifdef TARGET_I386
    fprintf(plugin_log, "After TB %#lx, CR3=%#lx next TB: %lx\n", tb->pc, env->cr[3], next_tb ? next_tb->pc : 0);
#endif
    return 1;
}

bool init_plugin(void) {
    panda_cb pcb;

    pcb.guest_hypercall = guest_hypercall_callback;
    register_panda_callback(PANDA_CB_GUEST_HYPERCALL, pcb);
    pcb.after_block = after_block_callback;
    register_panda_callback(PANDA_CB_AFTER_BLOCK, pcb);
    pcb.before_block = before_block_callback;
    register_panda_callback(PANDA_CB_BEFORE_BLOCK, pcb);

    plugin_log = fopen("sample_tblog.txt", "w");    
    if(!plugin_log) return false;
    else return true;
}

void uninit_plugin(void) {
    fclose(plugin_log);
}
