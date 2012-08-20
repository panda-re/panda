#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"

#include <stdio.h>
#include <stdlib.h>

int after_block_callback(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb);
int before_block_callback(CPUState *env, TranslationBlock *tb);
int guest_hypercall_callback(CPUState *env);
bool init_plugin(void *);
void uninit_plugin(void *);

FILE *plugin_log;

int guest_hypercall_callback(CPUState *env) {
#ifdef TARGET_I386
    if(env->regs[R_EAX] == 0xdeadbeef) printf("Hypercall called!\n");
#endif
    return 1;
}

int before_block_callback(CPUState *env, TranslationBlock *tb) {
    fprintf(plugin_log, "Next TB: " TARGET_FMT_lx 
#ifdef TARGET_I386
        ", CR3=" TARGET_FMT_lx
#endif
         "%s\n", tb->pc,
#ifdef TARGET_I386
        env->cr[3],
#endif
        "");
    return 1;
}

int after_block_callback(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb) {
    fprintf(plugin_log, "After TB " TARGET_FMT_lx 
#ifdef TARGET_I386
        ", CR3=" TARGET_FMT_lx
#endif
        " next TB: " TARGET_FMT_lx "\n", tb->pc,
#ifdef TARGET_I386
        env->cr[3],
#endif
        next_tb ? next_tb->pc : 0);
    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);
    pcb.after_block = after_block_callback;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK, pcb);
    pcb.before_block = before_block_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK, pcb);

    plugin_log = fopen("sample_tblog.txt", "w");    
    if(!plugin_log) return false;
    else return true;
}

void uninit_plugin(void *self) {
    printf("Unloading sample plugin.\n");
    fclose(plugin_log);
}
