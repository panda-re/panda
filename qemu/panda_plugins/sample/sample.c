#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
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

// Monitor callback. This gets a string that you can then parse for
// commands. Could do something more complex here, e.g. getopt.
int monitor_callback(Monitor *mon, const char *cmd) {
#ifdef CONFIG_SOFTMMU
    char *cmd_work = g_strdup(cmd);
    char *word;
    word = strtok(cmd_work, " ");
    do {
        if (strncmp("help", word, 4) == 0) {
            monitor_printf(mon,
                "sample plugin help:\n"
                "  sample_foo: do the foo action\n"
            );
        }
        else if (strncmp("sample_foo", word, 10) == 0) {
            printf("Doing the foo action\n");
            monitor_printf(mon, "I did the foo action!\n");
        }
    } while((word = strtok(NULL, " ")) != NULL);
    g_free(cmd_work);
#endif
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
    pcb.monitor = monitor_callback;
    panda_register_callback(self, PANDA_CB_MONITOR, pcb);

    plugin_log = fopen("sample_tblog.txt", "w");    
    if(!plugin_log) return false;
    else return true;
}

void uninit_plugin(void *self) {
    printf("Unloading sample plugin.\n");
    fflush(plugin_log);
    fclose(plugin_log);
}
