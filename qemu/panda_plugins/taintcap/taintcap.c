#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "disas.h"

#include "panda_plugin.h"

#include <stdio.h>
#include <stdlib.h>

int guest_hypercall_callback(CPUState *env);
bool init_plugin(void *);
void uninit_plugin(void *);

extern FILE *funclog;
FILE *plugin_log;

int guest_hypercall_callback(CPUState *env) {
#ifdef TARGET_I386
    if(env->regs[R_EAX] == 0xdeadbeef) {
        if (env->regs[R_EBX] == 0) {                // Taint label and start tracing
            target_ulong buf_start = env->regs[R_ECX];
            target_ulong buf_len = env->regs[R_EDX];

            if(!funclog) {
                funclog = fopen("/tmp/llvm-functions.log", "w");
                setbuf(funclog, NULL);
            }
            
            fprintf(funclog, "label " TARGET_FMT_lu " " TARGET_FMT_lu "\n", 
                buf_start, buf_len);
            printf("label " TARGET_FMT_lx " " TARGET_FMT_lu "\n", 
                buf_start, buf_len);

            execute_llvm = 1;
            generate_llvm = 1;
//            trace_llvm = 1;
            
            // Need this because existing TBs do not contain LLVM code
            panda_do_flush_tb();
        }
        else if (env->regs[R_EBX] == 1) {           // Taint query + stop tracing
            target_ulong buf_start = env->regs[R_ECX];
            target_ulong buf_len = env->regs[R_EDX];

            fprintf(funclog, "query " TARGET_FMT_lu " " TARGET_FMT_lu "\n", 
                buf_start, buf_len);
            printf("query " TARGET_FMT_lx " " TARGET_FMT_lu "\n", 
                buf_start, buf_len);
            execute_llvm = 0;
            generate_llvm = 0;
//            trace_llvm = 0;
        }
    }
#endif
    return 1;
}

#if 0
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
#endif

bool init_plugin(void *self) {
    panda_cb pcb;

    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);
    //pcb.monitor = monitor_callback;
    //panda_register_callback(self, PANDA_CB_MONITOR, pcb);

    return true;
}

void uninit_plugin(void *self) {
    fclose(funclog);
    printf("Unloading taintcap plugin.\n");
}
