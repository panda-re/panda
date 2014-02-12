/* PANDABEGINCOMMENT PANDAENDCOMMENT */
/* PANDABEGINCOMMENT PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "disas.h"

#include "panda_plugin.h"
//#include "qapi-types.h"
    // uses a field named "class"
//#include "sysemu.h"
    //includes qapi-types.h
typedef enum RunState
{
    RUN_STATE_DEBUG = 0,
    RUN_STATE_INMIGRATE = 1,
    RUN_STATE_INTERNAL_ERROR = 2,
    RUN_STATE_IO_ERROR = 3,
    RUN_STATE_PAUSED = 4,
    RUN_STATE_POSTMIGRATE = 5,
    RUN_STATE_PRELAUNCH = 6,
    RUN_STATE_FINISH_MIGRATE = 7,
    RUN_STATE_RESTORE_VM = 8,
    RUN_STATE_RUNNING = 9,
    RUN_STATE_SAVE_VM = 10,
    RUN_STATE_SHUTDOWN = 11,
    RUN_STATE_WATCHDOG = 12,
    RUN_STATE_MAX = 13,
} RunState;
    
    void vm_stop(RunState state);
}

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <set>
#include <list>
#include <algorithm>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

bool before_block_exec(CPUState *env, TranslationBlock *tb);
}


uint32_t target_block;
bool first_block = true;
bool before_block_exec(CPUState *env, TranslationBlock *tb) {

    last_basic_block = tb->pc;
    if (unlikely(((0 == target_block) || (tb->pc == target_block))
            && first_block)) {
        first_block = false;

        printf("Saving CPU state... at block %#X\n", tb->pc);
        FILE *cpuf = fopen("cpu_boot_state.env","wb");
        if (!fwrite(env, sizeof(CPUState), 1, cpuf)) {
            perror("fwrite");
            exit(1);
        }
        fclose(cpuf);

        printf("Saving RAM state...\n");
        FILE *memf = fopen("mem_boot_state.img","wb");
        panda_memsavep(memf);
        fclose(memf);
        //vm_stop(RUN_STATE_PAUSED);
        panda_load_plugin("mipsel-softmmu/panda_plugins/panda_llvm_trace.so");
        return true;
    }
    return false;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin rehosting\n");

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();

    pcb.before_block_exec_invalidate_opt = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);

    target_block = 0;
    int i;
    char* foo = NULL;
    for (i = 0; i < panda_argc; i++) {
      if (0 == strncmp(panda_argv[i], "rehosting", 6)) {
	foo = strrchr(panda_argv[i], '=');
	if (foo) foo++;
      }
    }
    if(foo){
        target_block = strtoul(foo, NULL, 0);
    }


    return true;
}

void uninit_plugin(void *self) {
}
