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

int before_block_exec(CPUState *env, TranslationBlock *tb);
}


uint32_t target_block;
bool first_block = true;
int before_block_exec(CPUState *env, TranslationBlock *tb) {

    if (unlikely(((0 == target_block) && first_block) ||
		 (tb->pc == target_block))) {
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
    }
    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin rehosting\n");

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();

    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

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
