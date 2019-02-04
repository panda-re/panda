
#ifndef __VL_H__
#define __VL_H__

#include <stdint.h>

typedef enum panda_main_mode {
    PANDA_NORMAL,              // just run panda/qemu as normal
    PANDA_INIT,               // initialize panda/qemu
    PANDA_RUN,                // run the emulate machine
    PANDA_FINISH}             // cleanup and exit
PandaMainMode;

void main_panda_run(void);

void main_loop(void);

int main_aux(int argc, char **argv, char **envp, PandaMainMode pmm);

#endif
