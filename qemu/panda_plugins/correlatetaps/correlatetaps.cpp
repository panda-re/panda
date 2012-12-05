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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <map>
#include <list>
#include <algorithm>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

struct prog_point {
    target_ulong caller;
    target_ulong pc;
    target_ulong cr3;
    bool operator <(const prog_point &p) const {
        return (this->pc < p.pc) || \
               (this->pc == p.pc && this->caller < p.caller) || \
               (this->pc == p.pc && this->caller == p.caller && this->cr3 < p.cr3);
    }
    bool operator ==(const prog_point &p) const {
        return (this->pc == p.pc && this->caller == p.caller && this->cr3 == p.cr3);
    }
};

struct recent_addr {
    prog_point p;
    target_ulong start_addr;
    target_ulong end_addr;
};

#define HISTORY_SIZE 5
recent_addr history[HISTORY_SIZE];
int history_pos = 0;
std::map<std::pair<prog_point,prog_point>,int> correlated;

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    prog_point p = {};
#ifdef TARGET_I386
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&p.caller, 4, 0);
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = env->cr[3];
#endif
    p.pc = pc;

    for (int i = history_pos; i < HISTORY_SIZE; i++) {
        if (addr == history[i].end_addr)
            correlated[std::make_pair(history[i].p, p)]++;
        else if (addr+size == history[i].start_addr)
            correlated[std::make_pair(p, history[i].p)]++;
    }

    history[history_pos] = {p, addr, addr+size};
    history_pos = (history_pos + 1) % HISTORY_SIZE;
 
    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin correlatetaps\n");

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    FILE *mem_report = fopen("correlated_taps.bin", "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }

    std::map<std::pair<prog_point,prog_point>,int>::iterator it;
    for(it = correlated.begin(); it != correlated.end(); it++) {
        fwrite(&it->first.first, sizeof(prog_point), 1, mem_report);
        fwrite(&it->first.second, sizeof(prog_point), 1, mem_report);
        fwrite(&it->second, sizeof(int), 1, mem_report);
    }
    fclose(mem_report);
}
