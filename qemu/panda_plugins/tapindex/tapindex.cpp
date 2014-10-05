/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
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
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

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
};

std::map<prog_point,long> read_tracker;
std::map<prog_point,long> write_tracker;
FILE *read_index;
FILE *write_index;

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    prog_point p = {};
#ifdef TARGET_I386
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&p.caller, 4, 0);
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = env->cr[3];
#endif
    p.pc = pc;
    write_tracker[p] += size;
 
    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    prog_point p = {};
#ifdef TARGET_I386
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&p.caller, 4, 0);
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = env->cr[3];
#endif
    p.pc = pc;
    read_tracker[p] += size;
 
    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin tapindex\n");

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);
    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    read_index = fopen("tap_reads.idx", "w");
    if(!read_index) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }

    write_index = fopen("tap_writes.idx", "w");
    if(!write_index) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }

    // Cross platform support: need to know how big a target_ulong is
    uint32_t target_ulong_size = sizeof(target_ulong);
    fwrite(&target_ulong_size, sizeof(uint32_t), 1, read_index);

    // Save reads
    std::map<prog_point,long>::iterator it;
    for(it = read_tracker.begin(); it != read_tracker.end(); it++) {
        fwrite(&it->first, sizeof(prog_point), 1, read_index);
        fwrite(&it->second, sizeof(long), 1, read_index);
    }
    fclose(read_index);

    // Cross platform support: need to know how big a target_ulong is
    fwrite(&target_ulong_size, sizeof(uint32_t), 1, write_index);

    // Save writes
    for(it = write_tracker.begin(); it != write_tracker.end(); it++) {
        fwrite(&it->first, sizeof(prog_point), 1, write_index);
        fwrite(&it->second, sizeof(long), 1, write_index);
    }
    fclose(write_index);
}
