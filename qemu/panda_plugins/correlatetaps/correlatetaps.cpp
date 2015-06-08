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

#include "../common/prog_point.h"
#include "pandalog.h"
#include "../callstack_instr/callstack_instr_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

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
    get_prog_point(env, &p);

    for (int i = 0; i < HISTORY_SIZE; i++) {
        if (history[i].p == p) continue;
        if (addr == history[i].end_addr)
            correlated[std::make_pair(history[i].p, p)]++;
        else if (addr+size == history[i].start_addr)
            correlated[std::make_pair(p, history[i].p)]++;
    }

    // Handle cases like rep stosd. We want to keep extending the
    // range if the program point hasn't changed and the new range 
    // is contiguous. If it's not contiguous, keep the most recent
    // one. Either way, don't add to the history until the program
    // point has actually changed.
    if (history[history_pos].p == p) {
        // Can we extend the old one?
        if (history[history_pos].start_addr == addr+size) {
            history[history_pos].start_addr = addr;
        }
        else if (history[history_pos].end_addr == addr) {
            history[history_pos].end_addr = addr+size;
        }
        else {
            // If not, replace it wholesale but do not update
            // history_pos
            history[history_pos].start_addr = addr;
            history[history_pos].end_addr = addr+size;
        }
    }
    else {
        history_pos = (history_pos + 1) % HISTORY_SIZE;
        history[history_pos].p = p;
        history[history_pos].start_addr = addr;
        history[history_pos].end_addr = addr+size;
    }
 
    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin correlatetaps\n");

    if(!init_callstack_instr_api()) return false;

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
