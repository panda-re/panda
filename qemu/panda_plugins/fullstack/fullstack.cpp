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
#include <set>
#include <iostream>
#include <fstream>

#include "../common/prog_point.h"
#include "../callstack_instr/callstack_instr_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

FILE *cs_file;
std::set<prog_point> tap_points;

bool done = false;

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    if(done) return 1;

    prog_point p = {};
    get_prog_point(env, &p);

    if (tap_points.find(p) != tap_points.end()) {
        tap_points.erase(p);
        target_ulong callers[16] = {0};
        int nret = get_callers(callers, 16, env);
        // Most recent callers are returned first, so print them
        // out in reverse order
        for (int i = nret-1; i >= 0; i--) {
            fprintf(cs_file, TARGET_FMT_lx " ", callers[i]);
            printf(TARGET_FMT_lx " ", callers[i]);
        }
        fprintf(cs_file, TARGET_FMT_lx " ", p.pc);
        fprintf(cs_file, TARGET_FMT_lx "\n", p.cr3);
        printf(TARGET_FMT_lx " ", p.pc);
        printf(TARGET_FMT_lx "\n", p.cr3);
    }
    
    if (tap_points.empty()) done = true;

    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin fullstack\n");
    
    std::ifstream taps("tap_points.txt");
    if (!taps) {
        printf("Couldn't open tap_points.txt; no tap points defined. Exiting.\n");
        return false;
    }

    prog_point p = {};
    while (taps >> std::hex >> p.caller) {
        taps >> std::hex >> p.pc;
        taps >> std::hex >> p.cr3;

        printf("Adding tap point (" TARGET_FMT_lx "," TARGET_FMT_lx "," TARGET_FMT_lx ")\n",
               p.caller, p.pc, p.cr3);
        tap_points.insert(p);
    }
    taps.close();

    if(!init_callstack_instr_api()) return false;

    cs_file = fopen("tap_callstacks.txt", "wb");

    panda_enable_precise_pc();
    panda_enable_memcb();    
    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    fclose(cs_file);
}
