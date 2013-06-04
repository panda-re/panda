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

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <set>
#include <iostream>
#include <fstream>

#include "../common/prog_point.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

typedef void (* get_prog_point_t)(CPUState *env, prog_point *p);
get_prog_point_t get_prog_point;

}

std::set<prog_point> tap_points;

bool done = false;

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    if(done) return 1;

    prog_point p = {};

    get_prog_point(env, &p);

    if (tap_points.find(p) != tap_points.end()) {
        tap_points.erase(p);
        char path[256];
        sprintf(path, TARGET_FMT_lx "." TARGET_FMT_lx "." TARGET_FMT_lx ".mem",
            p.caller, p.pc, p.cr3);
        FILE *f = fopen(path, "wb");
        panda_memsavep(f);
        fclose(f);
    }
    
    if (tap_points.empty()) done = true;

    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin memsnap\n");
    
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

    void *cs_plugin = panda_get_plugin_by_name("panda_callstack_instr.so");
    if (!cs_plugin) {
        printf("Couldn't load callstack plugin\n");
        return false;
    }
    dlerror();
    get_prog_point = (get_prog_point_t) dlsym(cs_plugin, "get_prog_point");
    char *err = dlerror();
    if (err) {
        printf("Couldn't find get_prog_point function in callstack library.\n");
        printf("Error: %s\n", err);
        return false;
    }

    panda_enable_precise_pc();
    panda_enable_memcb();    
    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {

}
