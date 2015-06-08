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

#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <set>
#include <iostream>
#include <fstream>


#include "../common/prog_point.h"

#include "pandalog.h"
#include "../callstack_instr/callstack_instr_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int read_mem_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int write_mem_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

uint64_t mem_counter;

std::set<prog_point> tap_points;
gzFile read_tap_buffers;
gzFile write_tap_buffers;

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, gzFile f) {
    prog_point p = {};
    get_prog_point(env, &p);

    if (tap_points.find(p) != tap_points.end()) {
        target_ulong callers[16] = {0};
        int nret = get_callers(callers, 16, env);
        for (unsigned int i = 0; i < size; i++) {
            for (int j = nret-1; j > 0; j--) {
                gzprintf(f, TARGET_FMT_lx " ", callers[j]);
            }
            gzprintf(f, TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx " %ld %02x\n",
                    p.caller, p.pc, p.cr3, addr+i, mem_counter, ((unsigned char *)buf)[i]);
        }
    }
    mem_counter++;

    return 1;
}

int read_mem_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, read_tap_buffers);
}
int write_mem_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf ) {
    return mem_callback(env, pc, addr, size, buf, write_tap_buffers);
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin textprinter\n");
    
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

    write_tap_buffers = gzopen("write_tap_buffers.txt.gz", "w");
    if(!write_tap_buffers) {
        printf("Couldn't open write_tap_buffers.txt for writing. Exiting.\n");
        return false;
    }
    read_tap_buffers = gzopen("read_tap_buffers.txt.gz", "w");
    if(!read_tap_buffers) {
        printf("Couldn't open read_tap_buffers.txt for writing. Exiting.\n");
        return false;
    }

    if(!init_callstack_instr_api()) return false;

    panda_enable_precise_pc();
    panda_enable_memcb();    

    pcb.virt_mem_write = write_mem_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.virt_mem_read = read_mem_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);

    return true;
}

void uninit_plugin(void *self) {
    gzclose(read_tap_buffers);
    gzclose(write_tap_buffers);
}
