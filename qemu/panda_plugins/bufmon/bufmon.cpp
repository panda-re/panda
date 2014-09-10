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
#include "../common/prog_point.h"
#include "../callstack_instr/callstack_instr_ext.h"

}

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <list>
#include <fstream>
#include <algorithm>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

struct bufdesc { target_ulong buf; target_ulong size; target_ulong cr3; };

std::list<bufdesc> bufs;
FILE *mem_report;

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write) {
    prog_point p = {};
    get_prog_point(env, &p);

    std::list<bufdesc>::iterator it;
    for(it = bufs.begin(); it != bufs.end(); it++) {
        if (p.cr3 != it->cr3) continue;
        target_ulong buf_first, buf_last;
        buf_first = it->buf;
        buf_last = it->buf + it->size - 1;
        if ((addr <= buf_first && buf_first < addr+size) ||
            (addr <= buf_last && buf_last < addr+size)   ||
            (buf_first <= addr && addr <= buf_last)      || 
            (buf_first <= addr+size && addr+size <= buf_last)) {

            fprintf(mem_report, "%s " TARGET_FMT_lx " " TARGET_FMT_lx " " 
                TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx,
                is_write ? "WRITE" : "READ ",
                p.caller, p.pc, p.cr3, addr, size);
            for (size_t i = 0; i < size; i++) {
                fprintf(mem_report, " %02x", *(((uint8_t *)buf)+i));
            }
            fprintf(mem_report, "\n");
        }
    }
 
    return 1;
}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, true); 
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, false); 
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin bufmon\n");

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    std::ifstream buffile("search_buffers.txt");
    if (!buffile) {
        printf("Couldn't open search_buffers.txt; no buffers to search for. Exiting.\n");
        return false;
    }

    bufdesc b = {};
    while (buffile >> std::hex >> b.buf) {
        buffile >> std::hex >> b.size;
        buffile >> std::hex >> b.cr3;

        printf("Adding buffer [" TARGET_FMT_lx "," TARGET_FMT_lx "), CR3=" TARGET_FMT_lx "\n",
               b.buf, b.buf+b.size, b.cr3);
        bufs.push_back(b);
    }
    buffile.close();

    mem_report = fopen("buffer_taps.txt", "w");
    if(!mem_report) {
        perror("fopen");
        return false;
    }

    if(!init_callstack_instr_api()) return false;

    pcb.virt_mem_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);
    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {

    fclose(mem_report);
}
