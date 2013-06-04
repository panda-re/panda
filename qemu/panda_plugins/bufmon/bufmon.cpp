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

struct match_entry {
    target_ulong caller;
    target_ulong pc;
    target_ulong cr3;
    bool is_write;
    target_ulong start;
    target_ulong size;
    bool operator <(const match_entry &p) const {
        return (this->pc < p.pc) || \
               (this->pc == p.pc && this->caller < p.caller) || \
               (this->pc == p.pc && this->caller == p.caller && this->cr3 < p.cr3);
    }
};

std::list<match_entry> matches;
std::list<bufdesc> bufs;

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write) {
    match_entry p = {};
#ifdef TARGET_I386
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&p.caller, 4, 0);
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = env->cr[3];
#endif
    p.pc = pc;

    std::list<bufdesc>::iterator it;
    for(it = bufs.begin(); it != bufs.end(); it++) {
        if (p.cr3 != it->cr3) continue;
        if ((it->buf >= addr && it->buf < addr+size) ||                       // start byte in range
            (it->buf+it->size-1 >= addr && it->buf+it->size-1 < addr+size)) { // end byte in range
            p.is_write = is_write;
            p.start = addr;
            p.size = size;
            matches.push_back(p);
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

    pcb.virt_mem_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);
    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

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


    return true;
}
void uninit_plugin(void *self) {
    FILE *mem_report = fopen("buffer_taps.txt", "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }
    std::list<match_entry>::iterator it;
    for(it = matches.begin(); it != matches.end(); it++) {
        fprintf(mem_report, "%s " TARGET_FMT_lx " " TARGET_FMT_lx " " 
            TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
            it->is_write ? "WRITE" : "READ ",
            it->caller, it->pc, it->start, it->size, it->cr3
        );
    }
    fclose(mem_report);
}
