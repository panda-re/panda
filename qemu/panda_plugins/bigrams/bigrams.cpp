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

#include "../callstack_instr/callstack_instr_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

uint64_t bytes_read, bytes_written;
uint64_t num_reads, num_writes;

struct text_counter {
    bool started;
    int num_bytes;
    unsigned char prev_char;
    std::map<unsigned short,unsigned int> hist;
};

std::map<prog_point,text_counter> text_tracker;
//FILE *text_memlog;

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    bytes_written += size;
    num_writes++;
    prog_point p = {};

    get_prog_point(env, &p);

    text_counter &tc = text_tracker[p];    

    for (unsigned int i = 0; i < size; i++) {
        unsigned char val = ((unsigned char *)buf)[i];
        //fprintf(text_memlog, TARGET_FMT_lx "." TARGET_FMT_lx " " TARGET_FMT_lx " %02x\n" , p.pc, p.caller, addr+i, val);
        if (!tc.started) {
            tc.prev_char = val;
            tc.started = true;
        } 
        else {
            unsigned short bigram;
            bigram = (tc.prev_char << 8) | val;
            tc.hist[bigram]++;
            tc.prev_char = val;
        }
        tc.num_bytes++;
    }
 
    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin bigrams\n");

    if (!init_callstack_instr_api()) return false;

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

    //text_memlog = fopen("text_memlog.txt", "w");

    return true;
}

void uninit_plugin(void *self) {
    printf("Memory statistics: %lu stores, %lu bytes written.\n",
        num_writes, bytes_written
    );

    FILE *mem_report = fopen("bigram_mem_report.bin", "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }

    // Cross platform support: need to know how big a target_ulong is
    uint32_t target_ulong_size = sizeof(target_ulong);
    fwrite(&target_ulong_size, sizeof(uint32_t), 1, mem_report);

    std::map<prog_point,text_counter>::iterator it;
    for(it = text_tracker.begin(); it != text_tracker.end(); it++) {
        // Skip low-data entries
        if (it->second.num_bytes < 80) continue;

        unsigned int hist_keys = 0;
        hist_keys = it->second.hist.size();

        // Write the program point
        fwrite(&it->first, sizeof(prog_point), 1, mem_report);

        // Write the number of keys
        fwrite(&hist_keys, sizeof(hist_keys), 1, mem_report);
        
        // Write each key/value of the (hopefully sparse) histogram
        std::map<unsigned short,unsigned int>::iterator it2;
        for(it2 = it->second.hist.begin(); it2 != it->second.hist.end(); it2++) {
            fwrite(&it2->first, sizeof(it2->first), 1, mem_report);   // Key: unsigned short
            fwrite(&it2->second, sizeof(it2->second), 1, mem_report); // Value: unsigned int
        }
        //printf("Wrote histogram with %d entries (%ld bytes)\n", 
        //    hist_keys, (sizeof(unsigned short)+sizeof(unsigned long))*hist_keys + sizeof(prog_point) + sizeof(hist_keys));
    }
    fclose(mem_report);
    
    //fclose(text_memlog);
}
