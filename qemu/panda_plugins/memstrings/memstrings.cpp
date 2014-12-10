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
#include "rr_log.h"
}

#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <map>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

#define MAX_STRLEN 256

struct string_pos {
    int nch;
    uint8_t ch[MAX_STRLEN];
};

std::map<target_ulong,string_pos> read_text_tracker;
std::map<target_ulong,string_pos> write_text_tracker;

gzFile mem_report = NULL;
int min_strlen;

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write,
                       std::map<target_ulong,string_pos> &text_tracker) {

    string_pos &sp = text_tracker[pc];

    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];
        if (isprint(val)) {
            sp.ch[sp.nch++] = val;
            // If we max out the string, chop it
            if (sp.nch == MAX_STRLEN - 1) {
                gzprintf(mem_report, "%.*s\n", sp.nch, sp.ch);
                sp.nch = 0;
            }
        }
        else {
            // Don't bother with strings shorter than min
            if (sp.nch >= min_strlen) {
                gzprintf(mem_report, "%.*s\n", sp.nch, sp.ch);
            }
            sp.nch = 0;
        }
    }
 
    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, false, read_text_tracker);

}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, true, write_text_tracker);
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin memstrings\n");

    panda_arg_list *args = panda_get_args("memstrings");

    const char *prefix = panda_parse_string(args, "name", "memstrings");
    min_strlen = panda_parse_ulong(args, "len", 4);

    char matchfile[128] = {};
    sprintf(matchfile, "%s_strings.txt.gz", prefix);
    mem_report = gzopen(matchfile, "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return false;
    }

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.virt_mem_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);

    return true;
}

void uninit_plugin(void *self) {
    // Save any that we haven't flushed yet
    for (auto &kvp : read_text_tracker)
        if (kvp.second.nch > min_strlen)
            gzprintf(mem_report, "%.*s\n", kvp.second.nch, kvp.second.ch);
    for (auto &kvp : write_text_tracker)
        if (kvp.second.nch > min_strlen)
            gzprintf(mem_report, "%.*s\n", kvp.second.nch, kvp.second.ch);
    gzclose(mem_report);
}
