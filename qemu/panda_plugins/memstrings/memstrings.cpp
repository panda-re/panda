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

#include <wctype.h>
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

struct ustring_pos {
    int nch;
    uint16_t ch[MAX_STRLEN];
};

std::map<target_ulong,string_pos> read_text_tracker;
std::map<target_ulong,string_pos> write_text_tracker;
std::map<target_ulong,ustring_pos> read_utext_tracker;
std::map<target_ulong,ustring_pos> write_utext_tracker;

gzFile mem_report = NULL;
int min_strlen;

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write) {

    string_pos &sp = is_write ? write_text_tracker[pc] : read_text_tracker[pc];
    ustring_pos &usp = is_write ? write_utext_tracker[pc] : read_utext_tracker[pc];

    // ASCII
    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];
        if (isprint(val)) {
            sp.ch[sp.nch++] = val;
            // If we max out the string, chop it
            if (sp.nch == MAX_STRLEN - 1) {
                gzprintf(mem_report, "%llu:%.*s\n", rr_get_guest_instr_count(), sp.nch, sp.ch);
                sp.nch = 0;
            }
        }
        else {
            // Don't bother with strings shorter than min
            if (sp.nch >= min_strlen) {
                gzprintf(mem_report, "%llu:%.*s\n", rr_get_guest_instr_count(), sp.nch, sp.ch);
            }
            sp.nch = 0;
        }
    }

    // Don't consider one-byte reads/writes for UTF-16
    if (size < 2) {
        return 1;
    }

    // UTF-16-LE
    for (unsigned int i = 0; i < size; i+=2) {
        uint8_t vall = ((uint8_t *)buf)[i];
        uint8_t valh = ((uint8_t *)buf)[i+1];
        uint16_t val = (valh << 8) | vall;
        if (iswprint(val)) {
            usp.ch[usp.nch++] = val;
            // If we max out the string, chop it
            if (usp.nch == MAX_STRLEN - 1) {
                gsize bytes_written = 0;
                gchar *out_str = g_convert((gchar *)usp.ch, usp.nch*2,
                    "UTF-8", "UTF-16LE", NULL, &bytes_written, NULL);
                gzprintf(mem_report, "%llu:%s\n", rr_get_guest_instr_count(), out_str);
                g_free(out_str);
                usp.nch = 0;
            }
        }
        else {
            // Don't bother with strings shorter than min
            if (usp.nch >= min_strlen) {
                gsize bytes_written = 0;
                gchar *out_str = g_convert((gchar *)usp.ch, usp.nch*2,
                    "UTF-8", "UTF-16LE", NULL, &bytes_written, NULL);
                gzprintf(mem_report, "%llu:%s\n", rr_get_guest_instr_count(), out_str);
                g_free(out_str);
            }
            usp.nch = 0;
        }
    }

    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, false);

}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, true);
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
    for (auto &kvp : read_text_tracker) {
        if (kvp.second.nch > min_strlen) {
            gzprintf(mem_report, "%llu:%.*s\n", rr_get_guest_instr_count(), kvp.second.nch, kvp.second.ch);
        }
    }
    for (auto &kvp : write_text_tracker) {
        if (kvp.second.nch > min_strlen) {
            gzprintf(mem_report, "%llu:%.*s\n", rr_get_guest_instr_count(), kvp.second.nch, kvp.second.ch);
        }
    }
    for (auto &kvp : read_utext_tracker) {
        if (kvp.second.nch > min_strlen) {
            gsize bytes_written = 0;
            gchar *out_str = g_convert((gchar *)kvp.second.ch, kvp.second.nch*2,
                "UTF-8", "UTF-16LE", NULL, &bytes_written, NULL);
            gzprintf(mem_report, "%llu:%s\n", rr_get_guest_instr_count(), out_str);
            g_free(out_str);
        }
    }
    for (auto &kvp : write_utext_tracker) {
        if (kvp.second.nch > min_strlen) {
            gsize bytes_written = 0;
            gchar *out_str = g_convert((gchar *)kvp.second.ch, kvp.second.nch*2,
                "UTF-8", "UTF-16LE", NULL, &bytes_written, NULL);
            gzprintf(mem_report, "%llu:%s\n", rr_get_guest_instr_count(), out_str);
            g_free(out_str);
        }
    }

    gzclose(mem_report);
}
