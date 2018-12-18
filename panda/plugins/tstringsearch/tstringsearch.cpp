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
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
}

#include "panda/plugin.h"
#include "taint2/taint2.h"
#include "stringsearch/stringsearch.h"

extern "C" {   
#include "taint2/taint2_ext.h"
}

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

#ifdef CONFIG_SOFTMMU

bool tstringsearch_label_on = true;

target_ulong the_pc;
target_ulong the_buf;
int the_len; 
uint32_t old_amt_ram_tainted;

uint64_t enable_taint_instr_count = 0;

bool positional_tainting = false;
bool only_first = false;
bool done_labeling = false;

void *plugin_self;

// turn on taint at right instr count
int tstringsearch_enable_taint(CPUState *env, target_ulong pc) {
    // enable taint if close to instruction count
    uint64_t ic = rr_get_guest_instr_count();
    if (!taint2_enabled()) {
        if (ic + 100 > enable_taint_instr_count) {
            tstringsearch_label_on = true;
            printf ("enabling taint at instr count %" PRIu64 "\n", ic);
            taint2_enable_taint();           
        }
    }
    return 0;
}

bool first_time = true;

// this is called from stringsearch upon a match
void tstringsearch_match(CPUState *env, target_ulong pc, target_ulong addr,
                         uint8_t *matched_string,
                         uint32_t matched_string_length, bool is_write,
                         bool in_memory)
{
    if (!in_memory) {
        printf("tstringsearch: match not in memory - not applying taint\n");
        return;
    }

    tstringsearch_enable_taint(env, pc);

    if (((only_first && first_time) || !only_first) && tstringsearch_label_on) {
        printf("\n*************************************************************"
               "***************\n");
        printf("applying taint labels to search string of length %d  @ "
               "p=0x" TARGET_FMT_lx "\n",
               matched_string_length, addr);
        printf("***************************************************************"
               "*************\n");

        uint8_t *buf =
            (uint8_t *)calloc(matched_string_length + 1, sizeof(*buf));
        panda_virtual_memory_read(env, addr, buf, matched_string_length);
        printf("tstringsearch: ascii = [");
        for (int i = 0; i < matched_string_length; i++) {
            if (isprint(buf[i])) {
                printf("%c", buf[i]);
            } else {
                printf(".");
            }
        }
        printf("]\n");
        printf("tstringsearch: hex = ");
        for (int i = 0; i < matched_string_length; i++) {
                printf("%X ", buf[i]);
        }
        printf("\n");
        free(buf);

        for (int i = 0; i < matched_string_length; i++) {
            hwaddr pa = panda_virt_to_phys(env, addr + i);
            if (positional_tainting) {
                taint2_label_ram(pa, i);
            } else {
                taint2_label_ram(pa, 10);
            }
        }
        first_time = false;
    }
}

#endif

bool init_plugin(void *self) {
    plugin_self = self;

    panda_require("stringsearch");
    panda_require("taint2");

#ifdef CONFIG_SOFTMMU

    panda_arg_list *args;

    args = panda_get_args("tstringsearch");    
    positional_tainting = panda_parse_bool_opt(args, "pos", "positional taint");
    only_first = panda_parse_bool_opt(args, "only_first", "only label first match");

    args = panda_get_args("general");
    enable_taint_instr_count = 
        panda_parse_uint64_opt(args, "first_instr", 0, 
                               "enable taint at this instruction");

    // this sets up the taint api fn ptrs so we have access
    assert(init_taint2_api());

    // register the tstringsearch_match fn to be called at the on_ssm site within panda_stringsearch
    PPP_REG_CB("stringsearch", on_ssm, tstringsearch_match) ;

    return true;
#else
    fprintf(stderr, "tstringsearch: plugin does not support linux-user mode\n");
    return false;
#endif
}


void uninit_plugin(void *self) {
}
