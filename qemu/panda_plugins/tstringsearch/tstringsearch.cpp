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

#include "panda/panda_addr.h"
#include "../taint2/taint2.h"

extern "C" {

#include <dlfcn.h>
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "rr_log.h"

#include "../stringsearch/stringsearch.h"
#include "panda_plugin_plugin.h"
#include "panda_common.h"

#include "../taint2/taint2_ext.h"
}

//#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
//#include <map>
//#include <fstream>
//#include <sstream>
//#include <string>

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

uint32_t positional_tainting = 0;

void *plugin_self;

// turn on taint at right instr count
int tstringsearch_enable_taint(CPUState *env, target_ulong pc) {
    // enable taint if close to instruction count
    uint64_t ic = rr_get_guest_instr_count();
    if (!taint2_enabled()) {
        if (ic + 100 > enable_taint_instr_count) {
            printf ("enabling taint at instr count %" PRIu64 "\n", ic);
            taint2_enable_taint();           
        }
    }
    return 0;
}

int tstringsearch_label(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    tstringsearch_enable_taint(env, pc);

    if (tstringsearch_label_on == false) {
        return 0;
    }
    if (pc == the_pc) {
        printf ("\n****************************************************************************\n");
        printf ("applying taint labels to search string of length %d  @ p=0x" TARGET_FMT_lx "\n", the_len, the_buf);
        printf ("******************************************************************************\n");
        // label that buffer 
        int i;
        for (i=0; i<the_len; i++) {
            target_ulong va = the_buf + i;
            target_phys_addr_t pa = cpu_get_phys_addr(cpu_single_env, va);
            if (pa != (target_phys_addr_t) -1) {
                if (positional_tainting) {
                    taint2_label_ram(pa, i);
                }
                else {
                    taint2_label_ram(pa, 10);
                }
            }
        }
        tstringsearch_label_on = false;
    }
    return 0;
}

bool first_time = true;

// this is called from stringsearch upon a match
void tstringsearch_match(CPUState *env, target_ulong pc, target_ulong addr,
        uint8_t *matched_string, uint32_t matched_string_length, 
        bool is_write) {

    // determine if the search string is sitting in memory, starting at addr - (strlen-1)
    // first, grab that string out of memory
    target_ulong p = addr - (matched_string_length-1);
    uint8_t thestring[MAX_STRLEN*2];
    panda_virtual_memory_rw(env, p, thestring, matched_string_length, 0);
    printf ("tstringsearch: thestring = [");
    for (unsigned i=0; i<matched_string_length; i++) {
        if (isprint(thestring[i])) {
            printf("%c", thestring[i]);
        }
        else {
            printf(".");
        }
    }
    printf ("]\ntstringsearch: ");
    for (unsigned i=0; i<matched_string_length; i++) {
        printf ("%02x ", thestring[i]);
    }
    printf ("\n");

    // now compare it to the search string
    // NOTE: this is a write, so the final byte of the string hasn't yet been
    // written to memory since write callback is at start of fn.
    // thus, the matched_string_length - 1.
    // yes, we can get this right. but, meh.
    if ((memcmp((char *)thestring, (char *)matched_string, matched_string_length-1)) == 0) {
        printf ("tstringsearch: string in memory @ 0x%lx\n", (long unsigned int) p);    
        // ok this is ugly.  save pc, buffer addr and len
        the_pc = pc;
        the_buf = p;
        the_len = matched_string_length;
        // this should enable
        tstringsearch_label_on = true;    

        if (first_time) {
            first_time = false;
            // add a callback for taint processor st 
            panda_cb pcb;
            pcb.phys_mem_read = tstringsearch_label;
            panda_register_callback(plugin_self, PANDA_CB_PHYS_MEM_READ, pcb);
            pcb.phys_mem_write = tstringsearch_label;
            panda_register_callback(plugin_self, PANDA_CB_PHYS_MEM_WRITE, pcb);
        }
    }
}

bool labeled = false;

#endif

bool init_plugin(void *self) {
    printf ("Initializing tstringsearch\n");

    plugin_self = self;

    panda_require("stringsearch");
    panda_require("taint2");

#ifdef CONFIG_SOFTMMU

    panda_arg_list *args;
    args = panda_get_args("tstringsearch");
    enable_taint_instr_count = panda_parse_uint64(args, "instr_count", 0);
    positional_tainting = panda_parse_bool(args, "pos");

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
