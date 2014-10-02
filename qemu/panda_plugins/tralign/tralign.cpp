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


#include "panda_common.h"

#include "../bir/index.hpp"


extern "C" {

#include <math.h>
#include <dlfcn.h>
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "../bir/bir_ext.h"
#include "rr_log.h"
#include "rr_log_all.h"
#include "panda_plugin_plugin.h"
    
    bool init_plugin(void *);
    void uninit_plugin(void *);

}


#ifdef CONFIG_SOFTMMU


// alignment will be with respect to this many blocks.  
// 0 means every bb is indexed individually
uint32_t numblocks = 0;

// n grams
uint32_t min_n = 1;
uint32_t max_n = 3;

uint64_t total_instr = 0;

char *traceind_pfx = NULL;

// current block
uint32_t block_num = 0;

uint8_t *buffer = NULL;
uint32_t buffer_len = 0;
uint32_t buffer_max = 0;

void *ind;
void *indc;

uint32_t bb_counter = 0;

uint64_t instr_this_block = 0;
uint64_t instr_this_block_indexed = 0;
uint64_t instr_per_block = 0;


        
bool pdice (float prob_yes) {
    if ((((float) (rand ())) / RAND_MAX) < prob_yes)
        return true;
    else
        return false;
}


float pincludebb = 0.01;


uint64_t total_bb = 0;

int tralign_before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (tb->size > 16) {
        total_bb ++;
        if (!rr_in_replay()) {
            return 0;
        }
        // grab current bb code
        if (tb->size > buffer_max) {
            while (tb->size > buffer_max) {
                buffer_max *= 2;
            }
            printf ("increased buffer_max to %d\n", buffer_max);
            buffer = (uint8_t *) realloc(buffer, buffer_max);
        }
        panda_virtual_memory_rw(env, tb->pc, buffer, tb->size, 0);
        // index it        
        index_this_passage_c(indc, ind, buffer, tb->size, block_num);
    }
    block_num ++;
  
    return 0;
}


#endif

bool init_plugin(void *self) {    

    bool x = init_bir_api();
    assert (x == true);

#ifdef CONFIG_SOFTMMU
    panda_arg_list *args = panda_get_args("tralign");
    if (args != NULL) {
        int i;
        for (i = 0; i < args->nargs; i++) {
            if (0 == strncmp(args->list[i].key, "numblocks", 9)) {
                numblocks = atoi(args->list[i].value);
                printf ("numblocks = %d\n", numblocks);
            }
            if (0 == strncmp(args->list[i].key, "min_n", 5)) {
                min_n = atoi(args->list[i].value);
            }
            if (0 == strncmp(args->list[i].key, "max_n", 5)) {
                max_n = atoi(args->list[i].value);
            }
            if (0 == strncmp(args->list[i].key, "traceind_pfx", 13)) {
                traceind_pfx = args->list[i].value;
            }
            if (0 == strncmp(args->list[i].key, "pincludebb", 10)) {
                pincludebb = atof(args->list[i].value);
                printf ("prob of incl a bb in trinv is %.5f\n", pincludebb);
            }
        }
    }
    if (traceind_pfx == NULL) {
        traceind_pfx = strdup("/tmp/trinv");
    }
    printf ("tralign n=%d,%d traceind_pfx=%s\n", min_n, max_n, traceind_pfx);
    printf ("numblocks = %d pincludebb=%.6f\n", numblocks, pincludebb);
    panda_cb pcb;
    pcb.before_block_exec = tralign_before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    buffer_max = 1024;
    buffer = (uint8_t *) malloc(buffer_max);
    indc = new_index_common_c(traceind_pfx, min_n, max_n, 100);    
    ind = new_index_c();
    return true;

#endif

    return false;
}



void uninit_plugin(void *self) {
#ifdef CONFIG_SOFTMMU
    printf ("total bb = %lu\n", total_bb);
    printf ("marshalling index common\n");
    marshall_index_common_c(indc);
    printf ("marshalling index\n");
    marshall_index_c(indc, ind, traceind_pfx);
    printf ("inverting\n");
    void *inv = invert_c(indc, ind);
    printf ("marshalling inv index\n");  
    marshall_invindex_c(indc, inv, traceind_pfx);

#endif
}
