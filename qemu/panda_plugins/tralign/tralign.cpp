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



// n grams
uint32_t min_n = 1;
uint32_t max_n = 3;

uint64_t total_instr = 0;

char *traceind_pfx = NULL;

// current block
uint64_t block_num = 0;

uint8_t *buffer = NULL;
uint32_t buffer_len = 0;
uint32_t buffer_max = 0;

// one index per cr3
std::map < uint64_t, void * > ind;
std::map < uint64_t, void * > indc;


uint64_t instr_this_block = 0;
uint64_t instr_this_block_indexed = 0;
uint64_t instr_per_block = 0;



// write physmem to a file
// and invoke volatility on it
void vol(char *outfilename) {
    printf ("vol %s\n", outfilename);
    std::string pmf = (std::string(outfilename)) + ".pmem";
    FILE *fp = fopen((char *) pmf.c_str(), "w");
    panda_memsavep(fp);
    fclose(fp);
    std::string cmd = "/usr/bin/volatility -f " + pmf + " --profile=Linux_Debian_Wheezy_3_2_0-4-686-pae_x86 linux_pslist";
    fp = popen(cmd.c_str(), "r");
    FILE *fp2 = fopen(outfilename, "w");
    char line[4096];
    while (fgets(line, sizeof(line)-1, fp) != NULL) {
        fprintf(fp2, "%s", line);
    }
    fclose(fp2);
    printf ("...done\n");
}
 
    
    
    
        
bool pdice (float prob_yes) {
    if ((((float) (rand ())) / RAND_MAX) < prob_yes)
        return true;
    else
        return false;
}





uint64_t total_bb = 0;


std::map < uint64_t, uint64_t > trace_bb_num_to_guest_instr_count;


int tralign_before_block_exec(CPUState *env, TranslationBlock *tb) {
    uint64_t cr3 = panda_current_asid(env);

    if (indc.count(cr3) == 0) {
        std::string pfx = std::string(traceind_pfx) + "-" + std::to_string(cr3);
        indc[cr3] = new_index_common_c((char *) pfx.c_str(), min_n, max_n, 100);    
        ind[cr3] = new_index_c();
    }
    if (tb->size > 16) {
        total_bb ++;
        /*
        if ((total_bb % 100000) == 0) {
            std::string fn = "/data/laredo/tleek/vo-" + (std::to_string(rr_get_guest_instr_count()));
            vol((char *) fn.c_str());
        }
        return 0;
        */
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
        index_this_passage_c(indc[cr3], ind[cr3], buffer, tb->size, block_num);
        // maintain mapping from trace basic block number back to where in 
        trace_bb_num_to_guest_instr_count [block_num] = rr_get_guest_instr_count();
        block_num ++;
    }
    //    if ((block_num % 100000) == 0) {
    //        printf ("block_num = %lu\n", block_num);
    //    }
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
            if (0 == strncmp(args->list[i].key, "min_n", 5)) {
                min_n = atoi(args->list[i].value);
            }
            if (0 == strncmp(args->list[i].key, "max_n", 5)) {
                max_n = atoi(args->list[i].value);
            }
            if (0 == strncmp(args->list[i].key, "traceind_pfx", 13)) {
                traceind_pfx = args->list[i].value;
            }
        }
    }
    if (traceind_pfx == NULL) {
        traceind_pfx = strdup("/tmp/trinv");
    }
    printf ("tralign n=%d,%d traceind_pfx=%s\n", min_n, max_n, traceind_pfx);
    panda_cb pcb;
    pcb.before_block_exec = tralign_before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    buffer_max = 1024;
    buffer = (uint8_t *) malloc(buffer_max);
    //    indc = new_index_common_c(traceind_pfx, min_n, max_n, 100);    
    //    ind = new_index_c();
    return true;

#endif

    return false;
}




void marshall_uint64_uint64_map(std::string filename, std::map < uint64_t, uint64_t > &uumap) {
    FILE *fp = fopen ((char *) filename.c_str(), "w");
    uint64_t occ = uumap.size();
    WU(occ);
    for ( auto &kvp : uumap ) {
        WU(kvp.first);
        WU(kvp.second);
    }
    fclose(fp);
}




void uninit_plugin(void *self) {
#ifdef CONFIG_SOFTMMU
    uint32_t n = ind.size();
    printf ("found %d cr3s\n", ind.size());
    std::string fn = std::string(traceind_pfx) + ".cr3";
    FILE *fp = fopen(fn.c_str(), "w");
    fwrite ((void *) &n, sizeof(n), 1, fp);
    for ( auto &kvp : ind ) {
        uint64_t cr3 = kvp.first;
        fwrite((void *) &cr3, sizeof(cr3), 1, fp);
        printf ("cr3=0x%lx\n", cr3);
        Index *i = reinterpret_cast<Index *> (kvp.second);
        IndexCommon *ic = reinterpret_cast<IndexCommon *> (indc[cr3]);
        printf ("marshalling index common\n");
        marshall_index_common_c(ic);
        printf ("marshalling index\n");
        marshall_index_c(ic, i, traceind_pfx);
        printf ("inverting\n");
        void *inv = invert_c(ic, i);
        printf ("marshalling inv index\n");  
        marshall_invindex_c(ic, inv, traceind_pfx);
    }
    fclose(fp);
    std::string filename = (std::string(traceind_pfx)) + ".tr2rr";
    marshall_uint64_uint64_map(filename, trace_bb_num_to_guest_instr_count);
#endif
}
