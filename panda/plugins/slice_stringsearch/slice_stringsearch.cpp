
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <iostream>
#include <fstream>
#include <sstream>

extern "C" {   
#include "panda/plugin.h"   
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
}

#include "stringsearch/stringsearch.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

using namespace std;

bool wrote_one = false;

OsiModule* lookup_libname(target_ulong curpc, GArray* ms){
    for (int i = 0; i < ms->len; i++){
        OsiModule *mod = &g_array_index(ms, OsiModule, i);

        if (curpc >= mod->base && curpc <= mod->base + mod->size){
            //we've found the module this belongs to
            //return name of module
            return mod;
        }
    }
    return NULL;
}


void stringsearch_match(CPUState *env, target_ulong pc, target_ulong addr,
        uint8_t *matched_string, uint32_t matched_string_length, 
        bool is_write, bool in_memory) {

    if (!in_memory) {
        fprintf(stderr, "Stringsearch match not in memory\n");
        return;
    }

    if (wrote_one) {
        return;
    }

    std::ofstream crit_file("criteria", std::ios::app);
    if (!crit_file.is_open()) {
            std::cout << "Error: stringsearch_match could not open crit_file!" << std::endl;
            exit(1);
    }           
    OsiModule* lib = NULL;

    OsiProc *current = get_current_process(env);
    // printf("proc name %s\n", current->name);
    GArray *ms = get_libraries(env, current);
        
    target_ulong curpc = panda_current_pc(env);

    if (ms == NULL) {
        lib = NULL;
    } else {
        lib = lookup_libname(curpc, ms);
        if (lib != NULL) {
            printf("Stringsearch lib_name %s\n", lib->name);
            crit_file << "VMA:" << lib->name << endl;
        }

        if (crit_file.bad()) {
           cout << "Writing to file failed" << endl;
           exit(1);
        }
    }

    printf("PC: " TARGET_FMT_lx "\n", pc);
    printf("Addr: " TARGET_FMT_lx "\n", addr);

    printf("Adding range " TARGET_FMT_lx "-" TARGET_FMT_lx " to slice\n", addr, addr+matched_string_length);
    crit_file << hex << "MEM_" << addr << "-" << addr+matched_string_length << endl;

    // Add rr_end for this match 
    crit_file << dec << "rr_end:" << rr_get_guest_instr_count() << endl;

    uint64_t curr_instr = rr_get_guest_instr_count();
    printf("Curr instr %lu\n", curr_instr);

    crit_file.close();

    wrote_one = true;
}


bool init_plugin(void *self) {
    panda_require("stringsearch");
    panda_require("osi");
    if(!init_osi_api()) return false;

    std::ofstream crit_file("criteria", std::ios::trunc);
    crit_file.close();

    // panda_arg_list *args;  

    // args = panda_get_args("stringsearch");    

    // register the stringsearch_match fn to be called at the on_ssm site within panda_stringsearch
    PPP_REG_CB("stringsearch", on_ssm, stringsearch_match);

    // OsiModule* lib = NULL;

    return true;
 
}


void uninit_plugin(void *self) {

}
