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

#include "panda/plugin.h"
#include "panda/rr/rr_log.h"

#include <stdio.h>

bool dump_done = false;

static bool should_close_after_dump = true;
static double percent = -1;
static uint64_t instr_count = 0;
static const char *filename = NULL;

bool init_plugin(void *);
void uninit_plugin(void *);
int before_block_exec(CPUState *env, TranslationBlock *tb);
void dump_memory(void);

void dump_memory(void){
    FILE* out = fopen(filename, "wb");
    panda_memsavep(out);
    fclose(out);
    dump_done = true;

    if(should_close_after_dump)
        rr_end_replay_requested = 1;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (dump_done) return 0;

    if (instr_count && rr_get_guest_instr_count() > instr_count) {
        printf("memsavep: Instruction count reached, saving memory to %s.\n", filename);
        dump_memory();
    } else if (rr_get_percentage() > percent) {
        printf("memsavep: Replay percentage reached, saving memory to %s.\n", filename);
        dump_memory();
    }

    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_arg_list *args = panda_get_args("memsavep");
    percent = panda_parse_double_opt(args, "percent", 200, "dump memory after a given percentage of the replay is reached");
    instr_count = panda_parse_uint64_opt(args, "instrcount", 0, "dump memory after a given instruction count is reached");
    filename = panda_parse_string_opt(args, "file", "memsavep.raw", "filename of the memory dump to create");

    if(!instr_count && percent > 100.0){
        printf("memsavep: You should specify either one of percent or instrcount");
        return false;
    }

    return true;
}

void uninit_plugin(void *self) {

}