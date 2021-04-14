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
#include "panda/rr/rr_api.h"

#include <stdio.h>

bool dump_done = false;

static bool should_close_after_dump = true;
static double percent = -1;
static uint64_t instr_count = 0;
static const char *filename = NULL;
static const char* register_filename = NULL;
static uint64_t pmem_len = 0;

bool init_plugin(void *);
void uninit_plugin(void *);
void before_block_exec(CPUState *env, TranslationBlock *tb);
void dump_memory(void);

static const uint8_t _zero_block[1024] = {0};
static void actually_dump_physical_memory(FILE* out, size_t len)
{
    hwaddr addr = 0;
    uint8_t block[sizeof(_zero_block)];

    if (!out)
        return;

    while (len != 0)
    {
        size_t l = sizeof(block);
        if (l > len)
            l = len;
        if (panda_physical_memory_rw(addr, block, l, false) == MEMTX_OK)
            fwrite(block, 1, l, out);
        else
            fwrite(_zero_block, 1, l, out);
        addr += l;
        len -= l;
    }
}

void dump_memory(void){
    FILE* out = fopen(filename, "wb");
    actually_dump_physical_memory(out, pmem_len);
    fclose(out);
    if (register_filename)
    {
        if ((out = fopen(register_filename, "w")) != NULL)
        {
            CPUState* cpu;
            CPU_FOREACH(cpu)
            {
                fprintf(out, "CPU#%d\n", cpu->cpu_index);
                cpu_dump_state(cpu, out, fprintf, CPU_DUMP_FPU);
            }
            fclose(out);
        }
    }
    dump_done = true;

    if(should_close_after_dump)
        panda_replay_end();
}

void before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (dump_done) return;

    if (instr_count && rr_get_guest_instr_count() > instr_count) {
        printf("memsavep: Instruction count reached, saving memory to %s.\n", filename);
        dump_memory();
    } else if (rr_get_percentage() > percent) {
        printf("memsavep: Replay percentage reached, saving memory to %s.\n", filename);
        dump_memory();
    }

    return;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_arg_list *args = panda_get_args("memsavep");
    percent = panda_parse_double_opt(args, "percent", 200, "dump memory after a given percentage of the replay is reached");
    instr_count = panda_parse_uint64_opt(args, "instrcount", 0, "dump memory after a given instruction count is reached");
    filename = panda_parse_string_opt(args, "file", "memsavep.raw", "filename of the memory dump to create");
    register_filename = panda_parse_string_opt(args, "regfile", NULL, "filename of the register file to create");
    pmem_len = panda_parse_uint64_opt(args, "size", ram_size, "number of bytes of physical memory");

    if(!instr_count && percent > 100.0){
        printf("memsavep: You should specify either one of percent or instrcount");
        return false;
    }

    return true;
}

void uninit_plugin(void *self) {

}
