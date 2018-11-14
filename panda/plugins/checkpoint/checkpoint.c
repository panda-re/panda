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
 * PANDAENDCOMMENT */

#include "panda/plugin.h"
#include "panda/rr/rr_log.h"
#include "panda/checkpoint.h"

uint64_t checkpoint_instr_size;

bool init_plugin(void *);
void uninit_plugin(void *);

bool before_block_exec(CPUState *env, TranslationBlock *tb);
void after_init(CPUState *env);

bool before_block_exec(CPUState *env, TranslationBlock *tb) {
    static int progress = 0;

    if (progress == 0 || rr_get_guest_instr_count()/checkpoint_instr_size > progress) {
        progress++;
        printf("Taking panda checkpoint %u... at %lu\n", progress, rr_get_guest_instr_count());
        panda_checkpoint();
        printf("Done.\n");
    }

    // If this found tb could contain a breakpoint or watchpoint that is set for some instruction count,
    // invalidate it and retranslate, so that a debug instruction is emitted for this tb
    CPUBreakpoint* bp;
    if (unlikely(!QTAILQ_EMPTY(&env->breakpoints))) {
        QTAILQ_FOREACH(bp, &env->breakpoints, entry) {
            if ((bp->rr_instr_count != 0 && rr_get_guest_instr_count() <= bp->rr_instr_count && bp->rr_instr_count < rr_get_guest_instr_count()+tb->icount) ||
                   (bp->pc != 0 && tb->pc <= bp->pc && bp->pc < tb->pc+tb->size)) {
                return true;
            };
        }
    }

    return false;
}

void after_init(CPUState* env) {
    panda_arg_list *args = panda_get_args("checkpoint");

    const char* avail_space = panda_parse_string_opt(args, "space", "6G", "Available disk/RAM space for storing checkpoints");
    uint64_t space_bytes;
    parse_option_size("space", avail_space, &space_bytes, NULL );

    // Get approx size of each checkpoint
    printf("Avail space %lx, ram_size %lx\n", space_bytes, ram_size);
    if (space_bytes < ram_size){
        fprintf(stderr, "Not enough RAM for a checkpoint!\n");
        abort();
    }
    uint64_t num_checkpoints = space_bytes/ram_size;
    printf("Number of checkpoints allowed:  %lu\n", num_checkpoints);
    checkpoint_instr_size = rr_nondet_log->last_prog_point.guest_instr_count/num_checkpoints;
    if (checkpoint_instr_size < 500000)
        checkpoint_instr_size = 500000;

    printf("Instructions per checkpoint: %lu\n", checkpoint_instr_size);

}

bool init_plugin(void *self) {

    panda_cb pcb;
    pcb.before_block_exec_invalidate_opt = before_block_exec ;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
    pcb.after_machine_init = after_init;
    panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);

    return true;
}

void uninit_plugin(void *self) { }
