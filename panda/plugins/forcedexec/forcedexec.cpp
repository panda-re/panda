/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Andrew Fasano          fasano@mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "panda/tcg-utils.h"

extern "C" {
#include "forcedexec_int_fns.h"
#include "panda/panda_api.h"
}

extern "C" {
  bool init_plugin(void *);
  void uninit_plugin(void *);
  PPP_PROT_REG_CB(on_branch);
}

// Handle to self
void* self = NULL;
panda_cb tcg_cb;

PPP_CB_BOILERPLATE(on_branch);

void tcg_parse(CPUState *env, TranslationBlock *tb, TCGContext *s) {
    // Called after we generated a TCG block but before it's lowered to host ISA

    // If the block contains a branch, call out
    // PPP("forcedexec", "should_flip") which gets the TB details.
    // If that returns true, flip it

    // Ignore kernel mode or kernel addresses
    if (panda_in_kernel(env) || tb->pc > 0xc0000000) {
    return;
    }

    // Iterate oi until it's last instruction in block
    TCGOp *op;
    int oi;

    // For each branch in the block - consider flipping it
    size_t idx = 0;
    for (oi = s->gen_op_buf[0].next; oi != 0; oi = op->next) {
        op = &s->gen_op_buf[oi];
        TCGOpcode c = op->opc;
        TCGArg *args;

        if (c == INDEX_op_brcond_i32 || c == INDEX_op_brcond_i64 ||
                                        c == INDEX_op_brcond2_i32) {
                IF_PPP_RUN_BOOL_CB(on_branch, env, tb, idx) {
                    args = &s->gen_opparam_buf[op->args];
                    // All the brcond cases in tcg/ppc/tcg-target-inc.c
                    // and tcg/arm/tcg-target.inc.c put the cond in args[2]
                    args[2] = tcg_invert_cond((TCGCond) args[2]);
                }
        }
        idx++;
    };
}

void enable_forcedexec() {
    assert(self != NULL);
    panda_enable_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, tcg_cb);
    panda_flush_tb();
}

void disable_forcedexec() {
    assert(self != NULL);
    panda_disable_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, tcg_cb);
    panda_flush_tb(); // Really we only need to flush blocks we flipped-
                      // we could track that and then optimize this.
}


bool init_plugin(void *_self) {
    self = _self;

    panda_arg_list *args = panda_get_args("forcedexec");

    bool disabled;
    disabled = panda_parse_bool_opt(args, "disabled", "disable at load");

    tcg_cb.before_tcg_codegen = tcg_parse;
    panda_register_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, tcg_cb);

    if (disabled) {
        disable_forcedexec();
    }

    return true;
}

void uninit_plugin(void *self) { }
