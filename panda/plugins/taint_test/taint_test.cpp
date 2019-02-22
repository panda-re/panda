
#include <iostream>
#include <fstream>
#include <sstream>

extern "C" {   
#include "panda/plugin.h"   
#include "panda/tcg-llvm.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "taint2/taint2_ext.h"
}

#include "taint2/taint2.h"
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"
#include "panda/rr/rr_log.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

bool before_block_exec(CPUState *env, TranslationBlock *tb);

// turn on taint at right instr count
int tainttest_enable_taint(CPUState *env, target_ulong pc) {
    // enable taint if close to instruction count
    if (!taint2_enabled()) {
        printf("enabling taint at pc " TARGET_FMT_lx " instr %lu\n", pc, rr_get_guest_instr_count());
        taint2_enable_taint();           
    }
    return 0;
}


void on_taint_change(Addr a, uint64_t size){
    printf("ON taint change\n");
    uint32_t num_tainted = 0;
    for (uint32_t i=0; i<size; i++){
        a.off = i;
        num_tainted += (taint2_query(a) != 0);
    }

    if (num_tainted > 0) {
        printf("In taint change!\n");
    }
}

Addr make_maddr(uint64_t a) {
  Addr ma;
  ma.typ = MADDR;
  ma.val.ma = a;
  ma.off = 0;
  ma.flag = (AddrFlag) 0;
  return ma;
}

uint64_t target_pc = 0x080484c0;
uint64_t end_pc = 0x08048586;

bool written = false;

bool before_block_exec(CPUState *env, TranslationBlock *tb) {
    // if (tb->pc <= end_pc && end_pc < tb->pc+tb->size) {
    //     printf("Reached end of main, halting replay\n");
    //     panda_end_replay();
    //     return false;
    // }

    int str_len = 12;
    if (rr_get_guest_instr_count() >= 9489938) {
        printf("Reached instr after decode at rr_get_guest_instr_count %lu\n", rr_get_guest_instr_count());
    //     // we've reached call to printf
    //     //query taint at out addr

        uint64_t out = 0x08049814;
        hwaddr out_pa = panda_virt_to_phys(env, out);
        printf("out_pa %lx\n", out_pa);

    //     Addr a = make_maddr(out_pa);

    //     int num_tainted = 0;
    //     for (uint32_t i = 0; i < str_len; i++) {
    //         a.off = i;
    //         num_tainted += (taint2_query(a) != 0);
    //         printf("Addr %lx tcn %d\n", out + i, taint2_query_tcn(a));
    //     }

    //     printf("num_tainted %d\n", num_tainted);

    //     if (pandalog && !written) {
    //         Panda__TaintedInstr *ti = (Panda__TaintedInstr *) malloc(sizeof(Panda__TaintedInstr));
    //         *ti = PANDA__TAINTED_INSTR__INIT;
    //         ti->call_stack = pandalog_callstack_create();
    //         ti->n_taint_query = num_tainted;
    //         ti->taint_query = (Panda__TaintQuery **) malloc (sizeof(Panda__TaintQuery *) * num_tainted);
    //         uint32_t j = 0;
    //         for (uint32_t i = 0; i < num_tainted; i++) {
    //             a.off = i;
    //             if (taint2_query(a)) {
    //                 ti->taint_query[j++] = taint2_query_pandalog(a, 0);
    //             }
    //         }
    //         Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    //         ple.tainted_instr = ti;
    //         if (pandalog) {
    //             pandalog_write_entry(&ple);
    //         }
    //         pandalog_callstack_free(ti->call_stack);
    //         for (uint32_t i = 0; i < num_tainted; i++) {
    //             pandalog_taint_query_free(ti->taint_query[i]);
    //         }
    //         free(ti);
    //         written = true;
    //     }

        printf("Reached end of decode, halting replay\n");
        pandalog_close();
        tcg_llvm_write_module(tcg_llvm_ctx, "./llvm-mod-taint.bc");

        exit(1);
    }
    
    if (rr_get_guest_instr_count() >= 9483436) {
        tainttest_enable_taint(env, tb->pc);
    }

    if (rr_get_guest_instr_count() >= 9485440) {
        // if at main
        uint64_t start_data = 0x8048610;

        for (int i = 0; i < str_len; i++) {
            hwaddr pa = panda_virt_to_phys(env, start_data + i);
            assert(pa != -1);
            taint2_label_ram(pa, i+1);
            // taint2_label_ram(pa, 10);
        }
    }

    return false;
}

extern "C" { extern TCGLLVMContext *tcg_llvm_ctx; }

bool init_plugin(void* self) {
    panda_require("taint2");
    assert(init_taint2_api());
    // taint2_enable_taint();

    panda_cb pcb;
    pcb.before_block_exec_invalidate_opt = before_block_exec ;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);

    panda_require("callstack_instr");
    assert (init_callstack_instr_api());

    return true;
}

void uninit_plugin(void* self) {


}
