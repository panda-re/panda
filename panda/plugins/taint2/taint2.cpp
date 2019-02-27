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

/*
 * PANDA taint analysis plugin
 * Ryan Whelan, Tim Leek, Sam Coe, Nathan VanBenschoten
 */

// Change Log:
// 2018-JUL-09   Propagate network related taint too.
// 2018-MAY-07   Add detaint_cb0 option to remove taint from bytes whose
//               control bits are all zero.
// 2019-FEB-21   In i386 build, save information needed to calculate condition
//               codes when the cpu_exec loop exits, and restore when it
//               re-enters, to avoid inconsistent taint results.


// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <iostream>

#include "panda/plugin.h"
#include "panda/tcg-llvm.h"

#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "llvm_taint_lib.h"
#include "shad.h"
#include "taint_ops.h"
#include "taint2.h"
#include "label_set.h"
#include "taint_api.h"
#include "taint2_hypercalls.h"

#define CPU_OFF(member) (uint64_t)(&((CPUArchState *)0)->member)

extern "C" {
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
int after_block_translate(CPUState *cpu, TranslationBlock *tb);
bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb);

// for i386 condition code adjustments
#if defined(TARGET_I386)
int i386_after_cpu_exec_enter(CPUState *cpu);
int i386_before_cpu_exec_exit(CPUState *cpu, bool ranBlock);
#endif

int phys_mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int phys_mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

// network related callbacks
int on_replay_net_transfer(CPUState *cpu, uint32_t type, uint64_t src_addr, uint64_t dst_addr, uint32_t num_bytes);
int on_replay_before_dma(CPUState *cpu, uint32_t is_write, uint8_t *src_addr, uint64_t dest_addr, uint32_t num_bytes);

void taint_state_changed(Shad *, uint64_t, uint64_t);
PPP_PROT_REG_CB(on_taint_change);
PPP_CB_BOILERPLATE(on_taint_change);

bool track_taint_state = false;
uint32_t max_tcn = 0;          // ie disabled
uint32_t max_taintset_card = 0;   // ie disabled - there is no maximum

// more i386 condition code adjustment information
#if defined(TARGET_I386)
bool haveSavedCC = false;
bool savedTaint = false;

target_ulong savedCCDst;
TaintData ccDstTaint[sizeof(target_ulong)];
uint64_t dstOff = CPU_OFF(cc_dst);

target_ulong savedCCSrc;
TaintData ccSrcTaint[sizeof(target_ulong)];
uint64_t srcOff = CPU_OFF(cc_src);

target_ulong savedCCSrc2;
TaintData ccSrc2Taint[sizeof(target_ulong)];
uint64_t src2Off = CPU_OFF(cc_src2);

uint32_t savedCCOp;
TaintData ccOpTaint[sizeof(uint32_t)];
uint64_t opOff = CPU_OFF(cc_op);

target_ulong savedEflags;
// CPUArchState->eflags is marked irrelevant, so it will never have taint
#endif

int asid_changed_callback(CPUState *env, target_ulong oldval, target_ulong newval);
}

ShadowState *shadow = nullptr; // Global shadow memory

// Pointer passed in init_plugin()
void *taint2_plugin = nullptr;

// Our pass manager to derive taint ops
llvm::FunctionPassManager *FPM = nullptr;

// Taint function pass.
llvm::PandaTaintFunctionPass *PTFP = nullptr;

// For now, taint becomes enabled when a label operation first occurs, and
// becomes disabled when a query operation subsequently occurs
bool taintEnabled = false;

// Lets us know right when taint was disabled
bool taintJustDisabled = false;

// Taint memlog
static taint2_memlog taint_memlog;

// Configuration
bool tainted_pointer = true;
bool optimize_llvm = true;
extern bool inline_taint;
bool debug_taint = false;
bool detaint_cb0_bytes = false;

/*
 * These memory callbacks are only for whole-system mode.  User-mode memory
 * accesses are captured by IR instrumentation.
 */
int phys_mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    taint_memlog_push(&taint_memlog, addr);
    return 0;
}

int phys_mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size) {
    taint_memlog_push(&taint_memlog, addr);
    return 0;
}

int replay_hd_transfer_callback(CPUState *cpu, uint32_t type, uint64_t src_addr,
                                uint64_t dst_addr, uint32_t num_bytes)
{
    if (!taintEnabled) {
        return 0;
    }

    Shad *src_shad, *dst_shad;

    switch (type) {
    case HD_TRANSFER_HD_TO_IOB:
        src_shad = &shadow->hd;
        dst_shad = &shadow->io;
        break;
    case HD_TRANSFER_IOB_TO_HD:
        src_shad = &shadow->io;
        dst_shad = &shadow->hd;
        break;
    case HD_TRANSFER_HD_TO_RAM:
        src_shad = &shadow->hd;
        dst_shad = &shadow->ram;
        break;
    case HD_TRANSFER_RAM_TO_HD:
        src_shad = &shadow->ram;
        dst_shad = &shadow->hd;
        break;
    default:
        fprintf(stderr, "invalid HD transfer type\n");
        return 0;
    }

    Shad::copy(dst_shad, dst_addr, src_shad, src_addr, num_bytes);

    return 0;
}

// network data has been transfered - transfer the associated taint too
int on_replay_net_transfer(CPUState *cpu, uint32_t type, uint64_t src_addr,
    uint64_t dst_addr, uint32_t num_bytes)
{
    if (!taintEnabled)
    {
        return 0;
    }
    
    Shad *src_shad;
    Shad *dst_shad;
    switch (type)
    {
    case NET_TRANSFER_RAM_TO_IOB:
        src_shad = &shadow->ram;
        dst_shad = &shadow->io;
        break;
    case NET_TRANSFER_IOB_TO_RAM:
        src_shad = &shadow->io;
        dst_shad = &shadow->ram;
        break;
    case NET_TRANSFER_IOB_TO_IOB:
        src_shad = &shadow->io;
        dst_shad = &shadow->io;
        break;
    default:
        fprintf(stderr, "Invalid network transfer type (%d)\n", type);
        return 0;
    }
    Shad::copy(dst_shad, dst_addr, src_shad, src_addr, num_bytes);
    return 0;
} // end of function on_replay_net_transfer

// transfer between IO and RAM - transfer any taint too
int on_replay_before_dma(CPUState *cpu, uint32_t is_write, uint8_t *src_addr,
    uint64_t dest_addr, uint32_t num_bytes)
{
    // in taint1, this was PANDA_CB_REPLAY_BEFORE_CPU_PHYSICAL_MEM_RW_RAM
    
    if (!taintEnabled)
    {
        return 0;
    }
    
    // per comments in plugin.h, src_addr is really the QEMU device's buffer in
    // QEMU's virtual memory, and dest_addr is the physical address of guest RAM
    // so, the signature for the PANDA_CB_BEFORE_DMA callback in plugin.h
    // doesn't really match the comment - which is source and which is
    // destination depends upon what is_write is
    
    // per the comments in the code generating this event...
    // ...is_write=1 means writing from IO buffer to RAM
    // ...is_write=0 means writing from RAM to IO buffer
    Shad *src_shad;
    Shad *dst_shad;
    uint64_t ss_addr;
    uint64_t ds_addr;
    if (1 == is_write)
    {
        src_shad = &shadow->io;
        dst_shad = &shadow->ram;
        ss_addr = (uint64_t)src_addr;
        ds_addr = dest_addr;
    }
    else if (0 == is_write)
    {
        src_shad = &shadow->ram;
        dst_shad = &shadow->io;
        ss_addr = dest_addr;
        ds_addr = (uint64_t)src_addr;
    }
    else
    {
        fprintf(stderr, "Invalid replay before DMA write flag (%d)\n", is_write);
        return 0;
    }
    Shad::copy(dst_shad, ds_addr, src_shad, ss_addr, num_bytes);
    return 0;
} // end of function on_replay_before_dma

void taint2_enable_tainted_pointer(void) {
    tainted_pointer = true;
}

void taint2_enable_taint(void) {
    if(taintEnabled) {return;}
    std::cerr << PANDA_MSG << __FUNCTION__ << std::endl;
    taintEnabled = true;
    panda_cb pcb;

    pcb.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(taint2_plugin, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
    pcb.phys_mem_before_read = phys_mem_read_callback;
    panda_register_callback(taint2_plugin, PANDA_CB_PHYS_MEM_BEFORE_READ, pcb);
    pcb.phys_mem_before_write = phys_mem_write_callback;
    panda_register_callback(taint2_plugin, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);
    pcb.asid_changed = asid_changed_callback;
    panda_register_callback(taint2_plugin, PANDA_CB_ASID_CHANGED, pcb);

    pcb.replay_hd_transfer = replay_hd_transfer_callback;
    panda_register_callback(taint2_plugin, PANDA_CB_REPLAY_HD_TRANSFER, pcb);

    // network related callbacks
    pcb.replay_net_transfer = on_replay_net_transfer;
    panda_register_callback(taint2_plugin, PANDA_CB_REPLAY_NET_TRANSFER, pcb);
    pcb.replay_before_dma = on_replay_before_dma;
    panda_register_callback(taint2_plugin, PANDA_CB_REPLAY_BEFORE_DMA, pcb);
    
    panda_enable_precise_pc(); //before_block_exec requires precise_pc for panda_current_asid

    if (!execute_llvm){
        panda_enable_llvm();
    }
    panda_enable_llvm_helpers();

    if (shadow) delete shadow;
    shadow = new ShadowState();

    // Initialize memlog.
    memset(&taint_memlog, 0, sizeof(taint_memlog));

    llvm::Module *mod = tcg_llvm_ctx->getModule();
    FPM = tcg_llvm_ctx->getFunctionPassManager();

    std::cerr << PANDA_MSG "LLVM optimizations " << PANDA_FLAG_STATUS(optimize_llvm) << std::endl;
    if (optimize_llvm) {
        llvm::PassManagerBuilder Builder;
        Builder.OptLevel = 2;
        Builder.SizeLevel = 0;
        Builder.populateFunctionPassManager(*FPM);
    }

    // Add the taint analysis pass to our taint pass manager
    PTFP = new llvm::PandaTaintFunctionPass(shadow, &taint_memlog);
    FPM->add(PTFP);

    FPM->doInitialization();

    // Populate module with helper function taint ops
    for (auto i = mod->begin(); i != mod->end(); i++){
        if (!i->isDeclaration()) PTFP->runOnFunction(*i);
    }

    std::cerr << PANDA_MSG "Done processing helper functions for taint." << std::endl;

    std::string err;
    if(verifyModule(*mod, llvm::AbortProcessAction, &err)){
        std::cerr << PANDA_MSG << err << std::endl;
        exit(1);
    }

#ifdef TAINT2_DEBUG
    tcg_llvm_write_module(tcg_llvm_ctx, "llvm-mod.bc");
#endif

    std::cerr << "Done verifying module. Running..." << std::endl;
}

// The i386 doesn't update the condition codes whenever executing an emulated
// instruction that chagnes them, but just saves some information needed to
// calculate the value should it be needed before the next change.  This causes
// problems in reporting taint beforec when the cpu executive loop (cpu_exec)
// exits, it updates the condition codes (without reporting taint), and the
// cpu_exec loop may exit at inconsistent times due to external events and the
// rcu thread not being deterministic.
// These callbacks work around this by saving the condition code calculation
// information just before cpu_exec updates it, and restores it just after it
// runs the enter callback.  (Apparently somebody outside of the cpu_exec needs
// to know the real condition codes.)
#if defined(TARGET_I386)
int i386_after_cpu_exec_enter(CPUState *cpu) {

    if (!haveSavedCC)
    {
        return 0;
    }

    // as have saved data, restore it
    CPUArchState *env = static_cast<CPUArchState*>(cpu->env_ptr);

    env->cc_dst = savedCCDst;
    env->cc_src = savedCCSrc;
    env->cc_src2 = savedCCSrc2;
    env->cc_op = savedCCOp;
    env->eflags = savedEflags;
    haveSavedCC = false;

    // if saved taint too, restore that
    if (taintEnabled) {
        if (savedTaint) {
            for (uint32_t i = 0; i < sizeof(target_ulong); i++) {
                shadow->gsv.set_full_quiet(dstOff + i, ccDstTaint[i]);
                shadow->gsv.set_full_quiet(srcOff + i, ccSrcTaint[i]);
                shadow->gsv.set_full_quiet(src2Off + i, ccSrc2Taint[i]);
            }
            for (uint32_t i = 0; i < sizeof(uint32_t); i++) {
                shadow->gsv.set_full_quiet(opOff + i, ccOpTaint[i]);
            }
            savedTaint = false;
        }
        else {
            // if taint enabled since saved info, wipe out any taint that
            // may have appeared on the data since the save
            shadow->gsv.remove_quiet(dstOff, sizeof(target_ulong));
            shadow->gsv.remove_quiet(srcOff, sizeof(target_ulong));
            shadow->gsv.remove_quiet(src2Off, sizeof(target_ulong));
            shadow->gsv.remove_quiet(opOff, sizeof(uint32_t));
        }
    }
    // if taint was disabled since saved the taint, I think we're just hosed
    // fortunately, it appears the feature to disable taint is not currently
    // implemented

    // return value isn't used, so don't worry about it
    return 0;
}

int i386_before_cpu_exec_exit(CPUState *cpu, bool ranBlock) {
    // it's possible for the cpu_exec loop to enter and then leave without
    // ever executing an LLVM block - don't update the saved information in
    // that case, as may have unrestored saved information to apply yet
    if (ranBlock) {
        CPUArchState *env = static_cast<CPUArchState*>(cpu->env_ptr);

        // save the data itself
        savedCCDst = env->cc_dst;
        savedCCSrc = env->cc_src;
        savedCCSrc2 = env->cc_src2;
        savedCCOp = env->cc_op;
        savedEflags = env->eflags;

        // save the taint on the data, if there might be any
        if (taintEnabled) {
            // the taint for this info is in the CPUState shadow
            // the offset into CPUX86State of each item of interest is used as
            // the address of the item's taint in the shadow
            for (uint32_t i = 0; i < sizeof(target_ulong); i++) {
                ccDstTaint[i] = shadow->gsv.query_full(dstOff + i);
                ccSrcTaint[i] = shadow->gsv.query_full(srcOff + i);
                ccSrc2Taint[i] = shadow->gsv.query_full(src2Off + i);
            }
            for (uint32_t i = 0; i < sizeof(uint32_t); i++) {
                ccOpTaint[i] = shadow->gsv.query_full(opOff + i);
            }
            savedTaint = true;
        }
        haveSavedCC = true;
    }
    // return value isn't used so don't worry about it
    return 0;
}
#endif

__attribute__((unused)) static void print_labels(uint32_t el, void *stuff) {
    printf("%d ", el);
}

__attribute__((unused)) static void record_bit(uint32_t el, void *array) {
    *(uint64_t *)array |= 1 << el;
}

#if 0
// move this to a generic utilities header/source file?
#define PANDA_MAX_STRING_READ 256
void panda_virtual_string_read(CPUState *cpu, target_ulong vaddr, char *str) {
    for (uint32_t i=0; i<PANDA_MAX_STRING_READ; i++) {
        uint8_t c = 0;
        if (-1 == panda_virtual_memory_rw(cpu, vaddr + i, &c, 1, false)) {
            printf("Can't access memory at " TARGET_FMT_lx "\n", vaddr + i);
            str[i] = 0;
            break;
        }
        str[i] = c;
        if (c==0) break;
    }
    str[PANDA_MAX_STRING_READ-1] = 0;
}
#endif

/**
 * @brief Wrapper for running the registered `on_taint_change` PPP callbacks.
 * Called by the shadow memory implementation whenever changes occur to it.
 */
void taint_state_changed(Shad *shad, uint64_t shad_addr, uint64_t size)
{
    Addr addr;
    if (shad == &shadow->llv) {
        addr = make_laddr(shad_addr / MAXREGSIZE, shad_addr % MAXREGSIZE);
    } else if (shad == &shadow->ram) {
        addr = make_maddr(shad_addr);
    } else if (shad == &shadow->grv) {
        addr = make_greg(shad_addr / sizeof(target_ulong), shad_addr % sizeof(target_ulong));
    } else if (shad == &shadow->gsv) {
        addr.typ = GSPEC;
        addr.val.gs = shad_addr;
        addr.off = 0;
        addr.flag = (AddrFlag)0;
    } else if (shad == &shadow->ret) {
        addr.typ = RET;
        addr.val.ret = 0;
        addr.off = shad_addr;
        addr.flag = (AddrFlag)0;
    } else if (shad == &shadow->hd) {
        addr = make_haddr(shad_addr);
    } else if (shad == &shadow->io) {
        addr = make_iaddr(shad_addr);
        /*    } else if (shad == &shadow->ports) {
                addr = make_paddr(shad_addr); */
    } else return;

    PPP_RUN_CB(on_taint_change, addr, size);
}

bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb) {
    if (taintEnabled) {
        return tb->llvm_tc_ptr ? false : true /* invalidate! */;
    }
    return false;
}


/**
 * @brief Basic initialization for `taint2` plugin.
 *
 * @note Taint propagation won't happen before you also call `taint2_enable_taint()`.
 */
bool init_plugin(void *self) {
    taint2_plugin = self;

    // set required panda options
    panda_enable_memcb();
    panda_disable_tb_chaining();

    // hook taint2 callbacks
#ifdef TAINT2_HYPERCALLS
    panda_cb pcb;
    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);
#endif
#if 0
    // also registered by taint2_enable_taint() - registering twice triggers assertion error
    // keep this commented until we figure out which one we should eliminate
    pcb.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
#endif

#if defined(TARGET_I386)
    panda_cb pcb2;
    pcb2.after_cpu_exec_enter = i386_after_cpu_exec_enter;
    panda_register_callback(self, PANDA_CB_AFTER_CPU_EXEC_ENTER, pcb2);
    pcb2.before_cpu_exec_exit = i386_before_cpu_exec_exit;
    panda_register_callback(self, PANDA_CB_BEFORE_CPU_EXEC_EXIT, pcb2);
#endif

    // parse arguments
    panda_arg_list *args = panda_get_args("taint2");
    tainted_pointer = !panda_parse_bool_opt(args, "no_tp", "track taint through pointer dereference");
    std::cerr << PANDA_MSG "propagation via pointer dereference " << PANDA_FLAG_STATUS(tainted_pointer) << std::endl;
    inline_taint = panda_parse_bool_opt(args, "inline", "inline taint operations");
    std::cerr << PANDA_MSG "taint operations inlining " << PANDA_FLAG_STATUS(inline_taint) << std::endl;
    optimize_llvm = panda_parse_bool_opt(args, "opt", "run LLVM optimization on taint");
    std::cerr << PANDA_MSG "llvm optimizations " << PANDA_FLAG_STATUS(optimize_llvm) << std::endl;
    debug_taint = panda_parse_bool_opt(args, "debug", "enable taint debugging");
    std::cerr << PANDA_MSG "taint debugging " << PANDA_FLAG_STATUS(debug_taint) << std::endl;
    detaint_cb0_bytes = panda_parse_bool_opt(args, "detaint_cb0", "detaint bytes whose control mask bits are 0");
    std::cerr << PANDA_MSG "detaint if control bits 0 " << PANDA_FLAG_STATUS(detaint_cb0_bytes) << std::endl;
    max_tcn = panda_parse_uint32_opt(args, "max_taintset_compute_number", 0,
        "stop propagating taint after it goes through this number of computations (0=never stop)");
    std::cerr << PANDA_MSG "maximum taint compute number (0=unlimited) " << max_tcn << std::endl;
    max_taintset_card = panda_parse_uint32_opt(args, "max_taintset_card", 0,
        "maximum size a label set can reach before stop tracking taint on it (0=never stop)");
    std::cerr << PANDA_MSG "maximum taintset cardinality (0=unlimited) " << max_taintset_card << std::endl;
    
    // load dependencies
    panda_require("callstack_instr");
    assert(init_callstack_instr_api());

    return true;
}

void uninit_plugin(void *self) {
    if (shadow) {
        delete shadow;
        shadow = nullptr;
    }

    // Check if tcg_llvm_ctx has been initialized before destroy
    if (taint2_enabled()) panda_disable_llvm();

    panda_disable_memcb();
    panda_enable_tb_chaining();
}
