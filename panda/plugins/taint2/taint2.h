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

#ifndef __TAINT2_H__
#define __TAINT2_H__

#include <cstdint>

#include <map>
#include <set>

#include "panda/plugin.h"

#include "fast_shad.h"
#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "taint_defines.h"

typedef const std::set<uint32_t> *LabelSetP;

typedef void (*on_branch2_t) (Addr, uint64_t);
typedef void (*on_indirect_jump_t) (Addr, uint64_t);
typedef void (*on_taint_change_t) (Addr, uint64_t);
typedef void (*on_ptr_load_t) (Addr, uint64_t, uint64_t);
typedef void (*on_ptr_store_t) (Addr, uint64_t, uint64_t);


struct ShadowState {
    uint64_t prev_bb; // label for previous BB.
    uint32_t num_vals;
    SdDir64 *hd;
    SdDir64 *io;
    SdDir32 *ports;
    FastShad ram;
    FastShad llv;  // LLVM registers, with multiple frames
    FastShad ret;  // LLVM return value, also temp register
    FastShad grv;  // guest general purpose registers
    FastShad gsv;  // guest special values, like FP, and parts of CPUState

    ShadowState() : prev_bb(0), num_vals(MAXFRAMESIZE),
        ram("RAM", ram_size),
        llv("LLVM", MAXFRAMESIZE * FUNCTIONFRAMES * MAXREGSIZE),
        ret("Ret", MAXREGSIZE),
        grv("Reg", NUM_REGS * sizeof(target_ulong)),
        gsv("CPUState", sizeof(CPUArchState)) {
        hd = shad_dir_new_64(12,12,16);
        io = shad_dir_new_64(12,12,16);
        ports = shad_dir_new_32(10,10,12);
    }

    std::pair<FastShad *, uint64_t> query_loc(const Addr &a) {
        switch (a.typ) {
            case HADDR:
            case IADDR:
            case PADDR:
            case CONST:
                return std::make_pair(nullptr, 0);
            case MADDR:
                return std::make_pair(&ram, a.val.ma + a.off);
            case LADDR:
                return std::make_pair(&llv, a.val.la * MAXREGSIZE + a.off);
            case GREG:
                return std::make_pair(&grv, a.val.gr * sizeof(target_ulong) + a.off);
            case GSPEC:
                return std::make_pair(&gsv, a.val.gs + a.off);
            case RET:
                return std::make_pair(&ret, a.off);
            default:
                assert(false);
                return std::make_pair(nullptr, 0);
        }
    }
};

extern "C" {
Addr make_maddr(uint64_t a);
Addr make_laddr(uint64_t a, uint64_t o);
Addr make_greg(uint64_t r, uint16_t off);
}

#endif
