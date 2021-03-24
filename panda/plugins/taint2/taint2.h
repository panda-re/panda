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

#include "shad.h"
#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "taint_defines.h"
#include "addr.h"
#include "query_res.h"

typedef const std::set<uint32_t> *LabelSetP;

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
typedef void (*on_branch2_t) (Addr, uint64_t, bool*);
typedef void (*on_indirect_jump_t) (Addr, uint64_t, bool*);
typedef void (*on_taint_change_t) (Addr, uint64_t);
typedef void (*on_taint_prop_t) (Addr, Addr, uint64_t);
typedef void (*on_ptr_load_t) (Addr, uint64_t, uint64_t);
typedef void (*on_ptr_store_t) (Addr, uint64_t, uint64_t);
typedef void (*on_after_load_t) (Addr, uint64_t, uint64_t);
typedef void (*on_after_store_t) (Addr, uint64_t, uint64_t);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

struct ShadowState {
    uint64_t prev_bb; // label for previous BB.
    uint32_t num_vals;
    FastShad ram;
    FastShad llv;  // LLVM registers, with multiple frames
    FastShad ret;  // LLVM return value, also temp register
    FastShad grv;  // guest general purpose registers
    FastShad gsv;  // guest special values, like FP, and parts of CPUState
    LazyShad hd;   // Hard Drive
    LazyShad io;   // I/O Buffer

    ShadowState()
        : prev_bb(0), num_vals(MAXFRAMESIZE), ram("RAM", ram_size),
          llv("LLVM", MAXFRAMESIZE * FUNCTIONFRAMES * MAXREGSIZE),
          ret("Ret", MAXREGSIZE), grv("Reg", NUM_REGS * sizeof(target_ulong)),
          gsv("CPUState", sizeof(CPUArchState)), hd("HD", UINT64_MAX),
          io("IO", UINT64_MAX)
    {
    }

    std::pair<Shad *, uint64_t> query_loc(const Addr &a)
    {
        switch (a.typ) {
            case HADDR:
                return std::make_pair(&hd, a.val.ha + a.off);
            case IADDR:
                return std::make_pair(&io, a.val.ia + a.off);
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
extern ShadowState *shadow; 

extern "C" {
Addr make_haddr(uint64_t a);
Addr make_iaddr(uint64_t a);
Addr make_maddr(uint64_t a);
Addr make_laddr(uint64_t a, uint64_t o);
Addr make_greg(uint64_t r, uint16_t off);
}

#endif
