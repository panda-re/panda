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

#ifndef __FAST_SHAD_H
#define __FAST_SHAD_H

#include <cassert>
#include <cstdint>

#include "defines.h"
#include "label_set.h"

class FastShad;

extern "C" {
#include "cpu.h"
#include "qemu-log.h"

extern bool track_taint_state;

extern void taint_state_changed(FastShad *fast_shad, uint64_t addr);
}

#define CPU_LOG_TAINT_OPS (1 << 14)
#ifndef TAINTDEBUG
#define taint_log(...) {}
#define tassert(...) {}
#else
#define tassert(cond) assert((cond))
#define taint_log(...) qemu_log_mask(CPU_LOG_TAINT_OPS, ## __VA_ARGS__)
//#define taint_log(...) printf(__VA_ARGS__)
#endif

void *memset(void *dest, int val, size_t n);
void *memcpy(void *dest, const void *src, size_t n);


struct TaintData {
    LabelSetP ls;
    uint32_t tcn;

    TaintData() : ls(NULL), tcn(0) {}
    TaintData(LabelSetP ls) : ls(ls), tcn(0) {}
    TaintData(LabelSetP ls, uint32_t tcn) : ls(ls), tcn(ls ? tcn : 0) {}

    void add(TaintData td) {
        ls = label_set_union(ls, td.ls);
        tcn = ls ? std::max(tcn, td.tcn) : 0;
    }

    static TaintData copy_union(TaintData td1, TaintData td2) {
        return TaintData(
                label_set_union(td1.ls, td2.ls),
                std::max(td1.tcn, td2.tcn));
    }

    static TaintData comp_union(TaintData td1, TaintData td2) {
        return TaintData(
                label_set_union(td1.ls, td2.ls),
                std::max(td1.tcn, td2.tcn) + 1);
    }
};

class FastShad {
private:
    TaintData *labels;
    TaintData *orig_labels;
    uint64_t size; // Number of labelsets contained.

    inline TaintData *get_td_p(uint64_t guest_addr) {
        //taint_log("  %lx->get_ls_p(%lx)\n", (uint64_t)this, guest_addr);
        tassert(guest_addr < size);
        return &labels[guest_addr];
    }

    inline bool range_tainted(uint64_t addr, uint64_t size) {
        for (unsigned i = addr; i < size; i++) {
            if (get_td_p(addr)->ls) return true;
        }
        return false;
    }

public:
    FastShad(uint64_t size);
    ~FastShad();

    uint64_t get_size() { return size; }

    // Taint an address with a labelset.
    inline void label(uint64_t addr, LabelSetP ls) {
        *get_td_p(addr) = TaintData(ls);
    }

    static inline void copy(FastShad *shad_dest, uint64_t dest, FastShad *shad_src, uint64_t src, uint64_t size) {
        tassert(dest + size >= dest);
        tassert(src + size >= src);
        tassert(dest + size <= shad_dest->size);
        tassert(src + size <= shad_src->size);
        
#ifdef TAINTDEBUG
        for (unsigned i = 0; i < size; i++) {
            if (shad_src->get_td_p(src + i)->ls != NULL) {
                taint_log("TAINTED COPY: %lx[%lx] <- %lx[%lx] (%lx)\n",
                        (uint64_t)shad_dest, dest + i,
                        (uint64_t)shad_src, src + i,
                        (uint64_t)shad_src->get_td_p(src + i)->ls);
                break;
            }
        }
#endif

        bool change = false;
        if (track_taint_state && (shad_dest->range_tainted(dest, size) ||
                    shad_src->range_tainted(src, size)))
            change = true;

        memcpy(shad_dest->get_td_p(dest), shad_src->get_td_p(src), size * sizeof(TaintData));

        if (change) taint_state_changed(shad_dest, dest);
    }

    // Remove taint.
    inline void remove(uint64_t addr, uint64_t remove_size) {
        tassert(addr + remove_size >= addr);
        tassert(addr + remove_size <= size);
        
#ifdef TAINTDEBUG
        for (unsigned i = 0; i < remove_size; i++) {
            if (get_td_p(addr + i)->ls != NULL) {
                taint_log("TAINTED DELETE\n");
                break;
            }
        }
#endif

        bool change = false;
        if (track_taint_state && range_tainted(addr, remove_size))
            change = true;
        memset(get_td_p(addr), 0, remove_size * sizeof(TaintData));

        if (change) taint_state_changed(this, addr);
    }

    // Query. NULL if untainted.
    inline LabelSetP query(uint64_t addr) {
        return get_td_p(addr)->ls;
    } 

    inline void reset_frame() {
        labels = orig_labels;
        //taint_log("reset: %lx\n", (uint64_t)labels);
    }

    inline void push_frame(uint64_t framesize) {
        labels += framesize;
        tassert(labels < orig_labels + size);
        taint_log("push: %lx\n", (uint64_t)labels);
    }

    inline void pop_frame(uint64_t framesize) {
        labels -= framesize;
        tassert(labels >= orig_labels);
        taint_log("pop: %lx\n", (uint64_t)labels);
    }

    inline TaintData query_full(uint64_t addr) {
        return labels[addr];
    }

    inline void set_full(uint64_t addr, TaintData td) {
        tassert(addr < size);

        bool change = false;
        if (td.ls != get_td_p(addr)->ls)
            change = true;
        labels[addr] = td;

        if (change) taint_state_changed(this, addr);
    }

    inline uint32_t query_tcn(uint64_t addr) {
        return (query_full(addr)).tcn;
    }

};

#endif
