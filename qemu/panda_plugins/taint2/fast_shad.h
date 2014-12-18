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

extern "C" {
#include "cpu.h"
#include "qemu-log.h"
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
void *memmove(void *dest, const void *src, size_t n);

typedef struct LabelSet *LabelSetP;

class FastShad {
private:
    LabelSetP *labels;
    LabelSetP *orig_labels;
    uint64_t size; // Number of labelsets contained.

    inline LabelSetP *get_ls_p(uint64_t guest_addr) {
        //taint_log("  %lx->get_ls_p(%lx)\n", (uint64_t)this, guest_addr);
        tassert(guest_addr < size);
        return &labels[guest_addr];
    }

public:
    FastShad(uint64_t size);
    ~FastShad();

    uint64_t get_size() { return size; }

    // Taint an address with a labelset.
    static inline void set(FastShad *fast_shad, uint64_t addr, LabelSetP ls) {
        *fast_shad->get_ls_p(addr) = ls;
    }

    static inline void copy(FastShad *shad_dest, uint64_t dest, FastShad *shad_src, uint64_t src, uint64_t size) {
        tassert(dest + size <= shad_dest->size);
        tassert(src + size <= shad_src->size);
        
#ifdef TAINTDEBUG
        unsigned i;
        for (i = 0; i < size; i++) {
            if (*shad_src->get_ls_p(src + i) != NULL) {
                taint_log("TAINTED COPY: %lx[%lx] <- %lx[%lx] (%lx)\n",
                        (uint64_t)shad_dest, dest + i,
                        (uint64_t)shad_src, src + i,
                        (uint64_t)*shad_src->get_ls_p(src + i));
                break;
            }
        }
#endif

        memcpy(shad_dest->get_ls_p(dest), shad_src->get_ls_p(src), size * sizeof(LabelSetP));
    }

    static inline void move(FastShad *shad_dest, uint64_t dest, FastShad *shad_src, uint64_t src, uint64_t size) {
        tassert(dest + size <= shad_dest->size);
        tassert(src + size <= shad_src->size);
        
#ifdef TAINTDEBUG
        unsigned i;
        for (i = 0; i < size; i++) {
            if (*shad_src->get_ls_p(src + i) != NULL) {
                taint_log("TAINTED MOVE\n");
                break;
            }
        }
#endif

        memmove(shad_dest->get_ls_p(dest), shad_src->get_ls_p(src), size * sizeof(LabelSetP));
    }

    // Remove taint.
    static inline void remove(FastShad *fast_shad, uint64_t addr, uint64_t size) {
        tassert(addr + size <= fast_shad->size);
        
#ifdef TAINTDEBUG
        unsigned i;
        for (i = 0; i < size; i++) {
            if (*fast_shad->get_ls_p(addr + i) != NULL) {
                taint_log("TAINTED DELETE\n");
                break;
            }
        }
#endif

        memset(fast_shad->get_ls_p(addr), 0, size * sizeof(LabelSetP));
    }

    // Query. NULL if untainted.
    static inline LabelSetP query(FastShad *fast_shad, uint64_t addr) {
        return *fast_shad->get_ls_p(addr);
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
};

#endif
