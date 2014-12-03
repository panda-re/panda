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

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#include "cpu.h"

#include "fast_shad.h"
#include "label_set.h"
#include "taint_ops.h"

uint64_t labelset_count;

// Memlog functions.

uint64_t taint2_memlog_pop(uint64_t memlog_ptr) {
    taint2_memlog *taint_memlog = (taint2_memlog *)memlog_ptr;
    uint64_t result = taint_memlog->ring[taint_memlog->idx];
    taint_memlog->idx = (taint_memlog->idx + TAINT2_MEMLOG_SIZE - 1) % TAINT2_MEMLOG_SIZE;;
    return result;
}

void taint2_memlog_push(uint64_t memlog_ptr, uint64_t val) {
    taint2_memlog *taint_memlog = (taint2_memlog *)memlog_ptr;
    taint_memlog->idx = (taint_memlog->idx + 1) % TAINT2_MEMLOG_SIZE;;
    taint_memlog->ring[taint_memlog->idx] = val;
}

// Bookkeeping.
void taint_breadcrumb(uint64_t dest_ptr, uint64_t bb_slot) {
    *(uint64_t *)dest_ptr = bb_slot;
}

// Stack frame operations

void taint_reset_frame(uint64_t shad_ptr) {
    // scorched earth!!
    /*volatile uint32_t *null = NULL;
    *(uint32_t *)null = 0xDEADBEEF;
    assert(false);
    printf("%d", 1 / 0);*/

    fast_shad_reset_frame((FastShad *)shad_ptr);
}

void taint_push_frame(uint64_t shad_ptr) {
    fast_shad_push_frame((FastShad *)shad_ptr);
}
void taint_pop_frame(uint64_t shad_ptr) {
    fast_shad_pop_frame((FastShad *)shad_ptr);
}

// Taint operations
void taint_copy(
        uint64_t shad_dest_ptr, uint64_t dest,
        uint64_t shad_src_ptr, uint64_t src,
        uint64_t size) {
    FastShad *shad_dest = (FastShad *)shad_dest_ptr;
    FastShad *shad_src = (FastShad *)shad_src_ptr;
    /*printf("dest: %lx[%lx], src: %lx[%lx], size: %lx (%lu)\n",
            shad_dest_ptr, dest, shad_src_ptr, src, size, size);*/
    if (dest > shad_dest->size || src > shad_src->size) {
#ifdef TAINTDEBUG
        //printf("taint_copy: ignoring IO mem rw.\n");
#endif
        return;
    }
    fast_shad_copy(shad_dest, dest, shad_src, src, size);
}

void taint_move(
        uint64_t shad_dest_ptr, uint64_t dest,
        uint64_t shad_src_ptr, uint64_t src,
        uint64_t size) {
    FastShad *shad_dest = (FastShad *)shad_dest_ptr;
    FastShad *shad_src = (FastShad *)shad_src_ptr;
    fast_shad_move(shad_dest, dest, shad_src, src, size);
}

void taint_parallel_compute(
        uint64_t shad_ptr,
        uint64_t dest, uint64_t ignored,
        uint64_t src1, uint64_t src2, uint64_t src_size) {
    FastShad *shad = (FastShad *)shad_ptr;
    uint64_t i;
    for (i = 0; i < src_size; ++i) {
        LabelSet *ls = label_set_union(
                fast_shad_query(shad, src1 + i),
                fast_shad_query(shad, src2 + i));
        fast_shad_set(shad, dest + i, ls);
    }
}

static inline LabelSet *mixed_labels(FastShad *shad, uint64_t addr, uint64_t size) {
    LabelSet *ls = NULL;
    uint64_t i;
    for (i = 0; i < size; ++i) {
        ls = label_set_union(ls, fast_shad_query(shad, addr + i));
    }
    return ls;
}

static inline void bulk_set(FastShad *shad, uint64_t addr, uint64_t size, LabelSet *ls) {
    uint64_t i;
    for (i = 0; i < size; ++i) {
        fast_shad_set(shad, addr + i, ls);
    }
}

void taint_mix_compute(
        uint64_t shad_ptr,
        uint64_t dest, uint64_t dest_size,
        uint64_t src1, uint64_t src2, uint64_t src_size) {
    FastShad *shad = (FastShad *)shad_ptr;
    LabelSet *ls = label_set_union(
            mixed_labels(shad, src1, src_size),
            mixed_labels(shad, src2, src_size));
    bulk_set(shad, dest, dest_size, ls);
}

void taint_delete(uint64_t shad_ptr, uint64_t dest, uint64_t size) {
    FastShad *shad = (FastShad *)shad_ptr;
    //printf("remove: %lx[%lx+%lx]\n", shad_ptr, dest, size);
    if (unlikely(dest >= shad->size)) {
        // Ignore IO rw.
        return;
    }
    fast_shad_remove(shad, dest, size);
}

void taint_set(
        uint64_t shad_dest_ptr, uint64_t dest, uint64_t dest_size,
        uint64_t shad_src_ptr, uint64_t src) {
    FastShad *shad_dest = (FastShad *)shad_dest_ptr;
    FastShad *shad_src = (FastShad *)shad_src_ptr;
    bulk_set(shad_dest, dest, dest_size, fast_shad_query(shad_src, src));
}

void taint_mix(
        uint64_t shad_ptr,
        uint64_t dest, uint64_t dest_size,
        uint64_t src, uint64_t src_size) {
    FastShad *shad = (FastShad *)shad_ptr;
    bulk_set(shad, dest, dest_size, mixed_labels(shad, src, src_size));
}

void taint_sext(uint64_t shad_ptr, uint64_t dest, uint64_t dest_size, uint64_t src, uint64_t src_size) {
    FastShad *shad = (FastShad *)shad_ptr;
    //printf("taint_sext\n");
    fast_shad_copy(shad, dest, shad, src, src_size);
    bulk_set(shad, dest + src_size, dest_size - src_size,
            fast_shad_query(shad, dest + src_size - 1));
}

const uint64_t ones = ~0UL;

// Takes a (~0UL, ~0UL)-terminated list of (value, selector) pairs.
void taint_select(
        uint64_t shad_ptr,
        uint64_t dest, uint64_t size, uint64_t selector,
        ...) {
    FastShad *shad = (FastShad *)shad_ptr;
    va_list argp;
    uint64_t src, srcsel;

    va_start(argp, selector);
    src = va_arg(argp, uint64_t);
    srcsel = va_arg(argp, uint64_t);
    while (!(src == ones && srcsel == ones)) {
        if (srcsel == selector) { // bingo!
            if (src != ones) { // otherwise it's a constant.
                //printf("taint_select\n");
                fast_shad_copy(shad, dest, shad, src, size);
            }
            return;
        }

        src = va_arg(argp, uint64_t);
        srcsel = va_arg(argp, uint64_t);
    } 

    assert(false && "Couldn't find selected argument!!");
}

// This should only be called on loads/stores from CPUState.
void taint_host_copy(
        uint64_t env_ptr, uint64_t addr,
        uint64_t llv_ptr, uint64_t llv_offset,
        uint64_t greg_ptr, uint64_t gspec_ptr,
        uint64_t size, bool is_store) {
    FastShad *llv = (FastShad *)llv_ptr;
    FastShad *greg = (FastShad *)greg_ptr;
    FastShad *gspec = (FastShad *)gspec_ptr;

    int64_t offset = addr - env_ptr;
    if (offset < 0 || offset >= sizeof(CPUState)) {
        // Irrelevant
        return;
    }

    FastShad *state_shad;
    
#define m_off(member) (uint64_t)(&((CPUState *)0)->member)
#define m_size(member) sizeof(((CPUState *)0)->member)
#define m_endoff(member) (m_off(member) + m_size(member))
#define contains_offset(member) (m_off(member) <= (unsigned)(offset) && (unsigned)(offset) < m_endoff(member))
    if (contains_offset(regs)) {
        state_shad = greg;
        offset -= m_off(regs);
    } else {
        state_shad = gspec;
    }
#undef contains_offset
#undef m_endoff
#undef m_size
#undef m_off

    FastShad *shad_src = is_store ? llv : state_shad;
    uint64_t src = is_store ? llv_offset : offset;
    FastShad *shad_dest = is_store ? state_shad : llv;
    uint64_t dest = is_store ? offset : llv_offset;

    /*printf("taint_host_copy\n");
    printf("env: %lx, addr: %lx, llv: %lx, offset: %lx\n", env_ptr, addr, llv_ptr, llv_offset);
    printf("greg: %lx, gspec: %lx, size: %lx, is_store: %u\n", greg_ptr, gspec_ptr, size, is_store);
    printf("src: %lx[%lx], dest: %lx[%lx]\n", (uint64_t)shad_src, src, (uint64_t)shad_dest, dest);*/
    fast_shad_copy(shad_dest, dest, shad_src, src, size);
}
