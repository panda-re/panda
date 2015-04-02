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

extern "C" {
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#include "cpu.h"
#include "qemu-log.h"
}

#include "fast_shad.h"
#include "label_set.h"
#include "taint_ops.h"

uint64_t labelset_count;

// Memlog functions.

uint64_t taint_memlog_pop(taint2_memlog *taint_memlog) {
    uint64_t result = taint_memlog->ring[taint_memlog->idx];
    taint_memlog->idx = (taint_memlog->idx + TAINT2_MEMLOG_SIZE - 1) % TAINT2_MEMLOG_SIZE;;

    taint_log("memlog_pop: %lx\n", result);
    return result;
}

void taint_memlog_push(taint2_memlog *taint_memlog, uint64_t val) {
    taint_log("memlog_push: %lx\n", val);
    taint_memlog->idx = (taint_memlog->idx + 1) % TAINT2_MEMLOG_SIZE;;
    taint_memlog->ring[taint_memlog->idx] = val;
}

// Bookkeeping.
void taint_breadcrumb(uint64_t *dest_ptr, uint64_t bb_slot) {
    *dest_ptr = bb_slot;
}

// Stack frame operations

void taint_reset_frame(FastShad *shad) {
    shad->reset_frame();
}

void taint_push_frame(FastShad *shad) {
    shad->push_frame(MAXREGSIZE * MAXFRAMESIZE);
}
void taint_pop_frame(FastShad *shad) {
    shad->pop_frame(MAXREGSIZE * MAXFRAMESIZE);
}

// Taint operations
void taint_copy(
        FastShad *shad_dest, uint64_t dest,
        FastShad *shad_src, uint64_t src,
        uint64_t size) {
    taint_log("copy: %lx[%lx+%lx] <- %lx[%lx] (",
            (uint64_t)shad_dest, dest, size, (uint64_t)shad_src, src);
#ifdef TAINTDEBUG
    unsigned i;
    for (i = 0; i < size; i++) {
        taint_log("%lx, ", (uint64_t)shad_src->query(src + i));
    }
    taint_log(")\n");
#endif

    if (dest + size >= shad_dest->get_size() || src + size >= shad_src->get_size()) {
        taint_log("Ignoring IO\n");
        return;
    }

    FastShad::copy(shad_dest, dest, shad_src, src, size);
}

void taint_parallel_compute(
        FastShad *shad,
        uint64_t dest, uint64_t ignored,
        uint64_t src1, uint64_t src2, uint64_t src_size) {
    taint_log("pcompute: %lx[%lx+%lx] <- %lx + %lx\n",
            (uint64_t)shad, dest, src_size, src1, src2);
    uint64_t i;
    for (i = 0; i < src_size; ++i) {
        TaintData td = TaintData::comp_union(
                shad->query_full(src1 + i),
                shad->query_full(src2 + i));
        shad->set_full(dest + i, td);
    }
}

static inline TaintData mixed_labels(FastShad *shad, uint64_t addr, uint64_t size) {
    TaintData td;
    uint64_t i;
    for (i = 0; i < size; ++i) {
        td.add(shad->query_full(addr + i));
    }
    return td;
}

static inline void bulk_set(FastShad *shad, uint64_t addr, uint64_t size, TaintData td) {
    uint64_t i;
    for (i = 0; i < size; ++i) {
        shad->set_full(addr + i, td);
    }
}

void taint_mix_compute(
        FastShad *shad,
        uint64_t dest, uint64_t dest_size,
        uint64_t src1, uint64_t src2, uint64_t src_size) {
    taint_log("mcompute: %lx[%lx+%lx] <- %lx + %lx\n",
            (uint64_t)shad, dest, dest_size, src1, src2);
    TaintData td = TaintData::comp_union(
            mixed_labels(shad, src1, src_size),
            mixed_labels(shad, src2, src_size));
    bulk_set(shad, dest, dest_size, td);
}

void taint_delete(FastShad *shad, uint64_t dest, uint64_t size) {
    taint_log("remove: %lx[%lx+%lx]\n", (uint64_t)shad, dest, size);
    if (unlikely(dest >= shad->get_size())) {
        taint_log("Ignoring IO RW\n");
        return;
    }
    shad->remove(dest, size);
}

void taint_set(
        FastShad *shad_dest, uint64_t dest, uint64_t dest_size,
        FastShad *shad_src, uint64_t src) {
    bulk_set(shad_dest, dest, dest_size, shad_src->query_full(src));
}

void taint_mix(
        FastShad *shad,
        uint64_t dest, uint64_t dest_size,
        uint64_t src, uint64_t src_size) {
    taint_log("mix: %lx[%lx+%lx] <- %lx+%lx\n",
            (uint64_t)shad, dest, dest_size, src, src_size);
    TaintData td = mixed_labels(shad, src, src_size);
    if (td.ls) td.tcn++;
    bulk_set(shad, dest, dest_size, td);
}

static const uint64_t ones = ~0UL;

void taint_pointer(
        FastShad *shad_dest, uint64_t dest,
        FastShad *shad_ptr, uint64_t ptr, uint64_t ptr_size,
        FastShad *shad_src, uint64_t src, uint64_t size) {
    taint_log("ptr: %lx[%lx+%lx] <- %lx[%lx] @ %lx[%lx+%lx]\n",
            (uint64_t)shad_dest, dest, size,
            (uint64_t)shad_src, src, (uint64_t)shad_ptr, ptr, ptr_size);

    if (unlikely(dest + size > shad_dest->get_size())) {
        taint_log("  Ignoring IO RW\n");
        return;
    } else if (unlikely(src + size > shad_src->get_size())) {
        taint_log("  Source IO.\n");
        src = ones; // ignore source.
    }

    TaintData td = mixed_labels(shad_ptr, ptr, ptr_size);
    if (td.ls) td.tcn++;
    if (src == ones) {
        bulk_set(shad_dest, dest, size, td);
    } else {
        unsigned i;
        for (i = 0; i < size; i++) {
            shad_dest->set_full(dest + i,
                    TaintData::copy_union(td, shad_src->query_full(src + i)));
        }
    }
}

void taint_sext(FastShad *shad, uint64_t dest, uint64_t dest_size, uint64_t src, uint64_t src_size) {
    taint_log("taint_sext\n");
    FastShad::copy(shad, dest, shad, src, src_size);
    bulk_set(shad, dest + src_size, dest_size - src_size,
            shad->query_full(dest + src_size - 1));
}

// Takes a (~0UL, ~0UL)-terminated list of (value, selector) pairs.
void taint_select(
        FastShad *shad,
        uint64_t dest, uint64_t size, uint64_t selector,
        ...) {
    va_list argp;
    uint64_t src, srcsel;

    va_start(argp, selector);
    src = va_arg(argp, uint64_t);
    srcsel = va_arg(argp, uint64_t);
    while (!(src == ones && srcsel == ones)) {
        if (srcsel == selector) { // bingo!
            if (src != ones) { // otherwise it's a constant.
                taint_log("slct\n");
                FastShad::copy(shad, dest, shad, src, size);
            }
            return;
        }

        src = va_arg(argp, uint64_t);
        srcsel = va_arg(argp, uint64_t);
    } 

    tassert(false && "Couldn't find selected argument!!");
}

static void find_offset(FastShad *greg, FastShad *gspec, uint64_t offset, uint64_t labels_per_reg, FastShad **dest, uint64_t *addr) {
#define m_off(member) (uint64_t)(&((CPUState *)0)->member)
#define m_size(member) sizeof(((CPUState *)0)->member)
#define m_endoff(member) (m_off(member) + m_size(member))
    if (m_off(regs) <= offset && offset < m_endoff(regs)) {
        *dest = greg;
        *addr = (offset - m_off(regs)) * labels_per_reg / sizeof(((CPUState *)0)->regs[0]);
    } else {
        *dest= gspec;
        *addr= offset;
    }
#undef contains_offset
#undef m_endoff
#undef m_size
#undef m_off
}

// This should only be called on loads/stores from CPUState.
void taint_host_copy(
        uint64_t env_ptr, uint64_t addr,
        FastShad *llv, uint64_t llv_offset,
        FastShad *greg, FastShad *gspec,
        uint64_t size, uint64_t labels_per_reg, bool is_store) {
    int64_t offset = addr - env_ptr;
    if (offset < 0 || (size_t)offset >= sizeof(CPUState)) {
        // Irrelevant
        taint_log("hostcopy: irrelevant\n");
        return;
    }

    FastShad *state_shad = NULL;
    uint64_t state_addr = 0;

    find_offset(greg, gspec, (uint64_t)offset, labels_per_reg,
            &state_shad, &state_addr);

    FastShad *shad_src = is_store ? llv : state_shad;
    uint64_t src = is_store ? llv_offset : state_addr;
    FastShad *shad_dest = is_store ? state_shad : llv;
    uint64_t dest = is_store ? state_addr : llv_offset;

    //taint_log("taint_host_copy\n");
    //taint_log("\tenv: %lx, addr: %lx, llv: %lx, offset: %lx\n", env_ptr, addr, llv_ptr, llv_offset);
    //taint_log("\tgreg: %lx, gspec: %lx, size: %lx, is_store: %u\n", greg_ptr, gspec_ptr, size, is_store);
#ifdef TAINTDEBUG
    taint_log("hostcopy: %lx[%lx+%lx] <- %lx[%lx] (offset %lx) (",
            (uint64_t)shad_dest, dest, size, (uint64_t)shad_src, src, offset);
    unsigned i;
    for (i = 0; i < size; i++) {
        taint_log("%lx, ", (uint64_t)shad_src->query(src + i));
    }
    taint_log(")\n");
#endif
    FastShad::copy(shad_dest, dest, shad_src, src, size);
}


void taint_host_memcpy(
        uint64_t env_ptr, uint64_t dest, uint64_t src,
        FastShad *greg, FastShad *gspec,
        uint64_t size, uint64_t labels_per_reg) {
    int64_t dest_offset = dest - env_ptr, src_offset = src - env_ptr;
    if (dest_offset < 0 || (size_t)dest_offset >= sizeof(CPUState) || 
            src_offset < 0 || (size_t)src_offset >= sizeof(CPUState)) {
        taint_log("hostmemcpy: irrelevant\n");
        return;
    }

    FastShad *shad_dest = NULL, *shad_src = NULL;
    uint64_t addr_dest = 0, addr_src = 0;

    find_offset(greg, gspec, (uint64_t)dest_offset, labels_per_reg,
            &shad_dest, &addr_dest);
    find_offset(greg, gspec, (uint64_t)src_offset, labels_per_reg,
            &shad_src, &addr_src);

#ifdef TAINTDEBUG
    taint_log("hostmemcpy: %lx[%lx+%lx] <- %lx[%lx] (offsets %lx <- %lx) (",
            (uint64_t)shad_dest, dest, size, (uint64_t)shad_src, src,
            dest_offset, src_offset);
    unsigned i;
    for (i = 0; i < size; i++) {
        taint_log("%lx, ", (uint64_t)shad_src->query(src + i));
    }
    taint_log(")\n");
#endif
    FastShad::copy(shad_dest, addr_dest, shad_src, addr_src, size);
}

void taint_host_delete(
        uint64_t env_ptr, uint64_t dest_addr,
        FastShad *greg, FastShad *gspec,
        uint64_t size, uint64_t labels_per_reg) {
    int64_t offset = dest_addr - env_ptr;

    if (offset < 0 || (size_t)offset >= sizeof(CPUState)) {
        taint_log("hostdel: irrelevant\n");
        return;
    }
    FastShad *shad = NULL;
    uint64_t dest = 0;

    find_offset(greg, gspec, offset, labels_per_reg, &shad, &dest);

    taint_log("hostdel: %lx[%lx+%lx]", (uint64_t)shad, dest, size);

    shad->remove(dest, size);
}
