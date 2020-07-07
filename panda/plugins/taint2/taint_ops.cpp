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
 * Change Log:
 * dynamic check if there is a mul X 0 or mul X 1, for no taint prop or parallel
 * propagation respetively
 * 04-DEC-2018:  don't update masks on data that is not tainted; fix bug in
 *    taint2 deboug output for host memcpy
 */

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <cstdio>
#include <cstdarg>
//#include <sstream>      // std::ostringstream
//#include <string>       // std::string

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Function.h>

#include "qemu/osdep.h"        // needed for host-utils.h
#include "qemu/host-utils.h"   // needed for clz64 and ctz64

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "shad.h"
#include "label_set.h"
#include "taint_ops.h"
#include "taint_utils.h"
#include"z3++.h"

uint64_t labelset_count;

extern "C" {

extern bool tainted_pointer;
extern bool detaint_cb0_bytes;

}

void detaint_on_cb0(Shad *shad, uint64_t addr, uint64_t size);
void taint_delete(FastShad *shad, uint64_t dest, uint64_t size);

const int CB_WIDTH = 128;
const llvm::APInt NOT_LITERAL(CB_WIDTH, ~0UL, true);

static inline bool is_ram_ptr(uint64_t addr)
{
    return RAM_ADDR_INVALID !=
           qemu_ram_addr_from_host(reinterpret_cast<void *>(addr));
}

// Remove the taint marker from any bytes whose control mask bits go to 0.
// A 0 control mask bit means that bit does not impact the value in the byte (or
// impacts it in an irreversible fashion, so they gave up on calculating the
// mask).  This reduces false positives by removing taint from bytes which were
// formerly tainted, but whose values are no longer (reversibly) controlled by
// any tainted data.
void detaint_on_cb0(Shad *shad, uint64_t addr, uint64_t size)
{
    uint64_t curAddr = 0;
    for (int i = 0; i < size; i++)
    {
        curAddr = addr + i;
        TaintData td = shad->query_full(curAddr);

        // query_full ALWAYS returns a TaintData object - but there's not really
        // any taint (controlled or not) unless there are labels too
        if ((td.cb_mask == 0) && (td.ls != NULL) && (td.ls->size() > 0))
        {
            taint_delete(shad, curAddr, 1);
            taint_log("detaint: control bits 0 for 0x%lx\n", curAddr);
        }
    }
}

// Memlog functions.

uint64_t taint_memlog_pop(taint2_memlog *taint_memlog) {
    uint64_t result = taint_memlog->ring[taint_memlog->idx];
    taint_memlog->idx = (taint_memlog->idx + TAINT2_MEMLOG_SIZE - 1) % TAINT2_MEMLOG_SIZE;;

    taint_log("memlog_pop: %lx\n", result);
    return result;
}

void taint_memlog_push(taint2_memlog *taint_memlog, uint64_t val) {
    taint_log("memlog_push: %lx\n", val);
    taint_memlog->idx = (taint_memlog->idx + 1) % TAINT2_MEMLOG_SIZE;
    taint_memlog->ring[taint_memlog->idx] = val;
}

// Bookkeeping.
void taint_breadcrumb(uint64_t *dest_ptr, uint64_t bb_slot) {
    *dest_ptr = bb_slot;
}

// Stack frame operations

void taint_reset_frame(Shad *shad)
{
    shad->reset_frame();
}

void taint_push_frame(Shad *shad)
{
    shad->push_frame(MAXREGSIZE * MAXFRAMESIZE);
}
void taint_pop_frame(Shad *shad)
{
    shad->pop_frame(MAXREGSIZE * MAXFRAMESIZE);
}

struct CBMasks {
    llvm::APInt cb_mask;
    llvm::APInt one_mask;
    llvm::APInt zero_mask;

    CBMasks()
        : cb_mask(CB_WIDTH, 0UL), one_mask(CB_WIDTH, 0UL),
          zero_mask(CB_WIDTH, 0UL)
    {
    }
};

static void update_cb(Shad *shad_dest, uint64_t dest, Shad *shad_src,
                      uint64_t src, uint64_t size, llvm::Instruction *I);

static inline CBMasks compile_cb_masks(Shad *shad, uint64_t addr,
                                       uint64_t size);
static inline void write_cb_masks(Shad *shad, uint64_t addr, uint64_t size,
                                  CBMasks value);

// Taint operations
void taint_copy(Shad *shad_dest, uint64_t dest, Shad *shad_src, uint64_t src,
                uint64_t size, llvm::Instruction *I)
{
    if (unlikely(src >= shad_src->get_size() || dest >= shad_dest->get_size())) {
        taint_log("  Ignoring IO RW\n");
        return;
    }

    taint_log("copy: %s[%lx+%lx] <- %s[%lx] ",
            shad_dest->name(), dest, size, shad_src->name(), src);
    taint_log_labels(shad_src, src, size);

    Shad::copy(shad_dest, dest, shad_src, src, size);

    if (I) update_cb(shad_dest, dest, shad_src, src, size, I);
}

void taint_parallel_compute(Shad *shad, uint64_t dest, uint64_t ignored,
                            uint64_t src1, uint64_t src2, uint64_t src_size,
                            llvm::Instruction *I)
{
    uint64_t shad_size = shad->get_size();
    if (unlikely(dest >= shad_size || src1 >= shad_size || src2 >= shad_size)) {
        taint_log("  Ignoring IO RW\n");
        return;
    }

    taint_log("pcompute: %s[%lx+%lx] <- %lx + %lx\n",
            shad->name(), dest, src_size, src1, src2);
    uint64_t i;
    for (i = 0; i < src_size; ++i) {
        TaintData td = TaintData::make_union(
                shad->query_full(src1 + i),
                shad->query_full(src2 + i), true);
        shad->set_full(dest + i, td);
    }

    // Unlike mixed computes, parallel computes guaranteed to be bitwise.
    // This means we can honestly compute CB masks; in fact we have to because
    // of the way e.g. the deposit TCG op is lifted to LLVM.
    CBMasks cb_mask_1 = compile_cb_masks(shad, src1, src_size);
    CBMasks cb_mask_2 = compile_cb_masks(shad, src2, src_size);
    CBMasks cb_mask_out;
    if (I && I->getOpcode() == llvm::Instruction::Or) {
        cb_mask_out.one_mask = cb_mask_1.one_mask | cb_mask_2.one_mask;
        cb_mask_out.zero_mask = cb_mask_1.zero_mask & cb_mask_2.zero_mask;
        // Anything that's a literal zero in one operand will not affect
        // the other operand, so those bits are still controllable.
        cb_mask_out.cb_mask =
            (cb_mask_1.zero_mask & cb_mask_2.cb_mask) |
            (cb_mask_2.zero_mask & cb_mask_1.cb_mask);
    } else if (I && I->getOpcode() == llvm::Instruction::And) {
        cb_mask_out.one_mask = cb_mask_1.one_mask & cb_mask_2.one_mask;
        cb_mask_out.zero_mask = cb_mask_1.zero_mask | cb_mask_2.zero_mask;
        // Anything that's a literal one in one operand will not affect
        // the other operand, so those bits are still controllable.
        cb_mask_out.cb_mask =
            (cb_mask_1.one_mask & cb_mask_2.cb_mask) |
            (cb_mask_2.one_mask & cb_mask_1.cb_mask);
    }
    taint_log(
        "pcompute_cb: 0x%.16lx%.16lx +  0x%.16lx%.16lx = 0x%.16lx%.16lx",
        apint_hi_bits(cb_mask_1.cb_mask), apint_lo_bits(cb_mask_1.cb_mask),
        apint_hi_bits(cb_mask_2.cb_mask), apint_lo_bits(cb_mask_2.cb_mask),
        apint_hi_bits(cb_mask_out.cb_mask), apint_lo_bits(cb_mask_out.cb_mask));
    taint_log_labels(shad, dest, src_size);
    write_cb_masks(shad, dest, src_size, cb_mask_out);

    if (detaint_cb0_bytes)
    {
        detaint_on_cb0(shad, dest, src_size);
    }
}

static inline TaintData mixed_labels(Shad *shad, uint64_t addr, uint64_t size,
                                     bool increment_tcn)
{
    TaintData td(shad->query_full(addr));
    for (uint64_t i = 1; i < size; ++i) {
        td = TaintData::make_union(td, shad->query_full(addr + i), false);
    }

    if (increment_tcn) td.increment_tcn();
    return td;
}

static inline void bulk_set(Shad *shad, uint64_t addr, uint64_t size,
                            TaintData td)
{
    uint64_t i;
    for (i = 0; i < size; ++i) {
        shad->set_full(addr + i, td);
    }
}

void taint_mix_compute(Shad *shad, uint64_t dest, uint64_t dest_size,
                       uint64_t src1, uint64_t src2, uint64_t src_size,
                       llvm::Instruction *ignored)
{
    TaintData td = TaintData::make_union(
            mixed_labels(shad, src1, src_size, false),
            mixed_labels(shad, src2, src_size, false),
            true);
    bulk_set(shad, dest, dest_size, td);
    taint_log("mcompute: %s[%lx+%lx] <- %lx + %lx ",
            shad->name(), dest, dest_size, src1, src2);
    taint_log_labels(shad, dest, dest_size);
}

void taint_mul_compute(Shad *shad, uint64_t dest, uint64_t dest_size,
                       uint64_t src1, uint64_t src2, uint64_t src_size,
                       llvm::Instruction *inst, uint64_t arg1_lo,
                       uint64_t arg1_hi, uint64_t arg2_lo, uint64_t arg2_hi)
{
    llvm::APInt arg1 = make_128bit_apint(arg1_hi, arg1_lo);
    llvm::APInt arg2 = make_128bit_apint(arg2_hi, arg2_lo);

    bool isTainted1 = false;
    bool isTainted2 = false;
    for (int i = 0; i < src_size; ++i) {
        isTainted1 |= shad->query(src1+i) != NULL;
        isTainted2 |= shad->query(src2+i) != NULL;
    }
    if (!isTainted1 && !isTainted2) {
        taint_log("mul_com: untainted args \n");
        return; //nothing to propagate
    } else if (!(isTainted1 && isTainted2)){ //the case we do special stuff
        llvm::APInt cleanArg = isTainted1 ? arg2 : arg1;
        taint_log("mul_com: one untainted arg 0x%.16lx%.16lx \n",
                  apint_hi_bits(cleanArg), apint_lo_bits(cleanArg));
        if (cleanArg == 0) return ; // mul X untainted 0 -> no taint prop
        else if (cleanArg == 1) { //mul X untainted 1(one) should be a parallel taint
            taint_parallel_compute(shad, dest, dest_size, src1, src2,  src_size, inst);
            taint_log("mul_com: mul X 1\n");
            return;
        }
    }
    taint_mix_compute(shad, dest, dest_size, src1, src2,  src_size, inst);
}

void taint_delete(Shad *shad, uint64_t dest, uint64_t size)
{
    taint_log("remove: %s[%lx+%lx]\n", shad->name(), dest, size);
    if (unlikely(dest >= shad->get_size())) {
        taint_log("Ignoring IO RW\n");
        return;
    }
    shad->remove(dest, size);
}

void taint_set(Shad *shad_dest, uint64_t dest, uint64_t dest_size,
               Shad *shad_src, uint64_t src)
{
    bulk_set(shad_dest, dest, dest_size, shad_src->query_full(src));
}

void taint_mix(Shad *shad, uint64_t dest, uint64_t dest_size, uint64_t src,
               uint64_t src_size, llvm::Instruction *I)
{
    TaintData td = mixed_labels(shad, src, src_size, true);
    bulk_set(shad, dest, dest_size, td);
    taint_log("mix: %s[%lx+%lx] <- %lx+%lx ",
            shad->name(), dest, dest_size, src, src_size);
    taint_log_labels(shad, dest, dest_size);

    if (I) update_cb(shad, dest, shad, src, dest_size, I);
}

static const uint64_t ones = ~0UL;

void taint_pointer_run(uint64_t src, uint64_t ptr, uint64_t dest, bool is_store, uint64_t size);

// Model for tainted pointer is to mix all the labels from the pointer and then
// union that mix with each byte of the actual copied data. So if the pointer
// is labeled [1], [2], [3], [4], and the bytes are labeled [5], [6], [7], [8],
// we get [12345], [12346], [12347], [12348] as output taint of the load/store.
void taint_pointer(Shad *shad_dest, uint64_t dest, Shad *shad_ptr, uint64_t ptr,
                   uint64_t ptr_size, Shad *shad_src, uint64_t src,
                   uint64_t size, uint64_t is_store)
{
    taint_log("ptr: %s[%lx+%lx] <- %s[%lx] @ %s[%lx+%lx]\n",
            shad_dest->name(), dest, size,
            shad_src->name(), src, shad_ptr->name(), ptr, ptr_size);

    if (unlikely(dest + size > shad_dest->get_size())) {
        taint_log("  Ignoring IO RW\n");
        return;
    } else if (unlikely(src + size > shad_src->get_size())) {
        taint_log("  Source IO.\n");
        src = ones; // ignore source.
    }

    // query taint on pointer either being read or written
    if (tainted_pointer & TAINT_POINTER_MODE_CHECK) {
        taint_pointer_run(src, ptr, dest, (bool) is_store, size);
    }

    // this is [1234] in our example
    TaintData ptr_td = mixed_labels(shad_ptr, ptr, ptr_size, false);
    if (src == ones) {
        bulk_set(shad_dest, dest, size, ptr_td);
    } else {
        for (unsigned i = 0; i < size; i++) {
            TaintData byte_td = shad_src->query_full(src + i);
            TaintData dest_td = TaintData::make_union(ptr_td, byte_td, false);

            // Unions usually destroy controlled bits. Tainted pointer is
            // a special case.
            uint8_t oldCBMask = dest_td.cb_mask;
            dest_td.cb_mask = byte_td.cb_mask;
            if (detaint_cb0_bytes && (byte_td.cb_mask == 0) && (oldCBMask != 0))
            {
                taint_delete(shad_dest, (dest + i), 1);
                taint_log("detaint: control bits 0 for 0x%lx\n",
                    (dest + i));
            }
            else
            {
                shad_dest->set_full(dest + i, dest_td);
            }
        }
    }
}

void taint_after_ld_run(uint64_t reg, uint64_t addr, uint64_t size);

// logically after taint transfer has happened for ld *or* st
void taint_after_ld(uint64_t reg, uint64_t memaddr, uint64_t size) {
    taint_after_ld_run(reg, memaddr, size);
}



void taint_sext(Shad *shad, uint64_t dest, uint64_t dest_size, uint64_t src,
                uint64_t src_size)
{
    taint_log("taint_sext\n");
    Shad::copy(shad, dest, shad, src, src_size);
    bulk_set(shad, dest + src_size, dest_size - src_size,
            shad->query_full(dest + src_size - 1));
}

// Takes a (~0UL, ~0UL)-terminated list of (value, selector) pairs.
void taint_select(Shad *shad, uint64_t dest, uint64_t size, uint64_t selector,
                  ...)
{
    va_list argp;
    uint64_t src, srcsel;

    va_start(argp, selector);
    src = va_arg(argp, uint64_t);
    srcsel = va_arg(argp, uint64_t);
    while (!(src == ones && srcsel == ones)) {
        if (srcsel == selector) { // bingo!
            if (src != ones) { // otherwise it's a constant.
                taint_log("select (copy): %s[%lx+%lx] <- %s[%lx+%lx] ",
                          shad->name(), dest, size, shad->name(), src, size);
                Shad::copy(shad, dest, shad, src, size);
                taint_log_labels(shad, dest, size);
            }
            return;
        }

        src = va_arg(argp, uint64_t);
        srcsel = va_arg(argp, uint64_t);
    }

    tassert(false && "Couldn't find selected argument!!");
}

#define cpu_off(member) (uint64_t)(&((CPUArchState *)0)->member)
#define cpu_size(member) sizeof(((CPUArchState *)0)->member)
#define cpu_endoff(member) (cpu_off(member) + cpu_size(member))
#define cpu_contains(member, offset) \
    (cpu_off(member) <= (size_t)(offset) && \
     (size_t)(offset) < cpu_endoff(member))

static void find_offset(Shad *greg, Shad *gspec, uint64_t offset,
                        uint64_t labels_per_reg, Shad **dest, uint64_t *addr)
{
#ifdef TARGET_PPC
    if (cpu_contains(gpr, offset)) {
#elif defined TARGET_MIPS
    if (cpu_contains(active_tc.gpr, offset)) {
#else
    if (cpu_contains(regs, offset)) {
#endif
        *dest = greg;
#ifdef TARGET_PPC
        *addr = (offset - cpu_off(gpr)) * labels_per_reg / sizeof(((CPUArchState *)0)->gpr[0]);
#elif defined TARGET_MIPS
        // env->active_tc.gpr
        *addr = (offset - cpu_off(active_tc.gpr)) * labels_per_reg / sizeof(((CPUArchState *)0)->active_tc.gpr[0]);
#else
        *addr = (offset - cpu_off(regs)) * labels_per_reg / sizeof(((CPUArchState *)0)->regs[0]);
#endif
    } else {
        *dest= gspec;
        *addr= offset;
    }
}

bool is_irrelevant(int64_t offset) {
#ifdef TARGET_I386
    bool relevant = cpu_contains(regs, offset) ||
        cpu_contains(eip, offset) ||
        cpu_contains(fpregs, offset) ||
        cpu_contains(xmm_regs, offset) ||
        cpu_contains(xmm_t0, offset) ||
        cpu_contains(mmx_t0, offset) ||
        cpu_contains(cc_dst, offset) ||
        cpu_contains(cc_src, offset) ||
        cpu_contains(cc_src2, offset) ||
        cpu_contains(cc_op, offset) ||
        cpu_contains(df, offset);
    return !relevant;
#else
    return offset < 0 || (size_t)offset >= sizeof(CPUArchState);
#endif
}

// This should only be called on loads/stores from CPUArchState.
void taint_host_copy(uint64_t env_ptr, uint64_t addr, Shad *llv,
                     uint64_t llv_offset, Shad *greg, Shad *gspec, Shad *mem,
                     uint64_t size, uint64_t labels_per_reg, bool is_store)
{
    Shad *shad_src = NULL;
    uint64_t src = UINT64_MAX;
    Shad *shad_dest = NULL;
    uint64_t dest = UINT64_MAX;

    int64_t offset = addr - env_ptr;

    if (true == is_ram_ptr(addr)) {
        ram_addr_t ram_addr;
        __attribute__((unused)) RAMBlock *ram_block = qemu_ram_block_from_host(
            reinterpret_cast<void *>(addr), false, &ram_addr);
        assert(NULL != ram_block);

        shad_src = is_store ? llv : mem;
        src = is_store ? llv_offset : ram_addr;
        shad_dest = is_store ? mem : llv;
        dest = is_store ? ram_addr : llv_offset;
    } else if (is_irrelevant(offset)) {
        // Irrelevant
        taint_log("hostcopy: irrelevant\n");
        return;
    } else {
        Shad *state_shad = NULL;
        uint64_t state_addr = 0;

        find_offset(greg, gspec, (uint64_t)offset, labels_per_reg, &state_shad,
                    &state_addr);

        shad_src = is_store ? llv : state_shad;
        src = is_store ? llv_offset : state_addr;
        shad_dest = is_store ? state_shad : llv;
        dest = is_store ? state_addr : llv_offset;
    }
    taint_log("hostcopy: %s[%lx+%lx] <- %s[%lx+%lx] ", shad_dest->name(), dest,
              size, shad_src->name(), src, size);
    taint_log_labels(shad_src, src, size);
    Shad::copy(shad_dest, dest, shad_src, src, size);
}

void taint_host_memcpy(uint64_t env_ptr, uint64_t dest, uint64_t src,
                       Shad *greg, Shad *gspec, uint64_t size,
                       uint64_t labels_per_reg)
{
    int64_t dest_offset = dest - env_ptr, src_offset = src - env_ptr;
    if (dest_offset < 0 || (size_t)dest_offset >= sizeof(CPUArchState) ||
            src_offset < 0 || (size_t)src_offset >= sizeof(CPUArchState)) {
        taint_log("hostmemcpy: irrelevant\n");
        return;
    }

    Shad *shad_dest = NULL, *shad_src = NULL;
    uint64_t addr_dest = 0, addr_src = 0;

    find_offset(greg, gspec, (uint64_t)dest_offset, labels_per_reg,
            &shad_dest, &addr_dest);
    find_offset(greg, gspec, (uint64_t)src_offset, labels_per_reg,
            &shad_src, &addr_src);

    taint_log("hostmemcpy: %s[%lx+%lx] <- %s[%lx] (offsets %lx <- %lx) ",
            shad_dest->name(), dest, size, shad_src->name(), src,
            dest_offset, src_offset);
    taint_log_labels(shad_src, addr_src, size);
    Shad::copy(shad_dest, addr_dest, shad_src, addr_src, size);
}

void taint_host_delete(uint64_t env_ptr, uint64_t dest_addr, Shad *greg,
                       Shad *gspec, uint64_t size, uint64_t labels_per_reg)
{
    int64_t offset = dest_addr - env_ptr;

    if (offset < 0 || (size_t)offset >= sizeof(CPUArchState)) {
        taint_log("hostdel: irrelevant\n");
        return;
    }
    Shad *shad = NULL;
    uint64_t dest = 0;

    find_offset(greg, gspec, offset, labels_per_reg, &shad, &dest);

    taint_log("hostdel: %s[%lx+%lx]\n", shad->name(), dest, size);

    shad->remove(dest, size);
}

// Update functions for the controlled bits mask.
// After a taint operation, we try and update the controlled bit mask to
// estimate which bits are still attacker-controlled.
// The information is stored on a byte level. LLVM operations give us the
// information on how to reconstruct word-level values. We use that information
// to reconstruct and deconstruct the full mask.
static inline CBMasks compile_cb_masks(Shad *shad, uint64_t addr, uint64_t size)
{
    // Control bit masks are assumed to have a width of CB_WIDTH, we can't
    // handle more than CB_WIDTH / 8 bytes.
    tassert(size <= (CB_WIDTH / 8));

    CBMasks result;
    for (int i = size - 1; i >= 0; i--) {
        TaintData td = shad->query_full(addr + i);
        result.cb_mask <<= 8;
        result.one_mask <<= 8;
        result.zero_mask <<= 8;
        result.cb_mask |= td.cb_mask;
        result.one_mask |= td.one_mask;
        result.zero_mask |= td.zero_mask;
    }
    return result;
}

static inline void write_cb_masks(Shad *shad, uint64_t addr, uint64_t size,
                                  CBMasks cb_masks)
{
    for (unsigned i = 0; i < size; i++) {
        TaintData td = shad->query_full(addr + i);
        td.cb_mask =
            static_cast<uint8_t>(cb_masks.cb_mask.trunc(8).getZExtValue());
        td.one_mask =
            static_cast<uint8_t>(cb_masks.one_mask.trunc(8).getZExtValue());
        td.zero_mask =
            static_cast<uint8_t>(cb_masks.zero_mask.trunc(8).getZExtValue());
        cb_masks.cb_mask = cb_masks.cb_mask.lshr(8);
        cb_masks.one_mask = cb_masks.one_mask.lshr(8);
        cb_masks.zero_mask = cb_masks.zero_mask.lshr(8);
        shad->set_full(addr + i, td);
    }
}

//seems implied via callers that for dyadic operations 'I' will have one tainted and one untainted arg
static void update_cb(Shad *shad_dest, uint64_t dest, Shad *shad_src,
                      uint64_t src, uint64_t size, llvm::Instruction *I)
{
    if (!I) return;

    // do not update masks on data that is not tainted (ie. has no labels)
    // this is because some operations cause constants to be put in the masks
    // (eg. SHL puts 1s in lower bits of zero mask), and this would then
    // generate a spurious taint change report
    bool tainted = false;
    for (uint32_t i = 0; i < size; i++) {
        if (shad_src->query(src + i) != NULL) {
            tainted = true;
        }
    }

    if (tainted) {
        CBMasks cb_masks = compile_cb_masks(shad_src, src, size);
        llvm::APInt &cb_mask = cb_masks.cb_mask;
        llvm::APInt &one_mask = cb_masks.one_mask;
        llvm::APInt &zero_mask = cb_masks.zero_mask;

        llvm::APInt orig_one_mask = one_mask, orig_zero_mask = zero_mask;
        __attribute__((unused)) llvm::APInt orig_cb_mask = cb_mask;
        std::vector<llvm::APInt> literals;
        llvm::APInt last_literal = NOT_LITERAL; // last valid literal.
        literals.reserve(I->getNumOperands());

        for (auto it = I->value_op_begin(); it != I->value_op_end(); it++) {
            const llvm::Value *arg = *it;
            const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(arg);
            llvm::APInt literal = NOT_LITERAL;
            if (NULL != CI) {
                literal = CI->getValue().zextOrSelf(CB_WIDTH);
            }
            literals.push_back(literal);
            if (literal != NOT_LITERAL)
                last_literal = literal;
        }

        static int warning_count = 0;
        if (10 > warning_count && NOT_LITERAL == last_literal) {
            fprintf(stderr,
                    "%sWARNING: Could not find last literal value, control "
                    "bits may be incorrect.\n",
                    PANDA_MSG);
            warning_count++;
            if (warning_count == 10) {
                fprintf(stderr,
                        "%sLast literal warning emitted %d times, suppressing "
                        "warning.\n",
                        PANDA_MSG, warning_count);
            }
        }

        int log2 = 0;

        unsigned int opcode = I->getOpcode();

        // guts of this function are in separate file so it can be more easily
        // tested without calling a function (which would slow things down even more)
#include "update_cb_switch.h"

        taint_log("update_cb: %s[%lx+%lx] CB (0x%.16lx%.16lx) -> "
                  "(0x%.16lx%.16lx), 0 (0x%.16lx%.16lx) -> (0x%.16lx%.16lx), 1 "
                  "(0x%.16lx%.16lx) -> (0x%.16lx%.16lx)\n",
                  shad_dest->name(), dest, size, apint_hi_bits(orig_cb_mask),
                  apint_lo_bits(orig_cb_mask), apint_hi_bits(cb_mask),
                  apint_lo_bits(cb_mask), apint_hi_bits(orig_one_mask),
                  apint_lo_bits(orig_one_mask), apint_hi_bits(one_mask),
                  apint_lo_bits(one_mask), apint_hi_bits(orig_zero_mask),
                  apint_lo_bits(orig_zero_mask), apint_hi_bits(zero_mask),
                  apint_lo_bits(zero_mask));

        write_cb_masks(shad_dest, dest, size, cb_masks);
    }

    // not sure it's possible to call update_cb with data that is unlabeled but
    // still has non-0 masks leftover from previous processing, so just in case
    // call detainter (if desired) even for unlabeled input
    if (detaint_cb0_bytes)
    {
        detaint_on_cb0(shad_dest, dest, size);
    }
}

char* hack(llvm::StringRef*);

char* hack(llvm::StringRef *s) {
  // Stringify a StringRef. For some reason s->str().c_str() was crashing?
  if (s == NULL) {
    return NULL;
  }
  if (s->empty()) {
    return NULL;
  }

  char* r = (char*)malloc(s->size()+1);
  const char* old = s->data();
  memcpy(r, old, s->size());
  r[s->size()] = 0; // Null term
  return r;
}

// Stringify LLVM Ops to Z3
// NOTE "In Z3Py, the operators <, <=, >, >=, /, % and >> correspond to the signed versions. The corresponding unsigned operators are ULT, ULE, UGT, UGE, UDiv, URem and LShR." - https://ericpony.github.io/z3py-tutorial/guide-examples.htm

bool get_mid_op(int code, char ret[]);
bool get_mid_op(int code, char ret[]) {
  // Ret should be a zero'd char[4] which we populated
  // return indicates success/failure
  // Ops to use between terms: i.e., A + B
/*
ID  LLVM-name
 8, Add
 9, FAdd
10, Sub
11, FSub
12, Mul
13, FMul
14, UDiv          SPECIAL
15, SDiv
16, FDiv
17, URem          SPECIAL
18, SRem
19, FRem

// Logical operators (integer operands)
20, Shl  // Shift left  (logical)
21, LShr // Shift right (logical)     SPECIAL
22, AShr // Shift right (arithmetic)
23, And
24, Or
25, Xor
 */

  switch(code) {
    case 8:  case 9:  ret[0] = '+'; break;
    case 10: case 11: ret[0] = '-'; break;
    case 12: case 13: ret[0] = '*'; break;
    case 15: case 16: ret[0] = '/'; break; // Note we don't use a / for unsigned div
    case 18: case 19: ret[0] = '%'; break; // Note we don't use % for unsigned rem

    // Simple shifts - << and >> (two characters)
    case 20: ret[0] = '<'; ret[1] = '<'; break;
    case 22: ret[0] = '>'; ret[1] = '>'; break;

    case 23: ret[0] = '&'; break;
    case 24: ret[0] = '|'; break;
    case 25: ret[0] = '^'; break;
    default:
              return false;
  }
  return true;
}

char * cmp_sym(int idx);
char * cmp_sym(int idx) {
  char * ret = (char*) malloc(4);
/*
ICMP_EQ    = 32,  ///< equal
ICMP_NE    = 33,  ///< not equal
ICMP_UGT   = 34,  ///< unsigned greater than
ICMP_UGE   = 35,  ///< unsigned greater or equal
ICMP_ULT   = 36,  ///< unsigned less than
ICMP_ULE   = 37,  ///< unsigned less or equal
ICMP_SGT   = 38,  ///< signed greater than
ICMP_SGE   = 39,  ///< signed greater or equal
ICMP_SLT   = 40,  ///< signed less than
ICMP_SLE   = 41,  ///< signed less or equal
 */
  // XXX: how to handle signed/unsigned compares?
  switch(idx) {
    case llvm::ICmpInst::ICMP_EQ: strncpy(ret, "==", 4); break;
    case llvm::ICmpInst::ICMP_NE: strncpy(ret, "!=", 4); break;

    case llvm::ICmpInst::ICMP_SGT: strncpy(ret, ">", 4); break;
    case llvm::ICmpInst::ICMP_SGE: strncpy(ret, ">=", 4); break;
    case llvm::ICmpInst::ICMP_SLT: strncpy(ret, "<", 4); break;
    case llvm::ICmpInst::ICMP_SLE: strncpy(ret, "<=", 4); break;

    case llvm::ICmpInst::ICMP_UGT: strncpy(ret, "UGT", 4); break;
    case llvm::ICmpInst::ICMP_UGE: strncpy(ret, "UGE", 4); break;
    case llvm::ICmpInst::ICMP_ULT: strncpy(ret, "ULT", 4); break;
    case llvm::ICmpInst::ICMP_ULE: strncpy(ret, "ULE", 4); break;

    default: strncpy(ret, "??", 4); break;
  }
  return ret;
}


char* back_slice (Shad *shad, llvm::Instruction*);
//std::string back_slice (Shad *shad, llvm::Instruction*);
//std::string back_slice (Shad *shad, llvm::Instruction* insn)
char* back_slice (Shad *shad, llvm::Instruction* insn)
{
  /* Recursively dump prior references to variables in insn
   * Base case with no variable operands: no-op
   * Normal case: recurse on operands
   *
   * For some reasons only variables/instruction references
   * are counting as operands, not constants?
   *
   * This finds the history of a variable before the compare.
   * i.e., if we load eax, sub 88 and then cmp 0, we're checking
   *  eax-88 vs 0 == eax vs 88
   */
  insn->dump();
  fflush(NULL);

    assert(insn != NULL);
    //auto this_type = v->getType();
    const char* opname = insn->getOpcodeName();
    int num_ops = insn->getNumOperands();

    //std::ostringstream str;
#define RES_SZ 1024
    char *res = (char*)malloc(RES_SZ); // XXX: probably overflowable
    char  *res_head, *res_tail;
    res_head = res;
    res_tail = res_head + RES_SZ;

    // We support cast/trunc and binary ops
    // For those, we will convert to Z3 and recurse on the prior uses
    // of each argument

    if (llvm::isa<llvm::CastInst>(insn)) {
      // CAST: grab op, new size and recurse on whatever's being cast
      llvm::CastInst *cast = llvm::dyn_cast<llvm::CastInst>(insn);
      auto dest_ty = cast->getDestTy();
      if (dest_ty->isIntegerTy()) { // Casting to int of fixed size
        llvm::IntegerType *IT = llvm::dyn_cast<llvm::IntegerType>(dest_ty);

        // Is it a truncation / zero-extend / sign extend? Or unhandled?
        if(llvm::isa<llvm::TruncInst>(insn)) {
          // XXX: extract(size, start, val) but is start ever non-zero?
          res_head+= snprintf(res_head, res_tail-res_head, "Extract(%d, 0, ", IT->getBitWidth());

        }else if (llvm::isa<llvm::ZExtInst>(insn)) {
          res_head+= snprintf(res_head, res_tail-res_head, "ZeroExt(%d, ", IT->getBitWidth());

        }else if (llvm::isa<llvm::SExtInst>(insn)) {
          res_head+= snprintf(res_head, res_tail-res_head, "SignExt(%d, ", IT->getBitWidth());

        } else { // This could also catch non-int dest_ty values
          printf("ERROR: Unhandled cast/truncation\n");
          res_head+= snprintf(res_head, res_tail-res_head, "ERROR(");
        }
      }else if (dest_ty->isPtrOrPtrVectorTy()) {
        res_head += snprintf(res_head, res_tail-res_head, "xxxptrcast(");
      }else{
        int dest_ty_id = dest_ty->getTypeID();
        res_head += snprintf(res_head, res_tail-res_head, "xxxcast(%d,", dest_ty_id);
      }

      // Now grab what's being cast and recurse - It's in operand(0)
      auto op = insn->getOperand(0);
      if (llvm::isa<llvm::Instruction>(op)) { // INSN - recurse unless it's of 'ending' type
        llvm::Instruction *i = llvm::dyn_cast<llvm::Instruction>(op);
          if (!llvm::isa<llvm::LoadInst>(i) && !llvm::isa<llvm::CallInst>(i)) {
            printf("Insn - recurse!\n");
            //std::string res = back_slice(shad, i);
            //str << res << ")";
            char* rec_res = back_slice(shad, i);
            res_head += snprintf(res_head, res_tail-res_head, "%s", rec_res);
            free(rec_res);
          }else{
            printf("INSN - terminate (pretend it's const)\n");
            //str << "constXXX" << ")";
            res_head += snprintf(res_head, res_tail-res_head, "constXXX");
          }
      }else{
        //str << "errorXXX" << ")";
        res_head += snprintf(res_head, res_tail-res_head, "errorXXX");
        printf("Non-insn?\n");
      }

    }else if (llvm::isa<llvm::BinaryOperator>(insn)) {
      // BINOP  - each arg is either const or insn. If insn recurse unless it's an 'ending' type
      llvm::BinaryOperator *binop = llvm::dyn_cast<llvm::BinaryOperator>(insn);
      // Depending on the instruction we'll want either A + B with the op in the middle
      // or UDiv(a,b) with the op as a function. UGH!
      // Only UDiv and LShr need to be functions, others are just ops in the middle

      // See Instruction.def for these IDs, can check vs things like Instruction::And
      int opcode = binop->getOpcode();
      printf("\tBINOP %d: %s\n", (int)opcode, opname);
      bool op_in_mid = true;

      // Wrap binop in parens: either (A+B) or (UDiv(A,B))
      res_head += snprintf(res_head, res_tail-res_head, "(");

      if (opcode == llvm::Instruction::UDiv || opcode == llvm::Instruction::LShr \
          || opcode == llvm::Instruction::URem) {
        // Just need OP(arg0, arg1)
        op_in_mid = false;
        if (opcode == llvm::Instruction::UDiv)
          res_head += snprintf(res_head, res_tail-res_head, "UDiv(");
        else if (opcode == llvm::Instruction::LShr)
          res_head += snprintf(res_head, res_tail-res_head, "LShr(");
        else if (opcode == llvm::Instruction::URem)
          res_head += snprintf(res_head, res_tail-res_head, "URem(");
      }

      // For each insn figure out if we need to recurse of if it's a const
      assert(num_ops == 2); // Binop - always two ops
      for (int op_idx = 0; op_idx < num_ops; op_idx++) {
        auto op = insn->getOperand(op_idx);

        if (llvm::isa<llvm::Instruction>(op)) { // INSN - recurse unless ending
          printf("\t\tBinop(%s) arg %d is insn", opname, op_idx);
          llvm::Instruction *i = llvm::dyn_cast<llvm::Instruction>(op);
          if (!llvm::isa<llvm::LoadInst>(i) && !llvm::isa<llvm::CallInst>(i)) {
            // Needs recursion
              printf(" - recurse!\n");
              //std::string res = back_slice(shad, i);
              //str << res;
              char* rec_res = back_slice(shad, i);
              res_head += snprintf(res_head, res_tail-res_head, "%s", rec_res);
              free(rec_res);

          }else if (llvm::isa<llvm::LoadInst>(i)){
            llvm::LoadInst *li = llvm::dyn_cast<llvm::LoadInst>(i);
            //printf(" - terminate (pretend it's const)\n");
            //str << "constXXX";
            llvm::StringRef sref = li->getName();
            char *stringified = hack(&sref);
            res_head += snprintf(res_head, res_tail-res_head, "const_%s", stringified);
            free(stringified);

            //res_head += snprintf(res_head, res_tail-res_head, "const_%s", hack());
          }else if (llvm::isa<llvm::CallInst>(i)){
            if (i->getName().empty()) {
              printf("EMPTY CALL\n");
            }else{
              printf("CALL todo %d\n", (int)i->getName().size());
            }
          }

        }else if (llvm::isa<llvm::ConstantInt>(op)) { // Constant - don't recurse
          const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(op);
          uint64_t raw_value = CI->getZExtValue();
          printf("\t\tBinop(%s) arg %d const: %ld\n", opname, op_idx, raw_value);
          //str << raw_value;
          res_head += snprintf(res_head, res_tail-res_head, "%ld", raw_value);

        }else{ // Unimplemented?
          printf("\tNon-const, unknown at %d\n", op_idx);
          //str << "non_constXXX";
          res_head += snprintf(res_head, res_tail-res_head, "non_constXXX");
        }

        if (op_idx == 0) { // Between args
          char op_char[4] = {0};
          op_char[0] = ',';
          if (op_in_mid) { // If necessary, put binop symbol in op_char
            if (!get_mid_op(opcode, op_char)) {
              op_char[0] = '?'; // Error
            }
          }
          // Insert , or binop symbol
          res_head += snprintf(res_head, res_tail-res_head, " %s ", op_char);
        }
      } // End for loop on args

    }else if (llvm::isa<llvm::CallInst>(insn)) {
      // Function calls - Not sure how to handle. Probaly need special case for
      // panda helpers?
      llvm::CallInst *CI = llvm::dyn_cast<llvm::CallInst>(insn);
      llvm::Function *F = CI->getCalledFunction();
      if (F->getName().startswith("helper_panda_")) {
        printf("FIN: panda-helper\n---\n");
      }
    }else if (llvm::isa<llvm::LoadInst>(insn)) {
      // The LOAD fills the value from qemu state - don't care
      // about qemu-loading logic that runs before here (i.e., load the
      // pointer to eax and dereference it to get the value of eax)
      printf("FIN: load\n---\n");
    }else{
      printf("OTHER INSNS %s with %d operand(s)\n", opname, num_ops);
    }

    //return str.str();
    *(res_head++) = ')';
    *(res_head++) = 0; // Null terminate
    return res;
}

char* str_value(Shad *shad, llvm::Value *v, uint64_t slot);
char* str_value(Shad *shad, llvm::Value *v, uint64_t slot) {
    /* Given a value, log if it's a const int or kick off a back_trace for an insn */
    // TODO: only log const ints if the other side of the compare is a tainted instr?
    char * result;

    if (llvm::isa<llvm::ConstantInt>(v)) {
        const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(v);
        uint64_t raw_value = CI->getZExtValue();
        result = (char*)malloc(10);
        if (NULL != CI) {
            snprintf(result, 10, "%ld", raw_value);
        }else{
            snprintf(result, 10, "??");
        }
    }else if (llvm::isa<llvm::Instruction>(v)) {
      // Tainted instruction - do a backwards slice
      if (shad->query(slot) != NULL) {
        llvm::Instruction *i = llvm::dyn_cast<llvm::Instruction>(v);
        //std::string res = back_slice(shad, i);
        result = back_slice(shad, i);
      }else{
        result = (char*)malloc(10);
        snprintf(result, 10, "no_taint");
      }
    } else {
      result = (char*)malloc(10);
      snprintf(result, 10, "???");
    }
    return result;
}
void log_tainted_cmp(Shad *shad, llvm::Instruction *I, uint64_t slot1, uint64_t slot2)
{
    llvm::CmpInst *cmpI = llvm::dyn_cast<llvm::CmpInst>(I);
    assert(cmpI && "log_tainted_cmp called on non cmpI instruction?"); // Will fail with floats

    llvm::CmpInst::Predicate p = cmpI->getPredicate();

#if 0
    // Notable predicate values
    ICMP_EQ    = 32,  ///< equal
    ICMP_NE    = 33,  ///< not equal
    ICMP_UGT   = 34,  ///< unsigned greater than
    ICMP_UGE   = 35,  ///< unsigned greater or equal
    ICMP_ULT   = 36,  ///< unsigned less than
    ICMP_ULE   = 37,  ///< unsigned less or equal
    ICMP_SGT   = 38,  ///< signed greater than
    ICMP_SGE   = 39,  ///< signed greater or equal
    ICMP_SLT   = 40,  ///< signed less than
    ICMP_SLE   = 41,  ///< signed less or equal
#endif
    // XXX when we printf %d slots sometimes they're <0 and then querying shadow memory seems to fail
    // is this a sane check?
    if ( !(((int)slot1 >= 0  && shad->query(slot1) != NULL) ||  ((int)slot2 >= 0  && shad->query(slot2) != NULL))) {
      return; // no taint
    }

    printf("\n\nTAINT COMPARE: type %d (slot1=%ld, slot2=%ld)\n\n", (int)p, slot1, slot2);

    llvm::Value *v1 = cmpI->getOperand(0);
    llvm::Value *v2 = cmpI->getOperand(1);

    // TWO OPS: If we have a const and an instr - query taint on the instr - if tainted log!
    // %12 = trunc i32 %tmp-25_v to i8
    // %tmp-25_v = sub i32 %eax_v, 88

    char* s1= str_value(shad, v1, slot1);
    char* s2 = str_value(shad, v2, slot2);
    char* cmp = cmp_sym((int)p);

    // Four special cases - usnigned comparisons where we want CMP(A,B)
    if ( p == llvm::ICmpInst::ICMP_UGT || p == llvm::ICmpInst::ICMP_UGE || \
         p == llvm::ICmpInst::ICMP_ULT || p == llvm::ICmpInst::ICMP_ULE) {
        printf("%s((%s),(%s))\n", cmp, s1, s2);

    }else {
      // Otherwise compare goes in the middle
      printf("((%s) %s (%s))\n", s1, cmp, s2);
    }

    free(cmp);
    free(s1);
    free(s2);
}
