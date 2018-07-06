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
 * 2018-MAY-07   Detaint bytes whose control mask bits all become 0
 */
 
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <cstdio>
#include <cstdarg>
#include <cassert>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "shad.h"
#include "label_set.h"
#include "taint_ops.h"

uint64_t labelset_count;

extern "C" {

extern bool tainted_pointer;
extern bool detaint_cb0_bytes;

}

void detaint_on_cb0(Shad *shad, uint64_t addr, uint64_t size);
void taint_delete(FastShad *shad, uint64_t dest, uint64_t size);

// Remove the taint marker from any bytes whose control mask bits go to 0.
// A 0 control mask bit means that bit does not impact the value in the byte.
// This reduces false positives by removing taint from bytes which were formerly
// tainted, but whose values are no longer controlled by any tainted data.
void detaint_on_cb0(Shad *shad, uint64_t addr, uint64_t size)
{
    uint64_t curAddr = 0;
    for (int i = 0; i < size; i++)
    {
        curAddr = addr + i;
        TaintData td = shad->query_full(curAddr);
        if (td.cb_mask == 0)
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
    uint64_t cb_mask;
    uint64_t one_mask;
    uint64_t zero_mask;
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
    CBMasks cb_mask_out = {0};
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
    taint_log("pcompute_cb: %#lx + %#lx = %lx ",
            cb_mask_1.cb_mask, cb_mask_2.cb_mask, cb_mask_out.cb_mask);
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
                taint_log("slct\n");
                Shad::copy(shad, dest, shad, src, size);
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
#else 
    if (cpu_contains(regs, offset)) {
#endif
        *dest = greg;
#ifdef TARGET_PPC
        *addr = (offset - cpu_off(gpr)) * labels_per_reg / sizeof(((CPUArchState *)0)->gpr[0]);
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
        cpu_contains(mmx_t0, offset);
    return !relevant;
#else
    return offset < 0 || (size_t)offset >= sizeof(CPUArchState);
#endif
}

// This should only be called on loads/stores from CPUArchState.
void taint_host_copy(uint64_t env_ptr, uint64_t addr, Shad *llv,
                     uint64_t llv_offset, Shad *greg, Shad *gspec,
                     uint64_t size, uint64_t labels_per_reg, bool is_store)
{
    int64_t offset = addr - env_ptr;
    if (is_irrelevant(offset)) {
        // Irrelevant
        taint_log("hostcopy: irrelevant\n");
        return;
    }

    Shad *state_shad = NULL;
    uint64_t state_addr = 0;

    find_offset(greg, gspec, (uint64_t)offset, labels_per_reg,
            &state_shad, &state_addr);

    Shad *shad_src = is_store ? llv : state_shad;
    uint64_t src = is_store ? llv_offset : state_addr;
    Shad *shad_dest = is_store ? state_shad : llv;
    uint64_t dest = is_store ? state_addr : llv_offset;

    //taint_log("taint_host_copy\n");
    //taint_log("\tenv: %lx, addr: %lx, llv: %lx, offset: %lx\n", env_ptr, addr, llv_ptr, llv_offset);
    //taint_log("\tgreg: %lx, gspec: %lx, size: %lx, is_store: %u\n", greg_ptr, gspec_ptr, size, is_store);
    taint_log("hostcopy: %s[%lx+%lx] <- %s[%lx] (offset %lx) ",
            shad_dest->name(), dest, size, shad_src->name(), src, offset);
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
    taint_log_labels(shad_src, src, size);
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
    CBMasks result = {0};
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
        td.cb_mask = (uint8_t)cb_masks.cb_mask;
        td.one_mask = (uint8_t)cb_masks.one_mask;
        td.zero_mask = (uint8_t)cb_masks.zero_mask;
        cb_masks.cb_mask >>= 8;
        cb_masks.one_mask >>= 8;
        cb_masks.zero_mask >>= 8;
        shad->set_full(addr + i, td);
    }
}

static void update_cb(Shad *shad_dest, uint64_t dest, Shad *shad_src,
                      uint64_t src, uint64_t size, llvm::Instruction *I)
{
    if (!I) return;

    CBMasks cb_masks = compile_cb_masks(shad_src, src, size);
    uint64_t &cb_mask = cb_masks.cb_mask;
    uint64_t &one_mask = cb_masks.one_mask;
    uint64_t &zero_mask = cb_masks.zero_mask;

    uint64_t orig_one_mask = one_mask, orig_zero_mask = zero_mask;
    __attribute__((unused)) uint64_t orig_cb_mask = cb_mask;
    std::vector<uint64_t> literals;
    uint64_t last_literal = ~0UL; // last valid literal.
    literals.reserve(I->getNumOperands());

    for (auto it = I->value_op_begin(); it != I->value_op_end(); it++) {
        const llvm::Value *arg = *it;
        const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(arg);
        uint64_t literal = CI ? CI->getZExtValue() : ~0UL;
        literals.push_back(literal);
        if (literal != ~0UL) last_literal = literal;
    }
    int log2 = 0;

    switch (I->getOpcode()) {
        // Totally reversible cases.
        case llvm::Instruction::Sub:
            if (literals[1] == ~0UL) {
                tassert(last_literal != ~0UL);
                // first operand is a variable. so negate.
                // throw out ones/zeroes info.
                // FIXME: handle better.
                one_mask = zero_mask = 0;
                break;
            } // otherwise fall through.
        case llvm::Instruction::Add:
            tassert(last_literal != ~0UL);
            log2 = 64 - __builtin_clz(last_literal);
            // FIXME: this isn't quite right. for example, if all bits ones,
            // adding one makes all bits zero.
            one_mask &= ~((1 << log2) - 1);
            zero_mask &= ~((1 << log2) - 1);
            break;

        case llvm::Instruction::Xor:
            one_mask &= ~last_literal;
            one_mask |= last_literal & orig_zero_mask;
            zero_mask &= ~last_literal;
            zero_mask |= last_literal & orig_one_mask;
            break;

        case llvm::Instruction::ZExt:
        case llvm::Instruction::IntToPtr:
        case llvm::Instruction::PtrToInt:
        case llvm::Instruction::BitCast:
        // This one copies the existing bits and adds non-controllable bits.
        // One and zero masks too complicated to compute. Bah.
        case llvm::Instruction::SExt:
        // Copies. These we ignore (the copy will copy the CB data for us)
        case llvm::Instruction::Store:
        case llvm::Instruction::Load:
        case llvm::Instruction::ExtractValue:
        case llvm::Instruction::InsertValue:
            break;

        case llvm::Instruction::Trunc:
            cb_mask &= (1 << (size * 8)) - 1;
            one_mask &= (1 << (size * 8)) - 1;
            zero_mask &= (1 << (size * 8)) - 1;
            break;

        case llvm::Instruction::Mul:
        {
            tassert(last_literal != ~0UL);
            // Powers of two in last_literal destroy reversibility.
            uint64_t trailing_zeroes = __builtin_ctz(last_literal);
            cb_mask <<= trailing_zeroes;
            zero_mask = (1 << trailing_zeroes) - 1;
            one_mask = 0;
            break;
        }

        case llvm::Instruction::URem:
        case llvm::Instruction::SRem:
            tassert(last_literal != ~0UL);
            log2 = 64 - __builtin_clz(last_literal);
            cb_mask &= (1 << log2) - 1;
            one_mask = 0;
            zero_mask = 0;
            break;

        case llvm::Instruction::UDiv:
        case llvm::Instruction::SDiv:
            tassert(last_literal != ~0UL);
            log2 = 64 - __builtin_clz(last_literal);
            cb_mask >>= log2;
            one_mask = 0;
            zero_mask = 0;
            break;

        case llvm::Instruction::And:
            tassert(last_literal != ~0UL);
            // Bits not in the bit mask are no longer controllable
            cb_mask &= last_literal;
            zero_mask |= ~last_literal;
            one_mask &= last_literal;
            break;

        case llvm::Instruction::Or:
            tassert(last_literal != ~0UL);
            // Bits in the bit mask are no longer controllable
            cb_mask &= ~last_literal;
            one_mask |= last_literal;
            zero_mask &= ~last_literal;
            break;

        case llvm::Instruction::Shl:
            tassert(last_literal != ~0UL);
            cb_mask <<= last_literal;
            one_mask <<= last_literal;
            zero_mask <<= last_literal;
            zero_mask |= (1 << last_literal) - 1;
            break;

        case llvm::Instruction::LShr:
            tassert(last_literal != ~0UL);
            cb_mask >>= last_literal;
            one_mask >>= last_literal;
            zero_mask >>= last_literal;
            zero_mask |= ~((1 << (64 - last_literal)) - 1);
            break;

        case llvm::Instruction::AShr: // High bits not really controllable.
            tassert(last_literal != ~0UL);
            cb_mask >>= last_literal;
            one_mask >>= last_literal;
            zero_mask >>= last_literal;

            // See if high bit is a last_literal
            if (orig_one_mask & (1 << (size * 8 - 1))) {
                one_mask |= ~((1 << (64 - last_literal)) - 1);
            } else if (orig_zero_mask & (1 << (size * 8 - 1))) {
                zero_mask |= ~((1 << (64 - last_literal)) - 1);
            }
            break;

        // Totally irreversible cases. Erase and bail.
        case llvm::Instruction::FAdd:
        case llvm::Instruction::FSub:
        case llvm::Instruction::FMul:
        case llvm::Instruction::FDiv:
        case llvm::Instruction::FRem:
        case llvm::Instruction::Call:
        case llvm::Instruction::ICmp:
        case llvm::Instruction::FCmp:
            cb_mask = 0;
            one_mask = 0;
            zero_mask = 0;
            break;

        case llvm::Instruction::GetElementPtr:
        {
            llvm::GetElementPtrInst *GEPI =
                llvm::dyn_cast<llvm::GetElementPtrInst>(I);
            tassert(GEPI);
            one_mask = 0;
            zero_mask = 0;
            // Constant indices => fully reversible
            if (GEPI->hasAllConstantIndices()) break;
            // Otherwise we know nothing.
            cb_mask = 0;
            break;
        }

        default:
            printf("Unknown instruction in update_cb: ");
            I->dump();
            fflush(stdout);
            return;
    }

    taint_log("update_cb: %s[%lx+%lx] CB %#lx -> 0x%#lx, 0 %#lx -> %#lx, 1 %#lx -> %#lx\n",
            shad_dest->name(), dest, size, orig_cb_mask, cb_mask,
            orig_zero_mask, zero_mask, orig_one_mask, one_mask);

    write_cb_masks(shad_dest, dest, size, cb_masks);
    
    if (detaint_cb0_bytes)
    {
        detaint_on_cb0(shad_dest, dest, size);
    }
}
