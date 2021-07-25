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

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Operator.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>

#include "qemu/osdep.h"        // needed for host-utils.h
#include "qemu/host-utils.h"   // needed for clz64 and ctz64

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#define SHAD_LLVM
#include "panda/tcg-llvm.h"

#include "addr.h"
#include "shad.h"
#include "label_set.h"
#include "sym_label.h"
#include "taint2.h"
#include "taint_ops.h"
#include "taint_utils.h"
#define CONC_LVL CONC_LVL_OFF
#include "concolic.h"

extern TCGLLVMTranslator *tcg_llvm_translator;
extern ShadowState *shadow;

uint64_t labelset_count;

extern "C" {

extern bool tainted_pointer;
extern bool detaint_cb0_bytes;
extern bool symexEnabled;

}

extern z3::context context;

std::string format_hex(uint64_t n) {
    std::stringstream stream;
    stream << std::hex << n;
    std::string result( stream.str() );
    return result;
}

/* Symbolic helper functions */
bool is_concrete_byte(z3::expr byte) {

    z3::expr zero = context.bv_val(0, 8);
    z3::expr simplified = (zero == byte).simplify();

    return simplified.is_true() || simplified.is_false() ||
           byte.is_true() || byte.is_false();

}

SymLabelP get_or_alloc_sym_label(Shad *shad, uint64_t addr) {
    if (!shad->query_full(addr)->sym) {
        shad->query_full(addr)->sym = new SymLabel();
    }
    return shad->query_full(addr)->sym;
}

z3::expr get_byte(std::shared_ptr<z3::expr> ptr, uint8_t offset, uint8_t concrete_byte, bool* symbolic) {

    if (ptr == nullptr)
        return context.bv_val(concrete_byte, 8);

    if (ptr->is_bool()) {
        if (ptr->is_true()) {
            assert(concrete_byte == 1);
            return context.bv_val(1, 8);
        }
        else if (ptr->is_false()) {
            assert(concrete_byte == 0);
            return context.bv_val(0, 8);
        }
        else {
            if (symbolic) *symbolic = true;
            return ite(*ptr, context.bv_val(1, 8), context.bv_val(0, 8));
        }
    }

    z3::expr expr = ptr->extract(8*offset + 7, 8*offset).simplify();
    if (symbolic) *symbolic = true;
    // assert(!is_concrete_byte(expr));
    return expr;
}

z3::expr bytes_to_expr(Shad *shad, uint64_t src, uint64_t size,
        uint64_t concrete, bool* symbolic) {
    z3::expr expr(context);
    for (uint64_t i = 0; i < size; i++) {
        auto src_tdp = shad->query_full(src+i)->sym;
        uint8_t concrete_byte = (concrete >> (8*i))&0xff;
        if (i == 0) {
            if (src_tdp && src_tdp->full_size > size) {
                *symbolic = true; //?
                return src_tdp->full_expr->extract(size*8-1, 0).simplify();
            }
            else if (src_tdp && src_tdp->full_size == size) {
                // std::cerr << "fast path: " << *src_tdp->full_expr << std::endl;
                *symbolic = true;
                return *src_tdp->full_expr;
            }
            else if (src_tdp && src_tdp->full_size > 0) {
                *symbolic = true;
                expr = *src_tdp->full_expr;
                i += (src_tdp->full_size - 1);
            }
            else if (src_tdp) {
                expr = get_byte(src_tdp->expr, src_tdp->offset, concrete_byte, symbolic);
            }
            else {
                expr = context.bv_val(concrete_byte, 8);
            }
        }
        else {
            if (src_tdp)
                expr = concat(get_byte(src_tdp->expr, src_tdp->offset, concrete_byte, symbolic), expr);
            else
                expr = concat(context.bv_val(concrete_byte, 8), expr);
        }
    }
    return expr.simplify();
}

void invalidate_full(Shad *shad, uint64_t src, uint64_t size) {
    auto src_tdp = shad->query_full(src)->sym;
    if (src_tdp) {
        src_tdp->full_expr = nullptr;
        src_tdp->full_size = 0;
        shad->query_full(src)->sym = nullptr;
    }
}

void copy_symbols(Shad *shad_dest, uint64_t dest, Shad *shad_src, 
        uint64_t src, uint64_t size) {

    if (size == 255)
        assert(false);
    CDEBUG(std::cerr << "copy_symbols shad src " << src << " dst " << dest << "\n");
    for (uint64_t i = 0; i < size; i++) {

        // When copy src bytes without symbolic data, make sure to clean dest byte
        if (!shad_src->query_full(src+i)->sym) {
            shad_src->query_full(dest+i)->sym = nullptr;
            continue;
        }
            
        auto src_tdp = shad_src->query_full(src+i)->sym;
        auto dst_tdp = get_or_alloc_sym_label(shad_dest, dest+i);
        assert(src_tdp && dst_tdp);

        if (i == 0) {
            if (src_tdp->full_size > size) {
                // large to small
                dst_tdp->full_expr = std::make_shared<z3::expr>(
                    src_tdp->full_expr->extract(8*size-1, 0).simplify());
                dst_tdp->full_size = size;
            }
            else if (src_tdp->full_size > 0) {
                // small to large or equal
                dst_tdp->full_expr = src_tdp->full_expr;
                dst_tdp->full_size = src_tdp->full_size;
            }
        }

        dst_tdp->expr = src_tdp->expr;
        dst_tdp->offset = src_tdp->offset;
    }
}

void expr_to_bytes(z3::expr expr, Shad *shad, uint64_t dest, 
        uint64_t size) {
    std::shared_ptr<z3::expr> ptr = std::make_shared<z3::expr>(expr);
    for (uint64_t i = 0; i < size; i++) {
        auto dst_tdp = get_or_alloc_sym_label(shad, dest+i);
        if (i == 0 && size != 1) {
            dst_tdp->full_expr = ptr;
            dst_tdp->full_size = size;
        }
        dst_tdp->expr = ptr;
        dst_tdp->offset = i;
    }
}

z3::expr icmp_compute(uint64_t pred, z3::expr expr1, z3::expr expr2) {

    llvm::CmpInst::Predicate p = (llvm::CmpInst::Predicate) pred;
    switch(p) {
        case llvm::ICmpInst::ICMP_EQ:
            return expr1 == expr2;
        case llvm::ICmpInst::ICMP_NE:
            return expr1 != expr2;
        case llvm::ICmpInst::ICMP_UGT:
            return z3::ugt(expr1, expr2);
        case llvm::ICmpInst::ICMP_UGE:
            return z3::uge(expr1, expr2);
        case llvm::ICmpInst::ICMP_ULT:
            return z3::ult(expr1, expr2);
        case llvm::ICmpInst::ICMP_ULE:
            return z3::ule(expr1, expr2);
        case llvm::ICmpInst::ICMP_SGT:
            return expr1 > expr2;
        case llvm::ICmpInst::ICMP_SGE:
            return expr1 >= expr2;
        case llvm::ICmpInst::ICMP_SLT:
            return expr1 < expr2;
        case llvm::ICmpInst::ICMP_SLE:
            return expr1 <= expr2;
        default:
            assert(false);
            return z3::expr(context);
    }
}

z3::expr icmp_compute(uint64_t pred, z3::expr expr1,
        uint64_t val, uint64_t nbytes) {
    assert(expr1.get_sort().is_bv());
    z3::expr expr2 = context.bv_val(val, nbytes*8);
    return icmp_compute(pred, expr1, expr2);
}

z3::expr bitop_compute(unsigned opcode, z3::expr expr1, z3::expr expr2) {
    switch(opcode) {
        case llvm::Instruction::And:
            return expr1 & expr2;
        case llvm::Instruction::Or:
            return expr1 | expr2;
        case llvm::Instruction::Xor:
            return expr1 ^ expr2;
        default:
            assert(false);
            return z3::expr(context);
    }
}

z3::expr bitop_compute(unsigned opcode, z3::expr expr1,
        uint64_t val, uint64_t nbytes) {
    assert(expr1.get_sort().is_bv());
    z3::expr expr2 = context.bv_val(val, nbytes*8);
    return bitop_compute(opcode, expr1, expr2);
}

/* taint2 functions */
PPP_PROT_REG_CB(on_taint_prop);
PPP_CB_BOILERPLATE(on_taint_prop);

void detaint_on_cb0(Shad *shad, uint64_t addr, uint64_t size);
void taint_delete(FastShad *shad, uint64_t dest, uint64_t size);

const int CB_WIDTH = 128;
const llvm::APInt NOT_LITERAL(CB_WIDTH, ~0UL, true);

static inline bool is_ram_ptr(uint64_t addr)
{
    return RAM_ADDR_INVALID !=
           qemu_ram_addr_from_host(reinterpret_cast<void *>(addr));
}

static std::vector<const llvm::ConstantInt *> getOperands(
        const uint64_t num_operands, va_list ap) {

    auto ctx = tcg_llvm_translator->getContext();

    std::vector<const llvm::ConstantInt *> operands;
    operands.reserve(num_operands);

    for(uint64_t i=0; i<num_operands; i++) {

        const uint64_t operand_size_in_bits = va_arg(ap, uint64_t);
        llvm::ConstantInt *operand = nullptr;

        if(operand_size_in_bits > 0) {

            llvm::IntegerType *intTy = nullptr;
            uint64_t lo;
            uint64_t hi;

            switch(operand_size_in_bits) {
                case 1:
                case 8:
                case 16: // small types get promoted to int
                    intTy = llvm::IntegerType::get(*ctx, operand_size_in_bits);
                    operand = llvm::ConstantInt::get(intTy,
                        va_arg(ap, unsigned int));
                    break;
                case 32:
                    intTy = llvm::IntegerType::get(*ctx, operand_size_in_bits);
                    operand = llvm::ConstantInt::get(intTy,
                        va_arg(ap, uint32_t));
                    break;
                case 64:
                    intTy = llvm::IntegerType::get(*ctx, operand_size_in_bits);
                    operand = llvm::ConstantInt::get(intTy,
                        va_arg(ap, uint64_t));
                    break;
                case 128:
                    lo = va_arg(ap, uint64_t);
                    hi = va_arg(ap, uint64_t);
                    operand = llvm::ConstantInt::get(*ctx,
                        make_128bit_apint(hi, lo));
                    break;
                default:
                    assert(false);
                    break;
            }
        }

        operands.push_back(operand);
    }
    return operands;
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
        TaintData td = *shad->query_full(curAddr);
        
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
        uint64_t src, uint64_t size, uint64_t opcode,
        uint64_t instruction_flags,
        std::vector<const llvm::ConstantInt *> &operands);

static inline CBMasks compile_cb_masks(Shad *shad, uint64_t addr,
                                       uint64_t size);
static inline void write_cb_masks(Shad *shad, uint64_t addr, uint64_t size,
                                  CBMasks value);

Addr get_addr_from_shad(Shad *shad, uint64_t shad_addr)
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
    } else {
        addr.typ = UNK;
        addr.val.ma = 0;
        addr.off = 0;
        addr.flag = (AddrFlag)0;
    }
    return addr;
}

// Taint operations
void taint_copy(Shad *shad_dest, uint64_t dest, Shad *shad_src, uint64_t src,
        uint64_t size, uint64_t opcode, uint64_t instruction_flags,
        uint64_t num_operands, ...)
{
    if (unlikely(src >= shad_src->get_size() ||
            dest >= shad_dest->get_size())) {
        taint_log("  Ignoring IO RW\n");
        return;
    }

    taint_log("copy: %s[%lx+%lx] <- %s[%lx] ", shad_dest->name(), dest, size,
        shad_src->name(), src);

    taint_log_labels(shad_src, src, size);

    va_list ap;
    va_start(ap, num_operands);
    std::vector<const llvm::ConstantInt *> operands = getOperands(num_operands,
        ap);
    va_end(ap);
    concolic_copy(shad_dest, dest, shad_src, src, size, opcode,
                    instruction_flags, operands);

    update_cb(shad_dest, dest, shad_src, src, size, opcode, instruction_flags,
        operands);

    // Taint propagation notifications.
    Addr dest_addr = get_addr_from_shad(shad_dest, dest);
    Addr src_addr = get_addr_from_shad(shad_src, src);
    PPP_RUN_CB(on_taint_prop, dest_addr, src_addr, size);
}

void taint_parallel_compute(Shad *shad, uint64_t dest, uint64_t ignored,
        uint64_t src1, uint64_t src2, uint64_t src_size, uint64_t opcode,
        uint64_t result_unused, uint64_t val1, uint64_t val2, uint64_t unused)
{
    uint64_t shad_size = shad->get_size();
    if (unlikely(dest >= shad_size || src1 >= shad_size || src2 >= shad_size)) {
        taint_log("  Ignoring IO RW\n");
        return;
    }

    taint_log("pcompute: %s[%lx+%lx] <- %lx + %lx\n",
            shad->name(), dest, src_size, src1, src2);
    uint64_t i;
    bool changed = false;
    for (i = 0; i < src_size; ++i) {
        TaintData td = TaintData::make_union(
                *shad->query_full(src1 + i),
                *shad->query_full(src2 + i), true);
        changed |= shad->set_full(dest + i, td);
    }
    // Taint propagation notifications.
    Addr dest_addr = get_addr_from_shad(shad, dest);
    Addr src1_addr = get_addr_from_shad(shad, src1);
    Addr src2_addr = get_addr_from_shad(shad, src2);
    PPP_RUN_CB(on_taint_prop, dest_addr, src1_addr, src_size);
    PPP_RUN_CB(on_taint_prop, dest_addr, src2_addr, src_size);


    // Unlike mixed computes, parallel computes guaranteed to be bitwise.
    // This means we can honestly compute CB masks; in fact we have to because
    // of the way e.g. the deposit TCG op is lifted to LLVM.
    CBMasks cb_mask_1 = compile_cb_masks(shad, src1, src_size);
    CBMasks cb_mask_2 = compile_cb_masks(shad, src2, src_size);
    CBMasks cb_mask_out;
    if (opcode == llvm::Instruction::Or) {
        cb_mask_out.one_mask = cb_mask_1.one_mask | cb_mask_2.one_mask;
        cb_mask_out.zero_mask = cb_mask_1.zero_mask & cb_mask_2.zero_mask;
        // Anything that's a literal zero in one operand will not affect
        // the other operand, so those bits are still controllable.
        cb_mask_out.cb_mask =
            (cb_mask_1.zero_mask & cb_mask_2.cb_mask) |
            (cb_mask_2.zero_mask & cb_mask_1.cb_mask);
    } else if (opcode == llvm::Instruction::And) {
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

    if (!changed || !symexEnabled) return;

    switch(opcode) {
        case llvm::Instruction::And:
        case llvm::Instruction::Or:
        case llvm::Instruction::Xor: {

            invalidate_full(shad, dest, src_size);
            for (int i = 0; i < src_size; i++) {
                uint8_t byte1 = (val1 >> (8*i))&0xff;
                uint8_t byte2 = (val2 >> (8*i))&0xff;
                bool symbolic = false;
                z3::expr expr1 = bytes_to_expr(shad, src1+i, 1, byte1, &symbolic);
                z3::expr expr2 = bytes_to_expr(shad, src2+i, 1, byte2, &symbolic);
                if (!symbolic) continue;
                z3::expr expr = bitop_compute(opcode, expr1, expr2);
                // simplify because one input may be constant
                expr = expr.simplify();
                if (!is_concrete_byte(expr))
                    expr_to_bytes(expr, shad, dest+i, 1);
            }
            break;
        }
        default: {
            CINFO(llvm::errs() << "Untracked taint_parallel_compute op: " << opcode << '\n');
        }

    }
}

static inline TaintData mixed_labels(Shad *shad, uint64_t addr, uint64_t size,
                                     bool increment_tcn)
{
    TaintData td(*shad->query_full(addr));
    for (uint64_t i = 1; i < size; ++i) {
        td = TaintData::make_union(td, *shad->query_full(addr + i), false);
    }

    if (increment_tcn) td.increment_tcn();
    return td;
}

static inline bool bulk_set(Shad *shad, uint64_t addr, uint64_t size,
                            TaintData td)
{
    uint64_t i;
    bool change = false;
    for (i = 0; i < size; ++i) {
        change |= shad->set_full(addr + i, td);
    }
    return change;
}

void taint_mix_compute(Shad *shad, uint64_t dest, uint64_t dest_size,
        uint64_t src1, uint64_t src2, uint64_t src_size, uint64_t opcode,
        uint64_t result_unused, uint64_t val1, uint64_t val2, uint64_t pred)
{
    TaintData td = TaintData::make_union(
            mixed_labels(shad, src1, src_size, false),
            mixed_labels(shad, src2, src_size, false),
            true);
    bool change = bulk_set(shad, dest, dest_size, td);
    taint_log("mcompute: %s[%lx+%lx] <- %lx + %lx ",
            shad->name(), dest, dest_size, src1, src2);
    taint_log_labels(shad, dest, dest_size);

    // Taint propagation notifications
    Addr src1_addr = get_addr_from_shad(shad, src1);
    Addr src2_addr = get_addr_from_shad(shad, src2);
    for (unsigned i = 0; i < dest_size; i++) {
        Addr dest_addr = get_addr_from_shad(shad, dest + i);
        PPP_RUN_CB(on_taint_prop, dest_addr, src1_addr, src_size);
        PPP_RUN_CB(on_taint_prop, dest_addr, src2_addr, src_size);
    }
    
    if (!change || !symexEnabled) return;

    switch(opcode) {
    case llvm::Instruction::Sub:
    case llvm::Instruction::Add:
    case llvm::Instruction::UDiv:
    case llvm::Instruction::Mul:
    {
        bool symbolic = false;
        z3::expr expr1 = bytes_to_expr(shad, src1, src_size, val1, &symbolic);
        z3::expr expr2 = bytes_to_expr(shad, src2, src_size, val2, &symbolic);

        if (!symbolic) break;

        z3::expr expr(context);
        if (opcode == llvm::Instruction::Sub)
            expr = expr1 - expr2;
        else if (opcode == llvm::Instruction::Add)
            expr = expr1 + expr2;
        else if (opcode == llvm::Instruction::UDiv)
            expr = expr1 / expr2;
        else if (opcode == llvm::Instruction::Mul)
            expr = expr1 * expr2;

        CDEBUG(std::cerr << "output expr: " << expr << "\n");

        expr_to_bytes(expr, shad, dest, src_size);
        break;
    }
    case llvm::Instruction::ICmp: {
        bool symbolic = false;
        z3::expr expr1 = bytes_to_expr(shad, src1, src_size, val1, &symbolic);
        z3::expr expr2 = bytes_to_expr(shad, src2, src_size, val2, &symbolic);

        if (!symbolic) break;
        CDEBUG(std::cerr << "Value 1: " << expr1 << "\n");
        CDEBUG(std::cerr << "Value 2: " << expr2 << "\n");
        z3::expr expr = icmp_compute(pred, expr1, expr2);
        auto sym = get_or_alloc_sym_label(shad, dest);
        sym->expr = std::make_shared<z3::expr>(expr);
        sym->offset = 0;
        break;
    }
    case llvm::Instruction::Call: {

        assert(dest_size == 2 * src_size);
        bool symbolic = false;
        z3::expr expr1 = bytes_to_expr(shad, src1, src_size, val1, &symbolic);
        z3::expr expr2 = bytes_to_expr(shad, src2, src_size, val2, &symbolic);

        if (!symbolic) break;

        CDEBUG(std::cerr << "expr1: " << expr1 << "\n");
        CDEBUG(std::cerr << "expr2: " << expr2 << "\n");
        // Assuming it's the following functions
        // llvm.uadd.with.overflow.i8
        // llvm.uadd.with.overflow.i32
        z3::expr expr = expr1 + expr2;
        CDEBUG(std::cerr << "expr: " << expr << "\n");

        expr_to_bytes(expr, shad, dest, src_size);

        z3::expr overflow = z3::ult(expr, expr1) && z3::ult(expr, expr2);
        overflow = overflow.simplify();
        CDEBUG(std::cerr << "overflow: " << overflow << "\n");
        auto dst_tdp = get_or_alloc_sym_label(shad, dest+src_size);
        if (!overflow.is_true() && !overflow.is_false()) {
            dst_tdp->expr = std::make_shared<z3::expr>(overflow);
            dst_tdp->offset = 0;
        }
        break;
    }        
    case llvm::Instruction::Shl:
    case llvm::Instruction::LShr:
    case llvm::Instruction::AShr: {

        bool symbolic = false;
        z3::expr expr(context);
        z3::expr expr1 = bytes_to_expr(shad, src1, src_size, val1, &symbolic);
        z3::expr expr2 = bytes_to_expr(shad, src2, src_size, val2, &symbolic);

        if (!symbolic) break;

        switch (opcode)
        {
        case llvm::Instruction::Shl:
            expr = shl(expr1, expr2);
            break;
        case llvm::Instruction::LShr:
            expr = lshr(expr1, expr2);
            break;
        case llvm::Instruction::AShr:
            expr = ashr(expr1, expr2);
            break;
        default:
            assert(false);
            break;
        }
        expr = expr.simplify();
        expr_to_bytes(expr, shad, dest, src_size);

        break;
    }
    default:
        CINFO(llvm::errs() << "Untracked taint_mix_compute instruction opcode: " << opcode << "\n");
        break;
    }

}

void taint_mul_compute(Shad *shad, uint64_t dest, uint64_t dest_size,
        uint64_t src1, uint64_t src2, uint64_t src_size, uint64_t arg1_lo,
        uint64_t arg1_hi, uint64_t arg2_lo, uint64_t arg2_hi,
        uint64_t opcode, uint64_t result_unused)
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
            taint_parallel_compute(shad, dest, dest_size, src1, src2, src_size,
                opcode, result_unused, arg1_lo, arg2_lo, result_unused);
            taint_log("mul_com: mul X 1\n");
            return;
        }
    }
    taint_mix_compute(shad, dest, dest_size, src1, src2,  src_size, opcode,
        result_unused, arg1_lo, arg2_lo, -1);
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
    bulk_set(shad_dest, dest, dest_size, *shad_src->query_full(src));
}

void taint_mix(Shad *shad, uint64_t dest, uint64_t dest_size, uint64_t src,
        uint64_t src_size, uint64_t concrete, uint64_t pred, uint64_t opcode,
        uint64_t instruction_flags, uint64_t num_operands, ...)
{
    TaintData td = mixed_labels(shad, src, src_size, true);
    bool change = bulk_set(shad, dest, dest_size, td);
    taint_log("mix: %s[%lx+%lx] <- %lx+%lx ",
            shad->name(), dest, dest_size, src, src_size);
    taint_log_labels(shad, dest, dest_size);

    va_list ap;
    va_start(ap, num_operands);
    std::vector<const llvm::ConstantInt *> operands = getOperands(num_operands,
        ap);
    va_end(ap);

    update_cb(shad, dest, shad, src, dest_size, opcode, instruction_flags,
        operands);

    // Taint propagation notifications.
    Addr src_addr = get_addr_from_shad(shad, src);
    for (unsigned i = 0; i < dest_size; i++) {
        Addr dest_addr = get_addr_from_shad(shad, dest + i);
        PPP_RUN_CB(on_taint_prop, dest_addr, src_addr, src_size);
    }

    if (!change || !symexEnabled) return;
    
    uint64_t val = 0;
    if (operands.size() >= 2 && (operands[0] || operands[1])) {
        val = (operands[0] ? operands[0] : operands[1])->getValue().getLimitedValue();
    }
    else {
        std::cerr << "opcode: " << opcode << "\n";
        std::cerr << "size: " << operands.size() << "\n";
    }

    switch (opcode) {
        case llvm::Instruction::ICmp: {
            CDEBUG(llvm::errs() << "Concrete Value: " << format_hex(concrete) << '\n');
            
            bool symbolic = false;
            z3::expr expr1 = bytes_to_expr(shad, src, src_size, concrete, &symbolic);

            if (!symbolic) break;
            CDEBUG(std::cerr << "Symbolic value: " << expr1 << "\n");

            z3::expr expr = icmp_compute(pred, expr1, val, src_size);

            auto sym = get_or_alloc_sym_label(shad, dest);
            sym->expr = std::make_shared<z3::expr>(expr);
            sym->offset = 0;
            break;
        }
        case llvm::Instruction::Shl:
        case llvm::Instruction::LShr:
        case llvm::Instruction::AShr: {
            assert(src_size == dest_size);

            bool symbolic = false;
            z3::expr expr = bytes_to_expr(shad, src, src_size, concrete, &symbolic);

            if (!symbolic) break;

            switch (opcode)
            {
            case llvm::Instruction::Shl:
                expr = shl(expr, context.bv_val(val, dest_size*8));
                break;
            case llvm::Instruction::LShr:
                expr = lshr(expr, context.bv_val(val, dest_size*8));
                break;
            case llvm::Instruction::AShr:
                expr = ashr(expr, context.bv_val(val, dest_size*8));
                break;
            default:
                assert(false);
                break;
            }
            expr = expr.simplify();
            expr_to_bytes(expr, shad, dest, src_size);

            break;
        }
        case llvm::Instruction::Sub:
        case llvm::Instruction::Add:
        case llvm::Instruction::UDiv:
        case llvm::Instruction::Mul:
        {
            bool symbolic = false;
            z3::expr expr = bytes_to_expr(shad, src, src_size, concrete, &symbolic);
            if (!symbolic) break;

            CDEBUG(std::cerr << "Immediate: " << val << "\n");
            CDEBUG(std::cerr << "input expr: " << expr << "\n");

            if (opcode == llvm::Instruction::Sub)
                expr = expr - context.bv_val(val, src_size*8);
            else if (opcode == llvm::Instruction::Add)
                expr = expr + context.bv_val(val, src_size*8);
            else if (opcode == llvm::Instruction::UDiv)
                expr = expr / context.bv_val(val, src_size*8);
            else if (opcode == llvm::Instruction::Mul)
                expr = expr * context.bv_val(val, src_size*8);

                
            CDEBUG(std::cerr << "output expr: " << expr << "\n");

            expr_to_bytes(expr, shad, dest, src_size);
            break;
        }
        default:
            llvm::errs() << "Untracked taint_mix opcode: " << opcode << "\n";
            break;
    }

}

static const uint64_t ones = UINT64_C(~0);

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

        // Taint propagation notifications.
        Addr ptr_addr = get_addr_from_shad(shad_ptr, ptr);
        for (unsigned i = 0; i < size; i++) {
            Addr dest_addr = get_addr_from_shad(shad_dest, dest + i);
            PPP_RUN_CB(on_taint_prop, dest_addr, ptr_addr, ptr_size);
        }
    } else {
        bool change = false;
        for (unsigned i = 0; i < size; i++) {
            TaintData byte_td = *shad_src->query_full(src + i);
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
                change |= shad_dest->set_full(dest + i, dest_td);

                // Taint propagation notifications.
                Addr dest_addr = get_addr_from_shad(shad_dest, dest + i);
                Addr src_addr = get_addr_from_shad(shad_src, src + i);
                PPP_RUN_CB(on_taint_prop, dest_addr, src_addr, 1);
                Addr ptr_addr = get_addr_from_shad(shad_ptr, ptr);
                PPP_RUN_CB(on_taint_prop, dest_addr, ptr_addr, ptr_size);
            }
        }
        if (change && symexEnabled) {
            copy_symbols(shad_dest, dest, shad_src, src, size);
        }
    }
}

void taint_after_ld_run(uint64_t reg, uint64_t addr, uint64_t size);

// logically after taint transfer has happened for ld *or* st
void taint_after_ld(uint64_t reg, uint64_t memaddr, uint64_t size) {
    taint_after_ld_run(reg, memaddr, size);
}



void taint_sext(Shad *shad, uint64_t dest, uint64_t dest_size, uint64_t src,
                uint64_t src_size, uint64_t opcode)
{
    taint_log("taint_sext\n");
    concolic_copy(shad, dest, shad, src, src_size, llvm::Instruction::SExt, 0, {});
    bulk_set(shad, dest + src_size, dest_size - src_size,
            *shad->query_full(dest + src_size - 1));
    auto src_tdp = shad->query_full(dest + src_size - 1)->sym;
    if (src_tdp && src_tdp->expr) {
        z3::expr top_byte = get_byte(src_tdp->expr, src_tdp->offset, 0, nullptr);
        z3::expr expr = ite(
                (top_byte & 0x80) == context.bv_val(0x80, 8), 
                context.bv_val(0xff, 8), context.bv_val(0, 8));
        expr = expr.simplify();
        std::shared_ptr<z3::expr> ptr = std::make_shared<z3::expr>(expr);
        for (uint64_t i = dest + src_size; i < dest + dest_size; i++) {
            auto dst_tdp = get_or_alloc_sym_label(shad, i);
            dst_tdp->expr = ptr;
            dst_tdp->offset = 0;
        }

    }
}

// Takes a (~0UL, ~0UL)-terminated list of (value, selector) pairs.
void taint_select(Shad *shad, uint64_t dest, uint64_t size, uint64_t selector, ...)
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
                concolic_copy(shad, dest, shad, src, size, llvm::Instruction::Select, 0, {});
                taint_log_labels(shad, dest, size);
                //Shad::copy(shad, dest, shad, src, size);
                Addr dest_addr = get_addr_from_shad(shad, dest);
                Addr src_addr = get_addr_from_shad(shad, src);
                PPP_RUN_CB(on_taint_prop, dest_addr, src_addr, size);
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
    concolic_copy(shad_dest, dest, shad_src, src, size, 0, 0, {});
    // Taint propagation notifications.
    Addr dest_addr = get_addr_from_shad(shad_dest, dest);
    Addr src_addr = get_addr_from_shad(shad_src, src);
    PPP_RUN_CB(on_taint_prop, dest_addr, src_addr, size);
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
    concolic_copy(shad_dest, addr_dest, shad_src, addr_src, size, 0, 0, {});
    // Taint propagation notifications.
    Addr dest_addr = get_addr_from_shad(shad_dest, dest);
    Addr src_addr = get_addr_from_shad(shad_src, src);
    PPP_RUN_CB(on_taint_prop, dest_addr, src_addr, size);
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
        TaintData td = *shad->query_full(addr + i);
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
        TaintData td = *shad->query_full(addr + i);
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
        uint64_t src, uint64_t size, uint64_t opcode,
        uint64_t instruction_flags,
        std::vector<const llvm::ConstantInt *> &operands)
{
    if (!opcode) return;

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
        literals.reserve(operands.size());

        for (auto operand : operands) {
            llvm::APInt literal = NOT_LITERAL;
            if (nullptr != operand) {
                literal = operand->getValue().zextOrSelf(CB_WIDTH);
            }
            literals.push_back(literal);
            if (literal != NOT_LITERAL) {
                last_literal = literal;
            }
        }

        int log2 = 0;

        // guts of this function are in separate file so it can be more easily
        // tested without calling a function (which would slow things down even more)
#include "update_cb_switch.h"

        taint_log("update_cb: %s[%lx+%lx] CB (0x%.16lx%.16lx) -> "
                  "(0x%.16lx%.16lx), 0 (0x%.16lx%.16lx) -> (0x%.16lx%.16lx), 1 "
                  "(0x%.16lx%.16lx) -> (0x%.16lx%.16lx)\n",
                  shad_dest->name(), dest, size, apint_hi_bits(orig_cb_mask),
                  apint_lo_bits(orig_cb_mask), apint_hi_bits(cb_mask),
                  apint_lo_bits(cb_mask), apint_hi_bits(orig_zero_mask),
                  apint_lo_bits(orig_zero_mask), apint_hi_bits(zero_mask),
                  apint_lo_bits(zero_mask), apint_hi_bits(orig_one_mask),
                  apint_lo_bits(orig_one_mask), apint_hi_bits(one_mask),
                  apint_lo_bits(one_mask));

        write_cb_masks(shad_dest, dest, size, cb_masks);
    }

    // not sure it's possible to call update_cb with data that is unlabeled but
    // still has non-0 masks leftover from previous processing, so just in case
    // call detainter (if desired) even for unlabeled input
    if (detaint_cb0_bytes) {
        detaint_on_cb0(shad_dest, dest, size);
    }
}

void concolic_copy(Shad *shad_dest, uint64_t dest, Shad *shad_src,
                     uint64_t src, uint64_t size, uint64_t opcode,
                     uint64_t instruction_flags,
                     std::vector<const llvm::ConstantInt *> operands)
{
    uint64_t val = 0;
    if (operands.size() >= 2 && (operands[0] || operands[1])) {
        val = (operands[0] ? operands[0] : operands[1])->getValue().getLimitedValue();
    }

    bool change = false;
    if (opcode && (opcode == llvm::Instruction::And ||
            opcode == llvm::Instruction::Or)) {
        // Perform byte-level copy for bitwise and/or
        assert(operands.size() >= 2);

        for (uint64_t i = 0; i < size; i++) {
            uint8_t mask = (val >> (8*i))&0xff;
            if (opcode == llvm::Instruction::And) {
                if (mask == 0)
                    change |= shad_dest->set_full(dest + i, TaintData());
                else
                    change |= shad_dest->set_full(dest + i, *shad_src->query_full(src+i));
            }
            else if (opcode == llvm::Instruction::Or) {
                if (mask == 0xff)
                    change |= shad_dest->set_full(dest + i, TaintData());
                else
                    change |= shad_dest->set_full(dest + i, *shad_src->query_full(src+i));
            }
        }
    }
    else {
        // Otherwise, copy together
        change = Shad::copy(shad_dest, dest, shad_src, src, size);
    }
    if (!change || !symexEnabled) return;
    switch (opcode) {
        case llvm::Instruction::And:
        case llvm::Instruction::Or:
        case llvm::Instruction::Xor: {
            CDEBUG(llvm::errs() << "Value: " << val << '\n');
            bool symbolic = false;
            invalidate_full(shad_dest, dest, size);
            for (int i = 0; i < size; i++) {
                uint8_t mask = (val >> (8*i))&0xff;
                // concrete value does not matter here (just use 0)
                // because concrete bytes won't propagate
                z3::expr expr1 = bytes_to_expr(shad_src, src+i, 1, 0, &symbolic);
                z3::expr expr = bitop_compute(opcode, expr1, mask, 1);
                // simplify because one input is constant
                expr = expr.simplify();
                expr_to_bytes(expr, shad_dest, dest+i, 1);

            }
            break;
        }
        // shift by zero bits got here
        case llvm::Instruction::Shl:
        case llvm::Instruction::LShr:
        case llvm::Instruction::AShr:
        case llvm::Instruction::SExt:
            // Higher bits handled by caller
        case llvm::Instruction::Trunc:
        case llvm::Instruction::ZExt:
        case llvm::Instruction::Load:
        case llvm::Instruction::Store:
        case llvm::Instruction::IntToPtr:
        case llvm::Instruction::PtrToInt:
        case 0:
            // From host_copy, host_memcpy
        case llvm::Instruction::ExtractValue:
            // Assuming extract value from following result
            // llvm.uadd.with.overflow.i8
            // llvm.uadd.with.overflow.i16
            // llvm.uadd.with.overflow.i32
            copy_symbols(shad_dest, dest, shad_src, src, size);
            break;
        default:
            CINFO(llvm::errs() << "Untracked opcode: " << opcode << "\n");
            break;
    }
}