#include <cstddef>
#include <iostream>
#include <map>
#include <memory>
#include <unordered_map>

#include <capstone/capstone.h>

#include "Block.h"
#include "Edge.h"
#include "EdgeInstrumentationDelegate.h"
#include "RecordProcessor.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "osi/os_intro.h"

#include "panda/tcg-utils.h"

namespace coverage
{

using RegisterFetcher = std::function<target_ulong()>;

#ifdef TARGET_I386
static target_ulong fetch_register_value(size_t cpu_offset, target_ulong mask, target_ulong shr)
{
    CPUArchState *env = static_cast<CPUArchState *>(first_cpu->env_ptr);
    return (*(reinterpret_cast<target_ulong *>((env + cpu_offset))) & mask) >> shr;
}
#define MK_REG_FETCHER(cpu_state_variable, mask, shift_right) std::bind(fetch_register_value, offsetof(CPUArchState, cpu_state_variable), mask, shift_right)

static target_ulong fetch_segment_value(size_t cpu_offset)
{
    CPUArchState *env = static_cast<CPUArchState *>(first_cpu->env_ptr);
    return reinterpret_cast<SegmentCache*>((env + cpu_offset))->base;
}
#define MK_SEG_FETCHER(cpu_state_variable) std::bind(fetch_segment_value, offsetof(CPUArchState, cpu_state_variable))

#endif

std::unordered_map<x86_reg, RegisterFetcher> CS_TO_QEMU_REG_FETCH = {
#ifdef TARGET_I386
    { X86_REG_AH, MK_REG_FETCHER(regs[R_EAX], 0x0000FF00, 8) },
    { X86_REG_AL, MK_REG_FETCHER(regs[R_EAX], 0x000000FF, 0) },
    { X86_REG_AX, MK_REG_FETCHER(regs[R_EAX], 0x0000FFFF, 0) },
    { X86_REG_EAX, MK_REG_FETCHER(regs[R_EAX], 0xFFFFFFFF, 0) },

    { X86_REG_BH, MK_REG_FETCHER(regs[R_EBX], 0x0000FF00, 8) },
    { X86_REG_BL, MK_REG_FETCHER(regs[R_EBX], 0x000000FF, 0) },
    { X86_REG_BX, MK_REG_FETCHER(regs[R_EBX], 0x0000FFFF, 0) },
    { X86_REG_EBX, MK_REG_FETCHER(regs[R_EBX], 0xFFFFFFFF, 0) },

    { X86_REG_CH, MK_REG_FETCHER(regs[R_ECX], 0x0000FF00, 8) },
    { X86_REG_CL, MK_REG_FETCHER(regs[R_ECX], 0x000000FF, 0) },
    { X86_REG_CX, MK_REG_FETCHER(regs[R_ECX], 0x0000FFFF, 0) },
    { X86_REG_ECX, MK_REG_FETCHER(regs[R_ECX], 0xFFFFFFFF, 0) },

    { X86_REG_DH, MK_REG_FETCHER(regs[R_ECX], 0x0000FF00, 8) },
    { X86_REG_DL, MK_REG_FETCHER(regs[R_ECX], 0x000000FF, 0) },
    { X86_REG_DX, MK_REG_FETCHER(regs[R_ECX], 0x0000FFFF, 0) },
    { X86_REG_EDX, MK_REG_FETCHER(regs[R_ECX], 0xFFFFFFFF, 0) },

    { X86_REG_ESI, MK_REG_FETCHER(regs[R_ESI], 0xFFFFFFFF, 0) },

    { X86_REG_EDI, MK_REG_FETCHER(regs[R_EDI], 0xFFFFFFFF, 0) },

    { X86_REG_SP, MK_REG_FETCHER(regs[R_ESP], 0x0000FFFF, 0) },
    { X86_REG_ESP, MK_REG_FETCHER(regs[R_ESP], 0xFFFFFFFF, 0) },

    { X86_REG_BP, MK_REG_FETCHER(regs[R_EBP], 0x0000FFFF, 0) },
    { X86_REG_EBP, MK_REG_FETCHER(regs[R_EBP], 0xFFFFFFFF, 0) },

    { X86_REG_GS, MK_SEG_FETCHER(segs[R_GS]) },

#ifdef TARGET_X86_64
    { X86_REG_RAX, MK_REG_FETCHER(regs[R_EAX], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RBX, MK_REG_FETCHER(regs[R_EBX], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RCX, MK_REG_FETCHER(regs[R_ECX], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RDX, MK_REG_FETCHER(regs[R_EDX], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RBP, MK_REG_FETCHER(regs[R_EBP], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_R9, MK_REG_FETCHER(regs[9], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_R10, MK_REG_FETCHER(regs[10], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_R11, MK_REG_FETCHER(regs[11], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_R12, MK_REG_FETCHER(regs[12], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_R13, MK_REG_FETCHER(regs[13], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_R14, MK_REG_FETCHER(regs[14], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_R15, MK_REG_FETCHER(regs[15], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RIP, MK_REG_FETCHER(eip, 0xFFFFFFFFFFFFFFFF, 0) },
#endif
#endif
};

struct JumpTargets
{
    bool has_dst1;
    target_ulong dst1;
    bool has_dst2;
    target_ulong dst2;
};

static bool cov_enabled = true;

// Maps Thread ID -> (previous) Block
static std::unordered_map<target_pid_t, Block> prev_blocks;
static Block* prev_block = nullptr;

// Maps Thread ID -> Jump Targets
static std::map<target_pid_t, JumpTargets> next_block_addrs;
//static std::unordered_map<target_pid_t, JumpTargets> next_block_addrs;

//static std::unique_ptr<OsiThread, decltype(free_osithread)*> current_thread(nullptr, free_osithread);
static JumpTargets* jump_target_set = nullptr;

/*static void task_change_callback(CPUState *cpu)
{
    current_thread.reset(get_current_thread(cpu));

    // jump target set
    auto ins_res = next_block_addrs.insert({ current_thread->tid, {
        .has_dst1 = false,
        .dst1 = 0x0,
        .has_dst2 = false,
        .dst2 = 0x0
    } });
    jump_target_set = &ins_res.first->second;

    // previous block
    auto pb_ins_res = prev_blocks.insert({ current_thread->tid, {} });
    prev_block = &pb_ins_res.first->second;
}*/


static void block_callback(RecordProcessor<Edge> *ep, TranslationBlock *tb)
{
    if (((!jump_target_set->has_dst1) || tb->pc != jump_target_set->dst1) &&
        ((!jump_target_set->has_dst2) || tb->pc != jump_target_set->dst2)) {
        return;
    }

    // Construct an edge and pass it to the edge processor.
    Block to_block {
        .addr = tb->pc,
        .size = tb->size
    };
    Edge edge {
        .from = *prev_block,
        .to = to_block
    };
    ep->handle(edge);
}

static void update_jump_targets(target_ulong prev_block_addr, target_ulong prev_block_size, const JumpTargets& jmp_targets)
{
    *jump_target_set = jmp_targets;

    // Update previous block for current thread.
    prev_block->addr = prev_block_addr;
    prev_block->size = prev_block_size;
}

/* Called right before a Jcc (JG, JNE, etc) instruction.
 *
 * Note that on x86, jump targets for Jcc instructions can always be determined
 * statically since the jump target is relative to the current PC, so there's
 * only one function to handle Jcc instructions. */
static void jcc_callback(target_ulong prev_block_addr,
                         target_ulong prev_block_size,
                         target_ulong next_insn_addr,
                         target_ulong jump_tgt_addr)
{
    if (!cov_enabled) {
        return;
    }

    update_jump_targets(prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = next_insn_addr,
        .has_dst2 = true,
        .dst2 = jump_tgt_addr
    });
}

// Called for JMP instructions where the jump target was resolved from static
// analysis.
static void static_jmp_callback(target_ulong prev_block_addr,
                                target_ulong prev_block_size,
                                target_ulong jump_tgt_addr)
{
    if (!cov_enabled) {
        return;
    }
    update_jump_targets(prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_tgt_addr,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void jmp_mem_direct_callback(CPUState *cpu, target_ulong prev_block_addr, target_ulong prev_block_size, target_ulong direct_address)
{
    if (!cov_enabled) {
        return;
    }
    target_ulong jump_target = 0x0;
    panda_virtual_memory_read(cpu, direct_address, (uint8_t *)&jump_target, sizeof(jump_target));
    update_jump_targets(prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_target,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}
#ifdef TARGET_I386
static void jmp_mem_indexed_callback(CPUState *cpu, target_ulong prev_block_addr, target_ulong prev_block_size, RegisterFetcher* index_register_fetcher, int scale, int64_t disp)
{
    if (!cov_enabled) {
        return;
    }
    target_ulong address = (*index_register_fetcher)() * scale + disp;
    target_ulong jump_target = 0x0;
    panda_virtual_memory_read(cpu, address, (uint8_t *)&jump_target, sizeof(jump_target));
    update_jump_targets(prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_target,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void jmp_mem_indirect(CPUState *cpu, target_ulong prev_block_addr, target_ulong prev_block_size, RegisterFetcher* base_register_fetch, int64_t disp)
{
    if (!cov_enabled) {
        return;
    }
    target_ulong address = (*base_register_fetch)() + disp;
    target_ulong jump_target = 0x0;
    panda_virtual_memory_read(cpu, address, (uint8_t *)&jump_target, sizeof(jump_target));
    update_jump_targets(prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_target,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void jmp_mem_indirect_disp_si_callback(CPUState *cpu, target_ulong prev_block_addr, target_ulong prev_block_size, RegisterFetcher *base_register_fetch, int64_t disp, RegisterFetcher *index_register_fetch, int scale)
{
    if (!cov_enabled) {
        return;
    }
    target_ulong address = (*base_register_fetch)() + disp + (*index_register_fetch)() * scale;
    target_ulong jump_target = 0x0;
    panda_virtual_memory_read(cpu, address, (uint8_t *)&jump_target, sizeof(jump_target));
    update_jump_targets(prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_target,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void jmp_reg_callback(CPUState *cpu,
                                target_ulong prev_block_addr,
                                target_ulong prev_block_size,
                                RegisterFetcher *reg_fetch)
{
    if (!cov_enabled) {
        return;
    }
    target_ulong jump_tgt_addr = (*reg_fetch)();
    update_jump_targets(prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_tgt_addr,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void ret_callback(CPUState *cpu,
                         target_ulong prev_block_addr,
                         target_ulong prev_block_size)
{
    if (!cov_enabled) {
        return;
    }

    // Read the return target address off the stack.
    CPUArchState *env_ptr = static_cast<CPUArchState *>(cpu->env_ptr);
    target_ulong return_addr = 0x0;
    panda_virtual_memory_read(cpu, env_ptr->regs[R_ESP], (uint8_t *)&return_addr, sizeof(return_addr));
    update_jump_targets(prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = return_addr,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}
#endif

static uint64_t resolve_static_jump_target(cs_insn *insn)
{
    assert(X86_OP_IMM == insn->detail->x86.operands[0].type);
    return insn->detail->x86.operands[0].imm;
}

static void instrument_jcc(CPUState *cpu, TCGOp *op, TranslationBlock *tb, cs_insn *insn)
{
    uint64_t jump_target_addr = resolve_static_jump_target(insn);
    uint64_t next_insn_addr = insn->address + insn->size;
    insert_call(&op, &jcc_callback, tb->pc, tb->size, next_insn_addr, jump_target_addr);
}

static void instrument_jmp(CPUState *cpu, TCGOp *op, TranslationBlock *tb, cs_insn *insn)
{
    if (X86_OP_IMM == insn->detail->x86.operands[0].type) {
        uint64_t jump_target_addr = resolve_static_jump_target(insn);
        insert_call(&op, static_jmp_callback, tb->pc, tb->size, jump_target_addr);
    } else if (X86_OP_MEM == insn->detail->x86.operands[0].type) {
        /*printf("JMP @ 0x%lX (segment=%u base=%u index=%u scale=%d disp=%ld)\n", insn->address,
            insn->detail->x86.operands[0].mem.segment,
            insn->detail->x86.operands[0].mem.base,
            insn->detail->x86.operands[0].mem.index,
            insn->detail->x86.operands[0].mem.scale,
            insn->detail->x86.operands[0].mem.disp); */

        //assert(insn->detail->x86.operands[0].mem.segment == X86_REG_INVALID);

        if (X86_REG_INVALID == insn->detail->x86.operands[0].mem.segment &&
            X86_REG_INVALID == insn->detail->x86.operands[0].mem.base &&
            X86_REG_INVALID == insn->detail->x86.operands[0].mem.index) {
            // direct addressing
            insert_call(&op, jmp_mem_direct_callback, cpu, tb->pc, tb->size, static_cast<target_ulong>(insn->detail->x86.operands[0].mem.disp));
        } else if (X86_REG_INVALID == insn->detail->x86.operands[0].mem.segment &&
                   X86_REG_INVALID == insn->detail->x86.operands[0].mem.index) {
#ifdef TARGET_I386
            // indirect addressing
            auto base_register_fetch = &CS_TO_QEMU_REG_FETCH.at(static_cast<x86_reg>(insn->detail->x86.operands[0].mem.base));
            insert_call(&op, jmp_mem_indirect, cpu, tb->pc, tb->size, base_register_fetch, insn->detail->x86.operands[0].mem.disp); 
#endif
        } else if (X86_REG_INVALID == insn->detail->x86.operands[0].mem.segment &&
                   X86_REG_INVALID == insn->detail->x86.operands[0].mem.base) {
#ifdef TARGET_I386
            // indexed addressing
            RegisterFetcher *index_register_fetcher = &CS_TO_QEMU_REG_FETCH.at(static_cast<x86_reg>(insn->detail->x86.operands[0].mem.index));
            insert_call(&op, jmp_mem_indexed_callback, cpu, tb->pc, tb->size, index_register_fetcher, insn->detail->x86.operands[0].mem.scale, insn->detail->x86.operands[0].mem.disp);
#endif
        } else if (X86_REG_INVALID != insn->detail->x86.operands[0].mem.segment &&
                   X86_REG_INVALID == insn->detail->x86.operands[0].mem.base &&
                   X86_REG_INVALID == insn->detail->x86.operands[0].mem.index) {
#ifdef TARGET_I386
            RegisterFetcher *srf = &CS_TO_QEMU_REG_FETCH.at(static_cast<x86_reg>(insn->detail->x86.operands[0].mem.segment));
            insert_call(&op, jmp_mem_indirect, cpu, tb->pc, tb->size, srf, insn->detail->x86.operands[0].mem.disp);
#endif
        } else {
#ifdef TARGET_I386
            // indirect with displacement and scaled-index
            RegisterFetcher *base_register_fetch = &CS_TO_QEMU_REG_FETCH.at(static_cast<x86_reg>(insn->detail->x86.operands[0].mem.base));
            RegisterFetcher *index_register_fetch = &CS_TO_QEMU_REG_FETCH.at(static_cast<x86_reg>(insn->detail->x86.operands[0].mem.index));
            insert_call(&op, jmp_mem_indirect_disp_si_callback, cpu, tb->pc, tb->size, base_register_fetch, insn->detail->x86.operands[0].mem.disp, index_register_fetch, insn->detail->x86.operands[0].mem.scale);
#endif

        }
    } else if (X86_OP_REG == insn->detail->x86.operands[0].type) {
#ifdef TARGET_I386
        auto reg_fetcher = &CS_TO_QEMU_REG_FETCH.at(static_cast<x86_reg>(insn->detail->x86.operands[0].reg));
        insert_call(&op, jmp_reg_callback, cpu, tb->pc, tb->size, reg_fetcher);
#endif
    }
}

static void instrument_ret(CPUState *cpu, TCGOp *op, TranslationBlock *tb, cs_insn *insn)
{
#ifdef TARGET_I386
    insert_call(&op, ret_callback, cpu, tb->pc, tb->size);
#endif
}

const std::unordered_map<unsigned int, void(*)(CPUState *, TCGOp *, TranslationBlock *, cs_insn *)> INSN_HANDLERS = {
    { X86_INS_JAE, instrument_jcc },
    { X86_INS_JA, instrument_jcc },
    { X86_INS_JBE, instrument_jcc },
    { X86_INS_JB, instrument_jcc },
    { X86_INS_JCXZ, instrument_jcc },
    { X86_INS_JECXZ, instrument_jcc },
    { X86_INS_JE, instrument_jcc },
    { X86_INS_JGE, instrument_jcc },
    { X86_INS_JG, instrument_jcc },
    { X86_INS_JLE, instrument_jcc },
    { X86_INS_JL, instrument_jcc },
    { X86_INS_JNE, instrument_jcc },
    { X86_INS_JNO, instrument_jcc },
    { X86_INS_JNP, instrument_jcc },
    { X86_INS_JNS, instrument_jcc },
    { X86_INS_JO, instrument_jcc },
    { X86_INS_JP, instrument_jcc },
    { X86_INS_JRCXZ, instrument_jcc },
    { X86_INS_JS, instrument_jcc },
    { X86_INS_JMP, instrument_jmp },
    { X86_INS_CALL, instrument_jmp }, // CALL instructions should be able to use the jmp callbacks
    { X86_INS_RET, instrument_ret },
    { X86_INS_LOOP, instrument_jcc }, // LOOP instructions should be able to use jcc callback
    { X86_INS_LOOPE, instrument_jcc },
    { X86_INS_LOOPNE, instrument_jcc },
};

EdgeInstrumentationDelegate::EdgeInstrumentationDelegate(std::unique_ptr<RecordProcessor<Edge>> ep) : edge_processor(std::move(ep)), capstone_initialized(false)
{
}

EdgeInstrumentationDelegate::~EdgeInstrumentationDelegate()
{
    cs_close(&handle);
}

void EdgeInstrumentationDelegate::instrument(CPUState *cpu, TranslationBlock *tb)
{
#ifdef TARGET_I386
    if (unlikely(!capstone_initialized)) {
        CPUArchState *env = static_cast<CPUArchState *>(first_cpu->env_ptr);
        if (!(env->cr[0] & 0x1)) {
            throw std::runtime_error("Real Mode is unsupported.");
        }
        // Check if we're in 64-bit or not.
        cs_mode mode = CS_MODE_LITTLE_ENDIAN;
        if (env->efer & 0x400) {
            // 64-bit mode (long bit set)
            mode = CS_MODE_64;
        } else {
            // 32-bit mode
            mode = CS_MODE_32;
        }
        cs_open(CS_ARCH_X86, mode, &handle);
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        capstone_initialized = true;

        task_changed("dummy", 0, 0); // XXX: huge ass hack
    }
#endif

    // Insert the block callback.
    TCGOp *insert_point = find_guest_insn(0);
    assert(NULL != insert_point);
    insert_call(&insert_point, &block_callback, edge_processor.get(), tb);

    // Instrument the control flow instructions.
    std::vector<uint8_t> block(tb->size);
    panda_virtual_memory_read(cpu, tb->pc, block.data(), block.size());
    cs_insn *insn;
    size_t insn_count = cs_disasm(handle, block.data(), block.size(), tb->pc, 0, &insn);
    if (!insn_count) {
        //log_message("capstone returned no instructions!");
        return;
    }
    //assert(insn_count > 0);

    for (int i = insn_count - 1; i > 0; i--) {
        auto it = INSN_HANDLERS.find(insn[i].id);
        if (INSN_HANDLERS.end() != it) {
            //printf("0x%" PRIx32 ":\t%s\t\t%s\n", (uint32_t)insn[i].address, insn[i].mnemonic, insn[i].op_str);
            TCGOp *op = find_guest_insn(i);
            assert(op);
            it->second(cpu, op, tb, &insn[i]);
            break;
        }
    }

    cs_free(insn, insn_count);
}

void EdgeInstrumentationDelegate::handle_enable(const std::string& unused)
{
    cov_enabled = true;
}

void EdgeInstrumentationDelegate::handle_disable()
{
    cov_enabled = false;
}

void EdgeInstrumentationDelegate::task_changed(const std::string& unused, target_pid_t pid, target_pid_t tid)
{
    //printf("process is now: %s\n", unused.c_str());
    // jump target set
    auto ins_res = next_block_addrs.insert({ tid, {
        .has_dst1 = false,
        .dst1 = 0x0,
        .has_dst2 = false,
        .dst2 = 0x0
    } });
    jump_target_set = &ins_res.first->second;

    // previous block
    auto pb_ins_res = prev_blocks.insert({ tid, {} });
    prev_block = &pb_ins_res.first->second;
}

}
