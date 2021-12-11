#include <cstddef>
#include <iostream>
#include <unordered_map>
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

// Uncomment the following for extra debugging messages.
//#define EDGE_INST_DEBUG

namespace coverage
{

using RegisterFetcher = std::function<target_ulong()>;
using InstructionInstrumenter = std::function<void(EdgeState *,
                                                   CPUState *, TCGOp *,
                                                   TranslationBlock *,
                                                   cs_insn *)>;

#ifdef TARGET_I386
static const RegisterFetcher INVALID_REGISTER_FETCHER = []() {
    throw std::runtime_error("Attempt to access an invalid register");
    return 0x0;
};

static target_ulong fetch_register_value(size_t cpu_offset, target_ulong mask,
                                         target_ulong shr)
{
    CPUArchState *env = static_cast<CPUArchState *>(first_cpu->env_ptr);
    return (*(reinterpret_cast<target_ulong *>((env + cpu_offset))) & mask) 
           >> shr;
}
#define MK_REG_FETCHER(cpu_state_variable, mask, shift_right) \
    std::bind(fetch_register_value, offsetof(CPUArchState, cpu_state_variable), \
              mask, shift_right)

static target_ulong fetch_segment_value(size_t cpu_offset)
{
    CPUArchState *env = static_cast<CPUArchState *>(first_cpu->env_ptr);
    return reinterpret_cast<SegmentCache*>((env + cpu_offset))->base;
}
#define MK_SEG_FETCHER(cpu_state_variable) \
    std::bind(fetch_segment_value, offsetof(CPUArchState, cpu_state_variable))

#endif

const static std::unordered_map<unsigned, RegisterFetcher>
    CS_TO_QEMU_REG_FETCH =
{
#ifdef TARGET_I386
    { X86_REG_INVALID, INVALID_REGISTER_FETCHER },

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

    { X86_REG_DH, MK_REG_FETCHER(regs[R_EDX], 0x0000FF00, 8) },
    { X86_REG_DL, MK_REG_FETCHER(regs[R_EDX], 0x000000FF, 0) },
    { X86_REG_DX, MK_REG_FETCHER(regs[R_EDX], 0x0000FFFF, 0) },
    { X86_REG_EDX, MK_REG_FETCHER(regs[R_EDX], 0xFFFFFFFF, 0) },

	{ X86_REG_SI, MK_REG_FETCHER(regs[R_ESI], 0x0000FFFF, 0) },
    { X86_REG_ESI, MK_REG_FETCHER(regs[R_ESI], 0xFFFFFFFF, 0) },

	{ X86_REG_DI, MK_REG_FETCHER(regs[R_EDI], 0x0000FFFF, 0) },
    { X86_REG_EDI, MK_REG_FETCHER(regs[R_EDI], 0xFFFFFFFF, 0) },

    { X86_REG_SP, MK_REG_FETCHER(regs[R_ESP], 0x0000FFFF, 0) },
    { X86_REG_ESP, MK_REG_FETCHER(regs[R_ESP], 0xFFFFFFFF, 0) },

    { X86_REG_BP, MK_REG_FETCHER(regs[R_EBP], 0x0000FFFF, 0) },
    { X86_REG_EBP, MK_REG_FETCHER(regs[R_EBP], 0xFFFFFFFF, 0) },

	{ X86_REG_ES, MK_SEG_FETCHER(segs[R_ES]) },

	{ X86_REG_CS, MK_SEG_FETCHER(segs[R_CS]) },

	{ X86_REG_SS, MK_SEG_FETCHER(segs[R_SS]) },

    { X86_REG_GS, MK_SEG_FETCHER(segs[R_GS]) },

#ifdef TARGET_X86_64
    { X86_REG_RAX, MK_REG_FETCHER(regs[R_EAX], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RBX, MK_REG_FETCHER(regs[R_EBX], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RCX, MK_REG_FETCHER(regs[R_ECX], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RDX, MK_REG_FETCHER(regs[R_EDX], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RBP, MK_REG_FETCHER(regs[R_EBP], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RSI, MK_REG_FETCHER(regs[R_ESI], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RDI, MK_REG_FETCHER(regs[R_EDI], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_RSP, MK_REG_FETCHER(regs[R_ESP], 0xFFFFFFFFFFFFFFFF, 0) },
    { X86_REG_R8, MK_REG_FETCHER(regs[8], 0xFFFFFFFFFFFFFFFF, 0) },
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

// This struct was initially an unordered_set of jump targets, but because
// control flow instructions have at most two targets, we can get away with
// this struct and avoid the worst case O(N) complexity of a hash table and
// this should be more cache friendly because setting the jump targets for
// the current thread basiclaly a memcpy or assignment.
struct JumpTargets
{
    bool has_dst1;
    target_ulong dst1;
    bool has_dst2;
    target_ulong dst2;
};

struct EdgeState
{
    EdgeState() : cov_enabled(true), prev_block(nullptr), jump_targets(nullptr)
    {
    }

    // Flag for enabling or disabling coverage.
    bool cov_enabled;

    // Maps Thread ID -> Previos Blocks
    std::unordered_map<target_pid_t, Block> prev_blocks;
    // Previous Block for Current Thread
    Block* prev_block;
    // Maps Thread ID -> Jump Targets
    std::unordered_map<target_pid_t, JumpTargets> next_block_addrs;
    // Jump Targets for Current Thread
    JumpTargets* jump_targets;
};

static void block_callback(EdgeState *edge_state,
                           RecordProcessor<Edge> *ep,
                           TranslationBlock *tb)
{
    if (((!edge_state->jump_targets->has_dst1) ||
          tb->pc != edge_state->jump_targets->dst1) &&
        ((!edge_state->jump_targets->has_dst2) ||
          tb->pc != edge_state->jump_targets->dst2)) {
        return;
    }

    // Construct an edge and pass it to the edge processor.
    Block to_block {
        .addr = tb->pc,
        .size = tb->size
    };
    Edge edge {
        .from = *edge_state->prev_block,
        .to = to_block
    };
    try {
        ep->handle(edge);
    } catch (std::system_error& err) {
        std::cerr << "Error while processing edge: "
                  << err.code().message() << "\n";
        std::exit(EXIT_FAILURE);
    }
}

#ifdef TARGET_I386

static void update_jump_targets(EdgeState* edge_state,
                                target_ulong prev_block_addr,
                                target_ulong prev_block_size,
                                const JumpTargets& jmp_targets)
{
    *edge_state->jump_targets = jmp_targets;
    edge_state->prev_block->addr = prev_block_addr;
    edge_state->prev_block->size = prev_block_size;
}

/* Called right before a Jcc (JG, JNE, etc) instruction.
 *
 * Note that on x86, jump targets for Jcc instructions can always be determined
 * statically since the jump target is relative to the current PC, so there's
 * only one function to handle Jcc instructions. */
static void jcc_callback(EdgeState *edge_state,
                         target_ulong prev_block_addr,
                         target_ulong prev_block_size,
                         target_ulong next_insn_addr,
                         target_ulong jump_tgt_addr)
{
    if (!edge_state->cov_enabled) {
        return;
    }
    update_jump_targets(edge_state, prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = next_insn_addr,
        .has_dst2 = true,
        .dst2 = jump_tgt_addr
    });
}

// Called for JMP instructions where the jump target was resolved from static
// analysis.
static void static_jmp_callback(EdgeState *edge_state,
                                target_ulong prev_block_addr,
                                target_ulong prev_block_size,
                                target_ulong jump_tgt_addr)
{
    if (!edge_state->cov_enabled) {
        return;
    }
    update_jump_targets(edge_state, prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_tgt_addr,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void jmp_mem_direct_callback(EdgeState *edge_state,
                                    CPUState *cpu,  
                                    target_ulong prev_block_addr,
                                    target_ulong prev_block_size,
                                    target_ulong direct_address)
{
    if (!edge_state->cov_enabled) {
        return;
    }
    target_ulong jump_target = 0x0;
    panda_virtual_memory_read(cpu, direct_address,
        reinterpret_cast<uint8_t *>(&jump_target), sizeof(jump_target));
    update_jump_targets(edge_state, prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_target,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void jmp_mem_indexed_callback(EdgeState *edge_state,
                                     CPUState *cpu,
                                     target_ulong prev_block_addr,
                                     target_ulong prev_block_size,
                                     RegisterFetcher* index_register_fetcher,
                                     int scale, int64_t disp)
{
    if (!edge_state->cov_enabled) {
        return;
    }
    target_ulong address = (*index_register_fetcher)() * scale + disp;
    target_ulong jump_target = 0x0;
    panda_virtual_memory_read(cpu, address,
        reinterpret_cast<uint8_t *>(&jump_target), sizeof(jump_target));
    update_jump_targets(edge_state, prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_target,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void jmp_mem_indirect(EdgeState* edge_state, CPUState *cpu,
                             target_ulong prev_block_addr,
                             target_ulong prev_block_size,
                             RegisterFetcher* base_register_fetch,
                             int64_t disp)
{
    if (!edge_state->cov_enabled) {
        return;
    }
    target_ulong address = (*base_register_fetch)() + disp;
    target_ulong jump_target = 0x0;
    panda_virtual_memory_read(cpu, address,
        reinterpret_cast<uint8_t *>(&jump_target), sizeof(jump_target));
    update_jump_targets(edge_state, prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_target,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void jmp_mem_indirect_no_index(EdgeState* edge_state, CPUState *cpu,
                             target_ulong prev_block_addr,
                             target_ulong prev_block_size,
							 RegisterFetcher* segment_register_fetch,
                             RegisterFetcher* base_register_fetch,
                             int64_t disp)
{
    if (!edge_state->cov_enabled) {
        return;
    }
    target_ulong address = (*segment_register_fetch)() +
    		(*base_register_fetch)() + disp;
    target_ulong jump_target = 0x0;
    panda_virtual_memory_read(cpu, address,
        reinterpret_cast<uint8_t *>(&jump_target), sizeof(jump_target));
    update_jump_targets(edge_state, prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_target,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void jmp_mem_indirect_disp_si_callback(EdgeState *edge_state,
                                              CPUState *cpu,
                                              target_ulong prev_block_addr,
                                              target_ulong prev_block_size,
                                              RegisterFetcher *brf,
                                              int64_t disp,
                                              RegisterFetcher *irf, int scale)
{
    if (!edge_state->cov_enabled) {
        return;
    }
    target_ulong address = (*brf)() + disp + (*irf)() * scale;
    target_ulong jump_target = 0x0;
    panda_virtual_memory_read(cpu, address,
        reinterpret_cast<uint8_t *>(&jump_target), sizeof(jump_target));
    update_jump_targets(edge_state, prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_target,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void jmp_reg_callback(EdgeState *edge_state, CPUState *cpu,
                             target_ulong prev_block_addr,
                             target_ulong prev_block_size,
                             RegisterFetcher *reg_fetch)
{
    if (!edge_state->cov_enabled) {
        return;
    }
    target_ulong jump_tgt_addr = (*reg_fetch)();
    update_jump_targets(edge_state, prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = jump_tgt_addr,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void ret_callback(EdgeState *edge_state,
                         CPUState *cpu,
                         target_ulong prev_block_addr,
                         target_ulong prev_block_size)
{
    if (!edge_state->cov_enabled) {
        return;
    }

    // Read the return target address off the stack.
    CPUArchState *env_ptr = static_cast<CPUArchState *>(cpu->env_ptr);
    target_ulong return_addr = 0x0;
    panda_virtual_memory_read(cpu, env_ptr->regs[R_ESP],
        reinterpret_cast<uint8_t *>(&return_addr), sizeof(return_addr));
    update_jump_targets(edge_state, prev_block_addr, prev_block_size, {
        .has_dst1 = true,
        .dst1 = return_addr,
        .has_dst2 = false,
        .dst2 = 0x0
    });
}

static void instrument_jcc(EdgeState *edge_state, CPUState *cpu, TCGOp *op,
                           TranslationBlock *tb, cs_insn *insn)
{
    target_ulong jt = static_cast<target_ulong>(
        insn->detail->x86.operands[0].imm);
    target_ulong nit = static_cast<target_ulong>(insn->address + insn->size);
    insert_call(&op, &jcc_callback, edge_state, tb->pc, tb->size, nit, jt);
}

static void instrument_jmp(EdgeState *edge_state, CPUState *cpu, TCGOp *op,
                           TranslationBlock *tb, cs_insn *insn)
{
    cs_x86_op& jmp_op = insn->detail->x86.operands[0];
    if (X86_OP_IMM == jmp_op.type) {
        target_ulong jt = static_cast<target_ulong>(jmp_op.imm);
        insert_call(&op, static_jmp_callback, edge_state, tb->pc, tb->size, jt);
    } else if (X86_OP_MEM == jmp_op.type) {

        static const RegisterFetcher *INVALID_REGISTER =
            &CS_TO_QEMU_REG_FETCH.at(X86_REG_INVALID);
        const RegisterFetcher *srf = &CS_TO_QEMU_REG_FETCH.at(
            jmp_op.mem.segment);
        const RegisterFetcher *brf = &CS_TO_QEMU_REG_FETCH.at(
            jmp_op.mem.base);
        const RegisterFetcher *irf = &CS_TO_QEMU_REG_FETCH.at(
            jmp_op.mem.index);

#ifdef EDGE_INST_DEBUG
        printf("JMP @ 0x%lX (segment=%u base=%u index=%u scale=%d disp=%ld)\n",
            insn->address,
            insn->detail->x86.operands[0].mem.segment,
            insn->detail->x86.operands[0].mem.base,
            insn->detail->x86.operands[0].mem.index,
            insn->detail->x86.operands[0].mem.scale,
            insn->detail->x86.operands[0].mem.disp);
#endif

        if (INVALID_REGISTER == srf && INVALID_REGISTER == brf &&
            INVALID_REGISTER == irf) {

            // direct addressing
            insert_call(&op, jmp_mem_direct_callback, edge_state, cpu, tb->pc,
                        tb->size, static_cast<target_ulong>(jmp_op.mem.disp));

        } else if (INVALID_REGISTER == srf && INVALID_REGISTER == irf) {

            // indirect addressing
            insert_call(&op, jmp_mem_indirect, edge_state, cpu, tb->pc,
                        tb->size, brf, jmp_op.mem.disp); 

        } else if (INVALID_REGISTER == srf && INVALID_REGISTER == brf) {

            // indexed addressing
            insert_call(&op, jmp_mem_indexed_callback, edge_state, cpu, tb->pc,
                        tb->size, irf, jmp_op.mem.scale, jmp_op.mem.disp);

        } else if (INVALID_REGISTER != srf && INVALID_REGISTER == brf &&
                   INVALID_REGISTER == irf) {

            // Indirect addressing, but with a segment register.
            insert_call(&op, jmp_mem_indirect, edge_state, cpu, tb->pc,
                        tb->size, srf, jmp_op.mem.disp);
        } else if (INVALID_REGISTER != srf && INVALID_REGISTER != brf &&
        		INVALID_REGISTER == irf) {

        	// Indirect addressing with segment and base registers.
        	insert_call(&op, jmp_mem_indirect_no_index, edge_state, cpu, tb->pc,
        			tb->size, srf, brf, jmp_op.mem.disp);

        } else if (INVALID_REGISTER != srf && INVALID_REGISTER == brf &&
        		INVALID_REGISTER != irf) {

        	// Indirect address with segment and index registers.
        	insert_call(&op, jmp_mem_indirect_disp_si_callback, edge_state,
        			cpu, tb->pc, tb->size, srf, jmp_op.mem.disp, irf,
					jmp_op.mem.scale);

        } else {

            // Indirect addressing with displacement and scaled-index
            insert_call(&op, jmp_mem_indirect_disp_si_callback, edge_state,
                        cpu, tb->pc, tb->size, brf, jmp_op.mem.disp, irf,
                        jmp_op.mem.scale);

        }
    } else if (X86_OP_REG == jmp_op.type) {
        const RegisterFetcher *reg_fetcher = &CS_TO_QEMU_REG_FETCH.at(
            jmp_op.reg);
        insert_call(&op, jmp_reg_callback, edge_state, cpu, tb->pc, tb->size,
                    reg_fetcher);
    }
}

static void instrument_ret(EdgeState *edge_state, CPUState *cpu, TCGOp *op,
                           TranslationBlock *tb, cs_insn *insn)
{
    insert_call(&op, ret_callback, edge_state, cpu, tb->pc, tb->size);
}
#endif

const static std::unordered_map<unsigned int,
                                InstructionInstrumenter> INSN_HANDLERS = {
#ifdef TARGET_I386
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
    // CALL instructions instrumented the same way as a jump.
    { X86_INS_CALL, instrument_jmp },
    { X86_INS_RET, instrument_ret },
    // LOOP instructions should be able to use jcc callback
    { X86_INS_LOOP, instrument_jcc },
    { X86_INS_LOOPE, instrument_jcc },
    { X86_INS_LOOPNE, instrument_jcc },
#endif
};

EdgeInstrumentationDelegate::EdgeInstrumentationDelegate(
    std::shared_ptr<RecordProcessor<Edge>> ep) : edge_processor(ep)
                                               , edge_state(new EdgeState())
{
#ifdef TARGET_I386
    cs_open(CS_ARCH_X86, CS_MODE_32, &handle32);
    cs_option(handle32, CS_OPT_DETAIL, CS_OPT_ON);
#ifdef TARGET_X86_64
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle64);
    cs_option(handle64, CS_OPT_DETAIL, CS_OPT_ON);
#endif
#endif
}

EdgeInstrumentationDelegate::~EdgeInstrumentationDelegate()
{
#ifdef TARGET_I386
    cs_close(&handle32);
#ifdef TARGET_X86_64
    cs_close(&handle64);
#endif
#endif
    panda_do_flush_tb();
}

void EdgeInstrumentationDelegate::instrument(CPUState *cpu,
                                             TranslationBlock *tb)
{
    csh handle = 0;
#ifdef TARGET_I386
    CPUArchState *env = static_cast<CPUArchState *>(cpu->env_ptr);
#ifdef TARGET_X86_64
    if ((env->hflags & (1 << HF_LMA_SHIFT)) && (env->hflags & (1 << HF_CS64_SHIFT))) {
        handle = handle64;
    } else {
#endif
        handle = handle32;
#ifdef TARGET_X86_64
    }
#endif
#endif

    // Insert the block callback.
    TCGOp *insert_point = find_first_guest_insn();
    assert(NULL != insert_point);
    insert_call(&insert_point, &block_callback, edge_state.get(),
        edge_processor.get(), tb);

    // Instrument the control flow instructions.
    // watch it - i386 may be running either 16- or 32-bit code
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    if ((env->hflags & HF_CS32_MASK) == 0) {
    	cs_option(handle, CS_OPT_MODE, CS_MODE_16);
    } else {
    	cs_option(handle, CS_OPT_MODE, CS_MODE_32);
    }
#endif
    std::vector<uint8_t> block(tb->size);
    panda_virtual_memory_read(cpu, tb->pc, block.data(), block.size());
    cs_insn *insn;
    size_t insn_count = cs_disasm(handle, block.data(), block.size(), tb->pc,
                                  0, &insn);
    if (!insn_count) {
        return;
    }

    for (int i = insn_count - 1; i > 0; i--) {
        auto it = INSN_HANDLERS.find(insn[i].id);
        if (INSN_HANDLERS.end() != it) {
#ifdef EDGE_INST_DEBUG
            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[i].address,
                                                 insn[i].mnemonic,
                                                 insn[i].op_str);
#endif
            TCGOp *op = find_guest_insn_by_addr(insn[i].address);
            assert(op);
            it->second(edge_state.get(), cpu, op, tb, &insn[i]);
            break;
        }
    }

    cs_free(insn, insn_count);
}

void EdgeInstrumentationDelegate::handle_enable(const std::string&)
{
    edge_state->cov_enabled = true;
}

void EdgeInstrumentationDelegate::handle_disable()
{
    edge_state->cov_enabled = false;
}

void EdgeInstrumentationDelegate::task_changed(const std::string&,
                                               target_pid_t pid,
                                               target_pid_t tid)
{
    // jump target set
    auto ins_res = edge_state->next_block_addrs.insert({ tid, {
        .has_dst1 = false,
        .dst1 = 0x0,
        .has_dst2 = false,
        .dst2 = 0x0
    } });
    edge_state->jump_targets = &ins_res.first->second;

    // previous block
    auto pb_ins_res = edge_state->prev_blocks.insert({ tid, {} });
    edge_state->prev_block = &pb_ins_res.first->second;
}

}
