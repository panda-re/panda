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
#define __STDC_FORMAT_MACROS

#include <distorm.h>
namespace distorm {
#include <mnemonics.h>
}

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "panda_plugin_plugin.h"

#include "callstack_instr.h"

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);
int before_block_exec(CPUState *env, TranslationBlock *tb);
int after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb);
int after_block_translate(CPUState *env, TranslationBlock *tb);

bool init_plugin(void *);
void uninit_plugin(void *);
}

#include <stdio.h>
#include <stdlib.h>

#include <map>
#include <set>
#include <vector>
#include <algorithm>

#include "../common/prog_point.h"

extern "C" {

#include "callstack_instr_int.h"

PPP_PROT_REG_CB(on_call);
PPP_PROT_REG_CB(on_ret);

}

PPP_CB_BOILERPLATE(on_call);
PPP_CB_BOILERPLATE(on_ret);

enum instr_type {
  INSTR_UNKNOWN = 0,
  INSTR_CALL,
  INSTR_RET,
  INSTR_SYSCALL,
  INSTR_SYSRET,
  INSTR_SYSENTER,
  INSTR_SYSEXIT,
  INSTR_INT,
  INSTR_IRET,
};

struct stack_entry {
    target_ulong pc;
    instr_type kind;
};

#define MAX_STACK_DIFF 5000

// Track the different stacks we have seen to handle multiple threads
// within a single process.
std::map<target_ulong,std::set<target_ulong>> stacks_seen;

// Use a typedef here so we can switch between the stack heuristic and
// the original code easily
#ifdef USE_STACK_HEURISTIC
typedef std::pair<target_ulong,target_ulong> stackid;
target_ulong cached_sp = 0;
target_ulong cached_asid = 0;
#else
typedef target_ulong stackid;
#endif

// stackid -> shadow stack
std::map<stackid, std::vector<stack_entry>> callstacks;
// stackid -> function entry points
std::map<stackid, std::vector<target_ulong>> function_stacks;
// EIP -> instr_type
std::map<target_ulong, instr_type> call_cache;
int last_ret_size = 0;

static inline bool in_kernelspace(CPUState *env) {
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
    return false;
#endif
}

#ifdef TARGET_ARM
// ARM: stolen from target-arm/helper.c
static uint32_t arm_get_vaddr_table(CPUState *env, uint32_t address)
{   
    uint32_t table;

    if (address & env->cp15.c2_mask)
        table = env->cp15.c2_base1 & 0xffffc000;
    else
        table = env->cp15.c2_base0 & env->cp15.c2_base_mask;

    return table;
}
#endif

static inline target_ulong get_asid(CPUState *env, target_ulong addr) {
#if defined(TARGET_I386)
    return env->cr[3];
#elif defined(TARGET_ARM)
    return arm_get_vaddr_table(env, addr);
#else
    return 0;
#endif
}

static inline target_ulong get_stack_pointer(CPUState *env) {
#if defined(TARGET_I386)
    return env->regs[R_ESP];
#elif defined(TARGET_ARM)
    return env->regs[13];
#else
    return 0;
#endif
}

static stackid get_stackid(CPUState *env, target_ulong addr) {
#ifdef USE_STACK_HEURISTIC
    target_ulong asid;
    
    // Track all kernel-mode stacks together
    if (in_kernelspace(env))
        asid = 0;
    else
        asid = get_asid(env, addr);

    // Invalidate cached stack pointer on ASID change
    if (cached_asid == 0 || cached_asid != asid) {
        cached_sp = 0;
        cached_asid = asid;
    }

    target_ulong sp = get_stack_pointer(env);

    // We can short-circuit the search in most cases
    if (std::abs(sp - cached_sp) < MAX_STACK_DIFF) {
        return std::make_pair(asid, cached_sp);
    }

    auto &stackset = stacks_seen[asid];
    if (stackset.empty()) {
        stackset.insert(sp);
        cached_sp = sp;
        return std::make_pair(asid,sp);
    }
    else {
        // Find the closest stack pointer we've seen
        auto lb = std::lower_bound(stackset.begin(), stackset.end(), sp);
        target_ulong stack1 = *lb;
        lb--;
        target_ulong stack2 = *lb;
        target_ulong stack = (std::abs(stack1 - sp) < std::abs(stack2 - sp)) ? stack1 : stack2;
        int diff = std::abs(stack-sp);
        if (diff < MAX_STACK_DIFF) {
            return std::make_pair(asid,stack);
        }
        else {
            stackset.insert(sp);
            cached_sp = sp;
            return std::make_pair(asid,sp);
        }
    }
#else
    return get_asid(env, addr);
#endif
}

instr_type disas_block(CPUState* env, target_ulong pc, int size) {
    unsigned char *buf = (unsigned char *) malloc(size);
    int err = panda_virtual_memory_rw(env, pc, buf, size, 0);
    if (err == -1) printf("Couldn't read TB memory!\n");
    instr_type res = INSTR_UNKNOWN;

#if defined(TARGET_I386)
    _DInst dec[256];
    unsigned int dec_count = 0;
    _DecodeType dt = (env->hflags & HF_LMA_MASK) ? Decode64Bits : Decode32Bits;

    _CodeInfo ci;
    ci.code = buf;
    ci.codeLen = size;
    ci.codeOffset = pc;
    ci.dt = dt;
    ci.features = DF_NONE;

    distorm_decompose(&ci, dec, 256, &dec_count);
    for (int i = dec_count - 1; i >= 0; i--) {
        if (dec[i].flags == FLAG_NOT_DECODABLE) {
            continue;
        }

        if (META_GET_FC(dec[i].meta) == FC_CALL) {
            res = INSTR_CALL;
            goto done;
        }
        else if (META_GET_FC(dec[i].meta) == FC_RET) {
            // Ignore IRETs
            if (dec[i].opcode == distorm::I_IRET) {
                res = INSTR_UNKNOWN;
            }
            else {
                // For debugging only
                if (dec[i].ops[0].type == O_IMM)
                    last_ret_size = dec[i].imm.sdword;
                else
                    last_ret_size = 0;
                res = INSTR_RET;
            }
            goto done;
        }
        else if (META_GET_FC(dec[i].meta) == FC_SYS) {
            res = INSTR_UNKNOWN;
            goto done;
        }
        else {
            res = INSTR_UNKNOWN;
            goto done;
        }
    }
#elif defined(TARGET_ARM)
    // Pretend thumb mode doesn't exist for now
    // Pretend conditional execution doesn't exist for now
    // This is super half-assed right now
    
    unsigned char *cur_instr;
    for (cur_instr = buf+size-4; cur_instr >= buf; cur_instr -= 4) {
        // Note: little-endian!
        if (cur_instr[3] == 0xe1 &&
            cur_instr[2] == 0x2f &&
            cur_instr[1] == 0xff &&
            cur_instr[0] == 0x1e) { // bx lr
            res = INSTR_RET;
            goto done;
        }
        else if ((cur_instr[3] & 0x0f) == 0x0b) {// bl
            res = INSTR_CALL;
            goto done;
        }
        else if (cur_instr[3] == 0xe1 &&
                 cur_instr[2] == 0xa0 &&
                 cur_instr[1] == 0xe0 &&
                 cur_instr[0] == 0x0f) { // mov lr, pc
            res = INSTR_CALL;
            goto done;
        }
        else
            continue;
    }
#endif

done:
    free(buf);
    return res;
}

int after_block_translate(CPUState *env, TranslationBlock *tb) {
    call_cache[tb->pc] = disas_block(env, tb->pc, tb->size);
    
    return 1;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    std::vector<stack_entry> &v = callstacks[get_stackid(env,tb->pc)];
    std::vector<target_ulong> &w = function_stacks[get_stackid(env,tb->pc)];
    if (v.empty()) return 1;

    // Search up to 10 down
    for (int i = v.size()-1; i > ((int)(v.size()-10)) && i >= 0; i--) {
        if (tb->pc == v[i].pc) {
            //printf("Matched at depth %d\n", v.size()-i);
            v.erase(v.begin()+i, v.end());

            PPP_RUN_CB(on_ret, env, w[i]);
            w.erase(w.begin()+i, w.end());

            break;
        }
    }

    return 0;
}

int after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next) {
    instr_type tb_type = call_cache[tb->pc];

    if (tb_type == INSTR_CALL) {
        stack_entry se = {tb->pc+tb->size,tb_type};
        callstacks[get_stackid(env,tb->pc)].push_back(se);

        // Also track the function that gets called
        target_ulong pc, cs_base;
        int flags;
        // This retrieves the pc in an architecture-neutral way
        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        function_stacks[get_stackid(env,tb->pc)].push_back(pc);

        PPP_RUN_CB(on_call, env, pc);
    }
    else if (tb_type == INSTR_RET) {
        //printf("Just executed a RET in TB " TARGET_FMT_lx "\n", tb->pc);
        //if (next) printf("Next TB: " TARGET_FMT_lx "\n", next->pc);
    }

    return 1;
}

// Public interface implementation
int get_callers(target_ulong callers[], int n, CPUState *env) {
    std::vector<stack_entry> &v = callstacks[get_stackid(env,env->panda_guest_pc)];
    auto rit = v.rbegin();
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        callers[i] = rit->pc;
    }
    return i;
}

int get_functions(target_ulong functions[], int n, CPUState *env) {
    std::vector<target_ulong> &v = function_stacks[get_stackid(env,env->panda_guest_pc)];
    if (v.empty()) {
        return 0;
    }
    auto rit = v.rbegin();
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        functions[i] = *rit;
    }
    return i;
}

void get_prog_point(CPUState *env, prog_point *p) {
    if (!p) return;

    // Get address space identifier
    target_ulong asid = get_asid(env, env->panda_guest_pc);
    // Lump all kernel-mode CR3s together

    if(!in_kernelspace(env))
        p->cr3 = asid;

    // Try to get the caller
    int n_callers = 0;
    n_callers = get_callers(&p->caller, 1, env);

    if (n_callers == 0) {
#ifdef TARGET_I386
        // fall back to EBP on x86
        int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
        panda_virtual_memory_rw(env, env->regs[R_EBP]+word_size, (uint8_t *)&p->caller, word_size, 0);
#endif
    }

    p->pc = env->panda_guest_pc;
}

bool init_plugin(void *self) {
    printf("Initializing plugin callstack_instr\n");

    panda_cb pcb;

    panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    
    return true;
}

void uninit_plugin(void *self) {
}
