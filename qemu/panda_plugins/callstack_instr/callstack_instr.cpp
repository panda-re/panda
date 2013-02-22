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

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);
int before_block_exec(CPUState *env, TranslationBlock *tb);
int after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb);
int after_block_translate(CPUState *env, TranslationBlock *tb);

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include <stdio.h>
#include <stdlib.h>

#include <unordered_map>
#include <map>
#include <vector>
#include <algorithm>

unsigned long misses;
unsigned long total;

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

std::unordered_map<target_ulong, std::vector<stack_entry>> callstacks;
std::unordered_map<target_ulong, instr_type> call_cache;
int last_ret_size = 0;
unsigned long mem_hits, mem_total;

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
    return 0;
#if defined(TARGET_I386)
    return env->cr[3];
#elif defined(TARGET_ARM)
    return arm_get_vaddr_table(env, addr);
#else
    return 0;
#endif
}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    std::vector<stack_entry> &v = callstacks[get_asid(env,addr)];

    // Don't try to do this until we have some callstack info
    if (!v.empty()) mem_hits += 1;
    mem_total += 1;

    return 1;
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
        else if (cur_instr[3] == 0xeb) {// bl
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
    bool popped = false;
    std::vector<stack_entry> &v = callstacks[get_asid(env,tb->pc)];
    if (v.empty()) return 1;

    // Search up to 10 down
    for (int i = v.size()-1; i > (v.size()-10) && i >= 0; i--) {
        if (tb->pc == v[i].pc) {
            //printf("Matched at depth %d\n", v.size()-i);
            v.erase(v.begin()+i, v.end());
            popped = true;
            break;
        }
    }

    if (popped) {
        target_ulong sw_caller = 0;
#if defined(TARGET_I386)
        int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
        //printf("I think the last ret was a ret %#x\n", last_ret_size);
        panda_virtual_memory_rw(env, env->regs[R_ESP]-word_size-last_ret_size, (uint8_t *)&sw_caller, word_size, 0);
#elif defined(TARGET_ARM)
        sw_caller = env->regs[14]; // R14 is the link register
#endif
        if (sw_caller != tb->pc) { 
            //printf("MISS: " TARGET_FMT_lx " != " TARGET_FMT_lx "\n", tb->pc, sw_caller);
            misses += 1;
        }
        total += 1;
    }

    return 0;
}

int after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next) {
    instr_type tb_type = call_cache[tb->pc];
    if (tb_type == INSTR_CALL) {
        stack_entry se = {tb->pc+tb->size,tb_type};
        callstacks[get_asid(env,tb->pc)].push_back(se);
    }
    else if (tb_type == INSTR_RET) {
        //printf("Just executed a RET in TB " TARGET_FMT_lx "\n", tb->pc);
        //if (next) printf("Next TB: " TARGET_FMT_lx "\n", next->pc);
    }

    return 1;
}

bool init_plugin(void *self) {
    printf("Initializing plugin callstack_instr\n");

#if defined(TARGET_I386) || defined(TARGET_ARM)
    panda_cb pcb;

    panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    
    //pcb.virt_mem_write = mem_write_callback;
    //panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
#endif

    return true;
}

void uninit_plugin(void *self) {
    printf("Misses: %lu Total: %lu\n", misses, total); 
    printf("Mem Hits: %lu Mem Total: %lu\n", mem_hits, mem_total); 
}
