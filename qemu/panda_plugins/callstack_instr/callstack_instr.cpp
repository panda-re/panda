#define __STDC_FORMAT_MACROS

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"

#include <distorm.h>

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);
int before_block_exec(CPUState *env, TranslationBlock *tb);

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include <stdio.h>
#include <stdlib.h>

#include <unordered_map>
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

#if 0
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
#ifdef TARGET_I386
    total += 1;
    std::vector<target_ulong> &v = callstacks[env->cr[3]];

    // Don't try to do this until we have some callstack info
    if (v.empty()) return 1;

    // stackwalk caller
    target_ulong sw_caller = 0;
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&sw_caller, 4, 0);

    // shadow stack caller
    target_ulong ss_caller = callstacks[env->cr[3]].back();

    // Slight mismatch between 
    int diff = ss_caller - sw_caller;
    if (diff > 10 || diff < -10) {
        printf("Caller discrepancy: Stackwalk: " TARGET_FMT_lx " Shadow stack: " TARGET_FMT_lx "\n",
            sw_caller, ss_caller);
        misses += 1;
    }
#endif
    return 1;
}
#endif

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

instr_type disas_instr(CPUState* env, target_ulong pc, int *instr_size){
#if defined(TARGET_I386)
    unsigned char buf[15];
    panda_virtual_memory_rw(env, pc, buf, 15, 0);

    _DInst dec[1];
    unsigned int dec_count = 0;
    _DecodeType dt = (env->hflags & HF_LMA_MASK) ? Decode64Bits : Decode32Bits;

    _CodeInfo ci;
    ci.code = buf;
    ci.codeLen = sizeof(buf);
    ci.codeOffset = pc;
    ci.dt = dt;
    ci.features = DF_NONE;

    distorm_decompose(&ci, dec, 1, &dec_count);
    if (dec[0].flags == FLAG_NOT_DECODABLE)
        return INSTR_UNKNOWN;
    *instr_size = dec[0].size;

    if (META_GET_FC(dec[0].meta) == FC_CALL) {
        return INSTR_CALL;
    }
    else if (META_GET_FC(dec[0].meta) == FC_RET) {
        // Ignore IRETs
        if (buf[0] == 0xCF) return INSTR_UNKNOWN;
        else return INSTR_RET;
    }
    else if (META_GET_FC(dec[0].meta) == FC_SYS) {
        return INSTR_UNKNOWN;
        /* ignore these for now
        if (buf[0] == 0x0F && buf[1] == 0x34){ //sysenter
          return INSTR_SYSENTER;
        } else if(buf[0] == 0x0F && buf[1] == 0x05){ // syscall
          return INSTR_SYSCALL;
        } else if(buf[0] == 0x0F && buf[1] == 0x35){ // sysexit
          return INSTR_SYSEXIT;
        } else if(buf[0] == 0x0F && buf[1] == 0x07){ // sysret
          return INSTR_SYSRET;
        }
        */
    }
    else {
        return INSTR_UNKNOWN;
    }
#elif defined(TARGET_ARM)
    unsigned char buf[4];

    // Pretend thumb mode doesn't exist for now
    // Pretend conditional execution doesn't exist for now
    // This is super half-assed right now
    *instr_size = 4;
    
    panda_virtual_memory_rw(env, pc, buf, 4, 0);
    // Note: little-endian!
    if (buf[3] == 0xe1 &&
        buf[2] == 0x2f &&
        buf[1] == 0xff &&
        buf[0] == 0x1e) // bx lr
        return INSTR_RET;
    else if (buf[3] == 0xeb) // bl
        return INSTR_CALL;
    else
        return INSTR_UNKNOWN;
#endif

    return INSTR_UNKNOWN;
}

// Check if the instruction is some kind of call
bool translate_callback(CPUState *env, target_ulong pc) {
  /* if we're in ARM mode, check for bl, blx, etc 
   BL: Fx xx  x
   BLX:
   BX:
  */
  
  /* if we're in THUMB mode, check for bl, etc */

    int sz;
    if(disas_instr(env, pc, &sz)!= INSTR_UNKNOWN)
        return true;
    return false;
}

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
    int instr_size = 0;
    instr_type instr = disas_instr(env, pc, &instr_size);
    if (instr == INSTR_SYSRET || instr == INSTR_RET || instr == INSTR_IRET || instr == INSTR_SYSEXIT){
      std::vector<stack_entry> &v = callstacks[get_asid(env,pc)];
      if (!v.empty()) {
        // Expected return address
        stack_entry popped = v.back();
        v.pop_back();
        total += 1;

        // We don't expect SYS* calls to match since they don't
        // put the return addr on the stack
        if (instr == INSTR_SYSRET || instr == INSTR_SYSEXIT) return 0;
        
        // Real return address
        target_ulong sw_caller = 0;
#if defined(TARGET_I386)
        int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
        panda_virtual_memory_rw(env, env->regs[R_ESP], (uint8_t *)&sw_caller, word_size, 0);
#elif defined(TARGET_ARM)
        sw_caller = env->regs[14]; // R14 is the link register
#endif

        // Compare
        int diff = popped.pc - sw_caller;
        if (diff > 10 || diff < -10) {
            //printf("Returning to unexpected place: Expected: " TARGET_FMT_lx " Actual: " TARGET_FMT_lx "\n",
            //    popped.pc, sw_caller);
            //printf("PC=" TARGET_FMT_lx "\n", pc);
            //printf("Return type: %d\n", instr);
            //printf("Stack:\n");
            //printf("   " TARGET_FMT_lx " %d\n", popped.pc, popped.kind);
            for(int i = v.size() - 1; i > (v.size() - 10) && i >= 0; i--) {
                int stdiff = sw_caller - v[i].pc;
                if (stdiff < 0) stdiff = -stdiff;
                //printf("%s  " TARGET_FMT_lx " %d\n", stdiff < 10 ? ">" : " ", v[i].pc, v[i].kind);
                v.pop_back();
                if (stdiff < 10) 
                    break;
            }
            misses += 1;
        }
      }
    }else if (instr == INSTR_SYSCALL || instr == INSTR_CALL || instr == INSTR_INT || instr == INSTR_SYSENTER){
      stack_entry se = {pc+instr_size,instr};
      callstacks[get_asid(env,pc)].push_back(se);
    }

    return 0;
}

// Use this to detect the case where a non-ret instruction
// simulates a return
int before_block_exec(CPUState *env, TranslationBlock *tb) {
    std::vector<stack_entry> &v = callstacks[get_asid(env,tb->pc)];
    if (!v.empty() && tb->pc == v.back().pc) {
        v.pop_back();
    }
    return 1;
}

bool init_plugin(void *self) {
    printf("Initializing plugin callstack_instr\n");

#if defined(TARGET_I386) || defined(TARGET_ARM)
    panda_cb pcb;

    //panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    
    //pcb.virt_mem_write = mem_write_callback;
    //panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
#endif

    return true;
}

void uninit_plugin(void *self) {
    printf("Misses: %lu Total: %lu\n", misses, total); 
}
