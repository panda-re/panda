#define __STDC_FORMAT_MACROS

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include <stdio.h>
#include <stdlib.h>

#include <unordered_map>
#include <vector>
std::unordered_map<target_ulong, std::vector<target_ulong>> callstacks;
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
        //printf("Caller discrepancy: Stackwalk: " TARGET_FMT_lx " Shadow stack: " TARGET_FMT_lx "\n",
        //    sw_caller, ss_caller);
        misses += 1;
    }
#endif
    return 1;
}

instr_type disas_instr(CPUState* env, target_ulong pc){
    unsigned char buf;
    panda_virtual_memory_rw(env, pc, &buf, 1, 0);
    // one byte
    if (buf == 0xFF || buf == 0xE8 || buf == 0x9A){ //call
      return INSTR_CALL;
    } else if (buf == 0xCF) {// iret
      return INSTR_IRET;
    } else if (buf == 0xCA || buf == 0xCB || buf == 0xC2 || buf == 0xC3) {// ret
      return INSTR_RET;
    } else if (buf == 0xCC || buf == 0xCD || buf == 0xF1 || buf == 0xCE) {// int
      return INSTR_INT;
    }
		      // two bytes
    unsigned char buf2[2];
    panda_virtual_memory_rw(env, pc, buf2, 2, 0);
    if (buf2[0] == 0x0F && buf2[1] == 0x34){ //sysenter
      return INSTR_SYSENTER;
    }else if(buf2[0] == 0x0F && buf2[1] == 0x05){ // syscall
      return INSTR_SYSCALL;
    }else if(buf2[0] == 0x0F && buf2[1] == 0x35){ // sysexit
      return INSTR_SYSEXIT;
    }else if(buf2[0] == 0x0F && buf2[1] == 0x07){ // sysret
      return INSTR_SYSRET;
    }

    return INSTR_UNKNOWN;
}

// Check if the instruction is some kind of call
bool translate_callback(CPUState *env, target_ulong pc) {
#ifdef TARGET_ARM
  /* if we're in ARM mode, check for bl, blx, etc 
   BL: Fx xx  x
   BLX:
   BX:
  */
  
  /* if we're in THUMB mode, check for bl, etc */
    return false;
#elif defined(TARGET_I386)
    if(disas_instr(env, pc)!= INSTR_UNKNOWN)
        return true;
    return false;
#endif
}

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
#ifdef TARGET_I386
    instr_type instr = disas_instr(env, pc);
    if (instr == INSTR_SYSRET || instr == INSTR_RET || instr == INSTR_IRET || instr == INSTR_SYSEXIT){
      callstacks[env->cr[3]].push_back(pc);
    }else if (instr == INSTR_SYSCALL || instr == INSTR_CALL || instr == INSTR_INT || instr == INSTR_SYSENTER){
      std::vector<target_ulong> &v = callstacks[env->cr[3]];
      if (!v.empty()) callstacks[env->cr[3]].pop_back();
    }
#endif
    return 0;
}

bool init_plugin(void *self) {
    printf("Initializing plugin callstack_instr\n");
// Don't bother if we're not on x86
#ifdef TARGET_I386
    panda_cb pcb;

    panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
#endif

    return true;
}

void uninit_plugin(void *self) {
    printf("Misses: %lu Total: %lu\n", misses, total); 
}
