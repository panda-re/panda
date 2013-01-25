#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"

#include <stdio.h>
#include <stdlib.h>

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);

bool init_plugin(void *);
void uninit_plugin(void *);

// This is where we'll write out the syscall data
FILE *plugin_log;

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

instr_type disas_instr(CPUState* env, target_ulong pc){
    unsigned char buf;
    panda_virtual_memory_rw(env, pc, buf, 1, 0);
    // one byte
    if (buf == 0xFF || buf == 0xE8 || buf == 0x9A){ //call
      return INSTR_CALL;
    } else if (buf == 0xCF) {// iret
      return INSTR_IRET;
    } else if (buf == 0xCA && buf == 0xCB || buf == 0xC2 || buf == 0xC3) {// ret
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

#elif defined(TARGET_I386)
		  
    if(disas_instr(env, pc)!= INSTR_UNKNOWN)
        return true;
    return false;
#endif
}

#include <stack>
#include <unordered_map>
//std::map<target_ulong, std::stack<target_ulong>> callstacks;
// Stacks don't let us read their contents
#include <vector>
std::unordered_map<target_ulong, std::vector<target_ulong>> callstacks;
#include <algorithm>

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
#ifdef TARGET_I386
    instr_type instr = disas_instr(env, pc);
    if (instr == INSTR_SYSRET || instr == INSTR_RET || instr == INSTR_IRET || instr == INSTR_SYSEXIT){
      callstacks[env->cr[3]].push_back(pc);
    }else if (instr == INSTR_SYSCALL || instr == INSTR_CALL || instr == INSTR_INT || instr == INSTR_SYSENTER){
      callstacks[env->cr[3]].pop_back();
    }
    // On Windows, the system call id is in EAX
    //fprintf(plugin_log, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx "\n", pc, env->regs[R_EAX]);
#endif
    return 0;
}

bool init_plugin(void *self) {
// Don't bother if we're not on x86
#ifdef TARGET_I386
    panda_cb pcb;

    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
#endif

    return true;
}

void uninit_plugin(void *self) {
}
