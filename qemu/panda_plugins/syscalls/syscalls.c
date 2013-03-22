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

// ARM OABI has the syscall number embedded in the swi: swi #90xxxx
#define CAPTURE_ARM_OABI 0

// Check if the instruction is sysenter (0F 34)
bool translate_callback(CPUState *env, target_ulong pc) {
#ifdef TARGET_I386
    unsigned char buf[2];
    panda_virtual_memory_rw(env, pc, buf, 2, 0);
    if (buf[0]== 0x0F && buf[1] == 0x34)
        return true;
    else
        return false;
#elif defined(TARGET_ARM)
    unsigned char buf[4];

    // Check for ARM mode syscall
    if(env->thumb == 0){
        panda_virtual_memory_rw(env, pc, buf, 4, 0);
	// EABI
        if( (buf[3] & 0x0F ==  0x0F)  && (buf[2] == 0) && (buf[1] == 0) && (buf[0] == 0) ){
            return true;
#if CAPTURE_ARM_OABI
        }else if((buf[3] & 0x0F == 0x0F)  && (buf[2] == 0x90)) {  // old ABI
	  return true;
#endif
	}
    } else { 
      panda_virtual_memory_rw(env, pc, buf, 2, 0);
    // check for Thumb mode syscall
      if (buf[1] == 0xDF && buf[0] == 0){
        return true;
      }
    }
    return false;
#endif
}

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
#ifdef TARGET_I386
    // On Windows, the system call id is in EAX
    fprintf(plugin_log, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx "\n", pc, env->regs[R_EAX]);
#elif defined(TARGET_ARM)
#if CAPTURE_ARM_OABI
    if(env->thumb == 0){
      // read 4 bytes, number may be in instruction.
      unsigned char buf[4];
      panda_virtual_memory_rw(env, pc, buf, 4, 0);
      if (buf[2] == 0x90) {
	fprintf(plugin_log, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx ", OLD ABI \n", pc, *(unsigned int*)&buf);
	return 0;
      }
    }
#endif

    // syscall is in R7
    fprintf(plugin_log, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx ", thumb=" TARGET_FMT_lx "\n", pc, env->regs[7], env->thumb);
#endif

    return 0;
}

bool init_plugin(void *self) {
// Don't bother if we're not on x86
#if  defined(TARGET_I386) || defined(TARGET_ARM)
    panda_cb pcb;

    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
#endif

    plugin_log = fopen("syscalls.txt", "w");    
    if(!plugin_log) return false;
    else return true;
}

void uninit_plugin(void *self) {
    fflush(plugin_log);
    fclose(plugin_log);
}
