#define __STDC_FORMAT_MACROS

extern "C"{

#include "config.h"
#include "qemu-common.h"
#include "cpu.h"



#include "panda_plugin.h"

#include <stdio.h>
#include <stdlib.h>
}
#include <functional>
#include <string>

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}
// This is where we'll write out the syscall data
FILE *plugin_log;

// ARM OABI has the syscall number embedded in the swi: swi #90xxxx
//#define CAPTURE_ARM_OABI 0

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
        if( ((buf[3] & 0x0F) ==  0x0F)  && (buf[2] == 0) && (buf[1] == 0) && (buf[0] == 0) ){
	  //if( (buf[3] ==  0xEF) ){
            return true;
#if defined(CAPTURE_ARM_OABI)
        }else if(((buf[3] & 0x0F) == 0x0F)  && (buf[2] == 0x90)) {  // old ABI
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


void finish_syscall(){}
std::function<void (const char*)> record_syscall;
std::function<void (target_ulong, const char*)> log_string;
std::function<void (target_ulong, const char*)> log_pointer;
std::function<void (target_ulong, const char*)> log_32;
std::function<void (target_ulong, target_ulong, const char*)> log_64;

// This will only be called for instructions where the
// translate_callback returned true
int exec_callback(CPUState *env, target_ulong pc) {
#ifdef TARGET_I386
    // On Windows, the system call id is in EAX
    fprintf(plugin_log, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx "\n", pc, env->regs[R_EAX]);
#elif defined(TARGET_ARM)
#if defined(CAPTURE_ARM_OABI)
#if (1)
    if(env->thumb == 0){ //Old ABI not possible with Thumb
      // read 4 bytes, number may be in instruction.
      unsigned char buf[4];
      panda_virtual_memory_rw(env, pc, buf, 4, 0);
        if (buf[2] == 0x90) {
	fprintf(plugin_log, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx ", OLD ABI \n", pc, *(unsigned int*)&buf);
	return 0;
      }
    }
#else
    fprintf(plugin_log, "SKIPPING OABI\n");
#endif
#endif// OABI
    if (env->regs[7] == 0xf0){ //skip sys_futex
      return 0;
    }

    record_syscall = [&env, &pc](const char* callname){
      fprintf(plugin_log, "CALL=%s, PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx ", thumb=" TARGET_FMT_lx "\n", callname, pc, env->regs[7], env->thumb);
    };

    log_string = [&env, &pc](target_ulong src, const char* argname){
      std::string value;
      char buff[4097];
      buff[4096] = 0;
      unsigned short len = 4096 - (src & 0xFFF);
      if(len == 0) len = 4096;
      do{
	// keep copying pages until the string terminates
	int ret = panda_virtual_memory_rw(env, src, (uint8_t*)buff, len, 0);
	if(ret < 0){ // not mapped
	  break;
	}
	if(strlen(buff) > len){

	  value.append(buff, len);
	  src += len;
	  len = 4096;
	}else {
	  value += buff;
	  break;
	}
      }while(true);
      fprintf(plugin_log, "STR, NAME=%s, VALUE=%s\n", argname, value.c_str());
    };

    log_pointer = [&env, &pc](target_ulong addr, const char* argname){
      fprintf(plugin_log, "PTR, NAME=%s, VALUE=" TARGET_FMT_lx"\n",argname, addr);
    };

    log_32 = [&env,&pc](target_ulong value, const char* argname){
      fprintf(plugin_log, "I32, NAME=%s, VALUE=" TARGET_FMT_lx"\n", argname, value);
    };

    log_64 = [&env,&pc](target_ulong high, target_ulong low, const char* argname){
      fprintf(plugin_log, "I64, NAME=%s, VALUE=%llx\n", argname, ((unsigned long long)high << 32) | low );
    };

#include "syscall_printer.c"

    // syscall is in R7
    fprintf(plugin_log, "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx ", thumb=" TARGET_FMT_lx "\n", pc, env->regs[7], env->thumb);
#endif

    return 0;
}

extern "C" {

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

}
