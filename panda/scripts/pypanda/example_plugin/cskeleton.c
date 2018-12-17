#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

bool init_plugin(void *);
void uninit_plugin(void *);

int before_block_exec(CPUState *env, TranslationBlock *tb);

uint32_t static_var = 0;

int progress ( const char * format, ... ){
	printf(ANSI_COLOR_GREEN + "[pypanda.c] " +ANSI_COLOR_RESET);
  	va_start(va, format);
	printf(format);
	va_end(va);
}


int before_block_exec(CPUState *env, TranslationBlock *tb) {	
	if (static_var == 10000){
		printf("EAX: %s EBX: %s ECX: %s EDX: %s ESP: %s EBP: %s ESI: %s EDI: %s EIP: %s EFLAGS: %s", 
			env->env_ptr.regs[0], env->env_ptr.regs[3], env->env_ptr.regs[1], env->env_ptr.regs[2], 
			env->env_ptr.regs[4], env->env_ptr.regs[5], env->env_ptr.regs[6], env->env_ptr.regs[7], 
			env->env_ptr.eip, env->env_ptr.eflags);
		sleep(0.4);
	}
	static_var = (static_var+1) % (10001);
	return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    return true;
}

void uninit_plugin(void *self) {
}
