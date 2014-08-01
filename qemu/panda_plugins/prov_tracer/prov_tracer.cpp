extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"
}

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <iostream>
#include <fstream>

extern "C" {
/*
 * Functions interfacing with QEMU/PANDA should be linked as C.
 * C++ function name mangling breaks linkage.
 */
bool init_plugin(void *);
void uninit_plugin(void *);
}

#define PROV_TRACER_DEFAULT_OUT "prov_tracer.txt"


/*
 *	--------------------
 *	Panda API Cheatsheet
 *	--------------------
 *	
 *	void panda_register_callback(void *plugin, PANDA_CB_USER_AFTER_SYSCALL, panda_cb cb);
 *	int panda_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write);
 *	target_phys_addr_t panda_virt_to_phys(CPUState *env, target_ulong addr);
 *	int panda_virtual_memory_rw(CPUState *env, target_ulong addr, uint8_t *buf, int len, int is_write);
 */


#if defined(TARGET_I386)
std::fstream ptout;

int before_block_exec_cb(CPUState *env, TranslationBlock *tb) {
	ptout << std::hex << env->regs[R_ESP] << ":" << (0xffffe000 & env->regs[R_ESP]) <<  std::endl;
	return 0;
}
#endif

bool init_plugin(void *self) {
#if defined(TARGET_I386)
	
	ptout.open(PROV_TRACER_DEFAULT_OUT, std::fstream::out | std::fstream::trunc);

	panda_cb pcb;
	pcb.before_block_exec = before_block_exec_cb;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	return true;
#else
	std::cerr << "WARN: Target not supported for panda_prov_tracer plugin." << std::endl;
	return false;
#endif
}

void uninit_plugin(void *self) {
#if defined(TARGET_I386)
	ptout.close();
#endif
}

