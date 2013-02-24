// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "disas.h"

#include "panda_plugin.h"

}

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <set>
#include <iostream>
#include <fstream>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

typedef int (* get_callers_t)(target_ulong callers[], int n, target_ulong asid);
get_callers_t get_callers;

}

uint64_t mem_counter;

struct prog_point {
    target_ulong caller;
    target_ulong pc;
    target_ulong cr3;
    bool operator <(const prog_point &p) const {
        return (this->pc < p.pc) || \
               (this->pc == p.pc && this->caller < p.caller) || \
               (this->pc == p.pc && this->caller == p.caller && this->cr3 < p.cr3);
    }
};


std::set<prog_point> tap_points;
FILE *tap_buffers;

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

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    prog_point p = {};

    // Get address space identifier
    target_ulong asid;
#if defined(TARGET_I386)
    asid = env->cr[3];
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = asid;
#elif defined(TARGET_ARM)
    asid = arm_get_vaddr_table(env, addr);
    if((env->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_SVC)
        p.cr3 = asid;
#endif

    // Try to get the caller
    int n_callers = 0;
    n_callers = get_callers(&p.caller, 1, asid);

    if (n_callers == 0) {
#ifdef TARGET_I386
        // fall back to EBP on x86
        int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
        panda_virtual_memory_rw(env, env->regs[R_EBP]+word_size, (uint8_t *)&p.caller, word_size, 0);
#endif
    }

    p.pc = pc;

    if (tap_points.find(p) != tap_points.end()) {
        for (unsigned int i = 0; i < size; i++) {
            fprintf(tap_buffers, TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx " %ld %02x\n",
                    p.caller, p.pc, p.cr3, addr+i, mem_counter, ((unsigned char *)buf)[i]);
        }
    }
    mem_counter++;

    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin textprinter\n");
    
    std::ifstream taps("tap_points.txt");
    if (!taps) {
        printf("Couldn't open tap_points.txt; no tap points defined. Exiting.\n");
        return false;
    }

    prog_point p = {};
    while (taps >> std::hex >> p.caller) {
        taps >> std::hex >> p.pc;
        taps >> std::hex >> p.cr3;

        printf("Adding tap point (" TARGET_FMT_lx "," TARGET_FMT_lx "," TARGET_FMT_lx ")\n",
               p.caller, p.pc, p.cr3);
        tap_points.insert(p);
    }
    taps.close();

    tap_buffers = fopen("tap_buffers.txt", "w");
    if(!tap_buffers) {
        printf("Couldn't open tap_buffers.txt for writing. Exiting.\n");
        return false;
    }

    void *cs_plugin = panda_get_plugin_by_name("panda_callstack_instr.so");
    if (!cs_plugin) {
        printf("Couldn't load callstack plugin\n");
        return false;
    }
    dlerror();
    get_callers = (get_callers_t) dlsym(cs_plugin, "get_callers");
    char *err = dlerror();
    if (err) {
        printf("Couldn't find get_callers function in callstack library.\n");
        printf("Error: %s\n", err);
        return false;
    }

    panda_enable_precise_pc();
    panda_enable_memcb();    
    pcb.virt_mem_write = mem_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    fclose(tap_buffers);

}
