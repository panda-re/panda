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
#include <map>
#include <list>
#include <algorithm>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

typedef int (* get_callers_t)(target_ulong callers[], int n, target_ulong asid);
get_callers_t get_callers;

}

uint64_t bytes_read, bytes_written;
uint64_t num_reads, num_writes;

struct text_counter {
    bool started;
    int num_bytes;
    unsigned char prev_char;
    std::map<unsigned short,unsigned int> hist;
};

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

std::map<prog_point,text_counter> text_tracker;
//FILE *text_memlog;

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

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    bytes_written += size;
    num_writes++;
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

    text_counter &tc = text_tracker[p];    

    for (unsigned int i = 0; i < size; i++) {
        unsigned char val = ((unsigned char *)buf)[i];
        //fprintf(text_memlog, TARGET_FMT_lx "." TARGET_FMT_lx " " TARGET_FMT_lx " %02x\n" , p.pc, p.caller, addr+i, val);
        if (!tc.started) {
            tc.prev_char = val;
            tc.started = true;
        } 
        else {
            unsigned short bigram;
            bigram = (tc.prev_char << 8) | val;
            tc.hist[bigram]++;
            tc.prev_char = val;
        }
        tc.num_bytes++;
    }
 
    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin bigrams\n");

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

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

    //text_memlog = fopen("text_memlog.txt", "w");

    return true;
}

void uninit_plugin(void *self) {
    printf("Memory statistics: %lu stores, %lu bytes written.\n",
        num_writes, bytes_written
    );

    FILE *mem_report = fopen("bigram_mem_report.bin", "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }

    // Cross platform support: need to know how big a target_ulong is
    uint32_t target_ulong_size = sizeof(target_ulong);
    fwrite(&target_ulong_size, sizeof(uint32_t), 1, mem_report);

    std::map<prog_point,text_counter>::iterator it;
    for(it = text_tracker.begin(); it != text_tracker.end(); it++) {
        // Skip low-data entries
        if (it->second.num_bytes < 80) continue;

        unsigned int hist_keys = 0;
        hist_keys = it->second.hist.size();

        // Write the program point
        fwrite(&it->first, sizeof(prog_point), 1, mem_report);

        // Write the number of keys
        fwrite(&hist_keys, sizeof(hist_keys), 1, mem_report);
        
        // Write each key/value of the (hopefully sparse) histogram
        std::map<unsigned short,unsigned int>::iterator it2;
        for(it2 = it->second.hist.begin(); it2 != it->second.hist.end(); it2++) {
            fwrite(&it2->first, sizeof(it2->first), 1, mem_report);   // Key: unsigned short
            fwrite(&it2->second, sizeof(it2->second), 1, mem_report); // Value: unsigned int
        }
        printf("Wrote histogram with %d entries (%ld bytes)\n", 
            hist_keys, (sizeof(unsigned short)+sizeof(unsigned long))*hist_keys + sizeof(prog_point) + sizeof(hist_keys));
    }
    fclose(mem_report);
    
    //fclose(text_memlog);
}
