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
#include <fstream>
#include <sstream>
#include <string>

#define MAX_STRINGS 16
#define MAX_STRLEN  256

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

// Silly: since we use these as map values, they have to be
// copy constructible. Plain arrays aren't, but structs containing
// arrays are. So we make these goofy wrappers.
struct match_strings {
    int val[MAX_STRINGS];
};
struct string_pos{
    uint8_t val[MAX_STRINGS];
};

std::map<prog_point,match_strings> matches;
std::map<prog_point,string_pos> read_text_tracker;
std::map<prog_point,string_pos> write_text_tracker;
uint8_t tofind[MAX_STRINGS][MAX_STRLEN];
uint8_t strlens[MAX_STRINGS];
int num_strings = 0;

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
                       target_ulong size, void *buf, bool is_write,
                       std::map<prog_point,string_pos> &text_tracker) {
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

    string_pos &sp = text_tracker[p];

    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];
        for(int str_idx = 0; str_idx < num_strings; str_idx++) {
            if (tofind[str_idx][sp.val[str_idx]] == val)
                sp.val[str_idx]++;
            else
                sp.val[str_idx] = 0;

            if (sp.val[str_idx] == strlens[str_idx]) {
                // Victory!
                printf("%s Match at: " TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
                    (is_write ? "WRITE" : "READ"), p.caller, p.pc, p.cr3);
                matches[p].val[str_idx]++;
                sp.val[str_idx] = 0;
            }
        }
    }
 
    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, false, read_text_tracker);

}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, true, write_text_tracker);
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin stringsearch\n");

    std::ifstream search_strings("search_strings.txt");
    if (!search_strings) {
        printf("Couldn't open search_strings.txt; no strings to search for. Exiting.\n");
        return false;
    }

    // Format: lines of colon-separated hex chars, e.g.
    // 0a:1b:2c:3d:4e
    std::string line;
    while(std::getline(search_strings, line)) {
        std::istringstream iss(line);
        
        std::string x;
        int i = 0;
        while (std::getline(iss, x, ':')) {
            tofind[num_strings][i++] = (uint8_t)strtoul(x.c_str(), NULL, 16);
            if (i >= MAX_STRLEN) {
                printf("WARN: Reached max number of characters (%d) on string %d, truncating.\n", MAX_STRLEN, num_strings);
                break;
            }
        }
        strlens[num_strings] = i;

        printf("stringsearch: added string of length %d to search set\n", i);

        if(++num_strings >= MAX_STRINGS) {
            printf("WARN: maximum number of strings (%d) reached, will not load any more.\n", MAX_STRINGS);
            break;
        }
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

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.virt_mem_read = mem_read_callback;
    //panda_register_callback(self, PANDA_CB_MEM_READ, pcb);


    return true;
}

void uninit_plugin(void *self) {
    FILE *mem_report = fopen("string_matches.txt", "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }
    std::map<prog_point,match_strings>::iterator it;
    for(it = matches.begin(); it != matches.end(); it++) {
        // Print prog point
        fprintf(mem_report, TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx,
            it->first.caller, it->first.pc, it->first.cr3);
        // Print strings that matched and how many times
        for(int i = 0; i < num_strings; i++)
            fprintf(mem_report, " %d", it->second.val[i]);
        fprintf(mem_report, "\n");
    }
    fclose(mem_report);
}
