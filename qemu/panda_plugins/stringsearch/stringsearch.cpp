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

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write,
                       std::map<prog_point,string_pos> &text_tracker) {
    prog_point p = {};
#ifdef TARGET_I386
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&p.caller, 4, 0);
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = env->cr[3];
#endif
    p.pc = pc;
    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];
        for(int str_idx = 0; str_idx < num_strings; str_idx++) {
            if (tofind[str_idx][text_tracker[p].val[str_idx]] == val)
                text_tracker[p].val[str_idx]++;
            else
                text_tracker[p].val[str_idx] = 0;

            if (text_tracker[p].val[str_idx] == strlens[str_idx]) {
                // Victory!
                printf("%s Match at: " TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
                    (is_write ? "WRITE" : "READ"), p.caller, p.pc, p.cr3);
                matches[p].val[str_idx]++;
                text_tracker[p].val[str_idx] = 0;
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

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.virt_mem_read = mem_read_callback;
    //panda_register_callback(self, PANDA_CB_MEM_READ, pcb);

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
