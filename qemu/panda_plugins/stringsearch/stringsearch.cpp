/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
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
#include "stringsearch.h"
#include "rr_log.h"
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


#include "../common/prog_point.h"
#include "panda_plugin_plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

typedef int (* get_callers_t)(target_ulong callers[], int n, CPUState *env);
get_callers_t get_callers;

typedef void (* get_prog_point_t)(CPUState *env, prog_point *p);
get_prog_point_t get_prog_point;

// prototype for the register-this-callback fn
PPP_PROT_REG_CB(on_ssm);

}

// Silly: since we use these as map values, they have to be
// copy constructible. Plain arrays aren't, but structs containing
// arrays are. So we make these goofy wrappers.
struct match_strings {
    int val[MAX_STRINGS];
};
struct string_pos {
    uint8_t val[MAX_STRINGS];
};
struct fullstack {
    int n;
    target_ulong callers[16];
    target_ulong pc;
    target_ulong asid;
};

std::map<prog_point,fullstack> matchstacks;
std::map<prog_point,match_strings> matches;
std::map<prog_point,string_pos> read_text_tracker;
std::map<prog_point,string_pos> write_text_tracker;
uint8_t tofind[MAX_STRINGS][MAX_STRLEN];
uint8_t strlens[MAX_STRINGS];
int num_strings = 0;

// this creates BOTH the global for this callback fn (on_ssm_func)
// and the function used by other plugins to register a fn (add_on_ssm)
PPP_CB_BOILERPLATE(on_ssm)

// this creates the 

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write,
                       std::map<prog_point,string_pos> &text_tracker) {
    prog_point p = {};
    get_prog_point(env, &p);

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
                printf("%s Match of str %d at: instr_count=%lu :  " TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
                       (is_write ? "WRITE" : "READ"), str_idx, rr_get_guest_instr_count(), p.caller, p.pc, p.cr3);
                matches[p].val[str_idx]++;
                sp.val[str_idx] = 0;

                // Also get the full stack here
                fullstack f = {0};
                f.n = get_callers(f.callers, 16, env);
                f.pc = p.pc;
                f.asid = p.cr3;
                matchstacks[p] = f;

                // call the i-found-a-match registered callbacks here
                PPP_RUN_CB(on_ssm, env, pc, addr, tofind[str_idx], strlens[str_idx], is_write)

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

    // Format: lines of colon-separated hex chars or quoted strings, e.g.
    // 0a:1b:2c:3d:4e
    // or "string" (no newlines)
    std::string line;
    while(std::getline(search_strings, line)) {
        std::istringstream iss(line);

        if (line[0] == '"') {
            size_t len = line.size() - 2;
            memcpy(tofind[num_strings], line.substr(1, len).c_str(), len);
            strlens[num_strings] = len;
        } else {
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
        }

        printf("stringsearch: added string of length %d to search set\n", strlens[num_strings]);

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
    dlerror();
    get_prog_point = (get_prog_point_t) dlsym(cs_plugin, "get_prog_point");
    err = dlerror();
    if (err) {
        printf("Couldn't find get_prog_point function in callstack library.\n");
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
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);


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

        // Most recent callers are returned first, so print them
        // out in reverse order
        fullstack &f = matchstacks[it->first];
        for (int i = f.n-1; i >= 0; i--) {
            fprintf(mem_report, TARGET_FMT_lx " ", f.callers[i]);
        }
        fprintf(mem_report, TARGET_FMT_lx " ", f.pc);
        fprintf(mem_report, TARGET_FMT_lx " ", f.asid);

        // Print strings that matched and how many times
        for(int i = 0; i < num_strings; i++)
            fprintf(mem_report, " %d", it->second.val[i]);
        fprintf(mem_report, "\n");
    }
    fclose(mem_report);
}
