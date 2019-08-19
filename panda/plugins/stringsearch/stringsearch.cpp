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

#include <cstdio>
#include <cstdlib>
#include <ctype.h>
#include <math.h>
#include <map>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>

#include "panda/plugin.h"

extern "C" {
#include "stringsearch.h"
}

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

using namespace std;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

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
    uint32_t val[MAX_STRINGS];
};
struct fullstack {
    int n;
    target_ulong callers[MAX_CALLERS];
    target_ulong pc;
    target_ulong sidFirst;
    target_ulong sidSecond;
    stack_type stackKind;
};

std::map<prog_point,fullstack> matchstacks;
std::map<prog_point,match_strings> matches;
std::map<prog_point,string_pos> read_text_tracker;
std::map<prog_point,string_pos> write_text_tracker;
uint8_t tofind[MAX_STRINGS][MAX_STRLEN];
uint32_t strlens[MAX_STRINGS];
int num_strings = 0;
int n_callers = 16;

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
                char *sid_string = get_stackid_string(p);
                printf("%s Match of str %d at: instr_count=%" PRIu64 " :  "
                       TARGET_FMT_lx " " TARGET_FMT_lx " %s\n",
                       (is_write ? "WRITE" : "READ"), str_idx,
                       rr_get_guest_instr_count(), p.caller, p.pc, sid_string);
                matches[p].val[str_idx]++;
                sp.val[str_idx] = 0;
                g_free(sid_string);

                // Also get the full stack here
                fullstack f = {0};
                f.n = get_callers(f.callers, n_callers, env);
                f.pc = p.pc;
                f.sidFirst = p.sidFirst;
                f.sidSecond = p.sidSecond;
                f.stackKind = p.stackKind;
                matchstacks[p] = f;

                // Check if the full string is in memory.
                uint8_t *tmp =
                    (uint8_t *)calloc(strlens[str_idx] + 1, sizeof(*tmp));
                target_ulong match_addr = (addr + i) - (strlens[str_idx] - 1);
                panda_virtual_memory_read(env, match_addr, tmp,
                                          strlens[str_idx]);
                bool in_memory =
                    memcmp(tmp, tofind[str_idx], strlens[str_idx]) == 0;
                free(tmp);

                // call the i-found-a-match registered callbacks here
                PPP_RUN_CB(on_ssm, env, pc, in_memory ? match_addr : addr,
                           tofind[str_idx], strlens[str_idx], is_write,
                           in_memory);
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

FILE *mem_report = NULL;

bool init_plugin(void *self) {
    panda_cb pcb;

    panda_require("callstack_instr");

    panda_arg_list *args = panda_get_args("stringsearch");

    const char *arg_str = panda_parse_string_opt(args, "str", "", "a single string to search for");
    size_t arg_len = strlen(arg_str);
    if (arg_len > 0) {
        memcpy(tofind[num_strings], arg_str, arg_len);
        strlens[num_strings] = arg_len;
        num_strings++;
    }

    n_callers = panda_parse_uint64_opt(args, "callers", 16, "depth of callstack for matches");
    if (n_callers > MAX_CALLERS) n_callers = MAX_CALLERS;

    const char *prefix = panda_parse_string_opt(args, "name", "", "prefix of filename containing search strings, which must have the suffix _search_strings.txt");
    if (strlen(prefix) > 0) {
        char stringsfile[128] = {};
        sprintf(stringsfile, "%s_search_strings.txt", prefix);

        printf ("search strings file [%s]\n", stringsfile);

        std::ifstream search_strings(stringsfile);
        if (!search_strings) {
            printf("Couldn't open %s; no strings to search for. Exiting.\n", stringsfile);
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
    }

    char matchfile[128] = {};
    sprintf(matchfile, "%s_string_matches.txt", prefix);
    mem_report = fopen(matchfile, "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return false;
    }

    if(!init_callstack_instr_api()) return false;

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_before_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
    pcb.virt_mem_after_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);


    return true;
}

void uninit_plugin(void *self) {
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
        char *sid_string = get_stackid_string(it->first);
        fprintf(mem_report, "%s ", sid_string);

        // Print strings that matched and how many times
        for(int i = 0; i < num_strings; i++)
            fprintf(mem_report, " %d", it->second.val[i]);
        fprintf(mem_report, "\n");
        g_free(sid_string);
    }
    fclose(mem_report);
}
