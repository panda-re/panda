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

}

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <set>
#include <iostream>
#include <fstream>

#include "../common/prog_point.h"
#include "../callstack_instr/callstack_api.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

add_on_call_t add_on_call;
add_on_ret_t add_on_ret;

}

// TODO: move these into prog_point
struct func_point {
    target_ulong func;
    target_ulong asid;
#ifdef __cplusplus
    bool operator <(const func_point &p) const {
        return (this->func < p.func) || \
               (this->func == p.func && this->asid < p.asid);
    }
    bool operator ==(const func_point &p) const {
        return (this->func == p.func && this->asid == p.asid);
    }
#endif
};

#ifdef __GXX_EXPERIMENTAL_CXX0X__
struct hash_func_point{
    size_t operator()(const func_point &p) const
    {
        size_t h1 = std::hash<target_ulong>()(p.func);
        size_t h2 = std::hash<target_ulong>()(p.asid);
        return h1 ^ h2;
    }
};
#endif

// XXX: factor this out
static inline target_ulong get_asid(CPUState *env, target_ulong addr) {
#if defined(TARGET_I386)
    return env->cr[3];
#else
    return 0;
#endif
}

#define NARGS 4
FILE *output = NULL;
std::set<func_point> func_points;

target_ulong buf_addr;
target_ulong buf_sz;

void get_args_on_call(CPUState *env, target_ulong pc) {
    func_point p;
    p.func = pc;
    p.asid = get_asid(env, pc);
    if (func_points.find(p) != func_points.end()) {
        // Track arguments
        fprintf(output, TARGET_FMT_lx " " TARGET_FMT_lx, p.func, p.asid);
#if defined(TARGET_I386)
        fprintf(output, " " TARGET_FMT_lx, env->regs[R_ECX]);
        int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
        target_ulong arg;
        for (int i = 0; i < NARGS; i++) {
            arg = 0;
            panda_virtual_memory_rw(env, env->regs[R_ESP]+word_size+(word_size*i), (uint8_t *)&arg, word_size, 0);
            fprintf(output, " " TARGET_FMT_lx, arg);
            // XXX HACK
            if (i == 0) {
                buf_addr = arg;
            }
            else if (i == 2) {
                buf_sz = arg;
            }
        }
#else
        // TODO
#endif
        fprintf(output, "\n");
    }
}

void dump_buf_on_ret(CPUState *env, target_ulong pc) {
    static int file_num = 0;
    func_point p;
    p.func = pc;
    p.asid = get_asid(env, pc);
    if (func_points.find(p) != func_points.end()) {
#if defined(TARGET_I386)
        uint8_t *databuf;
        if (buf_sz > 10*1024*1024) {
            printf("WARN: chunk is bigger than 10MB (%d bytes), skipping\n", (int)buf_sz);
            return;
        }

        databuf = (uint8_t *) malloc(buf_sz);

        fprintf(output, "Ret: " TARGET_FMT_lx " " TARGET_FMT_lx " retval " TARGET_FMT_lx "\n",
                p.func, p.asid, env->regs[R_EAX]);
        char fname[32];
        sprintf(fname, TARGET_FMT_lx ".%04d.dat", env->eip, file_num++);
        printf("Saving %d bytes from 0x" TARGET_FMT_lx " into %s\n", (int)buf_sz, buf_addr, fname);

        panda_virtual_memory_rw(env, buf_addr, databuf, buf_sz, 0);

        FILE *f = fopen(fname, "w");
        fwrite(databuf, buf_sz, 1, f);
        fclose(f);
        free(databuf);
#endif
    }
}

bool init_plugin(void *self) {
    printf("Initializing plugin argmon\n");

    std::ifstream taps("func_points.txt");
    if (!taps) {
        printf("Couldn't open func_points.txt; no tap points defined. Exiting.\n");
        return false;
    }

    func_point p = {};
    while (taps >> std::hex >> p.func ) {
        taps >> std::hex >> p.asid;

        printf("Adding function point (" TARGET_FMT_lx "," TARGET_FMT_lx ")\n",
               p.func, p.asid);
        func_points.insert(p);
    }
    taps.close();

    output = fopen("func_args.txt", "w");
    if(!output) {
        printf("Couldn't open func_args.txt for writing. Exiting.\n");
        return false;
    }

    void *cs_plugin = panda_get_plugin_by_name("panda_callstack_instr.so");
    if (!cs_plugin) {
        printf("Couldn't load callstack plugin\n");
        return false;
    }
    dlerror();
    add_on_call = (add_on_call_t) dlsym(cs_plugin, "add_on_call");
    char *err = dlerror();
    if (err) {
        printf("Couldn't find add_on_call function in callstack library.\n");
        printf("Error: %s\n", err);
        return false;
    }
    dlerror();
    add_on_ret = (add_on_ret_t) dlsym(cs_plugin, "add_on_ret");
    err = dlerror();
    if (err) {
        printf("Couldn't find add_on_ret function in retstack library.\n");
        printf("Error: %s\n", err);
        return false;
    }

    add_on_call(get_args_on_call);
    add_on_ret(dump_buf_on_ret);

    return true;
}

void uninit_plugin(void *self) {
    fclose(output);
}
