/* PANDABEGINCOMMENT PANDAENDCOMMENT */
/* PANDABEGINCOMMENT PANDAENDCOMMENT */
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

#include <zlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <set>
#include <iostream>
#include <fstream>

#include "../common/prog_point.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int read_mem_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
//int write_mem_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

#define ASSUMED_TB_SIZE 256

bool enabled_memcb = false;
prog_point tap_point;
FILE *read_tap_buffers;
//FILE *write_tap_buffers;

int before_block_translate_cb(CPUState *env, target_ulong pc) {
    if (pc <= tap_point.pc && tap_point.pc < pc+ASSUMED_TB_SIZE) {
        panda_enable_memcb();
        panda_enable_precise_pc();
        enabled_memcb = true;
    }
    return 1;
}

int after_block_translate_cb(CPUState *env, TranslationBlock *tb) {
    if (enabled_memcb) {
        // Check our assumption
        if (tb->size > ASSUMED_TB_SIZE) {
            printf("WARN: TB " TARGET_FMT_lx " is larger than we thought (%d bytes)\n", tb->pc, tb->size);
        }
        panda_disable_memcb();
        panda_disable_precise_pc();
        enabled_memcb = false;
    }
    return 1;
}

static inline int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, FILE *f) {
#ifdef TARGET_I386
    if (pc == tap_point.pc) {
        target_ulong caller = 0;
        int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
        panda_virtual_memory_rw(env, env->regs[R_EBP]+word_size, (uint8_t *)&caller, word_size, 0);
        if (caller == tap_point.caller) {
            fwrite(buf, size, 1, f);
            fflush(f);
        }
    }
#endif
    return 1;
}

int read_mem_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, read_tap_buffers);
}
//int write_mem_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf ) {
//    return mem_callback(env, pc, addr, size, buf, write_tap_buffers);
//}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin textprinter_fast\n");
    
    std::ifstream taps("tap_points.txt");
    if (!taps) {
        printf("Couldn't open tap_points.txt; no tap points defined. Exiting.\n");
        return false;
    }

    taps >> std::hex >> tap_point.caller;
    taps >> std::hex >> tap_point.pc;
    tap_point.cr3 = 0;

    printf("Added " TARGET_FMT_lx " " TARGET_FMT_lx "\n", tap_point.caller, tap_point.pc);

    taps.close();

//    write_tap_buffers = fopen("write_tap_buffers.txt", "w");
//    if(!write_tap_buffers) {
//        printf("Couldn't open write_tap_buffers.txt for writing. Exiting.\n");
//        return false;
//    }
    read_tap_buffers = fopen("read_tap_buffers.txt", "w");
    if(!read_tap_buffers) {
        printf("Couldn't open read_tap_buffers.txt for writing. Exiting.\n");
        return false;
    }

//    panda_enable_precise_pc();
//    panda_enable_memcb();    
//    pcb.virt_mem_write = write_mem_callback;
//    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.virt_mem_read = read_mem_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);
    pcb.before_block_translate = before_block_translate_cb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
    pcb.after_block_translate = after_block_translate_cb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    fclose(read_tap_buffers);
//    fclose(write_tap_buffers);
}
