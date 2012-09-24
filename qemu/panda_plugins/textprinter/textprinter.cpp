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
#include <set>
#include <iostream>
#include <fstream>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

uint64_t mem_counter;

struct text_counter { int num_text; int num_nontext; };

std::set<target_ulong> tap_points;
FILE *tap_buffers;

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    if (tap_points.find(pc) != tap_points.end()) {
        for (unsigned int i = 0; i < size; i++) {
            fprintf(tap_buffers, TARGET_FMT_lx " " TARGET_FMT_lx " %ld %02x\n", pc, addr+i, mem_counter, ((unsigned char *)buf)[i]);
        }
    }
    mem_counter++;

    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin textprinter\n");
    
    panda_enable_precise_pc();
    
    pcb.mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_MEM_WRITE, pcb);

    std::ifstream taps("tap_points.txt");
    if (!taps) {
        printf("Couldn't open tap_points.txt; no tap points defined. Exiting.\n");
        return false;
    }

    target_ulong x;
    while (taps >> std::hex >> x) {
        tap_points.insert(x);
    }
    taps.close();

    tap_buffers = fopen("tap_buffers.txt", "w");
    if(!tap_buffers) {
        printf("Couldn't open tap_buffers.txt for writing. Exiting.\n");
        return false;
    }

    return true;
}

void uninit_plugin(void *self) {
    fclose(tap_buffers);
}
