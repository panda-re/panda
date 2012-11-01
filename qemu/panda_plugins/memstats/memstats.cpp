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
#include <list>
#include <algorithm>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

uint64_t bytes_read, bytes_written;
uint64_t num_reads, num_writes;

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    bytes_written += size;
    num_writes++;

    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    bytes_read += size;
    num_reads++;
    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin memstats\n");

    // Enable memory logging
    panda_enable_memcb();

    pcb.mem_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_MEM_READ, pcb);
    pcb.mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_MEM_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    printf("Memory statistics: %lu loads, %lu stores, %lu bytes read, %lu bytes written.\n",
        num_reads, num_writes, bytes_read, bytes_written
    );
}
