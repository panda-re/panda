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

int bytes_read, bytes_written;
int num_reads, num_writes;

struct text_counter { int num_text; int num_nontext; };

std::map<target_ulong,text_counter> text_tracker;
FILE *text_memlog;

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    bytes_written += size;
    num_writes++;
    for (unsigned int i = 0; i < size; i++) {
        unsigned char val = ((unsigned char *)buf)[i];
        fprintf(text_memlog, TARGET_FMT_lx " " TARGET_FMT_lx " %02x\n" , pc, addr+i, val);
        if(isprint(val))
            text_tracker[pc].num_text++;
        else
            text_tracker[pc].num_nontext++;
    }
 
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

    printf("Initializing plugin textfinder\n");

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.mem_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_MEM_READ, pcb);
    pcb.mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_MEM_WRITE, pcb);

    text_memlog = fopen("text_memlog.txt", "w");

    return true;
}

// Wilson score interval. Text is +1, non-text is -1
double confidence(int ups, int downs) {
    int n = ups + downs;

    if (n == 0)
        return 0;

    double z = 1.6;  // 1.0 = 85%, 1.6 = 95%
    double phat = ((double)ups) / n;
    return sqrt(phat+z*z/(2*n)-z*((phat*(1-phat)+z*z/(4*n))/n))/(1+z*z/n);
}

bool confidence_compare(std::pair<target_ulong,text_counter> first,
                        std::pair<target_ulong,text_counter> second) {
    return confidence(first.second.num_text, first.second.num_nontext) < confidence(second.second.num_text, second.second.num_nontext);
}

void uninit_plugin(void *self) {
    std::list<std::pair<target_ulong,text_counter> > display_map;

    printf("Memory statistics: %d loads, %d stores, %d bytes read, %d bytes written.\n",
        num_reads, num_writes, bytes_read, bytes_written
    );

    // In order to sort this properly
    for(std::map<target_ulong,text_counter>::iterator it = text_tracker.begin(); it != text_tracker.end(); it++) {
        display_map.push_back(std::make_pair(it->first, it->second));
    }
    display_map.sort(confidence_compare);

    FILE *mem_report = fopen("mem_report.txt", "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }
    fprintf(mem_report, "PC          Text/Non-text\n");
    std::list<std::pair<target_ulong,text_counter> >::iterator it;
    for(it = display_map.begin(); it != display_map.end(); it++) {
        fprintf(mem_report, "0x" TARGET_FMT_lx "  %d/%d\n", it->first, it->second.num_text, it->second.num_nontext);
    }
    fclose(mem_report);
    
    fclose(text_memlog);
}
