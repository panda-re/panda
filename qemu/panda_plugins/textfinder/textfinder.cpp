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

struct text_counter { int hist[256]; };
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

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    bytes_written += size;
    num_writes++;
    prog_point p = {};
#ifdef TARGET_I386
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&p.caller, 4, 0);
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = env->cr[3];
#endif
    p.pc = pc;
    for (unsigned int i = 0; i < size; i++) {
        unsigned char val = ((unsigned char *)buf)[i];
        //fprintf(text_memlog, TARGET_FMT_lx "." TARGET_FMT_lx " " TARGET_FMT_lx " %02x\n" , p.pc, p.caller, addr+i, val);
        text_tracker[p].hist[val]++;
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

    pcb.virt_mem_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);
    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

    //text_memlog = fopen("text_memlog.txt", "w");

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

int num_text(text_counter t) {
    int sum = 0;
    for (int i = 0; i < 256; i++)
        if (isprint(i)) sum += t.hist[i];
    return sum;
}

int num_nontext(text_counter t) {
    int sum = 0;
    for (int i = 0; i < 256; i++)
        if (!isprint(i)) sum += t.hist[i];
    return sum;
}

bool confidence_compare(std::pair<prog_point,text_counter> first,
                        std::pair<prog_point,text_counter> second) {
    int first_text = num_text(first.second);
    int first_nontext = num_nontext(first.second);
    int second_text = num_text(second.second);
    int second_nontext = num_nontext(second.second);
    return confidence(first_text, first_nontext) < confidence(second_text, second_nontext);
}

double byte_entropy(text_counter t) {
    int sum = 0;
    for (int i = 0; i < 256; i++) {
        sum += t.hist[i];
    }
    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        double p_i = t.hist[i] / (double)sum;
        if (t.hist[i] != 0)
            ent += -(p_i*(log(p_i)/log(2.0)));
    }
    return ent;
}

void uninit_plugin(void *self) {
    std::list<std::pair<prog_point,text_counter> > display_map;

    printf("Memory statistics: %lu loads, %lu stores, %lu bytes read, %lu bytes written.\n",
        num_reads, num_writes, bytes_read, bytes_written
    );

    // In order to sort this properly
    for(std::map<prog_point,text_counter>::iterator it = text_tracker.begin(); it != text_tracker.end(); it++) {
        display_map.push_back(std::make_pair(it->first, it->second));
    }
    //display_map.sort(confidence_compare);

    FILE *mem_report = fopen("mem_report.bin", "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }
    //fprintf(mem_report, "PC          Text/Non-text\n");
    std::list<std::pair<prog_point,text_counter> >::iterator it;
    for(it = display_map.begin(); it != display_map.end(); it++) {
        //fprintf(mem_report, TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx, it->first.cr3, it->first.pc, it->first.caller);
        //for(int i = 0; i < 256; i++) fprintf(mem_report, " %d", it->second.hist[i]);
        //fprintf(mem_report, " %f", byte_entropy(it->second));
        //fprintf(mem_report, "\n");
        fwrite(&it->first, sizeof(prog_point), 1, mem_report);
        fwrite(&it->second, sizeof(text_counter), 1, mem_report);
    }
    fclose(mem_report);
    
    //fclose(text_memlog);
}
