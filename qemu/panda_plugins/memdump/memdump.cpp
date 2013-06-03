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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <map>
#include <list>
#include <algorithm>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

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

struct fpos { unsigned long off; };
std::map<prog_point,fpos> read_tracker;
std::map<prog_point,fpos> write_tracker;
FILE *read_log, *write_log;
unsigned char *read_buf, *write_buf;
unsigned long read_sz, write_sz;

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf,
                       std::map<prog_point,fpos> &tracker, unsigned char *log) {
    prog_point p = {};
#ifdef TARGET_I386
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&p.caller, 4, 0);
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = env->cr[3];
#endif
    p.pc = pc;
    
    //fseek(log, tracker[p].off, SEEK_SET);
    //fwrite((unsigned char *)buf, size, 1, log);
    fpos &fp = tracker[p];
    memcpy(log+fp.off, buf, size);
    fp.off += size;

    return 1;
}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, write_tracker, write_buf);
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, read_tracker, read_buf);
}

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin memdump\n");

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    FILE *read_idx, *write_idx;
    prog_point p = {};
    unsigned long off = 0;
    long size = 0;

    read_idx = fopen("tap_reads.idx", "r");
    if (read_idx) {
        printf("Calculating read indices...\n");
        fseek(read_idx, 4, SEEK_SET);
        while (!feof(read_idx)) {
            fread(&p, sizeof(p), 1, read_idx);
            fread(&size, sizeof(long), 1, read_idx);
            read_tracker[p].off = off;
            off += size;
        }

        pcb.virt_mem_read = mem_read_callback;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);

        read_sz = off;
        read_log = fopen("tap_reads.bin", "w+");
        if (!read_log)
            perror("fopen");
        ftruncate(fileno(read_log), read_sz);

        read_buf = (unsigned char *)mmap(NULL, read_sz, PROT_WRITE, MAP_SHARED, fileno(read_log), 0);
        if (read_buf == MAP_FAILED) perror("mmap");
        if (madvise(read_buf, read_sz, MADV_RANDOM) == -1)
            perror("madvise");
    }

    // reset
    off = 0;
    size = 0;

    write_idx = fopen("tap_writes.idx", "r");
    if (write_idx) {
        printf("Calculating write indices...\n");
        fseek(write_idx, 4, SEEK_SET);
        while (!feof(write_idx)) {
            fread(&p, sizeof(p), 1, write_idx);
            fread(&size, sizeof(long), 1, write_idx);
            write_tracker[p].off = off;
            off += size;
        }

        pcb.virt_mem_write = mem_write_callback;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

        write_sz = off;
        write_log = fopen("tap_writes.bin", "w+");
        if (!write_log)
            perror("fopen");
        ftruncate(fileno(write_log), write_sz);

        write_buf = (unsigned char *)mmap(NULL, write_sz, PROT_WRITE, MAP_SHARED, fileno(write_log), 0);
        if (write_buf == MAP_FAILED) perror("mmap");
        if (madvise(write_buf, write_sz, MADV_RANDOM) == -1)
            perror("madvise");
    }

    return true;
}

void uninit_plugin(void *self) {
    if (read_log) {
        if(msync(read_buf, read_sz, MS_SYNC) == -1)
            perror("msync");
        if(munmap(read_buf, read_sz) == -1)
            perror("munmap");
        fclose(read_log);
    }
    if (write_log) {
        if(msync(write_buf, write_sz, MS_SYNC) == -1)
            perror("msync");
        if(munmap(write_buf, write_sz) == -1)
            perror("munmap");
        fclose(write_log);
    }
}
