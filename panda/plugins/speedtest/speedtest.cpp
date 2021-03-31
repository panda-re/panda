/* PANDABEGINCOMMENT
 * 
 * Authors:
 * Andrew Fasano
 *
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include <sys/time.h>

#include <algorithm> 
#include <chrono> 
#include <iostream> 

extern "C" {
  bool init_plugin(void *);
  void uninit_plugin(void *);
}

#define FIFO_SIZE 400000
unsigned long bb_count = 0; // XXX: Will eventually overflow
unsigned long userspace_blocks = 0; // XXX: Will eventually overflow

uint64_t rel_time[FIFO_SIZE] = {0}; // deltas
bool rel_kernel[FIFO_SIZE] = {0}; // 1 if kernel, 0 if user
uint64_t last_block_time; // last block time

#define INT_SIZE 256
uint64_t int_count = 0;
uint64_t bbs_since_last_int[INT_SIZE] = {0};
uint64_t last_bb_count = 0; // block idx  at laist interrupt

int delay = 0; // Delay to inject in each bb


void block_counter(CPUState *cpu, TranslationBlock *tb);
void before_block_exec_ratio(CPUState *env, TranslationBlock *tb);
void before_block_exec_time(CPUState *env, TranslationBlock *tb);
int before_handle_interrupt(CPUState*cpu, int intno);

float avg_exec_time() {
    uint64_t sum_ms = 0; // Average microseconds per block for last FIFO_SIZE
    for (int i=0; i < FIFO_SIZE; i++) {
        sum_ms += rel_time[i];
    }
    return (float)sum_ms/FIFO_SIZE; // AVG time per block
}

float avg_blocks_per_int() {
    // Return average # blocks executed per interrupt
    uint64_t blocks_executed = 0;
    for (int i=0; i < INT_SIZE; i++) {
        blocks_executed += bbs_since_last_int[i];
    }
    return blocks_executed/INT_SIZE;
}

int before_handle_interrupt(CPUState*cpu, int32_t intno) {
    //uint64_t delta = bb_count - last_bb_count; // Blocks executed since last int
    uint64_t delta = userspace_blocks - last_bb_count; // USERSPACE blocks.
    int_count++;

    bbs_since_last_int[int_count % INT_SIZE] = delta;

    if (int_count % (INT_SIZE/4) == 0 && int_count > INT_SIZE) {
      // report
        printf("[SPEEDTEST] Average userspace blocks executed between interrupts %.2f (over the last %d interrupts)\n", avg_blocks_per_int(), INT_SIZE);
    }

    //last_bb_count = bb_count;
    last_bb_count = userspace_blocks;

    return intno; // Do not modify!
}

void block_counter(CPUState *cpu, TranslationBlock *tb) {
    if (delay) usleep(delay); // slow down. 1000*microsecs = 1 millisec
    bb_count++;
    if (!panda_in_kernel(cpu))  userspace_blocks++;

}

void before_block_exec_time(CPUState *env, TranslationBlock *tb) {
    // Get current time
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);

    uint64_t cur_time_microsecs;
    cur_time_microsecs = now.tv_sec * 1000000 + now.tv_nsec / 1000;

    if (bb_count == 0)  { // First block - just store current time
      last_block_time = cur_time_microsecs;
    }else{
      // Measure diff
      uint64_t diff = cur_time_microsecs - last_block_time;

      // Update last
      last_block_time = cur_time_microsecs;

      // Store in FIFO
      rel_time[bb_count % FIFO_SIZE] = diff;

      // Log ever FIFO_SIZE/4 events once we fill queue
      if ((bb_count % (FIFO_SIZE/4)) == 0 && bb_count > FIFO_SIZE) {
          printf("[SPEEDTEST] Average bock took %.3f microseconds to execute (over the last %d blocks)\n", avg_exec_time(), FIFO_SIZE);
      }
    }
}

float kernel_ratio() {
    uint64_t sum_in_k = 0;
    for (int i=0; i < FIFO_SIZE; i++) {
      if (rel_kernel[i]) sum_in_k++;
    }
    return float(sum_in_k)/FIFO_SIZE;
}


// Measure kernel ratio
void before_block_exec_ratio(CPUState *env, TranslationBlock *tb) {
    rel_kernel[bb_count % FIFO_SIZE] = panda_in_kernel(env);

    if ((bb_count % (FIFO_SIZE/4)) == 0 && bb_count > FIFO_SIZE) {
        printf("[SPEEDTEST] Kernel ratio %.4f (over the last %d blocks)\n", kernel_ratio(), FIFO_SIZE);
    }

    return;
}

bool report_time;
bool report_ratio;
bool report_ints;
bool final_log;

bool init_plugin(void *self) {
    report_time  = false;
    report_ratio = false;
    report_ints  = false;
    final_log    = false;

    panda_arg_list *args = panda_get_args("speedtest");
    if (args != NULL) {
        delay =       panda_parse_uint64_opt(args, "delay", 0, "Artifical delay (in microseconds) to introduce for every basic block");
        report_ratio =  panda_parse_bool_opt(args, "ratio",     "Record and report ratio of userspace vs kernelspace blocks executed");
        report_time =   panda_parse_bool_opt(args, "times",     "Record and report average block execution time");
        report_ints =   panda_parse_bool_opt(args, "ints",      "Record and report average blocks run between each interrupt");
        final_log =     panda_parse_bool_opt(args, "final_log", "Print a final report of last measurements when plugin is unloaded");
    }

    if (delay) {
        // This is a crazy option, make sure user knows they're _slowing down_ execution intentionally
        printf("[SPEEDTEST] Injecting delay of %d microseconds\n", delay);
    }

    // Always enabled - count blocks
    panda_cb pcb0 = { .before_block_exec = block_counter };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb0);

    // Track ratio between userspace and kernel
    if (report_ratio) {
        panda_cb pcb1 = { .before_block_exec = before_block_exec_ratio };
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb1);
    }

    // Track average block exec time
    if (report_time) {
        panda_cb pcb2 = { .before_block_exec = before_block_exec_time };
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb2);
    }

    if (report_ints) {
#ifdef TARGET_I386
        panda_cb pcb3 = { .before_handle_interrupt = before_handle_interrupt };
        panda_register_callback(self, PANDA_CB_BEFORE_HANDLE_INTERRUPT, pcb3);
#else
        printf("[SPEEDTEST] report_ints Unsupported for target architecture\n");
        return false;
#endif
    }

    return true;
}

void uninit_plugin(void *self) {
    // Report any requested data for final buffer (since last buffer/4 -> current)
    if (!final_log) {
        return;
    }

    if (report_ints) {
        uint64_t blocks_executed = 0;
        for (int i=(int_count % (INT_SIZE/4)); i < INT_SIZE/4; i++) {
            blocks_executed += bbs_since_last_int[i];
        }
        float x = blocks_executed/(INT_SIZE/4);
        printf("[SPEEDTEST] Over final %ld interrupts, average of %.3f userspace blocks per interrupt\n", (INT_SIZE/4 - (int_count % (INT_SIZE)/4)), x);
    }

    if (report_time) {
        uint64_t sum_ms = 0; // Average tenth-microseconds per block for last FIFO_SIZE
        for (int i=(bb_count % (FIFO_SIZE/4)); i < FIFO_SIZE%4; i++) {
            sum_ms += rel_time[i]*10;
        }
        float x = sum_ms/(FIFO_SIZE/4); // AVG time per block
        printf("[SPEEDTEST] Over final %ld blocks, average of %.3fs per block\n", (FIFO_SIZE/4 - (bb_count % (FIFO_SIZE)/4)), x);
    }

    if (report_ratio) {
        uint64_t sum_in_k = 0; // count of blocks in kernel
        for (int i=(bb_count % (FIFO_SIZE/4)); i < FIFO_SIZE%4; i++) {
            if (rel_kernel[i]) sum_in_k++;
        }
        float x = float(sum_in_k)/(FIFO_SIZE/4); // AVG time per block
        printf("[SPEEDTEST] Over final %ld blocks, kernel ratio %.4f\n", (FIFO_SIZE/4 - (bb_count % (FIFO_SIZE)/4)), x);
    }

}
