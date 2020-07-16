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

uint64_t rel_time[FIFO_SIZE] = {0}; // deltas
bool rel_kernel[FIFO_SIZE] = {0}; // 1 if kernel, 0 if user
uint64_t last_block_time; // last block time


void before_block_exec_ratio(CPUState *env, TranslationBlock *tb);
void before_block_exec_time(CPUState *env, TranslationBlock *tb);

float avg_exec_time() {
    uint64_t sum_ms = 0; // Average microseconds per block for last FIFO_SIZE
    for (int i=0; i < FIFO_SIZE; i++) {
        sum_ms += rel_time[i];
    }
    return sum_ms/FIFO_SIZE; // AVG time per block
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
          printf("[SPEEDTEST] Average bock took %.3f microsec to execute (over the last %d blocks)\n", avg_exec_time(), FIFO_SIZE);
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

    bb_count++;
    return;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec_ratio };
    //panda_cb pcb = { .before_block_exec = before_block_exec_time };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    return true;
}

void uninit_plugin(void *self) { }
