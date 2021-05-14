/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   TCG instrumentation by Andrea Biondo <andrea.biondo965@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */
#include "afl/config.h"
#include "tcg-op.h"
#include "afl/afl.h"

/* Declared in afl-qemu-cpu-inl.h */
extern unsigned char *afl_area_ptr;
extern target_ulong afl_start_code, afl_end_code;
extern  __thread target_ulong afl_prev_loc;
extern int aflStart;


void HELPER(afl_maybe_log)(target_ulong cur_loc) {

  register uintptr_t afl_idx = cur_loc ^ afl_prev_loc;

  INC_AFL_AREA(afl_idx);

  afl_prev_loc = cur_loc >> 1;

}



static inline target_ulong aflHash(target_ulong cur_loc)
{
  if(!aflStart)
    return 0;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return 0;

#ifdef DEBUG_EDGES
  if(1) {
    printf("exec %lx\n", cur_loc);
    fflush(stdout);
  }
#endif

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  target_ulong h = cur_loc;
#if TARGET_LONG_BITS == 32
  h ^= cur_loc >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
#else
  h ^= cur_loc >> 33;
  h *= 0xff51afd7ed558ccd;
  h ^= h >> 33;
  h *= 0xc4ceb9fe1a85ec53;
  h ^= h >> 33;
#endif

  h &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (h >= afl_inst_rms) return 0;
  return h;
}
/* Generates TCG code for AFL's tracing instrumentation. */
static void afl_gen_trace(target_ulong cur_loc)
{

  /*  shannon traces all ...
   *  otherwise there would be checks for start and end_code right here */

  if (!aflStart)
    return;

  /* Looks like QEMU always maps to fixed locations, so ASLR is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  TCGv cur_loc_v = tcg_const_tl(cur_loc);
  gen_helper_afl_maybe_log(cur_loc_v);
  tcg_temp_free(cur_loc_v);

}

static inline void gen_afl_compcov_log_16(uint64_t cur_loc,
                                          TCGv_i32 arg1, TCGv_i32 arg2) {
#if defined(AFL_DEBUG)
  printf("[d] Emitting 16 bit COMPCOV instrumentation for loc 0x%lx\n", cur_loc);
#endif

  TCGv_i64 tcur_loc = tcg_const_i64(cur_loc);
  gen_helper_afl_compcov_log_16(tcur_loc, arg1, arg2);

}

static inline void gen_afl_compcov_log_32(uint64_t cur_loc,
                                          TCGv_i32 arg1, TCGv_i32 arg2) {
#if defined(AFL_DEBUG)
  printf("[d] Emitting 32 bit COMPCOV instrumentation for loc 0x%lux\n", cur_loc);
#endif

  TCGv_i64 tcur_loc = tcg_const_i64(cur_loc);
  gen_helper_afl_compcov_log_32(tcur_loc, arg1, arg2);

}

static inline void gen_afl_compcov_log_64(uint64_t cur_loc,
                                          TCGv_i64 arg1, TCGv_i64 arg2) {
#if defined(AFL_DEBUG)
  printf("[d] Emitting 64 bit COMPCOV instrumentation for loc 0x%lux\n", cur_loc);
#endif

  TCGv_i64 tcur_loc = tcg_const_i64(cur_loc);
  gen_helper_afl_compcov_log_64(tcur_loc, arg1, arg2);

}


void HELPER(afl_compcov_log_16)(uint64_t cur_loc, uint32_t arg1,
                                uint32_t arg2) {

  if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(cur_loc); }

}

void HELPER(afl_compcov_log_32)(uint64_t cur_loc, uint32_t arg1,
                                uint32_t arg2) {

  if ((arg1 & 0xff000000) == (arg2 & 0xff000000)) {

    INC_AFL_AREA(cur_loc + 2);
    if ((arg1 & 0xff0000) == (arg2 & 0xff0000)) {

      INC_AFL_AREA(cur_loc + 1);
      if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(cur_loc); }

    }

  }

}

void HELPER(afl_compcov_log_64)(uint64_t cur_loc, uint64_t arg1,
                                uint64_t arg2) {

  if ((arg1 & 0xff00000000000000) == (arg2 & 0xff00000000000000)) {

    INC_AFL_AREA(cur_loc + 6);
    if ((arg1 & 0xff000000000000) == (arg2 & 0xff000000000000)) {

      INC_AFL_AREA(cur_loc + 5);
      if ((arg1 & 0xff0000000000) == (arg2 & 0xff0000000000)) {

        INC_AFL_AREA(cur_loc + 4);
        if ((arg1 & 0xff00000000) == (arg2 & 0xff00000000)) {

          INC_AFL_AREA(cur_loc + 3);
          if ((arg1 & 0xff000000) == (arg2 & 0xff000000)) {

            INC_AFL_AREA(cur_loc + 2);
            if ((arg1 & 0xff0000) == (arg2 & 0xff0000)) {

              INC_AFL_AREA(cur_loc + 1);
              if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(cur_loc); }

            }

          }

        }

      }

    }

  }

}

void afl_gen_compcov(uint64_t cur_loc, TCGv arg1,
                            TCGv arg2, TCGMemOp ot, int is_imm) {

  static int afl_compcov_level = -1;
  if (afl_compcov_level < 0) {
    char *compcov_level_str = getenv("AFL_COMPCOV_LEVEL");
    if (compcov_level_str) {
      afl_compcov_level = atoi(compcov_level_str);
      printf("Got AFL_COMPCOV_LEVEL %d.\n", afl_compcov_level);
    } else {
      printf("AFL_COMPCOV_LEVEL not set.\n");
      afl_compcov_level = 0;
    }
  }

  if (!afl_compcov_level || !afl_area_ptr) return;

  if (!is_imm && afl_compcov_level < 2) return;

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 7;

  if (cur_loc >= afl_inst_rms) return;

  switch (ot) {

    case MO_64: gen_afl_compcov_log_64(cur_loc, (TCGv_i64)arg1, (TCGv_i64)arg2); break;
    case MO_32: gen_afl_compcov_log_32(cur_loc, (TCGv_i32)arg1, (TCGv_i32)arg2); break;
    case MO_16: gen_afl_compcov_log_16(cur_loc, (TCGv_i32)arg1, (TCGv_i32)arg2); break;
    default: return;

  }

}
