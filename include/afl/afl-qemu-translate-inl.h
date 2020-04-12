+/*
+   american fuzzy lop - high-performance binary-only instrumentation
+   -----------------------------------------------------------------
+
+   Written by Andrew Griffiths <agriffiths@google.com> and
+              Michal Zalewski <lcamtuf@google.com>
+
+   Idea & design very much by Andrew Griffiths.
+
+   TCG instrumentation by Andrea Biondo <andrea.biondo965@gmail.com>
+
+   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+   you may not use this file except in compliance with the License.
+   You may obtain a copy of the License at:
+
+     http://www.apache.org/licenses/LICENSE-2.0
+
+   This code is a shim patched into the separately-distributed source
+   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
+   to implement AFL-style instrumentation and to take care of the remaining
+   parts of the AFL fork server logic.
+
+   The resulting QEMU binary is essentially a standalone instrumentation
+   tool; for an example of how to leverage it for other purposes, you can
+   have a look at afl-showmap.c.
+
+ */

#include "afl/config.h"
#include "tcg-op.h"

/* Declared in afl-qemu-cpu-inl.h */
extern unsigned char *afl_area_ptr;
extern unsigned int afl_inst_rms;
extern target_ulong afl_start_code, afl_end_code;
extern int aflStart;

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



  static __thread target_ulong prev_loc;
  TCGv index, count, new_prev_loc;
  TCGv_ptr prev_loc_ptr, count_ptr;

  cur_loc = aflHash(cur_loc);
  if(!cur_loc) return;

  /* index = prev_loc ^ cur_loc */
  prev_loc_ptr = tcg_const_ptr(&prev_loc);
  index = tcg_temp_new();
  tcg_gen_ld_tl(index, prev_loc_ptr, 0);
  tcg_gen_xori_tl(index, index, cur_loc);

  /* afl_area_ptr[index]++ */
  count_ptr = tcg_const_ptr(afl_area_ptr);
  tcg_gen_add_ptr(count_ptr, count_ptr, TCGV_NAT_TO_PTR(index));
  count = tcg_temp_new();
  tcg_gen_ld8u_tl(count, count_ptr, 0);
  tcg_gen_addi_tl(count, count, 1);
  tcg_gen_st8_tl(count, count_ptr, 0);

  /* prev_loc = cur_loc >> 1 */
  new_prev_loc = tcg_const_tl(cur_loc >> 1);
  tcg_gen_st_tl(new_prev_loc, prev_loc_ptr, 0);
}

