/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.2.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */
#include<stdio.h>
#include<signal.h>
#include<unistd.h>

#include <sys/shm.h>
#include "afl/afl.h"
#include "afl/config.h"

#include "tcg-op.h"
/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2(env, pc) do { \
    if(pc == afl_entry_point && pc && getenv("AFLGETWORK") == 0) { \
      afl_setup(); \
      afl_forkserver(env); \
    } \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char
               dummy[MAP_SIZE]; /* costs MAP_SIZE but saves a few instructions */
unsigned char *afl_area_ptr = dummy;          /* Exported for afl_gen_trace */

static u32            cycle_cnt;

/* Exported variables populated by the code patched into elfload.c: */

target_ulong afl_entry_point = 0, /* ELF entry point (_start) */
          afl_start_code = 0,  /* .text start pointer      */
          afl_end_code = 0xffffffff;    /* .text end pointer        */

target_ulong    afl_persistent_addr, afl_persistent_ret_addr;
unsigned int afl_persistent_cnt;
unsigned char is_persistent;
unsigned char persistent_first_pass = 1;

static int forkserver_installed = 0;


int aflStart = 0;               /* we've started fuzzing */
int aflEnableTicks = 0;         /* re-enable ticks for each test */
int aflGotLog = 0;              /* we've seen dmesg logging */

/* from command line options */
const char *aflFile = "/tmp/work";
unsigned long aflPanicAddr = (unsigned long)-1;
unsigned long aflDmesgAddr = (unsigned long)-1;

__thread target_ulong afl_prev_loc;
/* Set in the child process in forkserver mode: */

unsigned char afl_fork_child = 0;
int afl_wants_cpu_to_stop = 0;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

unsigned int afl_inst_rms = MAP_SIZE; /* Exported for afl_gen_trace */


/* Function declarations. */


static void afl_wait_tsl(CPUArchState*, int);


TranslationBlock *tb_htable_lookup(CPUState*, target_ulong, target_ulong, uint32_t);
static inline TranslationBlock *tb_find(CPUState*, TranslationBlock*, int);
/*static TranslationBlock *tb_find_slow(CPUArchState*, target_ulong,*/
/*target_ulong, uint64_t);*/


/* Data structure passed around by the translate handlers: */


struct afl_tb {
  target_ulong pc;
  target_ulong cs_base;
  uint32_t flags;
};

struct afl_tsl {
  struct afl_tb tb;
  char cmd;
};

struct afl_chain {
  struct afl_tb last_tb;
  int tb_exit;
};



/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }


  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (target_ulong)-1;

  }

}

static ssize_t uninterrupted_read(int fd, void *buf, size_t cnt)
{
    ssize_t n;
    while((n = read(fd, buf, cnt)) == -1 && errno == EINTR)
        continue;
    return n;
}

/* Fork server logic, invoked once we hit _start. */

void afl_forkserver(CPUArchState *env) {

  static unsigned char tmp[4];

  if (forkserver_installed == 1) return;
  forkserver_installed = 1;

  // if (!afl_area_ptr) return; // not necessary because of fixed dummy buffer

  pid_t child_pid;
  int   t_fd[2];
  u8    child_stopped = 0;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  int first_run = 1;

  /* All right, let's await orders... */

  while (1) {

    int status;
    u32 was_killed;

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) exit(2);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {

      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) exit(8);

    }

    if (!child_stopped) {

      /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

      if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
      close(t_fd[1]);

      aflStart=0;
      child_pid = fork();
      if (child_pid < 0) exit(4);

      if (!child_pid) {

        /* Child process. Close descriptors and run free. */

        afl_fork_child = 1;
        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        close(t_fd[0]);
        return;

      }

      /* Parent. */

      close(TSL_FD);

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* Parent. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(env, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0) exit(6);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)){
      child_stopped = 1;
      status = 0;
    }
    else if (unlikely(first_run && is_persistent)) {

      fprintf(stderr, "[AFL] ERROR: no persistent iteration executed\n");
      exit(12);  // Persistent is wrong

    }

    first_run = 0;

    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}

/* A simplified persistent mode handler, used as explained in
 * llvm_mode/README.md. */

void afl_persistent_start(void) {


  if (!afl_fork_child) return;

  if (persistent_first_pass) {

      /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       * On subsequent calls, the parent will take care of that, but on the first
       * iteration, it's our job to erase any trace of whatever happened
       * before the loop. */

          if (is_persistent) {

              memset(afl_area_ptr, 0, MAP_SIZE);
              afl_area_ptr[0] = 1;
              afl_prev_loc = 0;

          }

      cycle_cnt = afl_persistent_cnt;
      persistent_first_pass = 0;
      //persistent_stack_offset = TARGET_LONG_BITS / 8;

      return;

  }
}

void afl_persistent_stop(void) {

  if (!afl_fork_child) return;
  if (is_persistent) {

    if (--cycle_cnt) {

      afl_request_tsl(0, 0, 0, 0, 0, EXIT_TSL);

      raise(SIGSTOP);

      afl_area_ptr[0] = 1;
      afl_prev_loc = 0;

    } else {

      afl_area_ptr = dummy;
      exit(0);

    }

  }
}


/* todo: generate calls to helper_aflMaybeLog during translation */
static inline void helper_aflMaybeLog(target_ulong cur_loc) {
  static __thread target_ulong prev_loc;

  afl_area_ptr[cur_loc ^ prev_loc]++;
  prev_loc = cur_loc >> 1;
}

/* The equivalent of the tuple logging routine from afl-as.h. */

/*static inline void afl_maybe_log(target_ulong cur_loc) {*/
/*cur_loc = aflHash(cur_loc);*/
/*if(cur_loc)*/
/*helper_aflMaybeLog(cur_loc);*/
/*}*/


/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

void afl_request_tsl(target_ulong pc, target_ulong cb, uint32_t flags,
                            TranslationBlock *last_tb, int tb_exit, char cmd) {

  struct afl_tsl t;
  struct afl_chain c;


  if (!afl_fork_child) return;

  t.tb.pc      = pc;
  t.tb.cs_base = cb;
  t.tb.flags   = flags;
  t.cmd        = cmd;

  if ( cmd = TRANSLATE && last_tb != NULL)
      t.cmd = IS_CHAIN;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl)){
    afl_area_ptr = dummy;
    exit(0);
    return;
  }

  if (t.cmd == IS_CHAIN) {

    c.last_tb.pc = last_tb->pc;
    c.last_tb.cs_base = last_tb->cs_base;
    c.last_tb.flags = last_tb->flags;
    c.tb_exit = tb_exit;

    if (write(TSL_FD, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain)){
      afl_area_ptr = dummy;
      exit(0);
      return;
    }
  }
}


/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUArchState *env, int fd) {
  CPUState * cpu = ENV_GET_CPU(env);
  struct afl_tsl t;
  struct afl_chain c;
  TranslationBlock *tb, *last_tb;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    switch (t.cmd){
        case EXIT_TSL: return;
        case START_AFL: aflStart = 1; continue;
        case STOP_AFL: aflStart = 0; continue;
        default: break;
    }

    tb = tb_htable_lookup(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags);

    if(!tb) {
      mmap_lock();
      tb_lock();
      tb = tb_gen_code(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, 0);
      mmap_unlock();
      tb_unlock();

    }

    if (t.cmd == IS_CHAIN) {
      if (read(fd, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
        break;

      last_tb = tb_htable_lookup(cpu, c.last_tb.pc, c.last_tb.cs_base,
                                 c.last_tb.flags);
      if (last_tb) {
        tb_lock();
        if (!tb->invalid) {
          tb_add_jump(last_tb, c.tb_exit, tb);
        }
        tb_unlock();
      }
    }

  }

  close(fd);

}




