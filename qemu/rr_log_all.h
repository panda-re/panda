/*
 * Record and Replay for QEMU
 *
 * Copyright (c) 2007-2011 Massachusetts Institute of Technology
 *
 * Authors:
 *   Tim Leek <tleek@ll.mit.edu>
 *   Michael Zhivich <mzhivich@ll.mit.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __RR_LOG_H_ALL_
#define __RR_LOG_H_ALL_

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "osdep.h"
#include <signal.h>

#include <stdint.h>
#include <assert.h>

typedef enum {RR_OFF, RR_RECORD, RR_REPLAY} RR_mode;

extern volatile RR_mode rr_mode;

// Log management
void rr_create_record_log (const char *filename);
void rr_create_replay_log (const char *filename);
void rr_destroy_log(void);
uint8_t rr_replay_finished(void);

//mz Flags set by monitor to indicate requested record/replay action
extern volatile int rr_replay_requested;
extern volatile int rr_record_requested;
extern volatile int rr_end_record_requested;
extern volatile int rr_end_replay_requested;
extern const char *rr_requested_name;
extern const char *rr_snapshot_name;

// used from monitor.c 
int  rr_do_begin_record(const char *name, void *cpu_state);
void rr_do_end_record(void);
int  rr_do_begin_replay(const char *name, void *cpu_state);
void rr_do_end_replay(int is_error);
void rr_reset_state(void *cpu_state);

//mz display indication of replay progress
extern void replay_progress(void);

//bdg helper to find out how many instructions
//    are in our log
uint64_t replay_get_total_num_instructions(void);

void rr_quit_cpu_loop(void);
void rr_set_program_point(void);

//mz 10.20.2009 
//mz A record of a point in the program.  This is a subset of guest CPU state
//mz and the number of guest instructions executed so far.
typedef struct RR_prog_point_t {
  uint64_t pc;             
  uint64_t secondary;
  uint64_t guest_instr_count;
} RR_prog_point;
extern RR_prog_point rr_prog_point;

//mz number of guest instructions executed since start of session (for both
//mz record and replay)
//extern volatile uint64_t rr_guest_instr_count;
//mz part of replay state that determines whether we need to terminate a
//mz translation block early
extern volatile uint64_t rr_num_instr_before_next_interrupt;
//mz location of a call initiated by hardware emulation during record
//mz see RR_DO_RECORD_OR_REPLAY() macro
extern volatile sig_atomic_t rr_skipped_callsite_location;
//mz flag to manage nested recording attempts
//mz see RR_DO_RECORD_OR_REPLAY() macro
extern volatile sig_atomic_t rr_record_in_progress; 

extern volatile sig_atomic_t rr_use_live_exit_request;

static inline void rr_set_prog_point(uint64_t pc, uint64_t secondary, uint64_t guest_instr_count) {
  rr_num_instr_before_next_interrupt -= (guest_instr_count - rr_prog_point.guest_instr_count);
  rr_prog_point.guest_instr_count = guest_instr_count;
  rr_prog_point.pc = pc;
  rr_prog_point.secondary = secondary;
}

//mz Routine that handles the situation when program points disagree during
//mz replay. Typically, this means a fatal error - the routine prints some
//mz diagnostics.
extern void rr_signal_disagreement(RR_prog_point current, RR_prog_point recorded);


//
// Record/Replay log structures
//

// Skipped calls are records of machine emulation activity that were triggered
// by hardware devices during record session.  Since device emulation code is
// not run during replay, we'll need to replay these calls (at the right
// program point) to achieve the same effect.

typedef enum {
    RR_CALL_CPU_MEM_RW,             // cpu_physical_memory_rw()
    RR_CALL_CPU_REG_MEM_REGION,     // cpu_register_physical_memory()
    RR_CALL_CPU_MEM_UNMAP,          // cpu_physical_memory_unmap()
    RR_CALL_HD_TRANSFER,            // hd transfer
    RR_CALL_NET_TRANSFER,           // network transfer in device
    RR_CALL_HANDLE_PACKET,          // packet handling on send/receive
    RR_CALL_LAST
} RR_skipped_call_kind;

static const char *skipped_call_kind_str[] = {
    "RR_CALL_CPU_MEM_RW",
    "RR_CALL_CPU_REG_MEM_REGION",
    "RR_CALL_CPU_MEM_UNMAP",
    "RR_CALL_HD_TRANSFER",
    "RR_CALL_NET_TRANSFER",
    "RR_CALL_HANDLE_PACKET",
    "RR_CALL_LAST"
};

static inline const char *get_skipped_call_kind_string(RR_skipped_call_kind kind)
{
  //  if (kind >= 0 && kind <= RR_CALL_LAST)
  if (kind <= RR_CALL_LAST)
        return skipped_call_kind_str[kind];
    else
        return NULL;
}

// Log entries come in 3 different flavors:
// - IO input (1, 2, 4 and 8 bytes)
// - interrupt request (value is stored only when non-zero)
// - skipped call (as described above)

typedef enum {
    RR_INPUT_1,
    RR_INPUT_2,
    RR_INPUT_4,
    RR_INPUT_8,
    RR_INTERRUPT_REQUEST,
    RR_EXIT_REQUEST,
    RR_SKIPPED_CALL,
    RR_DEBUG,
    RR_LAST
} RR_log_entry_kind;

static const char *log_entry_kind_str[] = {
    "RR_INPUT_1",
    "RR_INPUT_2",
    "RR_INPUT_4",
    "RR_INPUT_8",
    "RR_INTERRUPT_REQUEST",
    "RR_EXIT_REQUEST",
    "RR_SKIPPED_CALL",
    "RR_DEBUG",
    "RR_LAST"
};

static inline const char *get_log_entry_kind_string(RR_log_entry_kind kind)
{
    if (kind <= RR_LAST)
        return log_entry_kind_str[kind];
    else
        return NULL;
}

//mz 10.20.2009 Unified view of all callsite ids for record/replay calls.
//mz These are used as additional sanity check during replay
typedef enum {
  RR_CALLSITE_DEFAULT_IOPORT_READW,
  RR_CALLSITE_CPU_INB,
  RR_CALLSITE_CPU_INW, 
  RR_CALLSITE_CPU_INL, 
  RR_CALLSITE_CPU_PHYSICAL_MEMORY_RW_1,
  RR_CALLSITE_CPU_PHYSICAL_MEMORY_RW_2,
  RR_CALLSITE_CPU_PHYSICAL_MEMORY_RW_3, 
  RR_CALLSITE_CPU_PHYSICAL_MEMORY_RW_4, 
  RR_CALLSITE_CPU_PHYSICAL_MEMORY_UNMAP,
  RR_CALLSITE_LDL_PHYS,  
  RR_CALLSITE_LDQ_PHYS,  
  RR_CALLSITE_IO_READ_0, 
  RR_CALLSITE_IO_READ_1, 
  RR_CALLSITE_IO_READ_2, 
  RR_CALLSITE_IO_READ_3, 
  RR_CALLSITE_WAIT_IO_EVENT,
  RR_CALLSITE_CPU_EXEC_0,
  RR_CALLSITE_CPU_EXEC_00,
  RR_CALLSITE_CPU_EXEC_000,
  RR_CALLSITE_CPU_EXEC_1, 
  RR_CALLSITE_CPU_EXEC_2, 
  RR_CALLSITE_CPU_EXEC_3,
  RR_CALLSITE_CPU_EXEC_4,
  RR_CALLSITE_CPU_EXEC_DBG,
  RR_CALLSITE_CPU_HALTED,
  RR_CALLSITE_RDTSC,
  RR_CALLSITE_TB_INVALIDATE_PHYS_PAGE_RANGE,
  RR_CALLSITE_CPU_OUTB,
  RR_CALLSITE_CPU_OUTW,
  RR_CALLSITE_CPU_OUTL,
  RR_CALLSITE_IO_WRITE_0, 
  RR_CALLSITE_IO_WRITE_1, 
  RR_CALLSITE_IO_WRITE_2, 
  RR_CALLSITE_IO_WRITE_3, 
  RR_CALLSITE_DEFAULT_IOPORT_WRITEW,
  RR_CALLSITE_MAIN_LOOP,
  RR_CALLSITE_MAIN_LOOP_WAIT,
  RR_CALLSITE_PHYS_MEM_IO_1,
  RR_CALLSITE_PHYS_MEM_IO_2,
  RR_CALLSITE_PHYS_MEM_IO_3,
  RR_CALLSITE_STL_PHYS_ND,
  RR_CALLSITE_STQ_PHYS_ND,
  RR_CALLSITE_STL_PHYS,
  RR_CALLSITE_DO_SMM_ENTER,
  RR_CALLSITE_HELPER_RSM,
  RR_CALLSITE_IOPORT_READ,
  RR_CALLSITE_IOPORT_WRITE,
  RR_CALLSITE_SPARC_CPU_EXEC_1,
  RR_CALLSITE_MIPS_CPU_EXEC_1,
  RR_CALLSITE_IDE_SECTOR_READ,
  RR_CALLSITE_IDE_SECTOR_WRITE,
  RR_CALLSITE_IDE_DMA_CB,
  RR_CALLSITE_IDE_DATA_WRITEW,
  RR_CALLSITE_IDE_DATA_WRITEL,
  RR_CALLSITE_IDE_DATA_READW,
  RR_CALLSITE_IDE_DATA_READL,
  RR_CALLSITE_E1000_RECEIVE_1,
  RR_CALLSITE_E1000_RECEIVE_2,
  RR_CALLSITE_E1000_RECEIVE_3,
  RR_CALLSITE_E1000_RECEIVE_MEMCPY_1,
  RR_CALLSITE_E1000_XMIT_SEG_1,
  RR_CALLSITE_E1000_XMIT_SEG_2,
  RR_CALLSITE_E1000_PROCESS_TX_DESC_1,
  RR_CALLSITE_E1000_PROCESS_TX_DESC_2,
  RR_CALLSITE_E1000_PROCESS_TX_DESC_MEMMOVE_1,
  RR_CALLSITE_E1000_PROCESS_TX_DESC_MEMMOVE_2,
  RR_CALLSITE_E1000_TXDESC_WRITEBACK,
  RR_CALLSITE_E1000_START_XMIT,
  RR_CALLSITE_LAST,
} RR_callsite_id;

static const char *callsite_str[] = {
  "RR_CALLSITE_DEFAULT_IOPORT_READW",
  "RR_CALLSITE_CPU_INB",
  "RR_CALLSITE_CPU_INW", 
  "RR_CALLSITE_CPU_INL", 
  "RR_CALLSITE_CPU_PHYSICAL_MEMORY_RW_1",
  "RR_CALLSITE_CPU_PHYSICAL_MEMORY_RW_2",
  "RR_CALLSITE_CPU_PHYSICAL_MEMORY_RW_3", 
  "RR_CALLSITE_CPU_PHYSICAL_MEMORY_RW_4", 
  "RR_CALLSITE_CPU_PHYSICAL_MEMORY_UNMAP",
  "RR_CALLSITE_LDL_PHYS",  
  "RR_CALLSITE_LDQ_PHYS",  
  "RR_CALLSITE_IO_READ_0", 
  "RR_CALLSITE_IO_READ_1", 
  "RR_CALLSITE_IO_READ_2", 
  "RR_CALLSITE_IO_READ_3", 
  "RR_CALLSITE_WAIT_IO_EVENT",
  "RR_CALLSITE_CPU_EXEC_0",
  "RR_CALLSITE_CPU_EXEC_00",
  "RR_CALLSITE_CPU_EXEC_000",
  "RR_CALLSITE_CPU_EXEC_1", 
  "RR_CALLSITE_CPU_EXEC_2", 
  "RR_CALLSITE_CPU_EXEC_3",
  "RR_CALLSITE_CPU_EXEC_4",
  "RR_CALLSITE_CPU_EXEC_DBG",
  "RR_CALLSITE_CPU_HALTED",
  "RR_CALLSITE_RDTSC",
  "RR_CALLSITE_TB_INVALIDATE_PHYS_PAGE_RANGE",
  "RR_CALLSITE_CPU_OUTB",
  "RR_CALLSITE_CPU_OUTW",
  "RR_CALLSITE_CPU_OUTL",
  "RR_CALLSITE_IO_WRITE_0", 
  "RR_CALLSITE_IO_WRITE_1", 
  "RR_CALLSITE_IO_WRITE_2", 
  "RR_CALLSITE_IO_WRITE_3", 
  "RR_CALLSITE_DEFAULT_IOPORT_WRITEW",
  "RR_CALLSITE_MAIN_LOOP",
  "RR_CALLSITE_MAIN_LOOP_WAIT",
  "RR_CALLSITE_PHYS_MEM_IO_1",
  "RR_CALLSITE_PHYS_MEM_IO_2",
  "RR_CALLSITE_PHYS_MEM_IO_3",
  "RR_CALLSITE_STL_PHYS_ND",
  "RR_CALLSITE_STQ_PHYS_ND",
  "RR_CALLSITE_STL_PHYS",
  "RR_CALLSITE_DO_SMM_ENTER",
  "RR_CALLSITE_HELPER_RSM",
  "RR_CALLSITE_IOPORT_READ",
  "RR_CALLSITE_IOPORT_WRITE",
  "RR_CALLSITE_SPARC_CPU_EXEC_1",
  "RR_CALLSITE_MIPS_CPU_EXEC_1",
  "RR_CALLSITE_IDE_SECTOR_READ",
  "RR_CALLSITE_IDE_SECTOR_WRITE",
  "RR_CALLSITE_IDE_DMA_CB",
  "RR_CALLSITE_IDE_DATA_WRITEW",
  "RR_CALLSITE_IDE_DATA_WRITEL",
  "RR_CALLSITE_IDE_DATA_READW",
  "RR_CALLSITE_IDE_DATA_READL",
  "RR_CALLSITE_E1000_RECEIVE_1",
  "RR_CALLSITE_E1000_RECEIVE_2",
  "RR_CALLSITE_E1000_RECEIVE_3",
  "RR_CALLSITE_E1000_RECEIVE_MEMCPY_1",
  "RR_CALLSITE_E1000_XMIT_SEG_1",
  "RR_CALLSITE_E1000_XMIT_SEG_2",
  "RR_CALLSITE_E1000_PROCESS_TX_DESC_1",
  "RR_CALLSITE_E1000_PROCESS_TX_DESC_2",
  "RR_CALLSITE_E1000_PROCESS_TX_DESC_MEMMOVE_1",
  "RR_CALLSITE_E1000_PROCESS_TX_DESC_MEMMOVE_2",
  "RR_CALLSITE_E1000_TXDESC_WRITEBACK",
  "RR_CALLSITE_E1000_START_XMIT",
  "RR_CALLSITE_LAST"
};


static inline const char *get_callsite_string(RR_callsite_id cid)
{
    if (cid <= RR_CALLSITE_LAST)
        return callsite_str[cid];
    else
        return NULL;
}

// Record routines
void rr_record_debug(RR_callsite_id call_site);
void rr_record_input_1(RR_callsite_id call_site, uint8_t data);
void rr_record_input_2(RR_callsite_id call_site, uint16_t data);
void rr_record_input_4(RR_callsite_id call_site, uint32_t data);
void rr_record_input_8(RR_callsite_id call_site, uint64_t data);

void rr_record_interrupt_request(RR_callsite_id call_site, uint32_t interrupt_request);
void rr_record_exit_request(RR_callsite_id call_site, uint32_t exit_request);

// Replay routines
void rr_replay_debug(RR_callsite_id call_site);
void rr_replay_input_1(RR_callsite_id call_site, uint8_t *data);
void rr_replay_input_2(RR_callsite_id call_site, uint16_t *data);
void rr_replay_input_4(RR_callsite_id call_site, uint32_t *data);
void rr_replay_input_8(RR_callsite_id call_site, uint64_t *data);

void rr_replay_interrupt_request(RR_callsite_id call_site, uint32_t *interrupt_request);
void rr_replay_exit_request(RR_callsite_id call_site, uint32_t *exit_request);

extern void rr_replay_skipped_calls_internal(RR_callsite_id cs);

// print current log entry
void rr_spit_queue_head(void);

// compare two program points current and recorded.
// if current < recorded, return -1.
// if current == recorded, return 0.
// current > recorded is a fatal error.
static inline int rr_prog_point_compare(RR_prog_point current,
                                        RR_prog_point recorded,
                                        RR_log_entry_kind kind) {
  //mz my contention is that we should never be in a situation where the
  //program point counts are higher than current item being replayed.  This is
  //cause for failure.
  if (current.guest_instr_count < recorded.guest_instr_count) {
     return (-1);
  }
  else if (current.guest_instr_count == recorded.guest_instr_count) {
      // the two counts are the same.  
      // other things should agree.  else, we are in trouble
      if (current.pc == recorded.pc && current.secondary == recorded.secondary) {
          return 0;
      }
      else if(current.pc == 0 && current.guest_instr_count == 0){
          return 0;
      }
      else {
          //jh old record/replay translated ops in the order:
          // increment instr count, do micro ops, update PC to next instruction
          // PANDA increments the instr count, sets the RR PC to the current instruction,
          // and executes the instruction. We no longer have wierd cases like hlt on x86
          // that don't account for themselves. The PC's definition has also changed from
          // next instruction to previous instruction, which is why we sometimes need the
          // bootstrap code above for pc == 0, instr count == 0

          //mz
          //rr_spit_queue_head();
          //rr_signal_disagreement(current, recorded);
          //mz we don't come back from rr_do_end_replay() - this is just to clean things up.
          //rr_do_end_replay(/*is_error=*/1);
          return -1;
      }
  }
  else {
      //mz if we've managed to get here, we're either ahead of the log or eip/ecx
      //values do not match.  In either case, fail.
      printf("Ahead of log while looking for log entry of type %s\n", log_entry_kind_str[kind]);
      rr_spit_queue_head();
      rr_signal_disagreement(current, recorded);
      //mz we don't come back from rr_do_end_replay() - this is just to clean things up.
      rr_do_end_replay(/*is_error=*/1);
      // to placate gcc.
      return 1;
  }
}

// Convenience routines that perform appropriate action based on rr_mode setting
static inline void rr_interrupt_request(int *interrupt_request) {
    switch (rr_mode) {
        case RR_RECORD:
	  rr_record_interrupt_request((RR_callsite_id) rr_skipped_callsite_location, *interrupt_request);
            break;
        case RR_REPLAY:
	  rr_replay_interrupt_request((RR_callsite_id) rr_skipped_callsite_location, (uint32_t *) interrupt_request);
            break;
        default:
            break;
    }
}

static inline void rr_exit_request(uint32_t *exit_request) {
    switch (rr_mode) {
        case RR_RECORD:
            rr_record_exit_request((RR_callsite_id) rr_skipped_callsite_location, *exit_request);
            break;
        case RR_REPLAY:
            rr_replay_exit_request((RR_callsite_id) rr_skipped_callsite_location, (uint32_t *) exit_request);
            break;
        default:
            break;
    }
}

static inline void rr_debug(void) {
    switch (rr_mode) {
        case RR_RECORD:
            rr_record_debug((RR_callsite_id) rr_skipped_callsite_location);
            break;
        case RR_REPLAY:
            rr_replay_debug((RR_callsite_id) rr_skipped_callsite_location);
            break;
        default:
            break;
    }
}

// used from exec.c and cpu-exec.c
static inline void rr_input_1(uint8_t *val) {
    switch (rr_mode) {
        case RR_RECORD:
            rr_record_input_1((RR_callsite_id) rr_skipped_callsite_location, *val);
            break;
        case RR_REPLAY:
            rr_replay_input_1((RR_callsite_id) rr_skipped_callsite_location, val);
            break;
        default:
            break;
    }
}

static inline void rr_input_2(uint16_t *val) {
    switch (rr_mode) {
        case RR_RECORD:
            rr_record_input_2((RR_callsite_id) rr_skipped_callsite_location, *val);
            break;
        case RR_REPLAY:
            rr_replay_input_2((RR_callsite_id) rr_skipped_callsite_location, val);
            break;
        default:
            break;
    }
}

static inline void rr_input_4(uint32_t *val) {
    switch (rr_mode) {
        case RR_RECORD:
            rr_record_input_4((RR_callsite_id) rr_skipped_callsite_location, *val);
            break;
        case RR_REPLAY:
            rr_replay_input_4((RR_callsite_id) rr_skipped_callsite_location, val);
            break;
        default:
            break;
    }
}

static inline void rr_input_8(uint64_t *val) {
    switch (rr_mode) {
        case RR_RECORD:
            rr_record_input_8((RR_callsite_id) rr_skipped_callsite_location, *val);
            break;
        case RR_REPLAY:
            rr_replay_input_8((RR_callsite_id) rr_skipped_callsite_location, val);
            break;
        default:
            break;
    }
}

//mz UGH. things in softmmu_template.h need these
#define rr_input_shift_0 rr_input_1
#define rr_input_shift_1 rr_input_2
#define rr_input_shift_2 rr_input_4
#define rr_input_shift_3 rr_input_8

static inline void rr_replay_skipped_calls(void) {
    rr_replay_skipped_calls_internal((RR_callsite_id) rr_skipped_callsite_location);
}

//mz 11.04.2009  Macros to use for a block of code to be replayed
//mz XXX this is not thread-safe!

#define RR_NO_ACTION  do { /* nothing */ } while (0);

//mz Parameters to this macro are as follows
//mz - ACTION = code that would have run if record/replay were disabled
//mz - RECORD_ACTION = whatever is necessary to create a record log for non-determinism caused by ACTION
//mz - REPLAY_ACTION = whatever is necessary to replay that non-determinism
//mz - LOCATION = one of RR_callsite_id constants
#define RR_DO_RECORD_OR_REPLAY(ACTION, RECORD_ACTION, REPLAY_ACTION, LOCATION) \
    do { \
        switch (rr_mode) { \
            case RR_RECORD: \
                { \
                   if (rr_record_in_progress) {	\
                        ACTION; \
                    } \
                    else { \
                        rr_record_in_progress = 1; \
                        rr_skipped_callsite_location = LOCATION; \
                        rr_set_program_point();    \
                        ACTION;                    \
                        RECORD_ACTION;             \
                        rr_record_in_progress = 0; \
                    } \
                } \
                break; \
            case RR_REPLAY: \
                { \
                    rr_skipped_callsite_location = LOCATION; \
                    /* mz we need to update program point! */ \
                    rr_set_program_point(); \
                    rr_replay_skipped_calls(); \
                    REPLAY_ACTION; \
                } \
                break; \
            case RR_OFF: \
            default: \
                ACTION; \
        } \
    } while (0);

//mz
//mz  Record/Replay Utilities
//mz

//
// Record/replay mode
//


// these are all returning booleans, really.
// return true iff we are in replay/record/off
static inline uint8_t rr_in_replay(void) {
  return (rr_mode == RR_REPLAY);
}

static inline uint8_t rr_in_record(void) {
  return (rr_mode == RR_RECORD);
}

static inline uint8_t rr_off(void) {
  return (rr_mode == RR_OFF);
}

static inline uint8_t rr_on(void) {
  return (!rr_off());
}

//mz flag indicating that TB cache flush has been requested
extern uint8_t rr_please_flush_tb;
// returns true if we are supposed to be flushing the tb whenever possible.
static inline uint8_t rr_flush_tb(void) {
  return rr_please_flush_tb;
}

// sets flag so that we'll flush tb whenever possible.
static inline void rr_flush_tb_on(void) {
  rr_please_flush_tb = 1;
}

// unsets flag so that we'll not flush tb whenever possible.
static inline void rr_flush_tb_off(void) {
  rr_please_flush_tb = 0;
}

// our own assertion mechanism

#define rr_assert(exp) if(exp); \
    else rr_assert_fail(#exp, __FILE__, __LINE__, __FUNCTION__);

inline void rr_assert_fail(const char *exp, const char *file, int line, const char *function);

//
// Debug level
//
#ifndef RR_LOG_STANDALONE
extern int is_cpu_log_rr_set(void);
#endif

typedef enum {
  RR_DEBUG_SILENT = 0,   // really nothing
  RR_DEBUG_WHISPER = 1,  // almost nothing
  RR_DEBUG_QUIET = 2,    // something
  RR_DEBUG_NOISY = 3     // lots
} RR_debug_level_type;
extern RR_debug_level_type rr_debug_level;

// debugging is on? 
static inline uint8_t rr_debug_on(void) {
  return (
#ifndef RR_LOG_STANDALONE
    is_cpu_log_rr_set() &&
#endif
        (rr_on()) && (rr_debug_level > RR_DEBUG_SILENT)
    );
}

// is the debug level this?
static inline uint8_t rr_debug_noisy(void) {
  return (rr_debug_on() && (rr_debug_level >= RR_DEBUG_NOISY));
}

static inline uint8_t rr_debug_whisper(void) {
  return (rr_debug_on() && (rr_debug_level >= RR_DEBUG_WHISPER));
}

static inline uint8_t rr_debug_quiet(void) {
  return (rr_debug_on() && (rr_debug_level >= RR_DEBUG_QUIET));
}


// set debug level
static inline void rr_set_debug_silent(void) {
  rr_debug_level = RR_DEBUG_SILENT;
}

static inline void rr_set_debug_whisper(void) {
  rr_debug_level = RR_DEBUG_WHISPER;
}

static inline void rr_set_debug_quiet(void) {
  rr_debug_level = RR_DEBUG_QUIET;
}

static inline void rr_set_debug_noisy(void) {
  rr_debug_level = RR_DEBUG_NOISY;
}

void rr_debug_log_prog_point(RR_prog_point pp);
void rr_print_history(void);
void rr_spit_prog_point(RR_prog_point pp);

/* Hard drive stuff.  Belongs here since it's target-independent. */

typedef enum {
  HD_TRANSFER_HD_TO_IOB,
  HD_TRANSFER_IOB_TO_HD,
  HD_TRANSFER_PORT_TO_IOB,
  HD_TRANSFER_IOB_TO_PORT,
  HD_TRANSFER_HD_TO_RAM,
  HD_TRANSFER_RAM_TO_HD
} Hd_transfer_type;

/*
static const char *hd_transfer_str[] = {
  "HD_TRANSFER_HD_TO_IOB",
  "HD_TRANSFER_IOB_TO_HD",
  "HD_TRANSFER_PORT_TO_IOB",
  "HD_TRANSFER_IOB_TO_PORT"
};
*/

// structure for arguments to hd_transfer
typedef struct {
  Hd_transfer_type type;   
  uint64_t src_addr;
  uint64_t dest_addr;
  uint32_t num_bytes;
} RR_hd_transfer_args;

void rr_record_hd_transfer(RR_callsite_id call_site,
    Hd_transfer_type transfer_type, uint64_t src_addr, uint64_t dest_addr,
    uint32_t num_bytes);

/* Network stuff. */

typedef enum {
  NET_TRANSFER_RAM_TO_IOB,
  NET_TRANSFER_IOB_TO_RAM,
  NET_TRANSFER_IOB_TO_IOB
} Net_transfer_type;

// structure for arguments to net_transfer
typedef struct {
  Net_transfer_type type;
  uint64_t src_addr;
  uint64_t dest_addr;
  uint32_t num_bytes;
} RR_net_transfer_args;

// structure for args to handle_packet
typedef struct {
  uint8_t *buf;
  uint32_t size;
  uint8_t direction;
} RR_handle_packet_args;

void rr_record_handle_packet_call(RR_callsite_id call_site, uint8_t *buf,
    int size, uint8_t direction);

void rr_record_net_transfer(RR_callsite_id call_site,
    Net_transfer_type transfer_type, uint64_t src_addr, uint64_t dest_addr,
    uint32_t num_bytes);

#endif

