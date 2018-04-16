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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __RR_LOG_H_ALL_
#define __RR_LOG_H_ALL_

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>

#include <stdint.h>
#include <assert.h>

#include "qemu/log.h"
#include "qom/cpu.h"

// Used later for enum to string macros
#define GENERATE_ENUM(ENUM) ENUM
#define GENERATE_STRING(STRING) #STRING

typedef enum { RR_OFF, RR_RECORD, RR_REPLAY } RR_mode;

typedef enum { RR_MEM_IO, RR_MEM_RAM, RR_MEM_UNKNOWN} RR_mem_type;

extern volatile RR_mode rr_mode;

// Log management
void rr_create_record_log(const char* filename);
void rr_create_replay_log(const char* filename);
void rr_destroy_log(void);
uint8_t rr_replay_finished(void);

// mz Flags set by monitor to indicate requested record/replay action
extern volatile int rr_replay_requested;
extern volatile int rr_record_requested;
extern volatile int rr_end_record_requested;
extern volatile int rr_end_replay_requested;
extern char* rr_requested_name;
extern char* rr_snapshot_name;

// used from monitor.c
int rr_do_begin_record(const char* name, CPUState* cpu_state);
void rr_do_end_record(void);
int rr_do_begin_replay(const char* name, CPUState* cpu_state);
void rr_do_end_replay(int is_error);
void rr_reset_state(CPUState* cpu_state);


// mz display indication of replay progress
extern void replay_progress(void);

// bdg helper to find out how many instructions
//    are in our log
uint64_t replay_get_total_num_instructions(void);
double rr_get_percentage(void);

void rr_quit_cpu_loop(void);

// mz 10.20.2009
// mz A record of a point in the program.  This is a subset of guest CPU state
// mz and the number of guest instructions executed so far.
typedef struct RR_prog_point_t {
    uint64_t guest_instr_count;
} RR_prog_point;

// mz location of a call initiated by hardware emulation during record
// mz see RR_DO_RECORD_OR_REPLAY() macro
extern volatile sig_atomic_t rr_skipped_callsite_location;
// mz flag to manage nested recording attempts
// mz see RR_DO_RECORD_OR_REPLAY() macro
extern volatile sig_atomic_t rr_record_in_progress;
// should be true iff we are executing device code
extern volatile sig_atomic_t rr_record_in_main_loop_wait;

// mz Routine that handles the situation when program points disagree during
// mz replay. Typically, this means a fatal error - the routine prints some
// mz diagnostics.
extern void rr_signal_disagreement(RR_prog_point current,
                                   RR_prog_point recorded);

//
// Record/Replay log structures

// Skipped calls are records of machine emulation activity that were triggered
// by hardware devices during record session.  Since device emulation code is
// not run during replay, we'll need to replay these calls (at the right
// program point) to achieve the same effect.

#define FOREACH_SKIPCALL(ACTION) \
    ACTION(RR_CALL_CPU_MEM_RW),         /* cpu_physical_memory_rw() */ \
    ACTION(RR_CALL_MEM_REGION_CHANGE),  /* cpu_register_physical_memory() */ \
    ACTION(RR_CALL_CPU_MEM_UNMAP),      /* cpu_physical_memory_unmap() */ \
    ACTION(RR_CALL_HD_TRANSFER),        /* hd transfer */ \
    ACTION(RR_CALL_NET_TRANSFER),       /* network transfer in device */ \
    ACTION(RR_CALL_HANDLE_PACKET),      /* packet handling on send/receive */ \
    ACTION(RR_CALL_LAST)

typedef enum {
    FOREACH_SKIPCALL(GENERATE_ENUM)
} RR_skipped_call_kind;

static const char* skipped_call_kind_str[] = {
    FOREACH_SKIPCALL(GENERATE_STRING)
};

static inline const char*
get_skipped_call_kind_string(RR_skipped_call_kind kind)
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

#define FOREACH_LOGTYPE(ACTION) \
    ACTION(RR_INPUT_1), \
    ACTION(RR_INPUT_2), \
    ACTION(RR_INPUT_4), \
    ACTION(RR_INPUT_8), \
    ACTION(RR_INTERRUPT_REQUEST), \
    ACTION(RR_EXIT_REQUEST), \
    ACTION(RR_SKIPPED_CALL), \
    ACTION(RR_END_OF_LOG),\
    ACTION(RR_PENDING_INTERRUPTS), \
    ACTION(RR_EXCEPTION), \
    ACTION(RR_LAST),

typedef enum {
    FOREACH_LOGTYPE(GENERATE_ENUM)
} RR_log_entry_kind;

static const char* log_entry_kind_str[] = {
    FOREACH_LOGTYPE(GENERATE_STRING)
};

static inline const char* get_log_entry_kind_string(RR_log_entry_kind kind)
{
    if (kind <= RR_LAST)
        return log_entry_kind_str[kind];
    else
        return NULL;
}

// mz 10.20.2009 Unified view of all callsite ids for record/replay calls.
// mz These are used as additional sanity check during replay
#define FOREACH_CALLSITE(ACTION) \
    ACTION(RR_CALLSITE_CPU_HANDLE_INTERRUPT_BEFORE), \
    ACTION(RR_CALLSITE_CPU_HANDLE_INTERRUPT_INTNO), \
    ACTION(RR_CALLSITE_CPU_HANDLE_INTERRUPT_AFTER), \
    ACTION(RR_CALLSITE_RDTSC), \
    ACTION(RR_CALLSITE_IO_READ_ALL), \
    ACTION(RR_CALLSITE_IO_WRITE_ALL), \
    ACTION(RR_CALLSITE_MAIN_LOOP_WAIT), \
    ACTION(RR_CALLSITE_DO_SMM_ENTER), \
    ACTION(RR_CALLSITE_HELPER_RSM), \
    ACTION(RR_CALLSITE_READ_8), \
    ACTION(RR_CALLSITE_READ_4), \
    ACTION(RR_CALLSITE_READ_2), \
    ACTION(RR_CALLSITE_READ_1), \
    ACTION(RR_CALLSITE_WRITE_8), \
    ACTION(RR_CALLSITE_WRITE_4), \
    ACTION(RR_CALLSITE_WRITE_2), \
    ACTION(RR_CALLSITE_WRITE_1), \
    ACTION(RR_CALLSITE_END_OF_LOG), \
    ACTION(RR_CALLSITE_CPU_PENDING_INTERRUPTS_BEFORE), \
    ACTION(RR_CALLSITE_CPU_PENDING_INTERRUPTS_AFTER), \
    ACTION(RR_CALLSITE_CPU_EXCEPTION_INDEX), \
    ACTION(RR_CALLSITE_E1000_RECEIVE_1), \
    ACTION(RR_CALLSITE_E1000_RECEIVE_2), \
    ACTION(RR_CALLSITE_E1000_RECEIVE_3), \
    ACTION(RR_CALLSITE_E1000_RECEIVE_MEMCPY_1), \
    ACTION(RR_CALLSITE_E1000_XMIT_SEG_1), \
    ACTION(RR_CALLSITE_E1000_XMIT_SEG_2), \
    ACTION(RR_CALLSITE_E1000_PROCESS_TX_DESC_1), \
    ACTION(RR_CALLSITE_E1000_PROCESS_TX_DESC_2), \
    ACTION(RR_CALLSITE_E1000_PROCESS_TX_DESC_MEMMOVE_1),            \
    ACTION(RR_CALLSITE_E1000_PROCESS_TX_DESC_MEMMOVE_2), \
    ACTION(RR_CALLSITE_E1000_TXDESC_WRITEBACK), \
    ACTION(RR_CALLSITE_E1000_START_XMIT), \
    ACTION(RR_CALLSITE_LAST)

typedef enum {
    FOREACH_CALLSITE(GENERATE_ENUM)
} RR_callsite_id;

static const char* callsite_str[] = {
    FOREACH_CALLSITE(GENERATE_STRING)
};

static inline const char* get_callsite_string(RR_callsite_id cid)
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

void rr_record_interrupt_request(RR_callsite_id call_site,
                                 int interrupt_request);
void rr_record_exit_request(RR_callsite_id call_site, uint32_t exit_request);

void rr_record_pending_interrupts(RR_callsite_id call_site, uint32_t pending_interrupt);
void rr_record_exception_index(RR_callsite_id call_site, int32_t exception_index);

// Replay routines
void rr_replay_debug(RR_callsite_id call_site);
void rr_replay_input_1(RR_callsite_id call_site, uint8_t* data);
void rr_replay_input_2(RR_callsite_id call_site, uint16_t* data);
void rr_replay_input_4(RR_callsite_id call_site, uint32_t* data);
void rr_replay_input_8(RR_callsite_id call_site, uint64_t* data);

void rr_replay_interrupt_request(RR_callsite_id call_site,
                                 int* interrupt_request);
bool rr_replay_pending_interrupts(RR_callsite_id call_site, uint32_t* pending_interrupt);
bool rr_replay_exception_index(RR_callsite_id call_site, int32_t* exception_index);
void rr_replay_exit_request(RR_callsite_id call_site, uint32_t* exit_request);
bool rr_replay_intno(uint32_t *intno);

extern void rr_replay_skipped_calls_internal(RR_callsite_id cs);

// print current log entry
void rr_spit_queue_head(void);

// compare two program points current and recorded.
// if current < recorded, return -1.
// if current == recorded, return 0.
// current > recorded is a fatal error.
static inline int rr_prog_point_compare(RR_prog_point current,
                                        RR_prog_point recorded,
                                        RR_log_entry_kind kind)
{
    // mz my contention is that we should never be in a situation where the
    // program point counts are higher than current item being replayed.  This
    // is
    // cause for failure.
    if (current.guest_instr_count < recorded.guest_instr_count) {
        return (-1);
    } else if (current.guest_instr_count == recorded.guest_instr_count) {
        return 0;
    } else {
        // mz if we've managed to get here, we're either ahead of the log or
        // eip/ecx
        // values do not match.  In either case, fail.
        printf("Ahead of log while looking for log entry of type %s\n",
               log_entry_kind_str[kind]);
        rr_spit_queue_head();
        rr_signal_disagreement(current, recorded);
        // mz we don't come back from rr_do_end_replay() - this is just to clean
        // things up.
        rr_do_end_replay(/*is_error=*/1);
        // to placate gcc.
        return 1;
    }
}

static inline bool rr_in_replay(void) { return rr_mode == RR_REPLAY; }
static inline bool rr_in_record(void) { return rr_mode == RR_RECORD; }
static inline bool rr_off(void) { return rr_mode == RR_OFF; }
static inline bool rr_on(void) { return !rr_off(); }

// Convenience routines that perform appropriate action based on rr_mode setting
#define RR_CONVENIENCE(name, arg_type)                                  \
    static inline void rr_ ## name ## _at(RR_callsite_id call_site,     \
            arg_type* val) {                                            \
        if (rr_in_record()) {                                           \
            rr_record_ ## name(call_site, *val);                        \
        } else if (rr_in_replay()) {                                    \
            rr_replay_ ## name(call_site, val);                         \
        }                                                               \
    }                                                                   \
    static inline void rr_ ## name(arg_type* val) {                     \
        rr_ ## name ## _at(                                             \
            (RR_callsite_id)rr_skipped_callsite_location, val);         \
    }

RR_CONVENIENCE(interrupt_request, int);
RR_CONVENIENCE(exit_request, uint32_t);
RR_CONVENIENCE(pending_interrupts, uint32_t);
RR_CONVENIENCE(exception_index, int32_t);
RR_CONVENIENCE(input_1, uint8_t);
RR_CONVENIENCE(input_2, uint16_t);
RR_CONVENIENCE(input_4, uint32_t);
RR_CONVENIENCE(input_8, uint64_t);

static inline void rr_replay_skipped_calls(void)
{
    rr_replay_skipped_calls_internal(
        (RR_callsite_id)rr_skipped_callsite_location);
}

// mz 11.04.2009  Macros to use for a block of code to be replayed
// mz XXX this is not thread-safe!

#define RR_NO_ACTION                                                           \
    do { /* nothing */                                                         \
    } while (0);

// mz Parameters to this macro are as follows
// mz - ACTION = code that would have run if record/replay were disabled
// mz - RECORD_ACTION = whatever is necessary to create a record log for
// non-determinism caused by ACTION
// mz - REPLAY_ACTION = whatever is necessary to replay that non-determinism
// mz - LOCATION = one of RR_callsite_id constants
#define RR_DO_RECORD_OR_REPLAY(ACTION, RECORD_ACTION, REPLAY_ACTION, LOCATION) \
    do {                                                                       \
        switch (rr_mode) {                                                     \
        case RR_RECORD: {                                                      \
            if (rr_record_in_progress || rr_record_in_main_loop_wait) {        \
                ACTION;                                                        \
            } else {                                                           \
                rr_record_in_progress = 1;                                     \
                rr_skipped_callsite_location = LOCATION;                       \
                ACTION;                                                        \
                RECORD_ACTION;                                                 \
                rr_record_in_progress = 0;                                     \
            }                                                                  \
        } break;                                                               \
        case RR_REPLAY: {                                                      \
            rr_skipped_callsite_location = LOCATION;                           \
            rr_replay_skipped_calls();                                         \
            REPLAY_ACTION;                                                     \
        } break;                                                               \
        case RR_OFF:                                                           \
        default:                                                               \
            ACTION;                                                            \
        }                                                                      \
    } while (0);

// mz
// mz  Record/Replay Utilities
// mz

//
// Record/replay mode
//

static inline void rr_replay_skipped_calls_from(RR_callsite_id location) {
    if (rr_in_replay()) {
        rr_skipped_callsite_location = location;
        rr_replay_skipped_calls();
    }
}

//
// Debug level
//

typedef enum {
    RR_DEBUG_SILENT = 0,  // really nothing
    RR_DEBUG_WHISPER = 1, // almost nothing
    RR_DEBUG_QUIET = 2,   // something
    RR_DEBUG_NOISY = 3    // lots
} RR_debug_level_type;
extern RR_debug_level_type rr_debug_level;

// debugging is on?
static inline uint8_t rr_debug_on(void)
{
    return (qemu_loglevel_mask(CPU_LOG_RR) && (rr_on()) &&
            (rr_debug_level > RR_DEBUG_SILENT));
}

// is the debug level this?
static inline uint8_t rr_debug_noisy(void)
{
    return (rr_debug_on() && (rr_debug_level >= RR_DEBUG_NOISY));
}

static inline uint8_t rr_debug_whisper(void)
{
    return (rr_debug_on() && (rr_debug_level >= RR_DEBUG_WHISPER));
}

static inline uint8_t rr_debug_quiet(void)
{
    return (rr_debug_on() && (rr_debug_level >= RR_DEBUG_QUIET));
}

// set debug level
static inline void rr_set_debug_silent(void)
{
    rr_debug_level = RR_DEBUG_SILENT;
}

static inline void rr_set_debug_whisper(void)
{
    rr_debug_level = RR_DEBUG_WHISPER;
}

static inline void rr_set_debug_quiet(void) { rr_debug_level = RR_DEBUG_QUIET; }

static inline void rr_set_debug_noisy(void) { rr_debug_level = RR_DEBUG_NOISY; }

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
                           Hd_transfer_type transfer_type, uint64_t src_addr,
                           uint64_t dest_addr, uint32_t num_bytes);

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
    uint8_t* buf;
    uint32_t size;
    uint8_t direction;
} RR_handle_packet_args;

void rr_record_handle_packet_call(RR_callsite_id call_site, uint8_t* buf,
                                  int size, uint8_t direction);

void rr_record_net_transfer(RR_callsite_id call_site,
                            Net_transfer_type transfer_type, uint64_t src_addr,
                            uint64_t dest_addr, uint32_t num_bytes);

// Needed from main-loop.c which is not target-specific
void rr_tracked_mem_regions_record(void);
void rr_begin_main_loop_wait(void);
void rr_end_main_loop_wait(void);

#endif
