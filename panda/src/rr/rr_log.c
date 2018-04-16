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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <libgen.h>

#include <zlib.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qmp-commands.h"
#include "hmp.h"
#include "panda/rr/rr_log.h"
#include "migration/migration.h"
#include "include/exec/address-spaces.h"
#include "include/exec/exec-all.h"
#include "migration/qemu-file.h"
#include "io/channel-file.h"
#include "sysemu/sysemu.h"
#include "panda/callback_support.h"
/******************************************************************************************/
/* GLOBALS */
/******************************************************************************************/
// mz record/replay mode
volatile RR_mode rr_mode = RR_OFF;

// mz FIFO queue of log entries read from the log file
// Implemented as ring buffer.
#define RR_QUEUE_MAX_LEN 65536
static RR_log_entry rr_queue[RR_QUEUE_MAX_LEN];
RR_log_entry* rr_queue_head;
RR_log_entry* rr_queue_tail;
RR_log_entry* rr_queue_end; // end of buffer.

// mz 11.06.2009 Flags to manage nested recording
volatile sig_atomic_t rr_record_in_progress = 0;
volatile sig_atomic_t rr_record_in_main_loop_wait = 0;
volatile sig_atomic_t rr_skipped_callsite_location = 0;
// mz the log of non-deterministic events
RR_log* rr_nondet_log = NULL;

bool rr_replay_complete = false;

#define RR_RECORD_FROM_REQUEST 2
#define RR_RECORD_REQUEST 1

// our own assertion mechanism
#define rr_assert(exp)                                                         \
    if (!(exp)) {                                                              \
        rr_assert_fail(#exp, __FILE__, __LINE__, __FUNCTION__);                \
    }

inline double rr_get_percentage(void) {
    return 100.0 * rr_get_guest_instr_count() /
        rr_nondet_log->last_prog_point.guest_instr_count;
}

static inline uint8_t rr_log_is_empty(void) {
    if ((rr_nondet_log->type == REPLAY) &&
        (rr_nondet_log->size == rr_nondet_log->bytes_read)) {
        return 1;
    } else {
        return 0;
    }
}

RR_debug_level_type rr_debug_level = RR_DEBUG_NOISY;

// mz Flags set by monitor to indicate requested record/replay action
volatile sig_atomic_t rr_record_requested = 0;
volatile sig_atomic_t rr_replay_requested = 0;
volatile sig_atomic_t rr_end_record_requested = 0;
volatile sig_atomic_t rr_end_replay_requested = 0;
char* rr_requested_name = NULL;
char* rr_snapshot_name = NULL;

unsigned rr_next_progress = 1;

//
// mz Other useful things
//

/******************************************************************************************/
/* UTILITIES */
/******************************************************************************************/

RR_log_entry* rr_get_queue_head(void) { return rr_queue_head; }

// Check if replay is really finished. Conditions:
// 1) The log is empty
// 2) The only thing in the queue is RR_END_OF_LOG
uint8_t rr_replay_finished(void)
{
    return rr_log_is_empty()
        && rr_queue_head->header.kind == RR_END_OF_LOG
        && rr_get_guest_instr_count() >=
               rr_queue_head->header.prog_point.guest_instr_count;
}

// mz "performance" counters - basically, how much of the log is taken up by
// mz each kind of entry.
unsigned long long rr_number_of_log_entries[RR_LAST];
unsigned long long rr_size_of_log_entries[RR_LAST];
unsigned long long rr_max_num_queue_entries;

// mz a history of last few log entries for replay
// mz use rr_print_history() to dump in a debugger
#define RR_HIST_SIZE 10
RR_log_entry rr_log_entry_history[RR_HIST_SIZE];
int rr_hist_index = 0;

// write this program point to this file
static void rr_spit_prog_point_fp(RR_prog_point pp)
{
    qemu_log("{guest_instr_count=%llu}\n",
             (unsigned long long)pp.guest_instr_count);
}

void rr_debug_log_prog_point(RR_prog_point pp) { rr_spit_prog_point_fp(pp); }

void rr_spit_prog_point(RR_prog_point pp) { rr_spit_prog_point_fp(pp); }

static void rr_spit_log_entry(RR_log_entry item)
{
    rr_spit_prog_point(item.header.prog_point);
    switch (item.header.kind) {
    case RR_INPUT_1:
        printf("\tRR_INPUT_1 from %s\n",
               get_callsite_string(item.header.callsite_loc));
        break;
    case RR_INPUT_2:
        printf("\tRR_INPUT_2 from %s\n",
               get_callsite_string(item.header.callsite_loc));
        break;
    case RR_INPUT_4:
        printf("\tRR_INPUT_4 from %s\n",
               get_callsite_string(item.header.callsite_loc));
        break;
    case RR_INPUT_8:
        printf("\tRR_INPUT_8 from %s\n",
               get_callsite_string(item.header.callsite_loc));
        break;
    case RR_INTERRUPT_REQUEST:
        printf("\tRR_INTERRUPT_REQUEST from %s\n",
               get_callsite_string(item.header.callsite_loc));
        break;
    case RR_EXIT_REQUEST:
        printf("\tRR_EXIT_REQUEST from %s\n",
               get_callsite_string(item.header.callsite_loc));
        break;
    case RR_SKIPPED_CALL:
        printf("\tRR_SKIPPED_CALL (%s) from %s\n",
               get_skipped_call_kind_string(item.variant.call_args.kind),
               get_callsite_string(item.header.callsite_loc));
        break;
    case RR_END_OF_LOG:
        printf("\tRR_END_OF_LOG\n");
        break;
    default:
        printf("\tUNKNOWN RR log kind %d\n", item.header.kind);
        break;
    }
}

void rr_spit_queue_head(void) { rr_spit_log_entry(*rr_queue_head); }

// mz use in debugger to print a short history of log entries
void rr_print_history(void)
{
    int i = rr_hist_index;
    do {
        rr_spit_log_entry(rr_log_entry_history[i]);
        i = (i + 1) % RR_HIST_SIZE;
    } while (i != rr_hist_index);
}

// mz here to prevent the need to #include<stdio.h> in rr_log.h
void rr_signal_disagreement(RR_prog_point current, RR_prog_point recorded)
{
    printf("FOUND DISAGREEMENT!\n");
    printf("Replay program point:\n");
    rr_spit_prog_point(current);
    printf("\n");
    printf("Record program point:\n");
    rr_spit_prog_point(recorded);
    printf("\n");
    if (current.guest_instr_count != recorded.guest_instr_count) {
        printf(">>> guest instruction counts disagree\n");
    }
}

// our debug rr_assert
static inline void rr_assert_fail(const char* exp, const char* file, int line,
                                  const char* function)
{
    printf("RR rr_assertion `%s' failed at %s:%d\n", exp, file, line);
    printf("Current log point:\n");
    if (rr_queue_head != rr_queue_tail) {
        rr_spit_prog_point(rr_queue_head->header.prog_point);
        printf("Next log entry type: %s\n",
               log_entry_kind_str[rr_queue_head->header.kind]);
    } else {
        printf("<queue empty>\n");
    }
    printf("Current replay point:\n");
    rr_spit_prog_point(rr_prog_point());
    if (rr_debug_whisper()) {
        qemu_log("RR rr_assertion `%s' failed at %s:%d in %s\n", exp, file,
                 line, function);
    }
    // just abort
    abort();
    rr_end_replay_requested = 1;
    // mz need to get out of cpu loop so that we can process the end_replay
    // request
    // mz this will call cpu_loop_exit(), which longjmps
    // bdg gosh I hope this is OK here. I think it should be as long as we only
    // ever call
    // bdg rr_assert from the CPU loop
    rr_quit_cpu_loop();
    /* NOT REACHED */
}

/******************************************************************************************/
/* RECORD */
/******************************************************************************************/

static inline size_t rr_fwrite(void *ptr, size_t size, size_t nmemb) {
    size_t result = fwrite(ptr, size, nmemb, rr_nondet_log->fp);
    rr_assert(result == nmemb);
    return result;
}

// mz write the current log item to file
static inline void rr_write_item(RR_log_entry item)
{
    // mz save the header
    if (!rr_in_record()) return;
    rr_assert(rr_nondet_log != NULL);

#define RR_WRITE_ITEM(field) rr_fwrite(&(field), sizeof(field), 1)
    // keep replay format the same.
    RR_WRITE_ITEM(item.header.prog_point.guest_instr_count);
    rr_fwrite(&(item.header.kind), 1, 1);
    rr_fwrite(&(item.header.callsite_loc), 1, 1);

    // mz also save the program point in the log structure to ensure that our
    // header will include the latest program point.
    rr_nondet_log->last_prog_point = item.header.prog_point;

    switch (item.header.kind) {
        case RR_INPUT_1:
            RR_WRITE_ITEM(item.variant.input_1);
            break;
        case RR_INPUT_2:
            RR_WRITE_ITEM(item.variant.input_2);
            break;
        case RR_INPUT_4:
            RR_WRITE_ITEM(item.variant.input_4);
            break;
        case RR_INPUT_8:
            RR_WRITE_ITEM(item.variant.input_8);
            break;
        case RR_INTERRUPT_REQUEST:
            RR_WRITE_ITEM(item.variant.interrupt_request);
            break;
        case RR_EXIT_REQUEST:
            RR_WRITE_ITEM(item.variant.exit_request);
            break;
        case RR_PENDING_INTERRUPTS:
            RR_WRITE_ITEM(item.variant.pending_interrupts);
            break;
        case RR_EXCEPTION:
            RR_WRITE_ITEM(item.variant.exception_index);
            break;
        case RR_SKIPPED_CALL: {
            RR_skipped_call_args* args = &item.variant.call_args;
            rr_fwrite(&(args->kind), 1, 1);
            switch (args->kind) {
                case RR_CALL_CPU_MEM_RW:
                    RR_WRITE_ITEM(args->variant.cpu_mem_rw_args);
                    rr_fwrite(args->variant.cpu_mem_rw_args.buf, 1,
                            args->variant.cpu_mem_rw_args.len);
                    break;
                case RR_CALL_CPU_MEM_UNMAP:
                    RR_WRITE_ITEM(args->variant.cpu_mem_unmap);
                    rr_fwrite(args->variant.cpu_mem_unmap.buf, 1,
                                args->variant.cpu_mem_unmap.len);
                    break;
                case RR_CALL_MEM_REGION_CHANGE:
                    RR_WRITE_ITEM(args->variant.mem_region_change_args);
                    rr_fwrite(args->variant.mem_region_change_args.name, 1,
                            args->variant.mem_region_change_args.len);
                    break;
                case RR_CALL_HD_TRANSFER:
                    RR_WRITE_ITEM(args->variant.hd_transfer_args);
                    break;
                case RR_CALL_NET_TRANSFER:
                    RR_WRITE_ITEM(args->variant.net_transfer_args);
                    break;
                case RR_CALL_HANDLE_PACKET:
                    RR_WRITE_ITEM(args->variant.handle_packet_args);
                    rr_fwrite(args->variant.handle_packet_args.buf,
                            args->variant.handle_packet_args.size, 1);
                    break;
                default:
                    // mz unimplemented
                    rr_assert(0 && "Unimplemented skipped call!");
            }
        } break;
        case RR_END_OF_LOG:
            // mz nothing to read
            break;
        default:
            // mz unimplemented
            rr_assert(0 && "Unimplemented replay log entry!");
    }
}

static inline RR_header rr_header(RR_log_entry_kind kind,
                                  RR_callsite_id call_site) {
    return (RR_header) {
        .kind = kind,
        .callsite_loc = call_site,
        .prog_point = rr_prog_point()
    };
}

// mz record 1-byte CPU input to log file
void rr_record_input_1(RR_callsite_id call_site, uint8_t data) {
    rr_write_item((RR_log_entry) {
        .header = rr_header(RR_INPUT_1, call_site),
        .variant.input_1 = data
    });
}

// mz record 2-byte CPU input to log file
void rr_record_input_2(RR_callsite_id call_site, uint16_t data) {
    rr_write_item((RR_log_entry) {
        .header = rr_header(RR_INPUT_2, call_site),
        .variant.input_2 = data
    });
}

// mz record 4-byte CPU input to log file
void rr_record_input_4(RR_callsite_id call_site, uint32_t data) {
    rr_write_item((RR_log_entry) {
        .header = rr_header(RR_INPUT_4, call_site),
        .variant.input_4 = data
    });
}

// mz record 8-byte CPU input to log file
void rr_record_input_8(RR_callsite_id call_site, uint64_t data) {
    rr_write_item((RR_log_entry) {
        .header = rr_header(RR_INPUT_8, call_site),
        .variant.input_8 = data
    });
}

/**
 * Save every time cpu->interrupt_request is different than the last time
 * we observed it (panda_current_interrupt_request. In replay, we use these
 * state transitions to always provide the correct value of
 * cpu->interrupt_request without having to record the value every time it is
 * checked
 */
int panda_current_interrupt_request = 0;
void rr_record_interrupt_request(RR_callsite_id call_site,
                                 int interrupt_request)
{
    if (panda_current_interrupt_request != interrupt_request) {
        rr_write_item((RR_log_entry) {
            .header = rr_header(RR_INTERRUPT_REQUEST, call_site),
            .variant.interrupt_request = interrupt_request
        });
        panda_current_interrupt_request = interrupt_request;
    }
}

int prev_guest_instr_count = -1;
uint32_t panda_prev_pending_int = -1;

//rw: Pending_interrupts field for powerpc
void rr_record_pending_interrupts(RR_callsite_id call_site, uint32_t pending_int){
    // Determine if pending interrupt has changed or not, and if not, do not rewrite log.
    RR_log_entry item;

    if (pending_int == panda_prev_pending_int){
        return;
    }
    panda_prev_pending_int = pending_int;

    uint64_t guest_instr_count = rr_get_guest_instr_count();
    if (guest_instr_count == prev_guest_instr_count){
        return;
    }
    prev_guest_instr_count = guest_instr_count;

    memset(&item, 0, sizeof(RR_log_entry));
    item.header.kind = RR_PENDING_INTERRUPTS;
    item.header.callsite_loc = call_site;
    item.header.prog_point = rr_prog_point();

    item.variant.pending_interrupts = pending_int;

    rr_write_item(item);
}

//rw 6/20/17: Added as a fix for powerpc
void rr_record_exception_index(RR_callsite_id call_site,
        int32_t exception_index) {
    if (exception_index != -1) {
        rr_write_item((RR_log_entry) {
            .header = rr_header(RR_EXCEPTION, call_site),
            .variant.exception_index = exception_index
        });
    }
}

void rr_record_exit_request(RR_callsite_id call_site, uint32_t exit_request)
{
    if (exit_request != 0) {
        rr_write_item((RR_log_entry) {
            .header = rr_header(RR_EXIT_REQUEST, call_site),
            .variant.exit_request = exit_request
        });
    }
}

static inline void rr_record_skipped_call(RR_skipped_call_args args) {
    rr_write_item((RR_log_entry) {
        .header = rr_header(RR_SKIPPED_CALL, rr_skipped_callsite_location),
        .variant.call_args = args
    });
}

// bdg Record the memory modified during a call to
// address_space_map/unmap.
void rr_device_mem_rw_call_record(hwaddr addr, const uint8_t* buf,
                                  int len, int is_write) {
    rr_record_skipped_call((RR_skipped_call_args) {
        .kind = RR_CALL_CPU_MEM_UNMAP,
        .variant.cpu_mem_unmap = {
            .addr = addr,
            .buf = (uint8_t *)buf,
            .len = len
        }
    });
}

extern QLIST_HEAD(rr_map_list, RR_MapList) rr_map_list;

void rr_tracked_mem_regions_record(void) {
    RR_MapList *region;
    QLIST_FOREACH(region, &rr_map_list, link) {
        uint32_t crc = crc32(0, Z_NULL, 0);
        crc = crc32(crc, region->ptr, region->len);
        if (crc != region->crc) {
            // Pretend this is just a mem_rw call
            rr_device_mem_rw_call_record(region->addr, region->ptr, region->len, 1);
        }
        // Update it so we don't keep recording it
        region->crc = crc;
    }
}

// bdg Record a change in the I/O memory map
void rr_mem_region_change_record(hwaddr start_addr, uint64_t size,
                                 const char *name, RR_mem_type mtype, bool added) {
    rr_record_skipped_call((RR_skipped_call_args) {
        .kind = RR_CALL_MEM_REGION_CHANGE,
        .variant.mem_region_change_args = {
            .start_addr = start_addr,
            .size = size,
            .name = (char *)name,
            .len = strlen(name),
            .mtype = mtype,
            .added = added
        }
    });
}

// SAC e1000.c network hooks need this
void rr_record_net_transfer(RR_callsite_id call_site,
                            Net_transfer_type transfer_type,
                            uint64_t src_addr, uint64_t dest_addr, uint32_t num_bytes) {
    rr_record_skipped_call((RR_skipped_call_args) {
        .kind = RR_CALL_NET_TRANSFER,
        .variant.net_transfer_args = {
            .type = transfer_type,
            .src_addr = src_addr,
            .dest_addr = dest_addr,
            .num_bytes = num_bytes
        }
    });
}


// SAC e1000.c network hooks needs this
void rr_record_handle_packet_call(RR_callsite_id call_site, uint8_t *buf, int size, uint8_t direction)
{
    rr_record_skipped_call((RR_skipped_call_args) {
        .kind = RR_CALL_HANDLE_PACKET,
        .variant.handle_packet_args = {
            .buf = buf,
            .size = size,
            .direction = direction
        }
    });
}

// mz record a marker for end of the log
static inline void rr_record_end_of_log(void) {
    rr_write_item((RR_log_entry) {
        .header = rr_header(RR_END_OF_LOG, RR_CALLSITE_END_OF_LOG)
    });
}

/******************************************************************************************/
/* REPLAY */
/******************************************************************************************/

static inline void free_entry_params(RR_log_entry* entry)
{
    // mz cleanup associated resources
    switch (entry->header.kind) {
    case RR_SKIPPED_CALL:
        switch (entry->variant.call_args.kind) {
        case RR_CALL_CPU_MEM_RW:
            g_free(entry->variant.call_args.variant.cpu_mem_rw_args.buf);
            entry->variant.call_args.variant.cpu_mem_rw_args.buf = NULL;
            break;
        case RR_CALL_CPU_MEM_UNMAP:
            g_free(entry->variant.call_args.variant.cpu_mem_unmap.buf);
            entry->variant.call_args.variant.cpu_mem_unmap.buf = NULL;
            break;
        case RR_CALL_HANDLE_PACKET:
            g_free(entry->variant.call_args.variant.handle_packet_args.buf);
            entry->variant.call_args.variant.handle_packet_args.buf = NULL;
            break;
        default: break;
        }
        break;
    case RR_INPUT_1:
    case RR_INPUT_2:
    case RR_INPUT_4:
    case RR_INPUT_8:
    case RR_INTERRUPT_REQUEST:
    default:
        break;
    }
}

static inline size_t rr_fread(void *ptr, size_t size, size_t nmemb) {
    size_t result = fread(ptr, size, nmemb, rr_nondet_log->fp);
    rr_nondet_log->bytes_read += nmemb * size;
    rr_assert(result == nmemb);
    return result;
}

static inline int rr_queue_size(void) {
    int distance = rr_queue_tail - rr_queue_head + 1 + RR_QUEUE_MAX_LEN;
    return distance % RR_QUEUE_MAX_LEN;
}

inline bool rr_queue_empty(void) {
    return rr_queue_head == NULL;
}

static inline bool rr_queue_has_space(void) {
    return rr_queue_size() < RR_QUEUE_MAX_LEN;
}

static inline RR_log_entry *rr_queue_alloc_back(void) {
    if (rr_queue_tail) {
        rr_queue_tail++;
        if (rr_queue_tail == rr_queue_end) {
            rr_queue_tail = rr_queue;
        }
        // we shouldn't be about to overwrite rr_queue_head.
        rr_assert(rr_queue_tail != rr_queue_head);
    } else {
        rr_queue_tail = rr_queue_head = rr_queue;
    }

    memset(rr_queue_tail, 0, sizeof(*rr_queue_tail));
    return rr_queue_tail;
}

static inline void rr_queue_push_back(RR_log_entry *entry) {
    *rr_queue_alloc_back() = *entry;
}

static inline void rr_queue_pop_front(void) {
    rr_assert(rr_queue_head); // nonempty.
    free_entry_params(rr_queue_head);
    if (rr_queue_head == rr_queue_tail) { // only 1 item.
        rr_queue_head = rr_queue_tail = NULL;
    } else {
        rr_queue_head++;
        if (rr_queue_head == rr_queue_end) {
            rr_queue_head = rr_queue;
        }
    }
}

// Add an entry to the back of the queue.
// Returns pointer to item just read.
static RR_log_entry *rr_read_item(void) {
    RR_log_entry *item = rr_queue_alloc_back();

    rr_assert(rr_in_replay());
    rr_assert(!rr_log_is_empty());
    rr_assert(rr_nondet_log->fp != NULL);

    item->header.file_pos = rr_nondet_log->bytes_read;

#define RR_READ_ITEM(field) rr_fread(&(field), sizeof(field), 1)
    // mz read header
    RR_READ_ITEM(item->header.prog_point.guest_instr_count);
    rr_fread(&(item->header.kind), 1, 1);
    rr_fread(&(item->header.callsite_loc), 1, 1);

    // mz read the rest of the item
    switch (item->header.kind) {
        case RR_INPUT_1:
            RR_READ_ITEM(item->variant.input_1);
            break;
        case RR_INPUT_2:
            RR_READ_ITEM(item->variant.input_2);
            break;
        case RR_INPUT_4:
            RR_READ_ITEM(item->variant.input_4);
            break;
        case RR_INPUT_8:
            RR_READ_ITEM(item->variant.input_8);
            break;
        case RR_INTERRUPT_REQUEST:
            RR_READ_ITEM(item->variant.interrupt_request);
            break;
        case RR_PENDING_INTERRUPTS:
            RR_READ_ITEM(item->variant.pending_interrupts);
            break;
        case RR_EXCEPTION:
            RR_READ_ITEM(item->variant.exception_index);
            break;
        case RR_EXIT_REQUEST:
            RR_READ_ITEM(item->variant.exit_request);
            break;
        case RR_SKIPPED_CALL: {
            RR_skipped_call_args* args = &item->variant.call_args;
            rr_fread(&(args->kind), 1, 1);
            switch (args->kind) {
                case RR_CALL_CPU_MEM_RW:
                    RR_READ_ITEM(args->variant.cpu_mem_rw_args);
                    // mz buffer length in args->variant.cpu_mem_rw_args.len
                    args->variant.cpu_mem_rw_args.buf =
                        g_malloc(args->variant.cpu_mem_rw_args.len);
                    // mz read the buffer
                    rr_fread(args->variant.cpu_mem_rw_args.buf, 1,
                            args->variant.cpu_mem_rw_args.len);
                    break;
                case RR_CALL_CPU_MEM_UNMAP:
                    RR_READ_ITEM(args->variant.cpu_mem_unmap);
                    args->variant.cpu_mem_unmap.buf =
                        g_malloc(args->variant.cpu_mem_unmap.len);
                    rr_fread(args->variant.cpu_mem_unmap.buf, 1,
                                args->variant.cpu_mem_unmap.len);
                    break;
                case RR_CALL_MEM_REGION_CHANGE:
                    RR_READ_ITEM(args->variant.mem_region_change_args);
                    args->variant.mem_region_change_args.name =
                        g_malloc0(args->variant.mem_region_change_args.len + 1);
                    rr_fread(args->variant.mem_region_change_args.name, 1,
                            args->variant.mem_region_change_args.len);
                    break;
                case RR_CALL_HD_TRANSFER:
                    RR_READ_ITEM(args->variant.hd_transfer_args);
                    break;

                case RR_CALL_NET_TRANSFER:
                    RR_READ_ITEM(args->variant.net_transfer_args);
                    break;

                case RR_CALL_HANDLE_PACKET:
                    RR_READ_ITEM(args->variant.handle_packet_args);
                    // mz XXX HACK
                    args->old_buf_addr = (uint64_t)args->variant.handle_packet_args.buf;
                    // mz buffer length in args->variant.cpu_mem_rw_args.len
                    // mz always allocate a new one. we free it when the item is added
                    // to the recycle list
                    args->variant.handle_packet_args.buf =
                        g_malloc(args->variant.handle_packet_args.size);
                    // mz read the buffer
                    rr_fread(args->variant.handle_packet_args.buf,
                            args->variant.handle_packet_args.size, 1);
                    break;

                default:
                    // mz unimplemented
                    rr_assert(0 && "Unimplemented skipped call!");
            }
        } break;
        case RR_END_OF_LOG:
            // mz nothing to read
            break;
        default:
            // mz unimplemented
            rr_assert(0 && "Unimplemented replay log entry!");
    }

    // mz let's do some counting
    rr_size_of_log_entries[item->header.kind] +=
        rr_nondet_log->bytes_read - item->header.file_pos;
    rr_number_of_log_entries[item->header.kind]++;

    return item;
}

// mz fill the queue of log entries from the file
void rr_fill_queue(void) {
    unsigned long long num_entries = 0;

    // mz first, some sanity checks.  The queue should be empty when this is
    // called.
    if (rr_mode != RR_REPLAY) return;
    rr_assert(rr_queue_empty());

    while (!rr_log_is_empty() && num_entries < RR_QUEUE_MAX_LEN) {
        RR_header header = rr_read_item()->header;
        num_entries++;

        if ((header.kind == RR_SKIPPED_CALL
                    && header.callsite_loc == RR_CALLSITE_MAIN_LOOP_WAIT)
                || header.kind == RR_INTERRUPT_REQUEST) {
            // Cut off queue so we don't run out of memory on long runs of
            // non-interrupts
            break;
        }
    }
    // mz let's gather some stats
    if (num_entries > rr_max_num_queue_entries) {
        rr_max_num_queue_entries = num_entries;
    }
}

// Makes sure queue is full and returns fron entry.
// after using, make sure to rr_queue_pop_front to consume.
static inline RR_log_entry* get_next_entry(void) {
    if (rr_queue_empty()) {
        // Try again; we may have failed because the queue got too big and we
        // need to refill
        rr_fill_queue();
        // If it's still empty, fail
        if (rr_queue_empty()) {
            printf("Queue is empty, will return NULL\n");
            return NULL;
        }
    }
    return rr_queue_head;
}

// same as above. make sure to consume after.
static inline RR_log_entry* get_next_entry_checked(RR_log_entry_kind kind,
        RR_callsite_id call_site, bool check_callsite) {
    RR_log_entry *entry = get_next_entry();
    if (!entry) return NULL;

    RR_header header = entry->header;
    // XXX FIXME this is a temporary hack to get around the fact that we
    // cannot currently do a tb_flush and a savevm in the same instant.
    if (header.prog_point.guest_instr_count == 0) {
        // We'll process this one beacuse it's the start of the log
    } else if (rr_prog_point_compare(rr_prog_point(),
                header.prog_point, kind) != 0) {
        // mz rr_prog_point_compare will fail if we're ahead of the log
        return NULL;
    }

    if (header.kind != kind) {
        return NULL;
    }

    if (check_callsite && header.callsite_loc != call_site) {
        return NULL;
    }

    return entry;
}

// mz replay 1-byte input to the CPU
void rr_replay_input_1(RR_callsite_id call_site, uint8_t* data) {
    RR_log_entry* current_item = get_next_entry_checked(RR_INPUT_1, call_site, true);
    rr_assert(current_item);
    *data = current_item->variant.input_1;
    rr_queue_pop_front();
}

// mz replay 2-byte input to the CPU
void rr_replay_input_2(RR_callsite_id call_site, uint16_t* data) {
    RR_log_entry* current_item = get_next_entry_checked(RR_INPUT_2, call_site, true);
    rr_assert(current_item);
    *data = current_item->variant.input_2;
    rr_queue_pop_front();
}

// mz replay 4-byte input to the CPU
void rr_replay_input_4(RR_callsite_id call_site, uint32_t* data) {
    RR_log_entry* current_item = get_next_entry_checked(RR_INPUT_4, call_site, true);
    rr_assert(current_item);
    *data = current_item->variant.input_4;
    rr_queue_pop_front();
}

// mz replay 8-byte input to the CPU
void rr_replay_input_8(RR_callsite_id call_site, uint64_t* data) {
    RR_log_entry* current_item = get_next_entry_checked(RR_INPUT_8, call_site, true);
    rr_assert(current_item);
    *data = current_item->variant.input_8;
    rr_queue_pop_front();
}

/**
 * Update the panda_currrent_interrupt_request state machine, if necessary,
 * and use it to return the correct value for cpu->interrupt_requested
 */
void rr_replay_interrupt_request(RR_callsite_id call_site,
                                 int* interrupt_request)
{
    RR_log_entry* current_item =
        get_next_entry_checked(RR_INTERRUPT_REQUEST, call_site, true);
    if (current_item != NULL) {
        panda_current_interrupt_request = current_item->variant.interrupt_request;
        rr_queue_pop_front();
    }
    *interrupt_request = panda_current_interrupt_request;
}

void rr_replay_exit_request(RR_callsite_id call_site, uint32_t* exit_request)
{
    RR_log_entry* current_item =
        get_next_entry_checked(RR_EXIT_REQUEST, call_site, false);
    if (current_item == NULL) {
        *exit_request = 0;
    } else {
        // mz final sanity checks
        if (current_item->header.callsite_loc != call_site) {
            printf("Callsite match failed; %s (log) != %s (replay)!\n",
                   get_callsite_string(current_item->header.callsite_loc),
                   get_callsite_string(call_site));
            rr_assert(current_item->header.callsite_loc == call_site);
        }
        *exit_request = current_item->variant.exit_request;
        rr_queue_pop_front();
    }
}

bool rr_replay_exception_index(RR_callsite_id call_site, int32_t* exception_index) {
    RR_log_entry* current_item = get_next_entry_checked(RR_EXCEPTION, call_site, true);

    if (!current_item) return false;

    *exception_index = current_item->variant.exception_index;

    rr_queue_pop_front();
    return true;
}

//rw: replay powerpc pending interrupts
bool rr_replay_pending_interrupts(RR_callsite_id callsite_id, uint32_t* pending_int) {
    RR_log_entry* current_item = get_next_entry_checked(RR_PENDING_INTERRUPTS, callsite_id, true);

    if (!current_item) return false;

    *pending_int = current_item->variant.pending_interrupts;

    rr_queue_pop_front();
    return true;
}

bool rr_replay_intno(uint32_t *intno) {
    RR_log_entry *current_item =
        get_next_entry_checked(RR_INPUT_4, RR_CALLSITE_CPU_HANDLE_INTERRUPT_INTNO, true);
    if (!current_item) return false;

    *intno = current_item->variant.input_4;
    rr_queue_pop_front();
    return true;
}

static void rr_create_memory_region(hwaddr start, uint64_t size, RR_mem_type mtype, char *name) {
    MemoryRegion *mr = g_new0(MemoryRegion, 1);
    if (mtype == RR_MEM_RAM) {
        Error *err = 0;
        memory_region_init_ram(mr, NULL, name, size, &err);
    } else if (mtype == RR_MEM_IO) {
        memory_region_init_io(mr, NULL, NULL, NULL, name, size);
    }
    memory_region_add_subregion_overlap(get_system_memory(),
            start, mr, 1);
}

static MemoryRegion * rr_memory_region_find_parent(MemoryRegion *root, MemoryRegion *search) {
    MemoryRegion *submr;
    QTAILQ_FOREACH(submr, &root->subregions, subregions_link) {
        if (submr == search) return root;
        MemoryRegion *ssmr = rr_memory_region_find_parent(submr, search);
        if (ssmr) return ssmr;
    }
    return NULL;
}

// mz this function consumes 2 types of entries:
// RR_SKIPPED_CALL_CPU_MEM_RW and RR_SKIPPED_CALL_CPU_REG_MEM_REGION
// XXX call_site parameter no longer used...
// bdg 07.2012: Adding RR_SKIPPED_CALL_CPU_MEM_UNMAP
void rr_replay_skipped_calls_internal(RR_callsite_id call_site)
{
#ifdef CONFIG_SOFTMMU
    uint8_t replay_done = 0;
    do {
        RR_log_entry* current_item =
            get_next_entry_checked(RR_SKIPPED_CALL, call_site, false);
        if (current_item == NULL) {
            // mz queue is empty or we've replayed all we can for this prog
            // point
            replay_done = 1;
        } else {
            
            RR_skipped_call_args args = current_item->variant.call_args;
            switch (args.kind) {
            case RR_CALL_CPU_MEM_RW: {
                cpu_physical_memory_rw(args.variant.cpu_mem_rw_args.addr,
                                       args.variant.cpu_mem_rw_args.buf,
                                       args.variant.cpu_mem_rw_args.len,
                                       /*is_write=*/1);
            } break;
            case RR_CALL_MEM_REGION_CHANGE: {
                // Add a mapping
                if (args.variant.mem_region_change_args.added) {
                    rr_create_memory_region(
                            args.variant.mem_region_change_args.start_addr,
                            args.variant.mem_region_change_args.size,
                            args.variant.mem_region_change_args.mtype,
                            args.variant.mem_region_change_args.name);
                }
                // Delete a mapping
                else {
                    MemoryRegionSection mrs = memory_region_find(get_system_memory(),
                            args.variant.mem_region_change_args.start_addr,
                            args.variant.mem_region_change_args.size);
                    MemoryRegion *parent = rr_memory_region_find_parent(get_system_memory(),
                            mrs.mr);
                    memory_region_del_subregion(parent, mrs.mr);
                }
            } break;
            case RR_CALL_CPU_MEM_UNMAP: {
                void* host_buf;
                hwaddr plen = args.variant.cpu_mem_unmap.len;
                host_buf = cpu_physical_memory_map(
                    args.variant.cpu_mem_unmap.addr, &plen,
                    /*is_write=*/1);
                memcpy(host_buf, args.variant.cpu_mem_unmap.buf,
                       args.variant.cpu_mem_unmap.len);
                cpu_physical_memory_unmap(host_buf, plen,
                                          /*is_write=*/1,
                                          args.variant.cpu_mem_unmap.len);
            } break;
            case RR_CALL_HANDLE_PACKET:
                {
                    // run all callbacks registered for packet handling
                    RR_handle_packet_args hp = args.variant.handle_packet_args;
                    panda_callbacks_handle_packet(first_cpu, hp.buf, hp.size, hp.direction, args.old_buf_addr);
                } break;
            case RR_CALL_NET_TRANSFER:
                {
                    // run all callbacks registered for transfers within network
                    // card (E1000)
                    RR_net_transfer_args nta =
                         args.variant.net_transfer_args;
                    panda_callbacks_net_transfer(first_cpu, nta.type, nta.src_addr, nta.dest_addr, nta.num_bytes);
                } break;
            default:
                // mz sanity check
                rr_assert(0);
            }
            rr_queue_pop_front();
        }
    } while (!replay_done);
#endif
}

/******************************************************************************************/
/* LOG MANAGEMENT */
/******************************************************************************************/

extern char* qemu_strdup(const char* str);

// create record log
void rr_create_record_log(const char* filename)
{
    // create log
    rr_nondet_log = g_new0(RR_log, 1);
    rr_assert(rr_nondet_log != NULL);

    rr_nondet_log->type = RECORD;
    rr_nondet_log->name = g_strdup(filename);
    rr_nondet_log->fp = fopen(rr_nondet_log->name, "w");
    rr_assert(rr_nondet_log->fp != NULL);

    if (rr_debug_whisper()) {
        qemu_log("opened %s for write.\n", rr_nondet_log->name);
    }
    // mz It would be very handy to know how "far" we are in a particular replay
    // execution.  To do this, let's store a header in the log (we'll fill it in
    // again when we close the log) that includes the maximum instruction
    // count as a monotonicly increasing measure of progress.
    // This way, when we print progress, we can use something better than size
    // of log consumed
    //(as that can jump //sporadically).
    rr_fwrite(&(rr_nondet_log->last_prog_point.guest_instr_count),
            sizeof(rr_nondet_log->last_prog_point.guest_instr_count), 1);
}

// create replay log
void rr_create_replay_log(const char* filename)
{
    struct stat statbuf = {0};
    // create log
    rr_nondet_log = g_new0(RR_log, 1);
    rr_assert(rr_nondet_log != NULL);

    rr_nondet_log->type = REPLAY;
    rr_nondet_log->name = g_strdup(filename);
    rr_nondet_log->fp = fopen(rr_nondet_log->name, "r");
    rr_assert(rr_nondet_log->fp != NULL);

    // mz fill in log size
    stat(rr_nondet_log->name, &statbuf);
    rr_nondet_log->size = statbuf.st_size;
    rr_nondet_log->bytes_read = 0;
    if (rr_debug_whisper()) {
        qemu_log("opened %s for read.  len=%llu bytes.\n", rr_nondet_log->name,
                 rr_nondet_log->size);
    }
    // mz read the last program point from the log header.
    rr_fread(&(rr_nondet_log->last_prog_point.guest_instr_count),
            sizeof(rr_nondet_log->last_prog_point.guest_instr_count), 1);
}

// close file and free associated memory
void rr_destroy_log(void)
{
    if (rr_nondet_log->fp) {
        // mz if in record, update the header with the last written prog point.
        if (rr_nondet_log->type == RECORD) {
            rewind(rr_nondet_log->fp);
            rr_fwrite(&(rr_nondet_log->last_prog_point.guest_instr_count),
                    sizeof(rr_nondet_log->last_prog_point.guest_instr_count), 1);
        }
        fclose(rr_nondet_log->fp);
        rr_nondet_log->fp = NULL;
    }
    g_free(rr_nondet_log->name);
    g_free(rr_nondet_log);
    rr_nondet_log = NULL;
}

struct timeval replay_start_time;

// mz display a measure of replay progress (using instruction counts and log
// size)
void replay_progress(void)
{
    if (rr_nondet_log) {
        if (rr_log_is_empty()) {
            printf("%s:  log is empty.\n", rr_nondet_log->name);
        } else {
            struct rusage rusage;
            getrusage(RUSAGE_SELF, &rusage);

            struct timeval* time = &rusage.ru_utime;
            float secs =
                ((float)time->tv_sec * 1000000 + (float)time->tv_usec) /
                1000000.0;
            char* dup_name = strdup(rr_nondet_log->name);
            char* name = basename(dup_name);
            char* dot = strrchr(name, '.');
            if (dot && dot - name > 10)
                *(dot - 10) = '\0';

            printf("%s:  %10" PRIu64
                   " (%6.2f%%) instrs. %7.2f sec. %5.2f GB ram.\n",
                   name, rr_get_guest_instr_count(),
                   ((rr_get_guest_instr_count() * 100.0) /
                    rr_nondet_log->last_prog_point.guest_instr_count),
                   secs, rusage.ru_maxrss / 1024.0 / 1024.0
#ifdef __APPLE__
                   / 1024.0
#endif
                   );
            free(dup_name);
        }
    }
}


uint64_t replay_get_total_num_instructions(void)
{
    if (rr_nondet_log) {
        return rr_nondet_log->last_prog_point.guest_instr_count;
    } else {
        return 0;
    }
}

/******************************************************************************************/
/* MONITOR CALLBACKS (top-level) */
/******************************************************************************************/
// mz from vl.c

// rr_name is the current rec/replay name.
// here we compute the snapshot name to use for rec/replay
static inline void rr_get_snapshot_file_name(char* rr_name, char* rr_path,
                                             char* snapshot_name,
                                             size_t snapshot_name_len)
{
    rr_assert(rr_name != NULL);
    snprintf(snapshot_name, snapshot_name_len, "%s/%s-rr-snp", rr_path,
             rr_name);
}

static inline void rr_get_nondet_log_file_name(char* rr_name, char* rr_path,
                                               char* file_name,
                                               size_t file_name_len)
{
    rr_assert(rr_name != NULL && rr_path != NULL);
    snprintf(file_name, file_name_len, "%s/%s-rr-nondet.log", rr_path, rr_name);
}

void rr_reset_state(CPUState* cpu)
{
    tb_flush(cpu);
    // clear flags
    rr_record_in_progress = 0;
    rr_skipped_callsite_location = 0;
    cpu->rr_guest_instr_count = 0;
}

//////////////////////////////////////////////////////////////
//
// QMP commands

#ifdef CONFIG_SOFTMMU

#include "qapi/error.h"
void qmp_begin_record(const char* file_name, Error** errp)
{
    rr_record_requested = RR_RECORD_REQUEST;
    rr_requested_name = g_strdup(file_name);
}

void qmp_begin_record_from(const char* snapshot, const char* file_name,
                                  Error** errp)
{
    rr_record_requested = RR_RECORD_FROM_REQUEST;
    rr_snapshot_name = g_strdup(snapshot);
    rr_requested_name = g_strdup(file_name);
}

void qmp_end_record(Error** errp)
{
    qmp_stop(NULL);
    rr_end_record_requested = 1;
}

void qmp_begin_replay(const char *file_name, Error **errp) {
  rr_replay_requested = 1;
  rr_requested_name = g_strdup(file_name);
  gettimeofday(&replay_start_time, 0);
}

void qmp_end_replay(Error** errp)
{
    qmp_stop(NULL);
    rr_end_replay_requested = 1;
}

void panda_end_replay(void) { rr_end_replay_requested = 1; }

#include "qemu-common.h"    // Monitor def
#include "qapi/qmp/qdict.h" // QDict def

// HMP commands (the "monitor")
void hmp_begin_record(Monitor* mon, const QDict* qdict)
{
    Error* err;
    const char* file_name = qdict_get_try_str(qdict, "file_name");
    qmp_begin_record(file_name, &err);
}

// HMP commands (the "monitor")
void hmp_begin_record_from(Monitor* mon, const QDict* qdict)
{
    Error* err;
    const char* snapshot = qdict_get_try_str(qdict, "snapshot");
    const char* file_name = qdict_get_try_str(qdict, "file_name");
    qmp_begin_record_from(snapshot, file_name, &err);
}

void hmp_end_record(Monitor* mon, const QDict* qdict)
{
    Error* err;
    qmp_end_record(&err);
}

void hmp_begin_replay(Monitor *mon, const QDict *qdict)
{
  Error *err;
  const char *file_name = qdict_get_try_str(qdict, "file_name");
  qmp_begin_replay(file_name, &err);
}

void hmp_end_replay(Monitor* mon, const QDict* qdict)
{
    Error* err;
    qmp_end_replay(&err);
}

#endif // CONFIG_SOFTMMU

static time_t rr_start_time;

// mz file_name_full should be full path to desired record/replay log file
int rr_do_begin_record(const char* file_name_full, CPUState* cpu_state)
{
#ifdef CONFIG_SOFTMMU
    char name_buf[1024];
    // decompose file_name_base into path & file.
    char* rr_path_base = g_strdup(file_name_full);
    char* rr_name_base = g_strdup(file_name_full);
    char* rr_path = dirname(rr_path_base);
    char* rr_name = basename(rr_name_base);
    int snapshot_ret = -1;
    if (rr_debug_whisper()) {
        qemu_log("Begin vm record for file_name_full = %s\n", file_name_full);
        qemu_log("path = [%s]  file_name_base = [%s]\n", rr_path, rr_name);
    }
    // first take a snapshot or load snapshot

    if (rr_record_requested == RR_RECORD_FROM_REQUEST) {
        printf("loading snapshot:\t%s\n", rr_snapshot_name);
        snapshot_ret = load_vmstate(rr_snapshot_name);
        g_free(rr_snapshot_name);
        rr_snapshot_name = NULL;
    }
    if (rr_record_requested == RR_RECORD_REQUEST || rr_record_requested == RR_RECORD_FROM_REQUEST) {
        // Force running state
        global_state_store_running();
        rr_get_snapshot_file_name(rr_name, rr_path, name_buf, sizeof(name_buf));
        printf("writing snapshot:\t%s\n", name_buf);
        QIOChannelFile* ioc =
            qio_channel_file_new_path(name_buf, O_WRONLY | O_CREAT, 0660, NULL);
        QEMUFile* snp = qemu_fopen_channel_output(QIO_CHANNEL(ioc));
        snapshot_ret = qemu_savevm_state(snp, NULL);
        qemu_fclose(snp);
        // log_all_cpu_states();
    }

    // save the time so we can report how long record takes
    time(&rr_start_time);

    // second, open non-deterministic input log for write.
    rr_get_nondet_log_file_name(rr_name, rr_path, name_buf, sizeof(name_buf));
    printf("opening nondet log for write :\t%s\n", name_buf);
    rr_create_record_log(name_buf);
    // reset record/replay counters and flags
    rr_reset_state(cpu_state);
    g_free(rr_path_base);
    g_free(rr_name_base);
    // set global to turn on recording
    rr_mode = RR_RECORD;
    return snapshot_ret;
#endif
}

static uint32_t rr_checksum_memory_internal(void);
void rr_do_end_record(void)
{
#ifdef CONFIG_SOFTMMU
    // mz put in end-of-log marker
    rr_record_end_of_log();

    char* rr_path_base = g_strdup(rr_nondet_log->name);
    char* rr_name_base = g_strdup(rr_nondet_log->name);
    // char *rr_path = dirname(rr_path_base);
    char* rr_name = basename(rr_name_base);

    if (rr_debug_whisper()) {
        qemu_log("End vm record for name = %s\n", rr_name);
        printf("End vm record for name = %s\n", rr_name);
    }

    time_t rr_end_time;
    time(&rr_end_time);
    printf("Time taken was: %ld seconds.\n", rr_end_time - rr_start_time);
    printf("Checksum of guest memory: %#08x\n", rr_checksum_memory_internal());

    // log_all_cpu_states();

    rr_destroy_log();

    g_free(rr_path_base);
    g_free(rr_name_base);

    // turn off logging
    rr_mode = RR_OFF;
#endif
}

extern void panda_cleanup(void);

// file_name_full should be full path to the record/replay log
int rr_do_begin_replay(const char* file_name_full, CPUState* cpu_state)
{
#ifdef CONFIG_SOFTMMU
    char name_buf[1024];
    // decompose file_name_base into path & file.
    char* rr_path = g_strdup(file_name_full);
    char* rr_name = g_strdup(file_name_full);
    __attribute__((unused)) int snapshot_ret;
    rr_path = dirname(rr_path);
    rr_name = basename(rr_name);
    if (rr_debug_whisper()) {
        qemu_log("Begin vm replay for file_name_full = %s\n", file_name_full);
        qemu_log("path = [%s]  file_name_base = [%s]\n", rr_path, rr_name);
    }
    // first retrieve snapshot
    rr_get_snapshot_file_name(rr_name, rr_path, name_buf, sizeof(name_buf));
    if (rr_debug_whisper()) {
        qemu_log("reading snapshot:\t%s\n", name_buf);
    }
    printf("loading snapshot\n");
    QIOChannelFile* ioc =
        qio_channel_file_new_path(name_buf, O_RDONLY, 0, NULL);
    if (ioc == NULL) {
        printf ("... snapshot file doesn't exist?\n");
        abort();
    }
    QEMUFile* snp = qemu_fopen_channel_input(QIO_CHANNEL(ioc));

    qemu_system_reset(VMRESET_SILENT);
    migration_incoming_state_new(snp);
    snapshot_ret = qemu_loadvm_state(snp);
    qemu_fclose(snp);
    migration_incoming_state_destroy();

    if (snapshot_ret < 0) {
        fprintf(stderr, "Failed to load vmstate\n");
        return snapshot_ret;
    }
    printf("... done.\n");
    // log_all_cpu_states();

    // save the time so we can report how long replay takes
    time(&rr_start_time);

    // second, open non-deterministic input log for read.
    rr_get_nondet_log_file_name(rr_name, rr_path, name_buf, sizeof(name_buf));
    printf("opening nondet log for read :\t%s\n", name_buf);
    rr_create_replay_log(name_buf);
    // reset record/replay counters and flags
    rr_reset_state(cpu_state);
    // set global to turn on replay
    rr_mode = RR_REPLAY;

    // set up event queue
    rr_queue_head = rr_queue_tail = NULL;
    rr_queue_end = &rr_queue[RR_QUEUE_MAX_LEN];
    rr_fill_queue();
    return 0; // snapshot_ret;
#endif
}

// mz XXX what about early replay termination? Can we save state and resume
// later?
void rr_do_end_replay(int is_error)
{
#ifdef CONFIG_SOFTMMU
    // log is empty - we're done
    // dump cpu state at exit as a sanity check.

    replay_progress();
    if (is_error) {
        printf("ERROR: replay failed!\n");
    } else {
        printf("Replay completed successfully. 1\n");
    }

    time_t rr_end_time;
    time(&rr_end_time);
    printf("Time taken was: %ld seconds.\n", rr_end_time - rr_start_time);

    printf("Stats:\n");
    int i;
    for (i = 0; i < RR_LAST; i++) {
        printf("%s number = %llu, size = %llu bytes\n",
               get_log_entry_kind_string(i), rr_number_of_log_entries[i],
               rr_size_of_log_entries[i]);
        rr_number_of_log_entries[i] = 0;
        rr_size_of_log_entries[i] = 0;
    }
    printf("max_queue_len = %llu\n", rr_max_num_queue_entries);
    rr_max_num_queue_entries = 0;

    printf("Checksum of guest memory: %#08x\n", rr_checksum_memory_internal());

    // mz some more sanity checks - the queue should contain only the RR_LAST
    // element
    if (rr_queue_head == rr_queue_tail && rr_queue_head != NULL &&
        rr_queue_head->header.kind == RR_END_OF_LOG) {
        printf("Replay completed successfully 2.\n");
    } else {
        if (is_error) {
            printf("ERROR: replay failed!\n");
        } else {
            printf("Replay terminated at user request.\n");
        }
    }
    rr_queue_head = NULL;
    rr_queue_tail = NULL;
    // mz print CPU state at end of replay
    // log_all_cpu_states();
    // close logs
    rr_destroy_log();
    // turn off replay
    rr_mode = RR_OFF;

    rr_replay_complete = true;
    
    // mz XXX something more graceful?
    if (is_error) {
        panda_cleanup();
        abort();
    } else {
        qemu_system_shutdown_request();
    }
#endif // CONFIG_SOFTMMU
}

// Record skipped calls.
void rr_begin_main_loop_wait(void) {
#ifdef CONFIG_SOFTMMU
    if (rr_in_record()) {
        rr_record_in_main_loop_wait = 1;
        rr_skipped_callsite_location = RR_CALLSITE_MAIN_LOOP_WAIT;
    }
#endif
}

void rr_end_main_loop_wait(void) {
#ifdef CONFIG_SOFTMMU
    if (rr_in_record()) {
        rr_record_in_main_loop_wait = 0;
        // Check if DMA-mapped regions have changed
        rr_tracked_mem_regions_record();
    }
#endif
}

#ifdef CONFIG_SOFTMMU
static uint32_t rr_checksum_memory_internal(void) {
    MemoryRegion *ram = memory_region_find(get_system_memory(), 0x2000000, 1).mr;
    rcu_read_lock();
    void *ptr = qemu_map_ram_ptr(ram->ram_block, 0);
    uint32_t crc = crc32(0, Z_NULL, 0);
    crc = crc32(crc, ptr, int128_get64(ram->size));
    rcu_read_unlock();

    return crc;
}

uint32_t rr_checksum_memory(void) {
    if (!qemu_in_vcpu_thread()) {
         printf("Need to be in VCPU thread!\n");
         return 0;
    }
    return rr_checksum_memory_internal();
}

uint32_t rr_checksum_regs(void) {
    if (!qemu_in_vcpu_thread()) {
         printf("Need to be in VCPU thread!\n");
         return 0;
    }
    CPUArchState *env = (CPUArchState *)first_cpu->env_ptr;
    uint32_t crc = crc32(0, Z_NULL, 0);
#if defined(TARGET_PPC)
    crc = crc32(crc, (unsigned char *)env->gpr, sizeof(env->gpr));
#else
    crc = crc32(crc, (unsigned char *)env->regs, sizeof(env->regs));
#endif
#if defined(TARGET_I386)
    crc = crc32(crc, (unsigned char *)&env->eip, sizeof(env->eip));
#elif defined(TARGET_ARM)
    crc = crc32(crc, (unsigned char *)&env->pc, sizeof(env->pc));
#endif
    return crc;
}

uint8_t rr_debug_readb(target_ulong addr);
uint8_t rr_debug_readb(target_ulong addr) {
    CPUState *cpu = first_cpu;
    uint8_t out = 0;

    cpu_memory_rw_debug(cpu, addr, (uint8_t *)&out, sizeof(out), 0);
    return out;
}

uint32_t rr_debug_readl(target_ulong addr);
uint32_t rr_debug_readl(target_ulong addr) {
    CPUState *cpu = first_cpu;
    uint32_t out = 0;

    cpu_memory_rw_debug(cpu, addr, (uint8_t *)&out, sizeof(out), 0);
    return out;
}
#endif

/**************************************************************************/
