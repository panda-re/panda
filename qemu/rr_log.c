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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libgen.h>

#include "qemu-common.h"
#include "qmp-commands.h"
#include "hmp.h"
#include "sysemu.h"
#include "rr_log.h"

#include "panda_plugin.h"


/******************************************************************************************/
/* GLOBALS */
/******************************************************************************************/
//mz record/replay mode
volatile RR_mode rr_mode = RR_OFF;

//mz program execution state
RR_prog_point rr_prog_point = {0, 0, 0};


uint64_t rr_get_pc(void) {
    return rr_prog_point.pc;
}

uint64_t rr_get_secondary(void) {
    return rr_prog_point.secondary;
}

uint64_t rr_get_guest_instr_count (void) {
    return rr_prog_point.guest_instr_count;
}

//volatile uint64_t rr_guest_instr_count;
volatile uint64_t rr_num_instr_before_next_interrupt;

//mz 11.06.2009 Flags to manage nested recording
volatile sig_atomic_t rr_record_in_progress = 0;
volatile sig_atomic_t rr_skipped_callsite_location = 0;

volatile sig_atomic_t rr_use_live_exit_request = 0;

//mz the log of non-deterministic events
RR_log *rr_nondet_log = NULL;

double rr_get_percentage (void) {
    return 100.0 * rr_prog_point.guest_instr_count /
        rr_nondet_log->last_prog_point.guest_instr_count;
}

static inline uint8_t rr_log_is_empty(void) {
    if ((rr_nondet_log->type == REPLAY) &&
        (rr_nondet_log->size - ftell(rr_nondet_log->fp) == 0)) {
        return 1;
    }
    else {
        return 0;
    }
}

RR_debug_level_type rr_debug_level = RR_DEBUG_NOISY;

// used as a signal that TB cache needs flushing.
uint8_t rr_please_flush_tb = 0;

//mz Flags set by monitor to indicate requested record/replay action
volatile sig_atomic_t rr_replay_requested = 0;
volatile sig_atomic_t rr_record_requested = 0;
volatile sig_atomic_t rr_end_record_requested = 0;
volatile sig_atomic_t rr_end_replay_requested = 0;
const char * rr_requested_name = NULL;
const char * rr_snapshot_name  = NULL;

//mz FIFO queue of log entries read from the log file
static RR_log_entry *rr_queue_head;
static RR_log_entry *rr_queue_tail;

//
//mz Other useful things
//
//mz from vl.c
extern void log_all_cpu_states(void);

/******************************************************************************************/
/* UTILITIES */
/******************************************************************************************/

RR_log_entry *rr_get_queue_head(void) {
    return rr_queue_head;
}

// Check if replay is really finished. Conditions:
// 1) The log is empty
// 2) The only thing in the queue is RR_LAST
uint8_t rr_replay_finished(void) {
    return rr_log_is_empty() && rr_queue_head->header.kind == RR_LAST && rr_prog_point.guest_instr_count >= rr_queue_head->header.prog_point.guest_instr_count;
}

//mz "performance" counters - basically, how much of the log is taken up by
//mz each kind of entry. 
volatile unsigned long long rr_number_of_log_entries[RR_LAST];
volatile unsigned long long rr_size_of_log_entries[RR_LAST];
volatile unsigned long long rr_max_num_queue_entries;

//mz a history of last few log entries for replay
//mz use rr_print_history() to dump in a debugger
#define RR_HIST_SIZE 10
RR_log_entry rr_log_entry_history[RR_HIST_SIZE];
int rr_hist_index = 0;


// write this program point to this file 
static void rr_spit_prog_point_fp(FILE *fp, RR_prog_point pp) {
    fprintf(fp, "{guest_instr_count=%llu pc=0x%08llx, secondary=0x%08llx}\n", 
        (unsigned long long)pp.guest_instr_count,
        (unsigned long long)pp.pc,
        (unsigned long long)pp.secondary);
}

void rr_debug_log_prog_point(RR_prog_point pp) {
  rr_spit_prog_point_fp(logfile,pp);
}

void rr_spit_prog_point(RR_prog_point pp) {
  rr_spit_prog_point_fp(stdout,pp);
}

static void rr_spit_log_entry(RR_log_entry item) {
    rr_spit_prog_point(item.header.prog_point);
    switch (item.header.kind) {
        case RR_INPUT_1:
            printf("\tRR_INPUT_1 from %s\n", get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INPUT_2:
            printf("\tRR_INPUT_2 from %s\n", get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INPUT_4:
            printf("\tRR_INPUT_4 from %s\n", get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INPUT_8:
            printf("\tRR_INPUT_8 from %s\n", get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INTERRUPT_REQUEST:
            printf("\tRR_INTERRUPT_REQUEST from %s\n", get_callsite_string(item.header.callsite_loc));
            break;
        case RR_EXIT_REQUEST:
            printf("\tRR_EXIT_REQUEST from %s\n", get_callsite_string(item.header.callsite_loc));
            break;
        case RR_SKIPPED_CALL:
            printf("\tRR_SKIPPED_CALL (%s) from %s\n", 
                    get_skipped_call_kind_string(item.variant.call_args.kind),
                    get_callsite_string(item.header.callsite_loc));
            break;
        case RR_LAST:
            printf("\tRR_LAST\n");
            break;
        case RR_DEBUG:
            printf("\tRR_DEBUG\n");
            break;
        default:
            printf("\tUNKNOWN RR log kind %d\n", item.header.kind);
            break;
    }
}

void rr_spit_queue_head(void) {
    rr_spit_log_entry(*rr_queue_head);
}

//mz use in debugger to print a short history of log entries
void rr_print_history(void) {
    int i = rr_hist_index;
    do {
        rr_spit_log_entry(rr_log_entry_history[i]);
        i = (i + 1) % RR_HIST_SIZE;
    } while (i != rr_hist_index);
}

//mz here to prevent the need to #include<stdio.h> in rr_log.h
void rr_signal_disagreement(RR_prog_point current, RR_prog_point recorded) {
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
      if (current.pc != recorded.pc) {
          printf(">>> guest PCs disagree\n");
      }
      if (current.secondary != recorded.secondary) {
          printf(">>> guest secondary info disagrees\n");
      }
}

// our debug rr_assert
inline void rr_assert_fail(const char *exp, const char *file, int line, const char *function) {
    printf("RR rr_assertion `%s' failed at %s:%d\n", exp, file, line);
    printf("Current log point:\n");
    if(rr_queue_head != NULL) {
        rr_spit_prog_point(rr_queue_head->header.prog_point);
        printf("Next log entry type: %s\n", log_entry_kind_str[rr_queue_head->header.kind]);
    }
    else {
        printf("<queue empty>\n");
    }
    printf("Current replay point:\n");
    rr_spit_prog_point(rr_prog_point);
    if(rr_debug_whisper()) {
        fprintf(logfile, "RR rr_assertion `%s' failed at %s:%d in %s\n", exp, file, line, function);
    }
    fflush(logfile);
    // just abort
    exit(1);
    rr_end_replay_requested = 1;
    //mz need to get out of cpu loop so that we can process the end_replay request
    //mz this will call cpu_loop_exit(), which longjmps
    //bdg gosh I hope this is OK here. I think it should be as long as we only ever call
    //bdg rr_assert from the CPU loop
    rr_quit_cpu_loop();
    /* NOT REACHED */
}

/******************************************************************************************/
/* RECORD */
/******************************************************************************************/

//mz write the current log item to file
static inline void rr_write_item(void) {
    RR_log_entry *item = &(rr_nondet_log->current_item);

    //mz save the header
    rr_assert (rr_in_record());
    rr_assert (rr_nondet_log != NULL);
    //mz this is more compact, as it doesn't include extra padding.
    fwrite(&(item->header.prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp);
    fwrite(&(item->header.kind), sizeof(item->header.kind), 1, rr_nondet_log->fp);
    fwrite(&(item->header.callsite_loc), sizeof(item->header.callsite_loc), 1, rr_nondet_log->fp);

    //mz also save the program point in the log structure to ensure that our
    //header will include the latest program point.
    rr_nondet_log->last_prog_point = item->header.prog_point;

    switch (item->header.kind) {
        case RR_INPUT_1:
            fwrite(&(item->variant.input_1), sizeof(item->variant.input_1), 1, rr_nondet_log->fp);
            break;
        case RR_INPUT_2:
            fwrite(&(item->variant.input_2), sizeof(item->variant.input_2), 1, rr_nondet_log->fp);
            break;
        case RR_INPUT_4:
            fwrite(&(item->variant.input_4), sizeof(item->variant.input_4), 1, rr_nondet_log->fp);
            break;
        case RR_INPUT_8:
            fwrite(&(item->variant.input_8), sizeof(item->variant.input_8), 1, rr_nondet_log->fp);
            break;
        case RR_INTERRUPT_REQUEST:
            fwrite(&(item->variant.interrupt_request), sizeof(item->variant.interrupt_request), 1, rr_nondet_log->fp);
            break;
        case RR_EXIT_REQUEST:
            fwrite(&(item->variant.exit_request), sizeof(item->variant.exit_request), 1, rr_nondet_log->fp);
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item->variant.call_args;
                //mz write kind first!
                fwrite(&(args->kind), sizeof(args->kind), 1, rr_nondet_log->fp);
                switch (args->kind) {
                    case RR_CALL_CPU_MEM_RW:
                        rr_assert(args->variant.cpu_mem_rw_args.buf != NULL || 
                                args->variant.cpu_mem_rw_args.len == 0);
                        fwrite(&(args->variant.cpu_mem_rw_args), 
			       sizeof(args->variant.cpu_mem_rw_args), 
			       1, rr_nondet_log->fp);
                        //mz write the buffer
                        fwrite(args->variant.cpu_mem_rw_args.buf, 1, 
			       args->variant.cpu_mem_rw_args.len, rr_nondet_log->fp);
                        break;
                    case RR_CALL_CPU_MEM_UNMAP:
                        //bdg same deal as RR_CALL_CPU_MEM_RW
                        rr_assert(args->variant.cpu_mem_unmap.buf != NULL || 
                                args->variant.cpu_mem_unmap.len == 0);
                        fwrite(&(args->variant.cpu_mem_unmap),
			       sizeof(args->variant.cpu_mem_unmap), 1, rr_nondet_log->fp);
                        fwrite(args->variant.cpu_mem_unmap.buf, 1, 
			       args->variant.cpu_mem_unmap.len, rr_nondet_log->fp);
                        break;
                    case RR_CALL_CPU_REG_MEM_REGION:
                        fwrite(&(args->variant.cpu_mem_reg_region_args), 
                               sizeof(args->variant.cpu_mem_reg_region_args), 1, rr_nondet_log->fp);
                        break;
                    case RR_CALL_HD_TRANSFER:
		        fwrite(&(args->variant.hd_transfer_args), 
                               sizeof(args->variant.hd_transfer_args), 1, rr_nondet_log->fp);
                        break;
                    case RR_CALL_NET_TRANSFER:
		        fwrite(&(args->variant.net_transfer_args), 
                               sizeof(args->variant.net_transfer_args), 1, rr_nondet_log->fp);
                        break;
                    case RR_CALL_HANDLE_PACKET:
                        assert(args->variant.handle_packet_args.buf != NULL || 
                                args->variant.handle_packet_args.size == 0);
                        fwrite(&(args->variant.handle_packet_args), 
			       sizeof(args->variant.handle_packet_args), 1, rr_nondet_log->fp);
                        //mz write the buffer
                        fwrite(args->variant.handle_packet_args.buf, 1, 
			       args->variant.handle_packet_args.size, rr_nondet_log->fp);
                        break;
                    default:
                        //mz unimplemented
                        rr_assert(0);
                }
            }
            break;
        case RR_LAST:
        case RR_DEBUG:
            //mz nothing to write
            break;
        default:
            //mz unimplemented
            rr_assert(0);
    }
    rr_nondet_log->item_number++;
}

//bdg in debug mode, to find divergences more quickly
void rr_record_debug(RR_callsite_id call_site) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_DEBUG;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    rr_write_item();
}

//mz record 1-byte CPU input to log file
void rr_record_input_1(RR_callsite_id call_site, uint8_t data) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_INPUT_1;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    item->variant.input_1 = data;

    rr_write_item();
}

//mz record 2-byte CPU input to file
void rr_record_input_2(RR_callsite_id call_site, uint16_t data) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_INPUT_2;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    item->variant.input_2 = data;

    rr_write_item();
}

//mz record 4-byte CPU input to file
void rr_record_input_4(RR_callsite_id call_site, uint32_t data) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_INPUT_4;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    item->variant.input_4 = data;

    rr_write_item();
}

//mz record 8-byte CPU input to file
void rr_record_input_8(RR_callsite_id call_site, uint64_t data) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_INPUT_8;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    item->variant.input_8 = data;

    rr_write_item();
}

//mz record interrupt request value to file (but only if non-zero)
void rr_record_interrupt_request(RR_callsite_id call_site, uint32_t interrupt_request) {
    //mz we only record interrupt_requests if the value is non-zero
    if (interrupt_request != 0) {
        RR_log_entry *item = &(rr_nondet_log->current_item);
        //mz just in case
        memset(item, 0, sizeof(RR_log_entry));

        item->header.kind = RR_INTERRUPT_REQUEST;
        item->header.callsite_loc = call_site;
        item->header.prog_point = rr_prog_point;

        item->variant.interrupt_request = interrupt_request;

        rr_write_item();
    }
}

void rr_record_exit_request(RR_callsite_id call_site, uint32_t exit_request) {
    if (exit_request != 0) {
        RR_log_entry *item = &(rr_nondet_log->current_item);
        //mz just in case
        memset(item, 0, sizeof(RR_log_entry));

        item->header.kind = RR_EXIT_REQUEST;
        item->header.callsite_loc = call_site;
        item->header.prog_point = rr_prog_point;

        item->variant.exit_request = exit_request;

        rr_write_item();
    }
}

//mz record call to cpu_physical_memory_rw() that will need to be replayed.
//mz only "write" modifications are recorded
void rr_record_cpu_mem_rw_call(RR_callsite_id call_site,
                                   target_phys_addr_t addr, uint8_t *buf, int len, int is_write) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_SKIPPED_CALL;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    item->variant.call_args.kind = RR_CALL_CPU_MEM_RW;
    item->variant.call_args.variant.cpu_mem_rw_args.addr = addr;
    item->variant.call_args.variant.cpu_mem_rw_args.buf = buf;
    item->variant.call_args.variant.cpu_mem_rw_args.len = len;
    //mz is_write is dropped on the floor, as we only record writes

    rr_write_item();
}

//bdg Record the memory modified during a call to cpu_physical_memory_map/unmap.
//bdg Really we could subsume the functionality of rr_record_cpu_mem_rw_call into this,
//bdg since they're both concerned with capturing the memory side effects of device code
void rr_record_cpu_mem_unmap(RR_callsite_id call_site,
                                   target_phys_addr_t addr, uint8_t *buf, target_phys_addr_t len, int is_write) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_SKIPPED_CALL;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    item->variant.call_args.kind = RR_CALL_CPU_MEM_UNMAP;
    item->variant.call_args.variant.cpu_mem_unmap.addr = addr;
    item->variant.call_args.variant.cpu_mem_unmap.buf = buf;
    item->variant.call_args.variant.cpu_mem_unmap.len = len;
    //mz is_write is dropped on the floor, as we only record writes

    rr_write_item();
}

//mz record a call to cpu_register_io_memory() that will need to be replayed.
void rr_record_cpu_reg_io_mem_region(RR_callsite_id call_site,
                                         target_phys_addr_t start_addr, ram_addr_t size, ram_addr_t phys_offset) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_SKIPPED_CALL;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    item->variant.call_args.kind = RR_CALL_CPU_REG_MEM_REGION;
    item->variant.call_args.variant.cpu_mem_reg_region_args.start_addr = start_addr;
    item->variant.call_args.variant.cpu_mem_reg_region_args.size = size;
    item->variant.call_args.variant.cpu_mem_reg_region_args.phys_offset = phys_offset;

    rr_write_item();
}



void rr_record_hd_transfer(RR_callsite_id call_site,
				  Hd_transfer_type transfer_type,
				  uint64_t src_addr, uint64_t dest_addr, uint32_t num_bytes) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_SKIPPED_CALL;
    //item->header.qemu_loc = rr_qemu_location;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    item->variant.call_args.kind = RR_CALL_HD_TRANSFER;
    item->variant.call_args.variant.hd_transfer_args.type = transfer_type;
    item->variant.call_args.variant.hd_transfer_args.src_addr = src_addr;
    item->variant.call_args.variant.hd_transfer_args.dest_addr = dest_addr;
    item->variant.call_args.variant.hd_transfer_args.num_bytes = num_bytes;

    rr_write_item();
}


void rr_record_net_transfer(RR_callsite_id call_site,
				  Net_transfer_type transfer_type,
				  uint64_t src_addr, uint64_t dest_addr, uint32_t num_bytes) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_SKIPPED_CALL;
    //item->header.qemu_loc = rr_qemu_location;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    item->variant.call_args.kind = RR_CALL_NET_TRANSFER;
    item->variant.call_args.variant.net_transfer_args.type = transfer_type;
    item->variant.call_args.variant.net_transfer_args.src_addr = src_addr;
    item->variant.call_args.variant.net_transfer_args.dest_addr = dest_addr;
    item->variant.call_args.variant.net_transfer_args.num_bytes = num_bytes;

    rr_write_item();
}


void rr_record_handle_packet_call(RR_callsite_id call_site, uint8_t *buf, int size, uint8_t direction)
{
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_SKIPPED_CALL;
    //item->header.qemu_loc = rr_qemu_location;
    item->header.callsite_loc = call_site;
    item->header.prog_point = rr_prog_point;

    item->variant.call_args.kind = RR_CALL_HANDLE_PACKET;
    item->variant.call_args.variant.handle_packet_args.buf = buf;
    item->variant.call_args.variant.handle_packet_args.size = size;
    item->variant.call_args.variant.handle_packet_args.direction = direction;

    rr_write_item();
}


//mz record a marker for end of the log
static void rr_record_end_of_log(void) {
    RR_log_entry *item = &(rr_nondet_log->current_item);
    //mz just in case
    memset(item, 0, sizeof(RR_log_entry));

    item->header.kind = RR_LAST;
    item->header.callsite_loc = RR_CALLSITE_LAST;
    item->header.prog_point = rr_prog_point;

    rr_write_item();
}



/******************************************************************************************/
/* REPLAY */
/******************************************************************************************/

//mz avoid actually releasing memory
static RR_log_entry *recycle_list = NULL;

static inline void free_entry_params(RR_log_entry *entry) 
{
    //mz cleanup associated resources
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

//mz "free" a used entry
static inline void add_to_recycle_list(RR_log_entry *entry)
{
    free_entry_params(entry);
    //mz add to the recycle list
    if (recycle_list == NULL) {
        recycle_list = entry;
    }
    else {
        entry->next = recycle_list;
        recycle_list = entry;
    }
    //mz save item in history
    //mz NB: we're not saving the buffer here (for RR_SKIPPED_CALL/RR_CALL_CPU_MEM_RW),
    //mz so don't try to read it later!
    rr_log_entry_history[rr_hist_index] = *entry;
    rr_hist_index = (rr_hist_index + 1) % RR_HIST_SIZE;
}

//mz allocate a new entry (not filled yet)
static inline RR_log_entry *alloc_new_entry(void) 
{
    RR_log_entry *new_entry = NULL;
    if (recycle_list != NULL) {
        new_entry = recycle_list;
        recycle_list = recycle_list->next;
        new_entry->next = NULL;
    }
    else {
        new_entry = g_new(RR_log_entry, 1);
    }
    memset(new_entry, 0, sizeof(RR_log_entry));
    return new_entry;
}

//mz fill an entry
static RR_log_entry *rr_read_item(void) {
    RR_log_entry *item = alloc_new_entry();

    //mz read header
    rr_assert (rr_in_replay());
    rr_assert ( ! rr_log_is_empty());
    rr_assert (rr_nondet_log->fp != NULL);

    //mz XXX we assume that the log is not trucated - should probably fix this.
    if (fread(&(item->header.prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp) != 1) {
        //mz an error occurred
        if (feof(rr_nondet_log->fp)) {
            // replay is done - we've reached the end of file
            //mz we should never get here!
            rr_assert(0);
        } 
        else {
            //mz some other kind of error
            //mz XXX something more graceful, perhaps?
            rr_assert(0);
        }
    }
    //mz this is more compact, as it doesn't include extra padding.
    rr_assert(fread(&(item->header.kind), sizeof(item->header.kind), 1, rr_nondet_log->fp) == 1);
    rr_assert(fread(&(item->header.callsite_loc), sizeof(item->header.callsite_loc), 1, rr_nondet_log->fp) == 1);

    //mz let's do some counting
    rr_number_of_log_entries[item->header.kind]++;
    //mz add the header - present for all entries
    rr_size_of_log_entries[item->header.kind] += sizeof(RR_prog_point) + sizeof(item->header.kind) + sizeof(item->header.callsite_loc);

    //mz read the rest of the item
    switch (item->header.kind) {
        case RR_INPUT_1:
            rr_assert(fread(&(item->variant.input_1), sizeof(item->variant.input_1), 1, rr_nondet_log->fp) == 1);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.input_1);
            break;
        case RR_INPUT_2:
            rr_assert(fread(&(item->variant.input_2), sizeof(item->variant.input_2), 1, rr_nondet_log->fp) == 1);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.input_2);
            break;
        case RR_INPUT_4:
            rr_assert(fread(&(item->variant.input_4), sizeof(item->variant.input_4), 1, rr_nondet_log->fp) == 1);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.input_4);
            break;
        case RR_INPUT_8:
            rr_assert(fread(&(item->variant.input_8), sizeof(item->variant.input_8), 1, rr_nondet_log->fp) == 1);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.input_8);
            break;
        case RR_INTERRUPT_REQUEST:
            rr_assert(fread(&(item->variant.interrupt_request), sizeof(item->variant.interrupt_request), 1, rr_nondet_log->fp) == 1);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.interrupt_request);
            break;
        case RR_EXIT_REQUEST:
            rr_assert(fread(&(item->variant.exit_request), sizeof(item->variant.exit_request), 1, rr_nondet_log->fp) == 1);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.exit_request);
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item->variant.call_args;
                //mz read kind first!
                rr_assert(fread(&(args->kind), sizeof(args->kind), 1, rr_nondet_log->fp) == 1);
                rr_size_of_log_entries[item->header.kind] += sizeof(args->kind);
                switch(args->kind) {
                    case RR_CALL_CPU_MEM_RW:
                        rr_assert(fread(&(args->variant.cpu_mem_rw_args), sizeof(args->variant.cpu_mem_rw_args), 1, rr_nondet_log->fp) == 1);
                        rr_size_of_log_entries[item->header.kind] += sizeof(args->variant.cpu_mem_rw_args);
                        //mz buffer length in args->variant.cpu_mem_rw_args.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.cpu_mem_rw_args.buf = g_malloc(args->variant.cpu_mem_rw_args.len);
                        //mz read the buffer
                        rr_assert(fread(args->variant.cpu_mem_rw_args.buf, 1, args->variant.cpu_mem_rw_args.len, rr_nondet_log->fp) > 0);
                        rr_size_of_log_entries[item->header.kind] += args->variant.cpu_mem_rw_args.len;
                        break;
                    case RR_CALL_CPU_MEM_UNMAP:
                        rr_assert(fread(&(args->variant.cpu_mem_unmap), sizeof(args->variant.cpu_mem_unmap), 1, rr_nondet_log->fp) == 1);
                        rr_size_of_log_entries[item->header.kind] += sizeof(args->variant.cpu_mem_unmap);
                        args->variant.cpu_mem_unmap.buf = g_malloc(args->variant.cpu_mem_unmap.len);
                        rr_assert(fread(args->variant.cpu_mem_unmap.buf, 1, args->variant.cpu_mem_unmap.len, rr_nondet_log->fp) > 0);
                        rr_size_of_log_entries[item->header.kind] += args->variant.cpu_mem_unmap.len;
                        break;

                    case RR_CALL_CPU_REG_MEM_REGION:
                        rr_assert(fread(&(args->variant.cpu_mem_reg_region_args), 
                              sizeof(args->variant.cpu_mem_reg_region_args), 1, rr_nondet_log->fp) == 1);
                        rr_size_of_log_entries[item->header.kind] += sizeof(args->variant.cpu_mem_reg_region_args);
                        break;
		     
		    case RR_CALL_HD_TRANSFER:
		        rr_assert(fread(&(args->variant.hd_transfer_args),
			      sizeof(args->variant.hd_transfer_args), 1, rr_nondet_log->fp) == 1);
			rr_size_of_log_entries[item->header.kind] += sizeof(args->variant.hd_transfer_args);
			break;
		    
                    case RR_CALL_NET_TRANSFER:
		        rr_assert(fread(&(args->variant.net_transfer_args),
			      sizeof(args->variant.net_transfer_args), 1, rr_nondet_log->fp) == 1);
			rr_size_of_log_entries[item->header.kind] += sizeof(args->variant.net_transfer_args);
			break;
		    
		    case RR_CALL_HANDLE_PACKET:
  		        rr_assert(fread(&(args->variant.handle_packet_args), 
					sizeof(args->variant.handle_packet_args), 1, rr_nondet_log->fp) == 1);
		        rr_size_of_log_entries[item->header.kind] += sizeof(args->variant.handle_packet_args);
			//mz XXX HACK
			args->old_buf_addr = (uint64_t) args->variant.handle_packet_args.buf;
			//mz buffer length in args->variant.cpu_mem_rw_args.len 
			//mz always allocate a new one. we free it when the item is added to the recycle list
			args->variant.handle_packet_args.buf = 
			  g_malloc(args->variant.handle_packet_args.size);
			//mz read the buffer 
			assert (fread(args->variant.handle_packet_args.buf, 
				      args->variant.handle_packet_args.size, 1,
                                      rr_nondet_log->fp) == 1 /*> 0*/);
			rr_size_of_log_entries[item->header.kind] += args->variant.handle_packet_args.size;
			break;

                    default:
                        //mz unimplemented
                        rr_assert(0);
                }
            }
            break;
        case RR_LAST:
        case RR_DEBUG:
            //mz nothing to read
            break;
        default:
            //mz unimplemented
            rr_assert(0);
    }
    rr_nondet_log->item_number++;

    return item;
}


//mz fill the queue of log entries from the file
static void rr_fill_queue(void) {
    RR_log_entry *log_entry = NULL;
    unsigned long long num_entries = 0;

    //mz first, some sanity checks.  The queue should be empty when this is called.
    rr_assert(rr_queue_head == NULL && rr_queue_tail == NULL);

    while ( ! rr_log_is_empty()) {
        log_entry = rr_read_item();

        //mz add it to the queue
        if (rr_queue_head == NULL) {
            rr_queue_head = rr_queue_tail = log_entry;
        }
        else {
            rr_queue_tail->next = log_entry;
            rr_queue_tail = rr_queue_tail->next;
        }
        num_entries++;

        if (log_entry->header.kind == RR_LAST) {
            // It's not really an interrupt, but needs to be set here so
            // that we can execute any remaining code.
            rr_num_instr_before_next_interrupt = log_entry->header.prog_point.guest_instr_count - rr_prog_point.guest_instr_count;
        }
        else if ((log_entry->header.kind == RR_SKIPPED_CALL && log_entry->header.callsite_loc == RR_CALLSITE_MAIN_LOOP_WAIT) ||
                 log_entry->header.kind == RR_INTERRUPT_REQUEST) {
#if RR_REPORT_PROGRESS
            static uint64_t num = 1;
            if ((rr_prog_point.guest_instr_count / (double)rr_nondet_log->last_prog_point.guest_instr_count) * 100 >= num) {
              replay_progress();
              num += 1;
            }
#endif /* RR_REPORT_PROGRESS */
            rr_num_instr_before_next_interrupt = log_entry->header.prog_point.guest_instr_count - rr_prog_point.guest_instr_count;
            break;
        }
    }
    //mz let's gather some stats
    if (num_entries > rr_max_num_queue_entries) {
        rr_max_num_queue_entries = num_entries;
    }
}

//mz return next log entry from the queue
static inline RR_log_entry *get_next_entry(RR_log_entry_kind kind, RR_callsite_id call_site, bool check_callsite) 
{
    RR_log_entry *current;
    //mz make sure queue is not empty, and that we have the right element next
    if (rr_queue_head == NULL) {
        printf("Queue is empty, will return NULL\n");
        return NULL;
    }

    if (kind != RR_INTERRUPT_REQUEST && kind != RR_SKIPPED_CALL) {
        while (rr_queue_head && rr_queue_head->header.kind == RR_DEBUG) {
            //printf("Removing RR_DEBUG because we are looking for %s\n", log_entry_kind_str[kind]);
            current = rr_queue_head;
            rr_queue_head = rr_queue_head->next;
            current->next = NULL;
            if (current == rr_queue_tail) {
                rr_queue_tail = NULL;
            }
        }
    }

    if (rr_queue_head->header.kind != kind) {
        return NULL;
    }

    if (check_callsite && rr_queue_head->header.callsite_loc != call_site) {
        return NULL;
    }

    // XXX FIXME this is a temporary hack to get around the fact that we
    // cannot currently do a tb_flush and a savevm in the same instant.
    if (rr_queue_head->header.prog_point.pc == 0 &&
        rr_queue_head->header.prog_point.secondary == 0 &&
        rr_queue_head->header.prog_point.guest_instr_count == 0) {
        // We'll process this one beacuse it's the start of the log
    }
    //mz rr_prog_point_compare will fail if we're ahead of the log
    else if (rr_prog_point_compare(rr_prog_point, rr_queue_head->header.prog_point, kind) != 0) {
        return NULL;
    }
    //mz remove log entry from queue and return it.
    current = rr_queue_head;
    rr_queue_head = rr_queue_head->next;
    current->next = NULL;
    if (current == rr_queue_tail) {
        rr_queue_tail = NULL;
    }
    return current;
}

void rr_replay_debug(RR_callsite_id call_site) {
    RR_log_entry *current_item;

    if (rr_queue_head == NULL) {
        return;
    }

    if (rr_queue_head->header.kind != RR_DEBUG) {
        return;
    }

    RR_prog_point log_point = rr_queue_head->header.prog_point;

    if (log_point.guest_instr_count > rr_prog_point.guest_instr_count) {
        // This is normal -- in replay we may hit the checkpoint more often
        // than in record due to TB chaining being off
        return;
    }
    else if (log_point.guest_instr_count == rr_prog_point.guest_instr_count) {
        // We think we're in the right place now, so let's do more stringent checks
        if (log_point.secondary != rr_prog_point.secondary || log_point.pc != rr_prog_point.pc)
            rr_signal_disagreement(rr_prog_point, log_point);
        
        // We passed all these, so consume the log entry
        current_item = rr_queue_head;
        rr_queue_head = rr_queue_head->next;
        current_item->next = NULL;
        if (current_item == rr_queue_tail) {
            rr_queue_tail = NULL;
        }

        add_to_recycle_list(current_item);
        printf("RR_DEBUG check passed: ");
        rr_spit_prog_point(rr_prog_point);
    }
    else { // log_point.guest_instr_count > rr_prog_point.guest_instr_count
        // This shouldn't happen. We're ahead of the log.
        //rr_signal_disagreement(rr_prog_point, log_point);
        current_item = rr_queue_head;
        rr_queue_head = rr_queue_head->next;
        current_item->next = NULL;
        if (current_item == rr_queue_tail) {
            rr_queue_tail = NULL;
        }

        add_to_recycle_list(current_item);

        //abort();
    }
}

//mz replay 1-byte input to the CPU
void rr_replay_input_1(RR_callsite_id call_site, uint8_t *data) {
    RR_log_entry *current_item = get_next_entry(RR_INPUT_1, call_site, false);
    if (current_item == NULL) {
        //mz we're trying to replay too early or we have the wrong kind of rr_nondet_log
        //entry.  this is cause for failure
        rr_assert(0);
    }
    //mz now we have our item and it is appropriate for replay here.
    //mz final sanity checks
    rr_assert(current_item->header.callsite_loc == call_site);
    *data = current_item->variant.input_1;
    //mz we've used the item - recycle it.
    add_to_recycle_list(current_item);
}

//mz replay 2-byte input to the CPU
void rr_replay_input_2( RR_callsite_id call_site, uint16_t *data) {
    RR_log_entry *current_item = get_next_entry(RR_INPUT_2, call_site, false);
    if (current_item == NULL) {
        //mz we're trying to replay too early or we have the wrong kind of rr_nondet_log
        //entry.  this is cause for failure
        rr_assert(0);
    }
    //mz now we have our item and it is appropriate for replay here.
    //mz final sanity checks
    rr_assert(current_item->header.callsite_loc == call_site);
    *data = current_item->variant.input_2;
    //mz we've used the item - recycle it.
    add_to_recycle_list(current_item);
}


//mz replay 4-byte input to the CPU
void rr_replay_input_4(RR_callsite_id call_site, uint32_t *data) {
    RR_log_entry *current_item = get_next_entry(RR_INPUT_4, call_site, false);

    if (current_item == NULL) {
        //mz we're trying to replay too early or we have the wrong kind of rr_nondet_log
        //entry.  this is cause for failure
        rr_assert(0);
    }

    //mz now we have our item and it is appropriate for replay here.
    //mz final sanity checks
    rr_assert(current_item->header.callsite_loc == call_site);
    *data = current_item->variant.input_4;
    //mz we've used the item - recycle it.
    add_to_recycle_list(current_item);
}


//mz replay 8-byte input to the CPU
void rr_replay_input_8(RR_callsite_id call_site, uint64_t *data) {
    RR_log_entry *current_item = get_next_entry(RR_INPUT_8, call_site, false);
    if (current_item == NULL) {
        //mz we're trying to replay too early or we have the wrong kind of rr_nondet_log
        //entry.  this is cause for failure
        rr_assert(0);
    }
    //mz now we have our item and it is appropriate for replay here.
    //mz final sanity checks
    rr_assert(current_item->header.callsite_loc == call_site);
    *data = current_item->variant.input_8;
    //mz we've used the item - recycle it.
    add_to_recycle_list(current_item);
}

//mz replay interrupt_request value.  if there's nothing in the log, the value
//mz was 0 during record.
void rr_replay_interrupt_request(RR_callsite_id call_site, uint32_t *interrupt_request) {
    RR_log_entry *current_item = get_next_entry(RR_INTERRUPT_REQUEST, call_site, true);
    if (current_item == NULL) {
        //mz we're trying to replay too early or we have the wrong kind of rr_nondet_log
        //entry.  this is NOT cause for failure as we do not record
        //interrupt_request values of 0 in the log (too many of them).
        *interrupt_request = 0;
    }
    else {
        *interrupt_request = current_item->variant.interrupt_request;
        //mz we've used the item
        add_to_recycle_list(current_item);
        //mz before we can return, we need to fill the queue with information
        //up to the next interrupt value!
        rr_fill_queue();
    }
}

void rr_replay_exit_request(RR_callsite_id call_site, uint32_t *exit_request) {
    RR_log_entry *current_item = get_next_entry(RR_EXIT_REQUEST, call_site, false);
    if (current_item == NULL) {
        *exit_request = 0;
    }
    else {
        //mz final sanity checks
        if(current_item->header.callsite_loc != call_site) {
            printf("Callsite match failed; %s (log) != %s (replay)!\n", get_callsite_string(current_item->header.callsite_loc), get_callsite_string(call_site));
            rr_assert(current_item->header.callsite_loc == call_site);
        }
        *exit_request = current_item->variant.exit_request;
        //mz we've used the item
        add_to_recycle_list(current_item);
        //mz before we can return, we need to fill the queue with information
        //up to the next exit_request value!
        //rr_fill_queue();
    }
}

//bdg Externs for replaying skipped calls
// FIXME: We want the real prototypes here at some point (with correct target address sizes)
//        I guess that will require figuring out how to rebuild this for each target?
/*
extern void cpu_physical_memory_rw(uint32_t addr, uint8_t *buf, int len, int is_write);
extern void cpu_register_physical_memory_log(uint32_t start_addr, uint32_t size, uint32_t phys_offset, uint32_t region_offset, bool log_dirty);
extern void *cpu_physical_memory_map(uint32_t addr, uint32_t *plen, int is_write);
extern void cpu_physical_memory_unmap(void *buffer, uint32_t len, int is_write, uint32_t access_len); 
*/

//mz this function consumes 2 types of entries:  
//RR_SKIPPED_CALL_CPU_MEM_RW and RR_SKIPPED_CALL_CPU_REG_MEM_REGION 
//XXX call_site parameter no longer used...
//bdg 07.2012: Adding RR_SKIPPED_CALL_CPU_MEM_UNMAP
void rr_replay_skipped_calls_internal(RR_callsite_id call_site) {
#ifdef CONFIG_SOFTMMU
    uint8_t replay_done = 0;
    do {
        RR_log_entry *current_item = get_next_entry(RR_SKIPPED_CALL, call_site, false);
        if (current_item == NULL) {
            //mz queue is empty or we've replayed all we can for this prog point
            replay_done = 1;
        }
        else {
            RR_skipped_call_args *args = &current_item->variant.call_args;
            switch (args->kind) {
                case RR_CALL_CPU_MEM_RW:
                    {
                        //mz XXX can we get a full prototype here?
                        cpu_physical_memory_rw(
                                args->variant.cpu_mem_rw_args.addr,
                                args->variant.cpu_mem_rw_args.buf,
                                args->variant.cpu_mem_rw_args.len,
                                /*is_write=*/1
                                );
                    }
                    break;
                case RR_CALL_CPU_REG_MEM_REGION:
                    {
                          cpu_register_physical_memory_log(
						       args->variant.cpu_mem_reg_region_args.start_addr,
						       args->variant.cpu_mem_reg_region_args.size,
						       args->variant.cpu_mem_reg_region_args.phys_offset,
						       0, false
						       );
                    }
                    break;
                case RR_CALL_CPU_MEM_UNMAP:
                    {
                        void *host_buf;
                        target_phys_addr_t plen = args->variant.cpu_mem_unmap.len;
                        host_buf = cpu_physical_memory_map(
                                args->variant.cpu_mem_unmap.addr,
                                &plen,
                                /*is_write=*/1
                                );
                        memcpy(host_buf, args->variant.cpu_mem_unmap.buf, args->variant.cpu_mem_unmap.len);
                        cpu_physical_memory_unmap(
                                host_buf,
                                plen,
                                /*is_write=*/1,
                                args->variant.cpu_mem_unmap.len
                                );
                    }
                    break;
	        case RR_CALL_HD_TRANSFER:
		  {
		    // run all callbacks registered for hd transfer
		    RR_hd_transfer_args *hdt = &(args->variant.hd_transfer_args);
		    panda_cb_list *plist;
		    for (plist = panda_cbs[PANDA_CB_REPLAY_HD_TRANSFER]; plist != NULL; plist = plist->next) {
		      plist->entry.replay_hd_transfer
			(cpu_single_env, 
			 hdt->type,
			 hdt->src_addr,
			 hdt->dest_addr,
			 hdt->num_bytes);
		    }
		  }
		  break;

	        case RR_CALL_HANDLE_PACKET:
		  {
		    // run all callbacks registered for packet handling
		    RR_handle_packet_args *hp = &(args->variant.handle_packet_args);
		    panda_cb_list *plist;
		    for (plist = panda_cbs[PANDA_CB_REPLAY_HANDLE_PACKET]; plist != NULL; plist = plist->next) {
		      plist->entry.replay_handle_packet
			(cpu_single_env, 
			 hp->buf,
			 hp->size, 
			 hp->direction,
                         args->old_buf_addr);
		    }
		
	          }
	          break;

                case RR_CALL_NET_TRANSFER:
                  {
                    // run all callbacks registered for transfers within network
                    // card (E1000)
                    RR_net_transfer_args *nta =
                        &(args->variant.net_transfer_args);
                    panda_cb_list *plist;
                    for (plist = panda_cbs[PANDA_CB_REPLAY_NET_TRANSFER];
                            plist != NULL; plist = plist->next) {
                      plist->entry.replay_net_transfer
                        (cpu_single_env, 
                         nta->type,
                         nta->src_addr,
                         nta->dest_addr,
                         nta->num_bytes);
                    }
                  }
                  break;

	    default:
                    //mz sanity check
                    rr_assert(0);
            }
            add_to_recycle_list(current_item);
            //bdg Now that we are also breaking on main loop skipped calls we have to 
            //bdg refill the queue here
            // RW ...but only if the queue is actually empty at this point
            if ((call_site == RR_CALLSITE_MAIN_LOOP_WAIT)
                    && (rr_queue_head == NULL)){ // RW queue is empty
                rr_fill_queue();
            }
        }
    } while ( ! replay_done);
#endif
}

/******************************************************************************************/
/* LOG MANAGEMENT */
/******************************************************************************************/

extern char *qemu_strdup(const char *str);
  
// create record log
void rr_create_record_log (const char *filename) {
  // create log
  rr_nondet_log = g_new0(RR_log, 1);
  rr_assert (rr_nondet_log != NULL);

  rr_nondet_log->type = RECORD;
  rr_nondet_log->name = g_strdup(filename);
  rr_nondet_log->fp = fopen(rr_nondet_log->name, "w");
  rr_assert(rr_nondet_log->fp != NULL);

  if (rr_debug_whisper()) {
    fprintf (logfile, "opened %s for write.\n", rr_nondet_log->name);
  }
  //mz It would be very handy to know how "far" we are in a particular replay
  //execution.  To do this, let's store a header in the log (we'll fill it in
  //again when we close the log) that includes the maximum instruction
  //count as a monotonicly increasing measure of progress.
  //This way, when we print progress, we can use something better than size of log consumed
  //(as that can jump //sporadically).
  fwrite(&(rr_nondet_log->last_prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp);
}


// create replay log
void rr_create_replay_log (const char *filename) {
  struct stat statbuf = {0};
  // create log
  rr_nondet_log = g_new0(RR_log,1);
  rr_assert (rr_nondet_log != NULL);

  rr_nondet_log->type = REPLAY;
  rr_nondet_log->name = g_strdup(filename);
  rr_nondet_log->fp = fopen(rr_nondet_log->name, "r");
  rr_assert(rr_nondet_log->fp != NULL);

  //mz fill in log size
  stat(rr_nondet_log->name, &statbuf);
  rr_nondet_log->size = statbuf.st_size;
  if (rr_debug_whisper()) {
    fprintf (logfile, "opened %s for read.  len=%llu bytes.\n",
	     rr_nondet_log->name, rr_nondet_log->size);
  }
  //mz read the last program point from the log header.
  rr_assert(fread(&(rr_nondet_log->last_prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp) == 1);
}


// close file and free associated memory
void rr_destroy_log(void) {
  if (rr_nondet_log->fp) {
    //mz if in record, update the header with the last written prog point.
    if (rr_nondet_log->type == RECORD) {
        rewind(rr_nondet_log->fp);
        fwrite(&(rr_nondet_log->last_prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp);
    }
    fclose(rr_nondet_log->fp);
    rr_nondet_log->fp = NULL;
  }
  g_free(rr_nondet_log->name);
  g_free(rr_nondet_log);
  rr_nondet_log = NULL;
}

//mz display a measure of replay progress (using instruction counts and log size)
void replay_progress(void) {
  if (rr_nondet_log) {
    if (rr_log_is_empty()) {
      printf ("%s:  log is empty.\n", rr_nondet_log->name);
    }
    else {
      printf ("%s:  %ld of %llu (%.2f%%) bytes, %llu of %llu (%.2f%%) instructions processed.\n", 
              rr_nondet_log->name,
              ftell(rr_nondet_log->fp),
              rr_nondet_log->size,
              (ftell(rr_nondet_log->fp) * 100.0) / rr_nondet_log->size,
              (unsigned long long)rr_queue_head->header.prog_point.guest_instr_count,
              (unsigned long long)rr_nondet_log->last_prog_point.guest_instr_count,
              ((rr_queue_head->header.prog_point.guest_instr_count * 100.0) / 
                    rr_nondet_log->last_prog_point.guest_instr_count)
      );
    }
  }
}

uint64_t replay_get_guest_instr_count(void) {
  if (rr_nondet_log) {
    return rr_queue_head->header.prog_point.guest_instr_count;
  }
  else {
    return 0;
  }
}    

uint64_t replay_get_total_num_instructions(void) {
  if (rr_nondet_log) {
    return rr_nondet_log->last_prog_point.guest_instr_count;
  }
  else {
    return 0;
  }
}

/******************************************************************************************/
/* MONITOR CALLBACKS (top-level) */
/******************************************************************************************/
//mz from vl.c

// rr_name is the current rec/replay name. 
// here we compute the snapshot name to use for rec/replay 
static inline void rr_get_snapshot_file_name (char *rr_name, char *rr_path, char *snapshot_name, size_t snapshot_name_len) {
  rr_assert (rr_name != NULL);
  snprintf(snapshot_name, snapshot_name_len, "%s/%s-rr-snp", rr_path, rr_name);
}


static inline void rr_get_nondet_log_file_name(char *rr_name, char *rr_path, char *file_name, size_t file_name_len) {
  rr_assert (rr_name != NULL && rr_path != NULL);
  snprintf(file_name, file_name_len, "%s/%s-rr-nondet.log", rr_path, rr_name);
}


void rr_reset_state(void *cpu_state) {
    //mz reset program point
    memset(&rr_prog_point, 0, sizeof(RR_prog_point));
    // set flag to signal that we'll be needing the tb flushed. 
    rr_flush_tb_on();
    // clear flags
    rr_record_in_progress = 0;
    rr_skipped_callsite_location = 0;
    rr_clear_rr_guest_instr_count(cpu_state);
}


//////////////////////////////////////////////////////////////
//
// QMP commands

#ifdef CONFIG_SOFTMMU

#include "error.h"
void qmp_begin_record(const char *file_name, Error **errp) {
  rr_record_requested = 1;
  rr_requested_name = g_strdup(file_name);
}

void qmp_begin_record_from(const char *snapshot, const char *file_name, Error **errp) {
  rr_record_requested = 2;
  rr_snapshot_name = g_strdup(snapshot);
  rr_requested_name = g_strdup(file_name);
}

void qmp_begin_replay(const char *file_name, Error **errp) {
  rr_replay_requested = 1;
  rr_requested_name = g_strdup(file_name);
}


void qmp_end_record(Error **errp) {
  qmp_stop(NULL);
  rr_end_record_requested = 1;
}

void qmp_end_replay(Error **errp) {
  qmp_stop(NULL);
  rr_end_replay_requested = 1;
}

#include "qemu-common.h"  // Monitor def
#include "qdict.h"        // QDict def

// HMP commands (the "monitor")
void hmp_begin_record(Monitor *mon, const QDict *qdict)
{
  Error *err;
  const char *file_name = qdict_get_try_str(qdict, "file_name");
  qmp_begin_record(file_name, &err);
}

// HMP commands (the "monitor")
void hmp_begin_record_from(Monitor *mon, const QDict *qdict)
{
  Error *err;
  const char *snapshot =  qdict_get_try_str(qdict, "snapshot");
  const char *file_name = qdict_get_try_str(qdict, "file_name");
  qmp_begin_record_from(snapshot, file_name, &err);
}

void hmp_begin_replay(Monitor *mon, const QDict *qdict)
{
  Error *err;
  const char *file_name = qdict_get_try_str(qdict, "file_name");
  qmp_begin_replay(file_name, &err);
}

void hmp_end_record(Monitor *mon, const QDict *qdict)
{
  Error *err;
  qmp_end_record(&err);
}

void hmp_end_replay(Monitor *mon, const QDict *qdict)
{
  Error *err;
  qmp_end_replay(&err);
}

#endif // CONFIG_SOFTMMU

static time_t rr_start_time;

//mz file_name_full should be full path to desired record/replay log file
int rr_do_begin_record(const char *file_name_full, void *cpu_state) {
#ifdef CONFIG_SOFTMMU 
 char name_buf[1024];
  // decompose file_name_base into path & file. 
  char *rr_path_base = g_strdup(file_name_full);
  char *rr_name_base = g_strdup(file_name_full);
  char *rr_path = dirname(rr_path_base);
  char *rr_name = basename(rr_name_base);
  int snapshot_ret = -1;
  if (rr_debug_whisper()) {
    fprintf (logfile,"Begin vm record for file_name_full = %s\n", file_name_full);    
    fprintf (logfile,"path = [%s]  file_name_base = [%s]\n", rr_path, rr_name);
  }
  // first take a snapshot or load snapshot

  if (rr_record_requested == 2) {
    printf ("loading snapshot:\t%s\n", rr_snapshot_name);
    snapshot_ret = load_vmstate(rr_snapshot_name);
    g_free(rr_snapshot_name); rr_snapshot_name = NULL;
  }
  if (rr_record_requested  == 1 || rr_record_requested == 2) {
    rr_get_snapshot_file_name(rr_name, rr_path, name_buf, sizeof(name_buf));
    printf ("writing snapshot:\t%s\n", name_buf);
    snapshot_ret = do_savevm_rr(get_monitor(), name_buf);
    log_all_cpu_states();
  }

  // save the time so we can report how long record takes
  time(&rr_start_time);

  // second, open non-deterministic input log for write. 
  rr_get_nondet_log_file_name(rr_name, rr_path, name_buf, sizeof(name_buf));
  printf ("opening nondet log for write :\t%s\n", name_buf);
  rr_create_record_log(name_buf);
  // reset record/replay counters and flags
  rr_reset_state(cpu_state);
  g_free(rr_path_base);
  g_free(rr_name_base);
  // set global to turn on recording
  rr_mode = RR_RECORD;
  //cpu_set_log(CPU_LOG_TB_IN_ASM|CPU_LOG_RR);
  return snapshot_ret;
#endif
}


void rr_do_end_record(void) {
#ifdef CONFIG_SOFTMMU
  //mz put in end-of-log marker
  rr_record_end_of_log();

  char *rr_path_base = g_strdup(rr_nondet_log->name);
  char *rr_name_base = g_strdup(rr_nondet_log->name);
  //char *rr_path = dirname(rr_path_base);
  char *rr_name = basename(rr_name_base);
  
  if (rr_debug_whisper()) {
    fprintf (logfile,"End vm record for name = %s\n", rr_name);
    printf ("End vm record for name = %s\n", rr_name);
  }

  time_t rr_end_time;
  time(&rr_end_time);
  printf("Time taken was: %ld seconds.\n", rr_end_time - rr_start_time);
  
  log_all_cpu_states();

  rr_destroy_log();

  g_free(rr_path_base);
  g_free(rr_name_base);

  // turn off logging
  rr_mode = RR_OFF;
#endif
}

// file_name_full should be full path to the record/replay log
int rr_do_begin_replay(const char *file_name_full, void *cpu_state) {
#ifdef CONFIG_SOFTMMU
  char name_buf[1024];
  // decompose file_name_base into path & file. 
  char *rr_path = g_strdup(file_name_full);
  char *rr_name = g_strdup(file_name_full);
  int snapshot_ret;
  rr_path = dirname(rr_path);
  rr_name = basename(rr_name);
  if (rr_debug_whisper()) {
    fprintf (logfile,"Begin vm replay for file_name_full = %s\n", file_name_full);    
    fprintf (logfile,"path = [%s]  file_name_base = [%s]\n", rr_path, rr_name);
  }
  // first retrieve snapshot
  rr_get_snapshot_file_name(rr_name, rr_path, name_buf, sizeof(name_buf));
  if (rr_debug_whisper()) {
    fprintf (logfile,"reading snapshot:\t%s\n", name_buf);
  }
  printf ("loading snapshot\n");
  //  vm_stop(0) RUN_STATE_RESTORE_VM);
    panda_cb_list *plist;
    for(plist = panda_cbs[PANDA_CB_BEFORE_REPLAY_LOADVM]; plist != NULL;
            plist = plist->next) {
        plist->entry.before_loadvm();
    }
  snapshot_ret = load_vmstate_rr(name_buf);
  // If the loadvm failed, fail
  /*if (0 != snapshot_ret){
      // TODO: free rr_path and rr_name
      printf("Failed to load snapshot for replay: %d\n", snapshot_ret);
      return snapshot_ret;
  }*/
  printf ("... done.\n");
  log_all_cpu_states();

  // save the time so we can report how long replay takes
  time(&rr_start_time);

  // second, open non-deterministic input log for read.  
  rr_get_nondet_log_file_name(rr_name, rr_path, name_buf, sizeof(name_buf));
  printf ("opening nondet log for read :\t%s\n", name_buf);
  rr_create_replay_log(name_buf);
  // reset record/replay counters and flags
  rr_reset_state(cpu_state);
  // set global to turn on replay
  rr_mode = RR_REPLAY;

  //cpu_set_log(CPU_LOG_TB_IN_ASM|CPU_LOG_RR);

  //mz fill the queue!
  rr_fill_queue();
  return 0; //snapshot_ret;
#endif
}


//mz XXX what about early replay termination? Can we save state and resume later?
void rr_do_end_replay(int is_error) {
#ifdef CONFIG_SOFTMMU
    // log is empty - we're done
    // dump cpu state at exit as a sanity check.   
    int i;
    replay_progress();
    if (is_error) {
        printf ("ERROR: replay failed!\n");
    }
    else {
        printf ("Replay completed successfully.\n");
    }

    time_t rr_end_time;
    time(&rr_end_time);
    printf("Time taken was: %ld seconds.\n", rr_end_time - rr_start_time);
    
    printf ("Stats:\n");
    for (i = 0; i < RR_LAST; i++) {
        printf("%s number = %llu, size = %llu bytes\n", get_log_entry_kind_string(i), 
                rr_number_of_log_entries[i], rr_size_of_log_entries[i]);
        rr_number_of_log_entries[i] = 0;
        rr_size_of_log_entries[i] = 0;
    }
    printf("max_queue_len = %llu\n", rr_max_num_queue_entries);
    rr_max_num_queue_entries = 0;
    // cleanup the recycled list for log entries
    {
        unsigned long num_items = 0;
        RR_log_entry *entry;
        while (recycle_list) {
            entry = recycle_list;
            recycle_list = entry->next;
            //mz entry params already freed
            g_free(entry);
            num_items++;
        }
        printf("%lu items on recycle list, %lu bytes total\n", num_items, num_items * sizeof(RR_log_entry));
    }
    //mz some more sanity checks - the queue should contain only the RR_LAST element
    if (rr_queue_head == rr_queue_tail && rr_queue_head != NULL && rr_queue_head->header.kind == RR_LAST) {
        printf("Replay completed successfully.");
    }
    else {
        if (is_error) {
            printf("ERROR: replay failed!\n");
        }
        else {
            printf("Replay terminated at user request.\n");
        }
    }
    // cleanup the queue
    {
        RR_log_entry *entry;
        while (rr_queue_head) {
            entry = rr_queue_head;
            rr_queue_head = entry->next;
            entry->next = NULL;
            free_entry_params(entry);
            g_free(entry);
        }
    }
    rr_queue_head = NULL;
    rr_queue_tail = NULL;
    //mz print CPU state at end of replay
    log_all_cpu_states();
    // close logs
    rr_destroy_log();
    // turn off replay
    rr_mode = RR_OFF;

    //mz XXX something more graceful?
    if (is_error) {
        abort();
    }
    else {
#ifdef RR_QUIT_AFTER_REPLAY
        qemu_system_shutdown_request();
#endif
    }
#endif // CONFIG_SOFTMMU
}

/**************************************************************************/
