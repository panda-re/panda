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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libgen.h>

#include "rr_log.h"


/******************************************************************************************/
/* GLOBALS */
/******************************************************************************************/
//mz record/replay mode
volatile RR_mode rr_mode = RR_OFF;

//mz program execution state
RR_prog_point rr_prog_point = {0, 0, 0};
volatile uint64_t rr_guest_instr_count;
volatile uint64_t rr_num_instr_before_next_interrupt;

//mz 11.06.2009 Flags to manage nested recording
volatile sig_atomic_t rr_record_in_progress = 0;
volatile sig_atomic_t rr_skipped_callsite_location = 0;

// a program-point indexed record/replay log
typedef enum {RECORD, REPLAY} RR_log_type;
typedef struct RR_log_t {
  //mz TODO this field seems redundant given existence of rr_mode
  RR_log_type type;            // record or replay
  RR_prog_point last_prog_point; // to report progress

  char *name;                  // file name
  FILE *fp;                    // file pointer for log
  unsigned long long size;     // for a log being opened for read, this will be the size in bytes

  RR_log_entry current_item;
  RR_bool current_item_valid;
  unsigned long long item_number;
} RR_log;

//mz the log of non-deterministic events
RR_log *rr_nondet_log = NULL;

static inline uint8_t log_is_empty() {
    if ((rr_nondet_log->type == REPLAY) &&
        (rr_nondet_log->size - ftell(rr_nondet_log->fp) == 0)) {
        return 1;
    }
    else {
        return 0;
    }
}


RR_debug_level_type rr_debug_level = RR_DEBUG_WHISPER;

// used as a signal that TB cache needs flushing.
uint8_t rr_please_flush_tb = 0;

//mz Flags set by monitor to indicate requested record/replay action
volatile sig_atomic_t rr_replay_requested = 0;
volatile sig_atomic_t rr_record_requested = 0;
volatile sig_atomic_t rr_end_record_requested = 0;
volatile sig_atomic_t rr_end_replay_requested = 0;
const char * rr_requested_name = NULL;

//
//mz Other useful things
//
//mz QEMU logfile
extern FILE *logfile;
//mz from vl.c
extern void log_all_cpu_states(void);

/******************************************************************************************/
/* UTILITIES */
/******************************************************************************************/

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
void rr_spit_prog_point_fp(FILE *fp, RR_prog_point pp) {
  fprintf(fp, "{guest_instr_count=%llu eip=0x%08x, ecx=0x%08x}\n", 
          (unsigned long long)pp.guest_instr_count,
	  pp.eip,
	  pp.ecx);
}

void rr_debug_log_prog_point(RR_prog_point pp) {
  rr_spit_prog_point_fp(logfile,pp);
}

void rr_spit_prog_point(RR_prog_point pp) {
  rr_spit_prog_point_fp(stdout,pp);
}


void rr_spit_log_entry(RR_log_entry item) {
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
        case RR_SKIPPED_CALL:
            printf("\tRR_SKIPPED_CALL (%s) from %s\n", 
                    get_skipped_call_kind_string(item.variant.call_args.kind),
                    get_callsite_string(item.header.callsite_loc));
            break;
        case RR_LAST:
            printf("\tRR_LAST\n");
    }
}

//mz use in debugger to print a short history of log entries
void rr_print_history() {
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
      if (current.eip != recorded.eip) {
          printf(">>> guest EIPs disagree\n");
      }
      if (current.ecx != recorded.ecx) {
          printf(">>> guest ECXs disagree\n");
      }
}

/******************************************************************************************/
/* RECORD */
/******************************************************************************************/

//mz write the current log item to file
static inline void rr_write_item() {
    RR_log_entry *item = &(rr_nondet_log->current_item);

    //mz save the header
    assert (rr_in_record());
    assert (rr_nondet_log != NULL);
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
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item->variant.call_args;
                //mz write kind first!
                fwrite(&(args->kind), sizeof(args->kind), 1, rr_nondet_log->fp);
                switch (args->kind) {
                    case RR_CALL_CPU_MEM_RW:
                        assert(args->variant.cpu_mem_rw_args.buf != NULL || 
                                args->variant.cpu_mem_rw_args.len == 0);
                        fwrite(&(args->variant.cpu_mem_rw_args), sizeof(args->variant.cpu_mem_rw_args), 1, rr_nondet_log->fp);
                        //mz write the buffer
                        fwrite(args->variant.cpu_mem_rw_args.buf, 1, args->variant.cpu_mem_rw_args.len, rr_nondet_log->fp);
                        break;
                    case RR_CALL_CPU_REG_MEM_REGION:
                        fwrite(&(args->variant.cpu_mem_reg_region_args), 
                               sizeof(args->variant.cpu_mem_reg_region_args), 1, rr_nondet_log->fp);
                        break;
                    default:
                        //mz unimplemented
                        assert(0);
                }
            }
            break;
        case RR_LAST:
            //mz nothing to write
            break;
        default:
            //mz unimplemented
            assert(0);
    }
    rr_nondet_log->item_number++;
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

//mz record call to cpu_physical_memory_rw() that will need to be replayed.
//mz only "write" modifications are recorded
void rr_record_cpu_mem_rw_call(RR_callsite_id call_site,
                                   uint32_t addr, uint8_t *buf, int len, int is_write) {
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

//mz record a call to cpu_register_io_memory() that will need to be replayed.
void rr_record_cpu_reg_io_mem_region(RR_callsite_id call_site,
                                         uint32_t start_addr, unsigned long size, unsigned long phys_offset) {
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

//mz record a marker for end of the log
void rr_record_end_of_log() {
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

//mz FIFO queue of log entries read from the log file
static RR_log_entry *queue_head;
static RR_log_entry *queue_tail;

//mz avoid actually releasing memory
static RR_log_entry *recycle_list = NULL;

static inline void free_entry_params(RR_log_entry *entry) 
{
    //mz cleanup associated resources
    switch (entry->header.kind) {
        case RR_SKIPPED_CALL:
            switch (entry->variant.call_args.kind) {
                case RR_CALL_CPU_MEM_RW:
                    qemu_free(entry->variant.call_args.variant.cpu_mem_rw_args.buf);
                    entry->variant.call_args.variant.cpu_mem_rw_args.buf = NULL;
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
static inline RR_log_entry *alloc_new_entry()
{
    RR_log_entry *new_entry = NULL;
    if (recycle_list != NULL) {
        new_entry = recycle_list;
        recycle_list = recycle_list->next;
        new_entry->next = NULL;
    }
    else {
        new_entry = qemu_malloc(sizeof(RR_log_entry));
    }
    memset(new_entry, 0, sizeof(RR_log_entry));
    return new_entry;
}

//mz fill an entry
RR_log_entry *rr_read_item() {
    RR_log_entry *item = alloc_new_entry();

    //mz read header
    assert (rr_in_replay());
    assert ( ! log_is_empty());
    assert (rr_nondet_log->fp != NULL);

    //mz XXX we assume that the log is not trucated - should probably fix this.
    if (fread(&(item->header.prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp) != 1) {
        //mz an error occurred
        if (feof(rr_nondet_log->fp)) {
            // replay is done - we've reached the end of file
            //mz we should never get here!
            assert(0);
        } 
        else {
            //mz some other kind of error
            //mz XXX something more graceful, perhaps?
            assert(0);
        }
    }
    //mz this is more compact, as it doesn't include extra padding.
    fread(&(item->header.kind), sizeof(item->header.kind), 1, rr_nondet_log->fp);
    fread(&(item->header.callsite_loc), sizeof(item->header.callsite_loc), 1, rr_nondet_log->fp);

    //mz let's do some counting
    rr_number_of_log_entries[item->header.kind]++;
    //mz add the header - present for all entries
    rr_size_of_log_entries[item->header.kind] += sizeof(RR_prog_point) + sizeof(item->header.kind) + sizeof(item->header.callsite_loc);

    //mz read the rest of the item
    switch (item->header.kind) {
        case RR_INPUT_1:
            fread(&(item->variant.input_1), sizeof(item->variant.input_1), 1, rr_nondet_log->fp);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.input_1);
            break;
        case RR_INPUT_2:
            fread(&(item->variant.input_2), sizeof(item->variant.input_2), 1, rr_nondet_log->fp);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.input_2);
            break;
        case RR_INPUT_4:
            fread(&(item->variant.input_4), sizeof(item->variant.input_4), 1, rr_nondet_log->fp);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.input_4);
            break;
        case RR_INPUT_8:
            fread(&(item->variant.input_8), sizeof(item->variant.input_8), 1, rr_nondet_log->fp);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.input_8);
            break;
        case RR_INTERRUPT_REQUEST:
            fread(&(item->variant.interrupt_request), sizeof(item->variant.interrupt_request), 1, rr_nondet_log->fp);
            rr_size_of_log_entries[item->header.kind] += sizeof(item->variant.interrupt_request);
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item->variant.call_args;
                //mz read kind first!
                fread(&(args->kind), sizeof(args->kind), 1, rr_nondet_log->fp);
                rr_size_of_log_entries[item->header.kind] += sizeof(args->kind);
                switch(args->kind) {
                    case RR_CALL_CPU_MEM_RW:
                        fread(&(args->variant.cpu_mem_rw_args), sizeof(args->variant.cpu_mem_rw_args), 1, rr_nondet_log->fp);
                        rr_size_of_log_entries[item->header.kind] += sizeof(args->variant.cpu_mem_rw_args);
                        //mz buffer length in args->variant.cpu_mem_rw_args.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.cpu_mem_rw_args.buf = qemu_malloc(args->variant.cpu_mem_rw_args.len);
                        //mz read the buffer
                        fread(args->variant.cpu_mem_rw_args.buf, 1, args->variant.cpu_mem_rw_args.len, rr_nondet_log->fp);
                        rr_size_of_log_entries[item->header.kind] += args->variant.cpu_mem_rw_args.len;
                        break;
                    case RR_CALL_CPU_REG_MEM_REGION:
                        fread(&(args->variant.cpu_mem_reg_region_args), 
                              sizeof(args->variant.cpu_mem_reg_region_args), 1, rr_nondet_log->fp);
                        rr_size_of_log_entries[item->header.kind] += sizeof(args->variant.cpu_mem_reg_region_args);
                        break;
                    default:
                        //mz unimplemented
                        assert(0);
                }
            }
            break;
        case RR_LAST:
            //mz nothing to read
            break;
        default:
            //mz unimplemented
            assert(0);
    }
    rr_nondet_log->item_number++;

    return item;
}


//mz fill the queue of log entries from the file
static void rr_fill_queue() {
    RR_log_entry *log_entry = NULL;
    unsigned long long num_entries = 0;

    //mz first, some sanity checks.  The queue should be empty when this is called.
    assert(queue_head == NULL && queue_tail == NULL);

    while ( ! log_is_empty()) {
        log_entry = rr_read_item();

        //mz add it to the queue
        if (queue_head == NULL) {
            queue_head = queue_tail = log_entry;
        }
        else {
            queue_tail->next = log_entry;
            queue_tail = queue_tail->next;
        }
        num_entries++;

        if (log_entry->header.kind == RR_LAST) {
            //mz it should be OK to terminate replay here, as in record the
            //last thing in the log before an RR_LAST should have been an
            //INTERRUPT_REQUEST with EXCP_EXIT_DEBUG value to quit the
            //cpu_exec() loop due to end_record command.
            //
            //mz from cpu-exec.c
            extern void rr_quit_cpu_loop();
            rr_end_replay_requested = 1;
            //mz need to get out of cpu loop so that we can process the end_replay request
            //mz this will call cpu_loop_exit(), which longjmps
            rr_quit_cpu_loop();
            /* NOT REACHED */
        }
        else if (log_entry->header.kind == RR_INTERRUPT_REQUEST) {
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
static inline RR_log_entry *get_next_entry(RR_log_entry_kind kind) 
{
    RR_log_entry *current;
    //mz make sure queue is not empty, and that we have the right element next
    if (queue_head == NULL || queue_head->header.kind != kind) {
        return NULL;
    }
    //mz rr_prog_point_compare will fail if we're ahead of the log
    if (rr_prog_point_compare(rr_prog_point, queue_head->header.prog_point) != 0) {
        return NULL;
    }
    //mz remove log entry from queue and return it.
    current = queue_head;
    queue_head = queue_head->next;
    current->next = NULL;
    if (current == queue_tail) {
        queue_tail = NULL;
    }
    return current;
}

//mz replay 1-byte input to the CPU
void rr_replay_input_1(RR_callsite_id call_site, uint8_t *data) {
    RR_log_entry *current_item = get_next_entry(RR_INPUT_1);
    if (current_item == NULL) {
        //mz we're trying to replay too early or we have the wrong kind of rr_nondet_log
        //entry.  this is cause for failure
        assert(0);
    }
    //mz now we have our item and it is appropriate for replay here.
    //mz final sanity checks
    assert(current_item->header.callsite_loc == call_site);
    *data = current_item->variant.input_1;
    //mz we've used the item - recycle it.
    add_to_recycle_list(current_item);
}

//mz replay 2-byte input to the CPU
void rr_replay_input_2( RR_callsite_id call_site, uint16_t *data) {
    RR_log_entry *current_item = get_next_entry(RR_INPUT_2);
    if (current_item == NULL) {
        //mz we're trying to replay too early or we have the wrong kind of rr_nondet_log
        //entry.  this is cause for failure
        assert(0);
    }
    //mz now we have our item and it is appropriate for replay here.
    //mz final sanity checks
    assert(current_item->header.callsite_loc == call_site);
    *data = current_item->variant.input_2;
    //mz we've used the item - recycle it.
    add_to_recycle_list(current_item);
}


//mz replay 4-byte input to the CPU
void rr_replay_input_4(RR_callsite_id call_site, uint32_t *data) {
    RR_log_entry *current_item = get_next_entry(RR_INPUT_4);
    if (current_item == NULL) {
        //mz we're trying to replay too early or we have the wrong kind of rr_nondet_log
        //entry.  this is cause for failure
        assert(0);
    }
    //mz now we have our item and it is appropriate for replay here.
    //mz final sanity checks
    assert(current_item->header.callsite_loc == call_site);
    *data = current_item->variant.input_4;
    //mz we've used the item - recycle it.
    add_to_recycle_list(current_item);
}


//mz replay 8-byte input to the CPU
void rr_replay_input_8(RR_callsite_id call_site, uint64_t *data) {
    RR_log_entry *current_item = get_next_entry(RR_INPUT_8);
    if (current_item == NULL) {
        //mz we're trying to replay too early or we have the wrong kind of rr_nondet_log
        //entry.  this is cause for failure
        assert(0);
    }
    //mz now we have our item and it is appropriate for replay here.
    //mz final sanity checks
    assert(current_item->header.callsite_loc == call_site);
    *data = current_item->variant.input_8;
    //mz we've used the item - recycle it.
    add_to_recycle_list(current_item);
}


//mz replay interrupt_request value.  if there's nothing in the log, the value
//mz was 0 during record.
void rr_replay_interrupt_request(RR_callsite_id call_site, uint32_t *interrupt_request) {
    RR_log_entry *current_item = get_next_entry(RR_INTERRUPT_REQUEST);
    if (current_item == NULL) {
        //mz we're trying to replay too early or we have the wrong kind of rr_nondet_log
        //entry.  this is NOT cause for failure as we do not record
        //interrupt_request values of 0 in the log (too many of them).
        *interrupt_request = 0;
    }
    else {
        //mz final sanity checks
        assert(current_item->header.callsite_loc == call_site);
        *interrupt_request = current_item->variant.interrupt_request;
        //mz we've used the item
        add_to_recycle_list(current_item);
        //mz before we can return, we need to fill the queue with information
        //up to the next interrupt value!
        rr_fill_queue();
    }
}


//mz this function consumes 2 types of entries:  
//RR_SKIPPED_CALL_CPU_MEM_RW and RR_SKIPPED_CALL_CPU_REG_MEM_REGION 
//XXX call_site parameter no longer used...
void rr_replay_skipped_calls_internal(RR_callsite_id call_site) {
    uint8_t replay_done = 0;
    do {
        RR_log_entry *current_item = get_next_entry(RR_SKIPPED_CALL);
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
                        extern void cpu_physical_memory_rw();
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
                        //mz XXX can we get a full prototype here?
                        extern void cpu_register_physical_memory();
                        cpu_register_physical_memory(
                                args->variant.cpu_mem_reg_region_args.start_addr,
                                args->variant.cpu_mem_reg_region_args.size,
                                args->variant.cpu_mem_reg_region_args.phys_offset
                                );
                    }
                    break;
                default:
                    //mz sanity check
                    assert(0);
            }
            add_to_recycle_list(current_item);
        }
    } while ( ! replay_done);
}

/******************************************************************************************/
/* LOG MANAGEMENT */
/******************************************************************************************/

extern char *qemu_strdup(const char *str);
  
// create record log
void rr_create_record_log (const char *filename) {
  // create log
  rr_nondet_log = (RR_log *) qemu_malloc (sizeof (RR_log));
  assert (rr_nondet_log != NULL);
  memset(rr_nondet_log, 0, sizeof(RR_log));

  rr_nondet_log->type = RECORD;
  rr_nondet_log->name = qemu_strdup(filename);
  rr_nondet_log->fp = fopen(rr_nondet_log->name, "w");
  assert(rr_nondet_log->fp != NULL);

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
  rr_nondet_log = (RR_log *) qemu_malloc (sizeof (RR_log));
  assert (rr_nondet_log != NULL);
  memset(rr_nondet_log, 0, sizeof(RR_log));

  rr_nondet_log->type = REPLAY;
  rr_nondet_log->name = qemu_strdup(filename);
  rr_nondet_log->fp = fopen(rr_nondet_log->name, "r");
  assert(rr_nondet_log->fp != NULL);

  //mz fill in log size
  stat(rr_nondet_log->name, &statbuf);
  rr_nondet_log->size = statbuf.st_size;
  if (rr_debug_whisper()) {
    fprintf (logfile, "opened %s for read.  len=%llu bytes.\n",
	     rr_nondet_log->name, rr_nondet_log->size);
  }
  //mz read the last program point from the log header.
  fread(&(rr_nondet_log->last_prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp);
}


// close file and free associated memory
void rr_destroy_log() {
  if (rr_nondet_log->fp) {
    //mz if in record, update the header with the last written prog point.
    if (rr_nondet_log->type == RECORD) {
        rewind(rr_nondet_log->fp);
        fwrite(&(rr_nondet_log->last_prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp);
    }
    fclose(rr_nondet_log->fp);
    rr_nondet_log->fp = NULL;
  }
  qemu_free(rr_nondet_log->name);
  qemu_free(rr_nondet_log);
  rr_nondet_log = NULL;
}

//mz display a measure of replay progress (using instruction counts and log size)
void replay_progress() {
  if (rr_nondet_log) {
    if (log_is_empty()) {
      printf ("%s:  log is empty.\n", rr_nondet_log->name);
    }
    else {
      printf ("%s:  %.2f%% of %llu bytes processed.\n", 
              rr_nondet_log->name,
              (ftell(rr_nondet_log->fp) * 100.0) / rr_nondet_log->size,
              rr_nondet_log->size);
      //mz use head of queue entry
      printf ("%s:  %.2f%% of %llu instructions processed.\n", 
              rr_nondet_log->name,
              ((queue_head->header.prog_point.guest_instr_count * 100.0) / 
                    rr_nondet_log->last_prog_point.guest_instr_count),
              (unsigned long long)rr_nondet_log->last_prog_point.guest_instr_count);
    }
  }
}

/******************************************************************************************/
/* MONITOR CALLBACKS (top-level) */
/******************************************************************************************/
//mz from vl.c
extern void do_savevm(const char *name);
extern void do_loadvm(const char *name);

// rr_name is the current rec/replay name. 
// here we compute the snapshot name to use for rec/replay 
// NB: path not used here.
static inline void rr_get_snapshot_name (char *rr_name, char *snapshot_name, size_t snapshot_name_len) {
  assert (rr_name != NULL);
  snprintf(snapshot_name, snapshot_name_len, "%s-rr-snp", rr_name);
}


static inline void rr_get_nondet_log_file_name(char *rr_name, char *rr_path, char *file_name, size_t file_name_len) {
  assert (rr_name != NULL && rr_path != NULL);
  snprintf(file_name, file_name_len, "%s/%s-rr-nondet.log", rr_path, rr_name);
}


static inline void rr_reset_state() {
    //mz reset program point
    memset(&rr_prog_point, 0, sizeof(RR_prog_point));
    // set flag to signal that we'll be needing the tb flushed. 
    rr_flush_tb_on();
    // clear flags
    rr_record_in_progress = 0;
    rr_skipped_callsite_location = 0;
    rr_guest_instr_count = 0;
}


//////////////////////////////////////////////////////////////
//
// QMP commands

#include "error.h"
void qmp_begin_record(const char *file_name, Error **errp) {
  rr_record_requested = 1;
  rr_requested_name = qemu_strdup(file_name);
}

void qmp_begin_replay(const char *file_name, Error **errp) {
  rr_replay_requested = 1;
  rr_requested_name = qemu_strdup(file_name);
}

void qmp_end_record(Error **errp) {
  do_stop();
  rr_end_record_requested = 1;
}

void qmp_end_replay(Error **errp) {
  do_stop();
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





//mz file_name_full should be full path to desired record/replay log file
void rr_do_begin_record(const char *file_name_full) {
  char name_buf[1024];
  // decompose file_name_base into path & file. 
  char *rr_path = qemu_strdup(file_name_full);
  char *rr_name = qemu_strdup(file_name_full);
  rr_path = dirname(rr_path);
  rr_name = basename(rr_name);
  if (rr_debug_whisper()) {
    fprintf (logfile,"Begin vm record for file_name_full = %s\n", file_name_full);    
    fprintf (logfile,"path = [%s]  file_name_base = [%s]\n", rr_path, rr_name);
  }
  // first take a snapshot
  rr_get_snapshot_name(rr_name, name_buf, sizeof(name_buf));
  printf ("writing snapshot:\t%s\n", name_buf);
  do_savevm(name_buf);
  log_all_cpu_states();
  // second, open non-deterministic input log for write. 
  rr_get_nondet_log_file_name(rr_name, rr_path, name_buf, sizeof(name_buf));
  printf ("opening nondet log for write :\t%s\n", name_buf);
  rr_create_record_log(name_buf);
  // reset record/replay counters and flags
  rr_reset_state();
  // set global to turn on recording
  rr_mode = RR_RECORD;
}


void rr_do_end_record() {  
  //mz put in end-of-log marker
  rr_record_end_of_log();

  if (rr_debug_whisper()) {
    fprintf (logfile,"End vm record for name = %s\n", rr_name);
    printf ("End vm record for name = %s\n", rr_name);
  }
  log_all_cpu_states();

  rr_destroy_log();

  // turn off logging
  rr_mode = RR_OFF;
}


// file_name_full should be full path to the record/replay log
void rr_do_begin_replay(const char *file_name_full) {
  char name_buf[1024];
  // decompose file_name_base into path & file. 
  char *rr_path = qemu_strdup(file_name_full);
  char *rr_name = qemu_strdup(file_name_full);
  rr_path = dirname(rr_path);
  rr_name = basename(rr_name);
  if (rr_debug_whisper()) {
    fprintf (logfile,"Begin vm replay for file_name_full = %s\n", file_name_full);    
    fprintf (logfile,"path = [%s]  file_name_base = [%s]\n", rr_path, rr_name);
  }

  // first retrieve snapshot
  rr_get_snapshot_name(rr_name, name_buf, sizeof(name_buf));
  if (rr_debug_whisper()) {
    fprintf (logfile,"reading snapshot:\t%s\n", name_buf);
  }
  printf ("loading snapsnot\n");
  do_loadvm(name_buf);
  printf ("... done.\n");
  log_all_cpu_states();
  // second, open non-deterministic input log for read.  
  rr_get_nondet_log_file_name(rr_name, rr_path, name_buf, sizeof(name_buf));
  printf ("opening nondet log for read :\t%s\n", name_buf);
  rr_create_replay_log(name_buf);
  // reset record/replay counters and flags
  rr_reset_state();
  // set global to turn on replay
  rr_mode = RR_REPLAY;
  //mz fill the queue!
  rr_fill_queue();
}


//mz XXX what about early replay termination? Can we save state and resume later?
void rr_do_end_replay(int is_error) {
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
            qemu_free(entry);
            num_items++;
        }
        printf("%lu items on recycle list, %lu bytes total\n", num_items, num_items * sizeof(RR_log_entry));
    }
    //mz some more sanity checks - the queue should contain only the RR_LAST element
    if (queue_head == queue_tail && queue_head != NULL && queue_head->header.kind == RR_LAST) {
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
        while (queue_head) {
            entry = queue_head;
            queue_head = entry->next;
            entry->next = NULL;
            free_entry_params(entry);
            qemu_free(entry);
        }
    }
    queue_head = NULL;
    queue_tail = NULL;
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
}

/**************************************************************************/
