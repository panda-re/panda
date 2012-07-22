#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#define RR_LOG_STANDALONE
#include "rr_log.h"

/******************************************************************************************/
/* GLOBALS */
/******************************************************************************************/
//mz record/replay mode
volatile RR_mode rr_mode = RR_REPLAY;

//mz program execution state
RR_prog_point rr_prog_point = {0, 0, 0};
//volatile uint64_t rr_guest_instr_count;
volatile uint64_t rr_num_instr_before_next_interrupt;

//mz 11.06.2009 Flags to manage nested recording
volatile sig_atomic_t rr_record_in_progress = 0;
volatile sig_atomic_t rr_skipped_callsite_location = 0;

volatile sig_atomic_t rr_use_live_exit_request = 0;

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
  uint8_t current_item_valid;
  unsigned long long item_number;
} RR_log;

//mz the log of non-deterministic events
RR_log *rr_nondet_log = NULL;

static inline uint8_t log_is_empty(void) {
    if ((rr_nondet_log->type == REPLAY) &&
        (rr_nondet_log->size - ftell(rr_nondet_log->fp) == 0)) {
        return 1;
    }
    else {
        return 0;
    }
}

RR_debug_level_type rr_debug_level = RR_DEBUG_WHISPER;

//mz Flags set by monitor to indicate requested record/replay action
volatile sig_atomic_t rr_replay_requested = 0;
volatile sig_atomic_t rr_record_requested = 0;
volatile sig_atomic_t rr_end_record_requested = 0;
volatile sig_atomic_t rr_end_replay_requested = 0;
const char * rr_requested_name = NULL;

// write this program point to this file 
static void rr_spit_prog_point_fp(FILE *fp, RR_prog_point pp) {
  fprintf(fp, "{guest_instr_count=%llu eip=0x%08x, ecx=0x%08x}\n", 
          (unsigned long long)pp.guest_instr_count,
	  pp.eip,
	  pp.ecx);
}

static void rr_spit_prog_point(RR_prog_point pp) {
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
            printf("\tRR_INTERRUPT_REQUEST %d from %s\n", item.variant.interrupt_request, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_EXIT_REQUEST:
            printf("\tRR_EXIT_REQUEST %d from %s\n", item.variant.exit_request, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_SKIPPED_CALL:
            printf("\tRR_SKIPPED_CALL (%s) from %s\n", 
                    get_skipped_call_kind_string(item.variant.call_args.kind),
                    get_callsite_string(item.header.callsite_loc));
            break;
        case RR_LAST:
            printf("\tRR_LAST\n");
            break;
        default:
            printf("\tUNKNOWN RR log kind %d\n", item.header.kind);
            break;
    }
}

//mz allocate a new entry (not filled yet)
static inline RR_log_entry *alloc_new_entry(void) 
{
    RR_log_entry *new_entry = NULL;
    new_entry = g_new(RR_log_entry, 1);
    memset(new_entry, 0, sizeof(RR_log_entry));
    return new_entry;
}

//mz fill an entry
static RR_log_entry *rr_read_item(void) {
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

    //mz read the rest of the item
    switch (item->header.kind) {
        case RR_INPUT_1:
            fread(&(item->variant.input_1), sizeof(item->variant.input_1), 1, rr_nondet_log->fp);
            break;
        case RR_INPUT_2:
            fread(&(item->variant.input_2), sizeof(item->variant.input_2), 1, rr_nondet_log->fp);
            break;
        case RR_INPUT_4:
            fread(&(item->variant.input_4), sizeof(item->variant.input_4), 1, rr_nondet_log->fp);
            break;
        case RR_INPUT_8:
            fread(&(item->variant.input_8), sizeof(item->variant.input_8), 1, rr_nondet_log->fp);
            break;
        case RR_INTERRUPT_REQUEST:
            fread(&(item->variant.interrupt_request), sizeof(item->variant.interrupt_request), 1, rr_nondet_log->fp);
            break;
        case RR_EXIT_REQUEST:
            fread(&(item->variant.exit_request), sizeof(item->variant.exit_request), 1, rr_nondet_log->fp);
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item->variant.call_args;
                //mz read kind first!
                fread(&(args->kind), sizeof(args->kind), 1, rr_nondet_log->fp);
                switch(args->kind) {
                    case RR_CALL_CPU_MEM_RW:
                        fread(&(args->variant.cpu_mem_rw_args), sizeof(args->variant.cpu_mem_rw_args), 1, rr_nondet_log->fp);
                        //mz buffer length in args->variant.cpu_mem_rw_args.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.cpu_mem_rw_args.buf = g_malloc(args->variant.cpu_mem_rw_args.len);
                        //mz read the buffer
                        fread(args->variant.cpu_mem_rw_args.buf, 1, args->variant.cpu_mem_rw_args.len, rr_nondet_log->fp);
                        break;
                    case RR_CALL_CPU_MEM_UNMAP:
                        fread(&(args->variant.cpu_mem_unmap), sizeof(args->variant.cpu_mem_unmap), 1, rr_nondet_log->fp);
                        //mz buffer length in args->variant.cpu_mem_unmap.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.cpu_mem_unmap.buf = g_malloc(args->variant.cpu_mem_unmap.len);
                        //mz read the buffer
                        fread(args->variant.cpu_mem_unmap.buf, 1, args->variant.cpu_mem_unmap.len, rr_nondet_log->fp);
                        break;
                    case RR_CALL_CPU_REG_MEM_REGION:
                        fread(&(args->variant.cpu_mem_reg_region_args), 
                              sizeof(args->variant.cpu_mem_reg_region_args), 1, rr_nondet_log->fp);
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

// create replay log
void rr_create_replay_log (const char *filename) {
  struct stat statbuf = {0};
  // create log
  rr_nondet_log = (RR_log *) g_malloc (sizeof (RR_log));
  assert (rr_nondet_log != NULL);
  memset(rr_nondet_log, 0, sizeof(RR_log));

  rr_nondet_log->type = REPLAY;
  rr_nondet_log->name = g_strdup(filename);
  rr_nondet_log->fp = fopen(rr_nondet_log->name, "r");
  assert(rr_nondet_log->fp != NULL);

  //mz fill in log size
  stat(rr_nondet_log->name, &statbuf);
  rr_nondet_log->size = statbuf.st_size;
  if (rr_debug_whisper()) {
    fprintf (stdout, "opened %s for read.  len=%llu bytes.\n",
	     rr_nondet_log->name, rr_nondet_log->size);
  }
  //mz read the last program point from the log header.
  fread(&(rr_nondet_log->last_prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp);
}

int main(int argc, char **argv) {
    rr_create_replay_log(argv[1]);
    while(!log_is_empty()) {
        RR_log_entry *log_entry = rr_read_item();
        rr_spit_log_entry(*log_entry);
    }
    return 0;
}
