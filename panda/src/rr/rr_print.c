#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <libgen.h>

#define RR_LOG_STANDALONE
#include "panda/include/panda/rr/rr_log.h"
#include "panda/include/panda/rr/panda_rr2.h"
#include "qemu/osdep.h"
#include "cpu.h"

/******************************************************************************************/
/* GLOBALS */
/******************************************************************************************/
// record/replay state
rr_control_t rr_control = {.mode = RR_REPLAY, .next = RR_NOCHANGE};

//mz program execution state

//mz 11.06.2009 Flags to manage nested recording
volatile sig_atomic_t rr_record_in_progress = 0;
volatile sig_atomic_t rr_record_in_main_loop_wait = 0;
volatile sig_atomic_t rr_skipped_callsite_location = 0;

//mz the log of non-deterministic events
RR_log *rr_nondet_log = NULL;

static inline uint8_t log_is_empty(void) {
    if ((rr_nondet_log->type == REPLAY) && 
	((rr_nondet_log->size - rr_nondet_log->bytes_read) == 0)){
        return 1;
    }
    else {
        return 0;
    }
}

RR_debug_level_type rr_debug_level = RR_DEBUG_WHISPER;

// write this program point to this file 
static void rr_spit_prog_point_fp(FILE *fp, RR_prog_point pp) {
  fprintf(fp, "{guest_instr_count=%llu}\n",
      (unsigned long long)pp.guest_instr_count);
}

void rr_spit_prog_point(RR_prog_point pp) {
  rr_spit_prog_point_fp(stdout,pp);
}


static void rr_spit_log_entry(RR_log_entry item) {
    rr_spit_prog_point(item.header.prog_point);
    switch (item.header.kind) {
        case RR_INPUT_1:
            printf("\tRR_INPUT_1 %d from %s\n", item.variant.input_1, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INPUT_2:
            printf("\tRR_INPUT_2 %d from %s\n", item.variant.input_2, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INPUT_4:
            printf("\tRR_INPUT_4 %d from %s\n", item.variant.input_4, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INPUT_8:
            printf("\tRR_INPUT_8 %" PRIu64 " from %s\n", item.variant.input_8, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_INTERRUPT_REQUEST:
            printf("\tRR_INTERRUPT_REQUEST_%d from %s\n", item.variant.interrupt_request, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_EXIT_REQUEST:
            printf("\tRR_EXIT_REQUEST_%d from %s\n", item.variant.exit_request, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_PENDING_INTERRUPTS:
            printf("\tRR_PENDING_INTERRUPTS_%d from %s\n", item.variant.pending_interrupts, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_EXCEPTION:
            printf("\tRR_EXCEPTION_%d from %s\n", item.variant.exception_index, get_callsite_string(item.header.callsite_loc));
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item.variant.call_args;
                int callbytes = 0;
                switch (item.variant.call_args.kind) {
                    case RR_CALL_CPU_MEM_RW:
                        callbytes = sizeof(args->variant.cpu_mem_rw_args) + args->variant.cpu_mem_rw_args.len;
                        break;
                    case RR_CALL_MEM_REGION_CHANGE:
                        callbytes = sizeof(args->variant.mem_region_change_args) + args->variant.mem_region_change_args.len;
                        break;
                    case RR_CALL_CPU_MEM_UNMAP:
                        callbytes = sizeof(args->variant.cpu_mem_unmap) + args->variant.cpu_mem_unmap.len;
                        break;
                    case RR_CALL_HD_TRANSFER:
                        callbytes = sizeof(args->variant.hd_transfer_args);
                        printf("This is a HD transfer. Source: 0x%" PRIx64 ", Dest: 0x%" PRIx64 ", Len: %d\n",
                            args->variant.hd_transfer_args.src_addr,
                            args->variant.hd_transfer_args.dest_addr,
                            args->variant.hd_transfer_args.num_bytes);
                        break;
                    case RR_CALL_SERIAL_SEND:
                        callbytes = sizeof(args->variant.serial_send_args);
                        break;
                    case RR_CALL_SERIAL_WRITE:
                        callbytes = sizeof(args->variant.serial_write_args);
                        break;
                    case RR_CALL_SERIAL_RECEIVE:
                        callbytes = sizeof(args->variant.serial_receive_args);
                        break;
                    case RR_CALL_SERIAL_READ:
                        callbytes = sizeof(args->variant.serial_read_args);
                        break;
                    default: break;
                }
                printf("\tRR_SKIPPED_CALL_(%s) from %s %d bytes\n", 
                        get_skipped_call_kind_string(item.variant.call_args.kind),
                        get_callsite_string(item.header.callsite_loc),
                        callbytes);
                break;
            }
        case RR_END_OF_LOG:
            printf("\tRR_END_OF_LOG\n");
            break;
        default:
            printf("\tUNKNOWN RR log kind %d\n", item.header.kind);
            break;
    }
}

//mz allocate a new entry (not filled yet)
static inline RR_log_entry *alloc_new_entry(void) 
{
    static RR_log_entry *new_entry = NULL;
    if(!new_entry) new_entry = g_new(RR_log_entry, 1);
    memset(new_entry, 0, sizeof(RR_log_entry));
    return new_entry;
}

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

static inline size_t rr_fread(void *ptr, size_t size, size_t nmemb){
    size_t result;
    if (rr_nondet_log->rr2){
        result = rrfile_fread(ptr, size, nmemb, rr_nondet_log->file.replay_rr);
    }
    else{
	result = fread(ptr, size, nmemb, rr_nondet_log->file.fp);
    }
    rr_nondet_log->bytes_read += nmemb * size;
    assert(result == nmemb);
    return result;
}

void rr_fseek_cur(size_t size){
    if (rr_nondet_log->rr2){
        rrfile_fseek_cur(rr_nondet_log->file.replay_rr, size);
    }
    else{
        fseek(rr_nondet_log->file.fp, size, SEEK_CUR);
    }
    rr_nondet_log->bytes_read += size;
}

//mz fill an entry
static RR_log_entry *rr_read_item(void) {
    RR_log_entry *item = alloc_new_entry();

    //mz read header
    assert (rr_in_replay());
    assert ( ! log_is_empty());
    if (rr_nondet_log->rr2) {
        assert(rr_nondet_log->file.replay_rr != NULL);
    }
    else {
        assert(rr_nondet_log->file.fp != NULL);
    }

#define RR_READ_ITEM(field) rr_fread(&(field), sizeof(field), 1)

    //mz XXX we assume that the log is not trucated - should probably fix this.
    RR_READ_ITEM(item->header.prog_point.guest_instr_count);

    //mz this is more compact, as it doesn't include extra padding.
    rr_fread(&(item->header.kind), 1, 1);
    rr_fread(&(item->header.callsite_loc), 1, 1);

    //mz read the rest of the item
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
        case RR_EXIT_REQUEST:
            RR_READ_ITEM(item->variant.exit_request);
            break;
        case RR_PENDING_INTERRUPTS:
            RR_READ_ITEM(item->variant.pending_interrupts);
            break;
        case RR_EXCEPTION:
            RR_READ_ITEM(item->variant.exception_index);
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item->variant.call_args;
                //mz read kind first!
                rr_fread(&(args->kind), 1, 1);
                switch(args->kind) {
                    case RR_CALL_CPU_MEM_RW:
			RR_READ_ITEM(args->variant.cpu_mem_rw_args);
                        //mz buffer length in args->variant.cpu_mem_rw_args.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        //args->variant.cpu_mem_rw_args.buf = g_malloc(args->variant.cpu_mem_rw_args.len);
                        //mz read the buffer
                        //assert(fread(args->variant.cpu_mem_rw_args.buf, 1, args->variant.cpu_mem_rw_args.len, rr_nondet_log->fp) > 0);
                        rr_fseek_cur(args->variant.cpu_mem_rw_args.len);
                        break;
                    case RR_CALL_CPU_MEM_UNMAP:
			RR_READ_ITEM(args->variant.cpu_mem_unmap);
                        //mz buffer length in args->variant.cpu_mem_unmap.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        //args->variant.cpu_mem_unmap.buf = g_malloc(args->variant.cpu_mem_unmap.len);
                        //mz read the buffer
                        //assert(fread(args->variant.cpu_mem_unmap.buf, 1, args->variant.cpu_mem_unmap.len, rr_nondet_log->fp) > 0);
                        rr_fseek_cur(args->variant.cpu_mem_unmap.len);
                        break;
                    case RR_CALL_MEM_REGION_CHANGE:
			RR_READ_ITEM(args->variant.mem_region_change_args);
                        rr_fseek_cur(args->variant.mem_region_change_args.len);
                        break;
                    case RR_CALL_HD_TRANSFER:
			RR_READ_ITEM(args->variant.hd_transfer_args);
                        break;
                    case RR_CALL_HANDLE_PACKET:
			RR_READ_ITEM(args->variant.handle_packet_args);
                        rr_fseek_cur(args->variant.handle_packet_args.size);
                        break;
                    case RR_CALL_NET_TRANSFER:
			RR_READ_ITEM(args->variant.net_transfer_args);
                        break;
                    case RR_CALL_SERIAL_RECEIVE:
			RR_READ_ITEM(args->variant.serial_receive_args);
                        break;
                    case RR_CALL_SERIAL_READ:
			RR_READ_ITEM(args->variant.serial_read_args);
                        break;
                    case RR_CALL_SERIAL_SEND:
			RR_READ_ITEM(args->variant.serial_send_args);
                        break;
                    case RR_CALL_SERIAL_WRITE:
			RR_READ_ITEM(args->variant.serial_write_args);
                        break;
                    default:
                        //mz unimplemented
                        printf("rr_read_item: Call type %d unimplemented!\n", args->kind);
                        assert(0);
                }
            }
            break;
        case RR_END_OF_LOG:
            //mz nothing to read
            break;
        default:
            //mz unimplemented
            printf("rr_read_item: Log type %d unimplemented!\n", item->header.kind);
            assert(0);
    }

    return item;
}

void rr1_create_replay_log(void){
  struct stat statbuf = {0};
  rr_nondet_log->file.fp = fopen(rr_nondet_log->name, "r");
  assert(rr_nondet_log->file.fp != NULL);

  //mz fill in log size
  stat(rr_nondet_log->name, &statbuf);
  rr_nondet_log->size = statbuf.st_size;
  fprintf (stdout, "opened %s for read.  len=%llu bytes.\n",
     rr_nondet_log->name, rr_nondet_log->size);
  //mz read the last program point from the log header.
  rr_fread(&(rr_nondet_log->last_prog_point), sizeof(RR_prog_point), 1);
}

void rr2_create_replay_log(void){
  if (!RRFILE_SUCCESS(rrfile_open_read(rr_nondet_log->name, "nondetlog", &(rr_nondet_log->file.replay_rr)))) {
      fprintf(stderr, "Failed to open nondetlog from RR archive\n");
      exit(1);
  } 
  assert(rr_nondet_log->file.replay_rr != NULL);

  //mz fill in log size
  rr_nondet_log->size = rrfile_section_size(rr_nondet_log->file.replay_rr);
  
  rr_nondet_log->bytes_read = 0;
  fprintf (stdout, "opened %s for read.  len=%llu bytes.\n",
     rr_nondet_log->name, rr_nondet_log->size);
  //mz read the last program point from the log header.
  rr_fread(&(rr_nondet_log->last_prog_point), sizeof(RR_prog_point), 1);
}

// create replay log
void rr_create_replay_log (const char *filename) {
  // create log
  rr_nondet_log = (RR_log *) g_malloc (sizeof (RR_log));
  assert (rr_nondet_log != NULL);
  memset(rr_nondet_log, 0, sizeof(RR_log));

  rr_nondet_log->type = REPLAY;
  //check if using rr2 format
  rr_nondet_log->rr2 = is_rr2_file(filename);
  if (rr_nondet_log->rr2){
    rr_nondet_log->name = rr2_name(filename);
    rr2_create_replay_log();
  }
  else{
    rr_nondet_log->name = g_strdup(filename);
    rr1_create_replay_log();
  }
}

int main(int argc, char **argv) {
    rr_create_replay_log(argv[1]);
    printf("RR Log with %llu instructions\n", (unsigned long long) rr_nondet_log->last_prog_point.guest_instr_count);
    RR_log_entry *log_entry = NULL;
    while(!log_is_empty()) {
        log_entry = rr_read_item();
        rr_spit_log_entry(*log_entry);
    }
    if (log_entry) g_free(log_entry);
    return 0;
}
