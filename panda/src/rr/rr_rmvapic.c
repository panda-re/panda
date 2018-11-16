#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#define RR_LOG_STANDALONE
#include <panda/include/panda/rr/rr_log.h>
#include "qemu/osdep.h"
#include "cpu.h"

/******************************************************************************************/
/* GLOBALS */
/******************************************************************************************/
//mz record/replay mode
volatile RR_mode rr_mode = RR_REPLAY;

//mz program execution state

//mz 11.06.2009 Flags to manage nested recording
volatile sig_atomic_t rr_record_in_progress = 0;
volatile sig_atomic_t rr_record_in_main_loop_wait = 0;
volatile sig_atomic_t rr_skipped_callsite_location = 0;

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
char * rr_requested_name = NULL;

//mz allocate a new entry (not filled yet)
static inline RR_log_entry *alloc_new_entry(void) 
{
    static RR_log_entry *new_entry = NULL;
    if(!new_entry) new_entry = g_new(RR_log_entry, 1);
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
    if (fread(&(item->header.prog_point.guest_instr_count),
                sizeof(item->header.prog_point.guest_instr_count), 1, rr_nondet_log->fp) != 1) {
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
    assert(fread(&(item->header.kind), 1, 1, rr_nondet_log->fp) == 1);
    assert(fread(&(item->header.callsite_loc), 1, 1, rr_nondet_log->fp) == 1);

    //mz read the rest of the item
    switch (item->header.kind) {
        case RR_INPUT_1:
            assert(fread(&(item->variant.input_1), sizeof(item->variant.input_1), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_INPUT_2:
            assert(fread(&(item->variant.input_2), sizeof(item->variant.input_2), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_INPUT_4:
            assert(fread(&(item->variant.input_4), sizeof(item->variant.input_4), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_INPUT_8:
            assert(fread(&(item->variant.input_8), sizeof(item->variant.input_8), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_INTERRUPT_REQUEST:
            assert(fread(&(item->variant.interrupt_request), sizeof(item->variant.interrupt_request), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_EXIT_REQUEST:
            assert(fread(&(item->variant.exit_request), sizeof(item->variant.exit_request), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_PENDING_INTERRUPTS:
            assert(fread(&(item->variant.pending_interrupts), sizeof(item->variant.pending_interrupts), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_EXCEPTION:
            assert(fread(&(item->variant.exception_index), sizeof(item->variant.exception_index), 1, rr_nondet_log->fp) == 1);
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item->variant.call_args;
                //mz read kind first!
                assert(fread(&(args->kind), 1, 1, rr_nondet_log->fp) == 1);
                switch(args->kind) {
                    case RR_CALL_CPU_MEM_RW:
                        assert(fread(&(args->variant.cpu_mem_rw_args), sizeof(args->variant.cpu_mem_rw_args), 1, rr_nondet_log->fp) == 1);
                        //mz buffer length in args->variant.cpu_mem_rw_args.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.cpu_mem_rw_args.buf =
                            g_malloc(args->variant.cpu_mem_rw_args.len);
                        //mz read the buffer
                        assert(fread(args->variant.cpu_mem_rw_args.buf, 1,
                                     args->variant.cpu_mem_rw_args.len,
                                     rr_nondet_log->fp) > 0);
                        break;
                    case RR_CALL_CPU_MEM_UNMAP:
                        assert(fread(&(args->variant.cpu_mem_unmap), sizeof(args->variant.cpu_mem_unmap), 1, rr_nondet_log->fp) == 1);
                        //mz buffer length in args->variant.cpu_mem_unmap.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.cpu_mem_unmap.buf =
                            g_malloc(args->variant.cpu_mem_unmap.len);
                        //mz read the buffer
                        assert(fread(args->variant.cpu_mem_unmap.buf, 1,
                                     args->variant.cpu_mem_unmap.len,
                                     rr_nondet_log->fp) > 0);
                        break;
                    case RR_CALL_MEM_REGION_CHANGE:
                        assert(fread(&(args->variant.mem_region_change_args),
                            sizeof(args->variant.mem_region_change_args), 1,
                            rr_nondet_log->fp) == 1);
                        args->variant.mem_region_change_args.name = g_malloc0(
                            args->variant.mem_region_change_args.len + 1);
                        assert(fread(args->variant.mem_region_change_args.name,
                                     1,
                                     args->variant.mem_region_change_args.len,
                                     rr_nondet_log->fp) > 0);
                        break;
                    case RR_CALL_HD_TRANSFER:
                        assert(fread(&(args->variant.hd_transfer_args),
                              sizeof(args->variant.hd_transfer_args), 1, rr_nondet_log->fp) == 1);
                        break;
                    case RR_CALL_HANDLE_PACKET:
                        assert(fread(&(args->variant.handle_packet_args),
                              sizeof(args->variant.handle_packet_args), 1, rr_nondet_log->fp) == 1);
                        args->old_buf_addr =
                            (uint64_t)args->variant.handle_packet_args.buf;
                        // mz buffer length in args->variant.cpu_mem_rw_args.len
                        // mz always allocate a new one. we free it when the
                        // item is added to the recycle list
                        args->variant.handle_packet_args.buf =
                            g_malloc(args->variant.handle_packet_args.size);
                        // mz read the buffer
                        assert(fread(args->variant.handle_packet_args.buf,
                                     args->variant.handle_packet_args.size, 1,
                                     rr_nondet_log->fp) > 0);

                        break;
                    case RR_CALL_NET_TRANSFER:
                        assert(fread(&(args->variant.net_transfer_args),
                              sizeof(args->variant.net_transfer_args), 1, rr_nondet_log->fp) == 1);
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
  fprintf (stdout, "opened %s for read.  len=%llu bytes.\n",
     rr_nondet_log->name, rr_nondet_log->size);
  //mz read the last program point from the log header.
  assert(fread(&(rr_nondet_log->last_prog_point), sizeof(RR_prog_point), 1, rr_nondet_log->fp) == 1);
}

FILE *out_fp;

static inline size_t rr_fwrite(void *ptr, size_t size, size_t nmemb)
{
    size_t result = fwrite(ptr, size, nmemb, out_fp);
    assert(result == nmemb);
    return result;
}

// mz write the current log item to file
static inline void rr_write_item(RR_log_entry item)
{
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
        RR_skipped_call_args *args = &item.variant.call_args;
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
        case RR_CALL_HANDLE_PACKET: {
            uint8_t *buf = args->variant.handle_packet_args.buf;
            args->variant.handle_packet_args.buf =
                (uint8_t *)args->old_buf_addr;
            RR_WRITE_ITEM(args->variant.handle_packet_args);
            rr_fwrite(buf, args->variant.handle_packet_args.size, 1);
        } break;
        default:
            // mz unimplemented
            assert(0 && "Unimplemented skipped call!");
        }
    } break;
    case RR_END_OF_LOG:
        // mz nothing to read
        break;
    default:
        // mz unimplemented
        assert(0 && "Unimplemented replay log entry!");
    }
}

// function that copies one file to another - used to copy snapshots
static void copy_file(char *out, char *in)
{
    char buffer[4096];
    size_t bytes;

    FILE *src = fopen(in, "r");
    FILE *dest = fopen(out, "w");

    while (0 < (bytes = fread(buffer, 1, sizeof(buffer), src))) {
        fwrite(buffer, 1, bytes, dest);
    }

    fclose(src);
    fclose(dest);
}

const char *log_suffix = "-rr-nondet.log";
const char *snp_suffix = "-rr-snp";
const char *new_prefix = "novapic-";

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("usage: %s <recording name>\n\n", argv[0]);
        printf("Removes events at the polled interrupt callsite from a "
               "recording.\n\n");
        return 1;
    }

    char *in_recording_name = basename(argv[1]);
    printf("recording name: %s\n", in_recording_name);

    // Generate input file names.
    size_t in_log_name_len = strlen(argv[1]) + strlen(log_suffix) + 1;
    size_t in_snp_name_len = strlen(argv[1]) + strlen(snp_suffix) + 1;
    char *in_log_name = malloc(in_log_name_len);
    char *in_snp_name = malloc(in_snp_name_len);
    snprintf(in_log_name, in_log_name_len, "%s%s", argv[1], log_suffix);
    snprintf(in_snp_name, in_snp_name_len, "%s%s", argv[1], snp_suffix);
    printf("input log name: %s\n", in_log_name);
    printf("input snp name: %s\n", in_snp_name);

    // Generate output file names.
    size_t out_log_name_len =
        strlen(new_prefix) + strlen(in_recording_name) + strlen(log_suffix) + 1;
    size_t out_snp_name_len =
        strlen(new_prefix) + strlen(in_recording_name) + strlen(snp_suffix) + 1;
    char *out_log_name = malloc(out_log_name_len);
    char *out_snp_name = malloc(out_snp_name_len);
    snprintf(out_log_name, out_log_name_len, "%s%s%s", new_prefix,
             in_recording_name, log_suffix);
    snprintf(out_snp_name, out_log_name_len, "%s%s%s", new_prefix,
             in_recording_name, snp_suffix);
    printf("output log name: %s\n", out_log_name);
    printf("output snp name: %s\n", out_snp_name);

    // Open the output log file and process the input log.
    out_fp = fopen(out_log_name, "w");
    rr_create_replay_log(in_log_name);
    fwrite(&rr_nondet_log->last_prog_point.guest_instr_count,
           sizeof(rr_nondet_log->last_prog_point.guest_instr_count), 1, out_fp);
    printf(
        "RR Log with %llu instructions\n",
        (unsigned long long)rr_nondet_log->last_prog_point.guest_instr_count);
    RR_log_entry *log_entry = NULL;
    while (!log_is_empty()) {
        log_entry = rr_read_item();
        if (log_entry->header.callsite_loc == 0) {
            printf("Skipping event with interrupt poll callsite @ instruction "
                   "count = %lu.\n",
                   log_entry->header.prog_point.guest_instr_count);
            continue;
        }
        log_entry->header.callsite_loc -= 1;
        rr_write_item(*log_entry);
    }
    if (log_entry) g_free(log_entry);
    fclose(out_fp);

    // Copy the snapshot to a new file.
    copy_file(out_snp_name, in_snp_name);

    free(in_log_name);
    free(in_snp_name);
    free(out_log_name);
    free(out_snp_name);

    return 0;
}
