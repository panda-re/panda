/* Scissors plugin for making smaller replays.
 *
 * Use -panda-arg scissors:start and -panda-arg scissors:end
 * to control beginning and end of new replay. Output goes to
 * a new replay named "scissors" by default (-panda-arg scissors:name
 * to change)
 */

#include <stdio.h>
#include <libgen.h>
#include <dirent.h>
#include <errno.h>

#include "panda/plugin.h"
#include "panda/rr/rr_log.h"
#include "panda/rr/rr_api.h"
#include "panda/common.h"
#include "panda/include/panda/rr/panda_rr2.h"

#include "migration/migration.h"
#include "migration/savevm.h"
#include "include/exec/address-spaces.h"
#include "migration/qemu-file.h"
#include "io/channel-file.h"
#include "sysemu/sysemu.h"

bool init_plugin(void *);
void uninit_plugin(void *);
void before_block_exec(CPUState *env, TranslationBlock *tb);

void check_start_snip(CPUState *env);
void check_end_snip(CPUState *env);

static uint64_t start_count;
static uint64_t actual_start_count;
static uint64_t end_count;

static char *nondet_name;
static char *snp_name;
static char *cmdline_file_name;
static char *new_rr2_name;

static bool oldlog_rr2;
static bool newlog_rr2;
union {
    struct rr_file *rr2; // used if input is rr2 format
    FILE *rr1; // used if input is old format
} oldlog;
static FILE *newlog = NULL;
struct rr_file_state* new_rr_archive;
static size_t bytes_read = 0;
static RR_log_type rr_nondet_log_type;
static unsigned long long rr_nondet_log_size;

//static RR_log_entry entry;
static RR_prog_point orig_last_prog_point = {0};
static RR_prog_point pp_last_copied_log_entry;

static bool snipping = false;
static bool done = false;

static RR_prog_point copy_entry(void);
static void sassert(bool condition, int which);

static void sassert(bool condition, int which) {
    if (!condition) {
        printf("scissors.c: sassert %d\n", which);
        rr_do_end_replay(true);
    }
}

#define INLINEIT inline

static INLINEIT size_t rr_fwrite(void *ptr, size_t size, size_t nmemb, FILE *f) {
    size_t result = fwrite(ptr, size, nmemb, f);
    sassert(result == nmemb, 1);
    return result;
}

static INLINEIT size_t rr_fread(void *ptr, size_t size, size_t nmemb) {
    size_t result;
    if (oldlog_rr2) {
        result = rrfile_fread(ptr, size, nmemb, oldlog.rr2);
    } else {
        result = fread(ptr, size, nmemb, oldlog.rr1);
    }
    sassert(result == nmemb, 2);
    bytes_read += nmemb * size;
    return result;
}

static INLINEIT void rr_fcopy(void *ptr, size_t size, size_t nmemb, FILE *newlog) {
    rr_fread(ptr, size, nmemb);
    rr_fwrite(ptr, size, nmemb, newlog);
}

static INLINEIT bool rr_log_is_empty(void) {
    if (rr_nondet_log_type == REPLAY){
        return bytes_read == rr_nondet_log_size;
    } else {
        return false;
    }
}

static INLINEIT RR_log_entry *alloc_new_entry(void)
{
    static RR_log_entry *new_entry = NULL;
    if(!new_entry) new_entry = g_new(RR_log_entry, 1);
    memset(new_entry, 0, sizeof(RR_log_entry));
    return new_entry;
}

static void rr_fseek_set(size_t bytes){
  if (oldlog_rr2) {
      rrfile_fseek_set(&(oldlog.rr2), rr_nondet_log->name, bytes);
  } else {
      fseek(oldlog.rr1, bytes, SEEK_SET);
  }
  bytes_read = bytes;
}

static inline char *rr1_cmdline_file_name(char* replay_name) {
    size_t needed;
    char* cmdline_name;
    needed = snprintf(NULL, 0, "%s-rr.cmd", replay_name);
    cmdline_name = malloc(needed+1);
    snprintf(cmdline_name, needed+1, "%s-rr.cmd", replay_name);
    return cmdline_name;
}

// Returns guest instr count (in old replay counting mode)
static RR_prog_point copy_entry(void) {
    // Code copied from rr_log.c.
    // Copy entry.
    RR_log_entry *item = alloc_new_entry();

    rr_fread(&(item->header.prog_point.guest_instr_count), sizeof(item->header.prog_point.guest_instr_count), 1);

    if (item->header.prog_point.guest_instr_count > end_count) {
        // We don't want to copy this one.
        rr_fseek_set(bytes_read);
        return item->header.prog_point;
    }

    //ph Fix up instruction count
    RR_prog_point original_prog_point = item->header.prog_point;
    item->header.prog_point.guest_instr_count -= actual_start_count;
    rr_fwrite(&item->header.prog_point, sizeof(item->header.prog_point), 1, newlog);

#define RR_COPY_ITEM(field) rr_fcopy(&(field), sizeof(field), 1, newlog)
    //rw only read 1 byte for kind and callsite_loc even though it's an enum, due to mz's optimization (see rr_log.h)
    rr_fcopy(&(item->header.kind), 1, 1, newlog);
    rr_fcopy(&(item->header.callsite_loc), 1, 1, newlog);

    //mz read the rest of the item
    switch (item->header.kind) {
        case RR_INPUT_1:
            RR_COPY_ITEM(item->variant.input_1);
            break;
        case RR_INPUT_2:
            RR_COPY_ITEM(item->variant.input_2);
            break;
        case RR_INPUT_4:
            RR_COPY_ITEM(item->variant.input_4);
            break;
        case RR_INPUT_8:
            RR_COPY_ITEM(item->variant.input_8);
            break;
        case RR_INTERRUPT_REQUEST:
            RR_COPY_ITEM(item->variant.interrupt_request);
            break;
        case RR_PENDING_INTERRUPTS:
            RR_COPY_ITEM(item->variant.pending_interrupts);
            break;
        case RR_EXCEPTION:
            RR_COPY_ITEM(item->variant.exception_index);
            break;
        case RR_EXIT_REQUEST:
            RR_COPY_ITEM(item->variant.exit_request);
            break;
        case RR_SKIPPED_CALL: {
            RR_skipped_call_args *args = &item->variant.call_args;
            //mz read kind first!
            rr_fcopy(&args->kind, 1, 1, newlog);

            switch(args->kind) {
                case RR_CALL_CPU_MEM_RW:
                    RR_COPY_ITEM(args->variant.cpu_mem_rw_args);
                    args->variant.cpu_mem_rw_args.buf =
                        g_malloc(args->variant.cpu_mem_rw_args.len);
                    rr_fcopy(args->variant.cpu_mem_rw_args.buf, 1,
                            args->variant.cpu_mem_rw_args.len,
                            newlog);
                    break;
                case RR_CALL_CPU_MEM_UNMAP:
                    RR_COPY_ITEM(args->variant.cpu_mem_unmap);
                    args->variant.cpu_mem_unmap.buf =
                        g_malloc(args->variant.cpu_mem_unmap.len);
                    rr_fcopy(args->variant.cpu_mem_unmap.buf, 1,
                                args->variant.cpu_mem_unmap.len,
                                newlog);
                    break;
                case RR_CALL_MEM_REGION_CHANGE:
                    RR_COPY_ITEM(args->variant.mem_region_change_args);
                    args->variant.mem_region_change_args.name =
                        g_malloc0(args->variant.mem_region_change_args.len + 1);
                    rr_fcopy(args->variant.mem_region_change_args.name, 1,
                            args->variant.mem_region_change_args.len,
                            newlog);
                    break;
                case RR_CALL_HD_TRANSFER:
                    RR_COPY_ITEM(args->variant.hd_transfer_args);
                    break;
                case RR_CALL_NET_TRANSFER:
                    RR_COPY_ITEM(args->variant.net_transfer_args);
                    break;
                case RR_CALL_HANDLE_PACKET:
                    RR_COPY_ITEM(args->variant.handle_packet_args);
                    args->variant.handle_packet_args.buf =
                        g_malloc(args->variant.handle_packet_args.size);
                    rr_fcopy(args->variant.handle_packet_args.buf,
                            args->variant.handle_packet_args.size, 1,
                            newlog);
                    break;
                case RR_CALL_SERIAL_READ:
                    RR_COPY_ITEM(args->variant.serial_read_args);
                    break;
                case RR_CALL_SERIAL_RECEIVE:
                    RR_COPY_ITEM(args->variant.serial_receive_args);
                    break;
                case RR_CALL_SERIAL_SEND:
                    RR_COPY_ITEM(args->variant.serial_send_args);
                    break;
                case RR_CALL_SERIAL_WRITE:
                    RR_COPY_ITEM(args->variant.serial_write_args);
                    break;
                default:
                    //mz unimplemented
                    sassert(0, 3);
            }
        } break;
        case RR_END_OF_LOG:
            //mz nothing to read
            //ph We don't copy RR_END_OF_LOG here; write out afterwards.
            break;
        default:
            //mz unimplemented
            sassert(0, 4);
    }

    return original_prog_point;
}

static inline void save_snp_shot(void) {
    // Force running state
    global_state_store_running();
    QIOChannelFile* ioc =
        qio_channel_file_new_path(snp_name, O_WRONLY | O_CREAT, 0660, NULL);
    QEMUFile* snp = qemu_fopen_channel_output(QIO_CHANNEL(ioc));

    set_rr_snapshot();

    qemu_savevm_state(snp, NULL);
    qemu_fclose(snp);

    unset_rr_snapshot();
}

static void create_command_file(void) {
    char *replay_name = strdup(panda_get_rr_name());
    FILE *fp = fopen(cmdline_file_name, "w");
    sassert(fp!=NULL, 5);

    if (oldlog_rr2) {
        char* cmdline_contents;
        rrfile_read_cmdline(replay_name, &cmdline_contents);
        fwrite(cmdline_contents, 1, strlen(cmdline_contents), fp);
    } else {
        fprintf (fp, "created with the scissors plugin\n");
    }
    free(replay_name);
    fclose(fp);
}

static bool open_old_log(void){
    bool success;
    if (oldlog_rr2) {
        success = (rrfile_open_read(rr_nondet_log->name, "nondetlog", &(oldlog.rr2)) == 0) ? true : false;
    } else {
        success = (oldlog.rr1 = fopen(rr_nondet_log->name, "r"));
    }
    return success;
}

static void write_to_rr2(void) {
    printf("Moving files over to rr2 archive %s\n", new_rr2_name);
    printf("    moving cmdline to %s/capture.cmd ...\n", new_rr2_name);
    sassert(rrfile_add_recording_file(new_rr_archive, "capture.cmd", cmdline_file_name), 8);

    printf("    moving snapshot to %s/snapshot ...\n", new_rr2_name);
    sassert(rrfile_add_recording_file(new_rr_archive, "snapshot", snp_name), 7);

    printf("    moving nondetlog entries to %s/nondetlog ...\n", new_rr2_name);
    sassert(rrfile_add_recording_file(new_rr_archive, "nondetlog", nondet_name), 9);
    rrfile_finalize(new_rr_archive);
}

static void clean_up(void){
    free(nondet_name);
    free(snp_name);
    if (newlog_rr2) {
        free(cmdline_file_name);
        free(new_rr2_name);
    }
    if (oldlog_rr2) {
        rrfile_free(oldlog.rr2);
    }
}

static void start_snip(uint64_t count) {
    oldlog_rr2 = rr_nondet_log->rr2;
    sassert(open_old_log(), 10);
    rr_nondet_log_type = rr_nondet_log->type;
    rr_nondet_log_size = rr_nondet_log->size;

    // initiate rr2 file creation
    if (newlog_rr2) {
        new_rr_archive = rrfile_open_write(new_rr2_name);
        sassert(new_rr_archive, 11);
        printf("Writing cmdline to %s ...\n", cmdline_file_name);
        create_command_file();
    }

    sassert(rr_fread(&orig_last_prog_point, sizeof(RR_prog_point), 1) == 1, 12);
    printf("Original ending prog point: %" PRId64 "\n", (uint64_t) orig_last_prog_point.guest_instr_count);

    actual_start_count = count;
    printf("Saving snapshot at instr count %" PRIx64 "...\n", count);
    printf("Writing snapshot to %s ...\n", snp_name);
    save_snp_shot();

    printf("Beginning cut-and-paste process at prog point: % " PRId64 "\n", (uint64_t) rr_get_guest_instr_count());
    printf("Writing entries to %s ...\n", nondet_name);
    newlog = fopen(nondet_name, "w");
    sassert(newlog, 13);
    // We'll fix this up later.
    RR_prog_point prog_point = {0};
    fwrite(&prog_point.guest_instr_count,
           sizeof(prog_point.guest_instr_count), 1, newlog);

    rr_fseek_set(rr_nondet_log->bytes_read);

    // If there are items in the queue, then start copying the log
    // from there
    RR_log_entry *item = rr_get_queue_head();
    if (item != NULL) rr_fseek_set(item->header.file_pos);

    //rw: For some reason I need to add an interrupt entry at the beginning of the log?
    RR_log_entry temp;

    memset(&temp, 0, sizeof(RR_log_entry));
    temp.header.kind = RR_INTERRUPT_REQUEST;
    temp.header.callsite_loc = RR_CALLSITE_CPU_HANDLE_INTERRUPT_BEFORE;
    temp.variant.pending_interrupts = 2;

    fwrite(&temp.header.prog_point, sizeof(temp.header.prog_point), 1, newlog);
    fwrite(&temp.header.kind, 1, 1, newlog);
    fwrite(&temp.header.callsite_loc, 1, 1, newlog);
    fwrite(&temp.variant.pending_interrupts, sizeof(temp.variant.pending_interrupts), 1, newlog);

    while (prog_point.guest_instr_count < end_count && !rr_log_is_empty()) {
        prog_point = copy_entry();
    }
    pp_last_copied_log_entry = prog_point;

    snipping = true;
    printf("Continuing with replay.\n");
}

static void end_snip(void) {
    RR_prog_point prog_point = rr_prog_point();
    printf("Ending cut-and-paste on prog point: %" PRId64 "\n", prog_point.guest_instr_count);

    RR_prog_point pp = pp_last_copied_log_entry;
    end_count = prog_point.guest_instr_count;
    if (pp.guest_instr_count < end_count) {
        printf ("because actual end snip point differs from that requested on cmd line, we need to copy a few additional nd-log entries...\n");
        while (pp.guest_instr_count < end_count && !rr_log_is_empty()) {
            printf ("copied also log entry @ instr %" PRId64 "\n", pp.guest_instr_count);
            pp = copy_entry();
        }
    }


    printf ("rr_queue_empy = %d\n", (int) rr_queue_empty());

    prog_point.guest_instr_count -= actual_start_count;

    RR_header end;
    end.kind = RR_END_OF_LOG;
    end.callsite_loc = RR_CALLSITE_LAST;
    end.prog_point = prog_point;
    sassert(fwrite(&(end.prog_point.guest_instr_count),
                sizeof(end.prog_point.guest_instr_count), 1, newlog) == 1, 14);
    sassert(fwrite(&(end.kind), 1, 1, newlog) == 1, 15);
    sassert(fwrite(&(end.callsite_loc), 1, 1, newlog) == 1, 16);

    rewind(newlog);
    fwrite(&prog_point.guest_instr_count,
            sizeof(prog_point.guest_instr_count), 1, newlog);
    fclose(newlog);

    if (newlog_rr2) {
        write_to_rr2();
    }
    clean_up();
    printf("...complete!\n");
    done = true;
}

bool request_start_snip = false;
bool snip_started = false;
bool snip_done = false;
bool request_end_snip = false;
bool snip_ended = false;

void check_start_snip(CPUState *env) {
    if (!request_start_snip) return;
    // only one snip per replay!
    if (snip_started) return;
    if (snip_ended) return;
    request_start_snip = false;
    snip_started = true;
    start_snip(rr_get_guest_instr_count());
}

void check_end_snip(CPUState *env) {
    if (!request_end_snip) return;
    if (snip_ended) return;
    request_end_snip = false;
    snip_ended = true;
    end_snip();
}

void before_block_exec(CPUState *env, TranslationBlock *tb) {
    uint64_t count = rr_get_guest_instr_count();
    if (!snipping && count+tb->icount > start_count) {
        panda_exit_loop = true;
        request_start_snip = true;
    }
    if (snipping && !done && count > end_count) {
        panda_exit_loop = true;
        request_end_snip = true;
        panda_replay_end();
    }
    return;
}

static inline char*  initialize_file_name(char* sciss_dir, const char* name, const char* ext) {
    size_t needed;
    needed = snprintf(NULL, 0, "%s/%s%s", sciss_dir, name, ext);
    char * file_name = malloc(needed+1);
    snprintf(file_name, needed+1, "%s/%s%s", sciss_dir, name, ext);
    return file_name;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.top_loop = check_start_snip;
    panda_register_callback(self, PANDA_CB_TOP_LOOP, pcb);

    pcb.top_loop = check_end_snip;
    panda_register_callback(self, PANDA_CB_TOP_LOOP, pcb);


    start_count = 0;
    end_count = UINT64_MAX;
    const char *name = "scissors";

    panda_arg_list *args = panda_get_args("scissors");
    if (args != NULL) {
        name = panda_parse_string_req(args, "name", "name of the scissored replay");
        start_count = panda_parse_uint64_opt(args, "start", 0, "starting instruction count");
        end_count = panda_parse_uint64_opt(args, "end", UINT64_MAX, "ending instruction count");
    }

    // we will seg fault in savevm if path to scissors files doesnt exist...
    char* name_copy = strdup(name);
    char* rr_base_name = basename(name_copy);
    char* rr_name = remove_rr2_ext(rr_base_name);
    char* sciss_dir = dirname(name_copy);
    DIR* dir = opendir(sciss_dir);
    if (dir) {
        /* Directory exists. */
        closedir(dir);
    } else if (ENOENT == errno) {
        /* Directory does not exist. */
        printf ("Path to scissor files (name arg) does not exist\n");
        return false;
    } else {
        /* opendir() failed for some other reason. */
        printf ("Some other error occurred wrt path to scissor file (name arg)\n");
        return false;
    }

    newlog_rr2 = has_rr2_file_extention(name_copy);
    nondet_name = initialize_file_name(sciss_dir, rr_name, "-rr-nondet.log");
    snp_name = initialize_file_name(sciss_dir, rr_name, "-rr-snp");
    if (newlog_rr2) {
        cmdline_file_name = initialize_file_name(sciss_dir, rr_name, "-rr.cmd");
        new_rr2_name = initialize_file_name(sciss_dir, rr_name, ".rr2");
    }

    free(name_copy);
    free(rr_name);

    return true;
}

void uninit_plugin(void *self) {
    if (snipping && !done) end_snip();
}
