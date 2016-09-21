/* Scissors plugin for making smaller replays.
 *
 * Use -panda-arg scissors:start and -panda-arg scissors:end
 * to control beginning and end of new replay. Output goes to
 * a new replay named "scissors" by default (-panda-arg scissors:name
 * to change)
 */

#include <stdio.h>

#include "panda/plugin.h"
#include "panda/rr/rr_log.h"

#include "migration/migration.h"
#include "include/exec/address-spaces.h"
#include "migration/qemu-file.h"
#include "io/channel-file.h"
#include "sysemu/sysemu.h"

bool init_plugin(void *);
void uninit_plugin(void *);
int before_block_exec(CPUState *env, TranslationBlock *tb);

extern RR_log *rr_nondet_log;

static uint64_t start_count;
static uint64_t actual_start_count;
static uint64_t end_count;

static char nondet_name[128];
static char snp_name[128];

static FILE *oldlog = NULL;
static FILE *newlog = NULL;

static RR_log_entry entry;
static RR_prog_point orig_last_prog_point = {0, 0, 0};

static bool snipping = false;
static bool done = false;

static RR_prog_point copy_entry(void);
static void sassert(bool condition);

static void sassert(bool condition) {
    if (!condition) {
        printf("Assertion failure @ count %lu!\n", entry.header.prog_point.guest_instr_count);
        rr_do_end_replay(true);
    }
}

static inline size_t rr_fwrite(void *ptr, size_t size, size_t nmemb, FILE *f) {
    size_t result = fwrite(ptr, size, nmemb, f);
    sassert(result == nmemb);
    return result;
}

static inline size_t rr_fread(void *ptr, size_t size, size_t nmemb, FILE *f) {
    size_t result = fread(ptr, size, nmemb, f);
    rr_nondet_log->bytes_read += nmemb * size;
    sassert(result == nmemb);
    return result;
}

static inline void rr_fcopy(void *ptr, size_t size, size_t nmemb, FILE *oldlog, FILE *newlog) {
    rr_fread(ptr, size, nmemb, oldlog);
    rr_fwrite(ptr, size, nmemb, newlog);
}

// Returns guest instr count (in old replay counting mode)
static RR_prog_point copy_entry(void) {
    // Code copied from rr_log.c.
    // Copy entry.
    RR_log_entry item;

    rr_fread(&item.header.prog_point, sizeof(item.header.prog_point), 1, oldlog);
    if (item.header.prog_point.guest_instr_count > end_count) {
        // We don't want to copy this one.
        return item.header.prog_point;
    }

    //ph Fix up instruction count
    RR_prog_point original_prog_point = item.header.prog_point;
    item.header.prog_point.guest_instr_count -= actual_start_count;
    rr_fwrite(&item.header.prog_point, sizeof(item.header.prog_point), 1, newlog);

    //mz this is more compact, as it doesn't include extra padding.
#define RR_COPY_ITEM(field) rr_fcopy(&(field), sizeof(field), 1, oldlog, newlog)
    RR_COPY_ITEM(item.header.kind);
    RR_COPY_ITEM(item.header.callsite_loc);

    //mz read the rest of the item
    switch (item.header.kind) {
        case RR_INPUT_1:
            RR_COPY_ITEM(item.variant.input_1);
            break;
        case RR_INPUT_2:
            RR_COPY_ITEM(item.variant.input_2);
            break;
        case RR_INPUT_4:
            RR_COPY_ITEM(item.variant.input_4);
            break;
        case RR_INPUT_8:
            RR_COPY_ITEM(item.variant.input_8);
            break;
        case RR_INTERRUPT_REQUEST:
            RR_COPY_ITEM(item.variant.interrupt_request);
            break;
        case RR_EXIT_REQUEST:
            RR_COPY_ITEM(item.variant.exit_request);
            break;
        case RR_SKIPPED_CALL: {
            RR_skipped_call_args *args = &item.variant.call_args;
            //mz read kind first!
            RR_COPY_ITEM(args->kind);
            switch(args->kind) {
                case RR_CALL_CPU_MEM_RW:
                    RR_COPY_ITEM(args->variant.cpu_mem_rw_args);
                    args->variant.cpu_mem_rw_args.buf =
                        g_malloc(args->variant.cpu_mem_rw_args.len);
                    rr_fcopy(args->variant.cpu_mem_rw_args.buf, 1,
                            args->variant.cpu_mem_rw_args.len,
                            oldlog, newlog);
                case RR_CALL_CPU_MEM_UNMAP:
                    RR_COPY_ITEM(args->variant.cpu_mem_unmap);
                    args->variant.cpu_mem_unmap.buf =
                        g_malloc(args->variant.cpu_mem_unmap.len);
                    rr_fcopy(args->variant.cpu_mem_unmap.buf, 1,
                                args->variant.cpu_mem_unmap.len,
                                oldlog, newlog);
                case RR_CALL_MEM_REGION_CHANGE:
                    RR_COPY_ITEM(args->variant.mem_region_change_args);
                    args->variant.mem_region_change_args.name =
                        g_malloc0(args->variant.mem_region_change_args.len + 1);
                    rr_fcopy(args->variant.mem_region_change_args.name, 1,
                            args->variant.mem_region_change_args.len,
                            oldlog, newlog);
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
                            oldlog, newlog);
                    break;
                default:
                    //mz unimplemented
                    sassert(0);
            }
        } break;
        case RR_LAST:
        case RR_DEBUG:
            //mz nothing to read
            //ph We don't copy RR_LAST here; write out afterwards.
            break;
        default:
            //mz unimplemented
            sassert(0);
    }

    return original_prog_point;
}

static void end_snip(void) {
    RR_prog_point prog_point = rr_prog_point();
    printf("Ending cut-and-paste on prog point:\n");
    rr_spit_prog_point(prog_point);
    prog_point.guest_instr_count -= actual_start_count;

    RR_header end;
    end.kind = RR_LAST;
    end.callsite_loc = RR_CALLSITE_LAST;
    end.prog_point = prog_point;
    sassert(fwrite(&(end.prog_point), sizeof(end.prog_point), 1, newlog) == 1);
    sassert(fwrite(&(end.kind), sizeof(end.kind), 1, newlog) == 1);
    sassert(fwrite(&(end.callsite_loc), sizeof(end.callsite_loc), 1, newlog) == 1);

    rewind(newlog);
    fwrite(&prog_point, sizeof(RR_prog_point), 1, newlog);
    fclose(newlog);

    done = true;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    uint64_t count = rr_get_guest_instr_count();
    if (!snipping && count+tb->icount > start_count) {
        sassert((oldlog = fopen(rr_nondet_log->name, "r")));
        sassert(fread(&orig_last_prog_point, sizeof(RR_prog_point), 1, oldlog) == 1);
        printf("Original ending prog point: ");
        rr_spit_prog_point(orig_last_prog_point);

        actual_start_count = count;
        printf("Saving snapshot at instr count %lu...\n", count);

        // Force running state
        global_state_store_running();
        printf("writing snapshot:\t%s\n", snp_name);
        QIOChannelFile* ioc =
            qio_channel_file_new_path(snp_name, O_WRONLY | O_CREAT, 0660, NULL);
        QEMUFile* snp = qemu_fopen_channel_output(QIO_CHANNEL(ioc));
        qemu_savevm_state(snp, NULL);
        qemu_fclose(snp);

        printf("Beginning cut-and-paste process at prog point:\n");
        rr_spit_prog_point(rr_prog_point());
        printf("Writing entries to %s...\n", nondet_name);
        newlog = fopen(nondet_name, "w");
        sassert(newlog);
        // We'll fix this up later.
        RR_prog_point prog_point = {0, 0, 0};
        fwrite(&prog_point, sizeof(RR_prog_point), 1, newlog);

        fseek(oldlog, ftell(rr_nondet_log->fp), SEEK_SET);

        // If there are items in the queue, then start copying the log
        // from there
        RR_log_entry *item = rr_get_queue_head();
        if (item != NULL) fseek(oldlog, item->header.file_pos, SEEK_SET);

        while (prog_point.guest_instr_count < end_count && !feof(oldlog)) {
            prog_point = copy_entry();
        }
        if (!feof(oldlog)) { // prog_point is the first one AFTER what we want
            printf("Reached end of old nondet log.\n");
        } else {
            printf("Past desired ending point for log.\n");
        }

        snipping = true;
        printf("Continuing with replay.\n");
    }

    if (snipping && !done && count > end_count) {
        end_snip();

        rr_end_replay_requested = 1;
    }

    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    start_count = 0;
    end_count = UINT64_MAX;
    const char *name = "scissors";

    panda_arg_list *args = panda_get_args("scissors");
    if (args != NULL) {
        name = panda_parse_string(args, "name", "scissors");
        start_count = panda_parse_uint64(args, "start", 0);
        end_count = panda_parse_uint64(args, "end", UINT64_MAX);
    }

    snprintf(nondet_name, 128, "%s-rr-nondet.log", name);
    snprintf(snp_name, 128, "%s-rr-snp", name);

    return true;
}

void uninit_plugin(void *self) {
    if (snipping && !done) end_snip();
}
