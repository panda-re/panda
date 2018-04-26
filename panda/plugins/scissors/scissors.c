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

void check_start_snip(CPUState *env);
void check_end_snip(CPUState *env);

extern bool panda_exit_loop;

static uint64_t start_count;
static uint64_t actual_start_count;
static uint64_t end_count;

static char nondet_name[128];
static char snp_name[128];

static FILE *oldlog = NULL;
static FILE *newlog = NULL;

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

static INLINEIT size_t rr_fread(void *ptr, size_t size, size_t nmemb, FILE *f) {
    size_t result = fread(ptr, size, nmemb, f);
    sassert(result == nmemb, 2);
    return result;
}

static INLINEIT void rr_fcopy(void *ptr, size_t size, size_t nmemb, FILE *oldlog, FILE *newlog) {
    rr_fread(ptr, size, nmemb, oldlog);
    rr_fwrite(ptr, size, nmemb, newlog);
}

static INLINEIT RR_log_entry *alloc_new_entry(void) 
{
    static RR_log_entry *new_entry = NULL;
    if(!new_entry) new_entry = g_new(RR_log_entry, 1);
    memset(new_entry, 0, sizeof(RR_log_entry));
    return new_entry;
}

static INLINEIT bool rr_log_is_empty(void) {
    if (rr_nondet_log->type == REPLAY){
        long pos = ftell(oldlog);
        return pos == rr_nondet_log->size;
    } else {
        return false;
    }
}

// Returns guest instr count (in old replay counting mode)
static RR_prog_point copy_entry(void) {
    // Code copied from rr_log.c.
    // Copy entry.
    RR_log_entry *item = alloc_new_entry();

    long pos = ftell(oldlog);

    rr_fread(&(item->header.prog_point.guest_instr_count), sizeof(item->header.prog_point.guest_instr_count), 1, oldlog);

    if (item->header.prog_point.guest_instr_count > end_count) {
        // We don't want to copy this one.
        fseek(oldlog, pos, SEEK_SET);
        return item->header.prog_point;
    }

    //ph Fix up instruction count
    RR_prog_point original_prog_point = item->header.prog_point;
    item->header.prog_point.guest_instr_count -= actual_start_count;
    rr_fwrite(&item->header.prog_point, sizeof(item->header.prog_point), 1, newlog);

#define RR_COPY_ITEM(field) rr_fcopy(&(field), sizeof(field), 1, oldlog, newlog)
    //rw only read 1 byte for kind and callsite_loc even though it's an enum, due to mz's optimization (see rr_log.h)
    rr_fcopy(&(item->header.kind), 1, 1, oldlog, newlog);
    rr_fcopy(&(item->header.callsite_loc), 1, 1, oldlog, newlog);

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
            rr_fcopy(&args->kind, 1, 1, oldlog, newlog);

            switch(args->kind) {
                case RR_CALL_CPU_MEM_RW:
                    RR_COPY_ITEM(args->variant.cpu_mem_rw_args);
                    args->variant.cpu_mem_rw_args.buf =
                        g_malloc(args->variant.cpu_mem_rw_args.len);
                    rr_fcopy(args->variant.cpu_mem_rw_args.buf, 1,
                            args->variant.cpu_mem_rw_args.len,
                            oldlog, newlog);
                    break;
                case RR_CALL_CPU_MEM_UNMAP:
                    RR_COPY_ITEM(args->variant.cpu_mem_unmap);
                    args->variant.cpu_mem_unmap.buf =
                        g_malloc(args->variant.cpu_mem_unmap.len);
                    rr_fcopy(args->variant.cpu_mem_unmap.buf, 1,
                                args->variant.cpu_mem_unmap.len,
                                oldlog, newlog);
                    break;
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


static void start_snip(uint64_t count) {
    sassert((oldlog = fopen(rr_nondet_log->name, "r")), 8);
    sassert(fread(&orig_last_prog_point, sizeof(RR_prog_point), 1, oldlog) == 1, 9);
    printf("Original ending prog point: %" PRId64 "\n", (uint64_t) orig_last_prog_point.guest_instr_count);

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
    
    printf("Beginning cut-and-paste process at prog point: % " PRId64 "\n", (uint64_t) rr_get_guest_instr_count());

    printf("Writing entries to %s...\n", nondet_name);
    newlog = fopen(nondet_name, "w");
    sassert(newlog, 10);
    // We'll fix this up later.
    RR_prog_point prog_point = {0};
    fwrite(&prog_point.guest_instr_count,
           sizeof(prog_point.guest_instr_count), 1, newlog);
    
    fseek(oldlog, ftell(rr_nondet_log->fp), SEEK_SET);
    
    // If there are items in the queue, then start copying the log
    // from there
    RR_log_entry *item = rr_get_queue_head();
    if (item != NULL) fseek(oldlog, item->header.file_pos, SEEK_SET);
    
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
                sizeof(end.prog_point.guest_instr_count), 1, newlog) == 1, 5);
    sassert(fwrite(&(end.kind), 1, 1, newlog) == 1, 6);
    sassert(fwrite(&(end.callsite_loc), 1, 1, newlog) == 1, 7);

    rewind(newlog);
    fwrite(&prog_point.guest_instr_count,
            sizeof(prog_point.guest_instr_count), 1, newlog);
    fclose(newlog);

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


int before_block_exec(CPUState *env, TranslationBlock *tb) {
    uint64_t count = rr_get_guest_instr_count();
    if (!snipping && count+tb->icount > start_count) {
        panda_exit_loop = true;
        request_start_snip = true;
    }
    if (snipping && !done && count > end_count) {
        panda_exit_loop = true;
        request_end_snip = true;
        rr_end_replay_requested = 1;
    }
    return 0;
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

    snprintf(nondet_name, 128, "%s-rr-nondet.log", name);
    snprintf(snp_name, 128, "%s-rr-snp", name);

    return true;
}

void uninit_plugin(void *self) {
    if (snipping && !done) end_snip();
}
