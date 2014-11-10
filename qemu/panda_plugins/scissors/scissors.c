/* Scissors plugin for making smaller replays.
 *
 * Use -panda-arg scissors:start and -panda-arg scissors:end
 * to control beginning and end of new replay. Output goes to
 * a new replay named "scissors" by default (-panda-arg scissors:name
 * to change)
 */

#include <stdio.h>

#include "panda_plugin.h"
#include "panda_common.h"

#include "rr_log.h"
#include "monitor.h"
#include "sysemu.h"
#include "qemu-timer.h"

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

// Returns guest instr count (in old replay counting mode)
static void write_entry(RR_log_entry *item) {
    // Code copied from rr_log.c.
    
    // Copy entry.
    entry = *item;
    item = &entry;

    if (item->header.prog_point.guest_instr_count > end_count) {
        // We don't want to copy this one.
        return;
    }

    //ph Fix up instruction count
    item->header.prog_point.guest_instr_count -= actual_start_count;
    sassert(fwrite(&(item->header.prog_point), sizeof(RR_prog_point), 1, newlog) == 1);

    //mz this is more compact, as it doesn't include extra padding.
    sassert(fwrite(&(item->header.kind), sizeof(item->header.kind), 1, newlog) == 1);
    sassert(fwrite(&(item->header.callsite_loc), sizeof(item->header.callsite_loc), 1, newlog) == 1);

    //mz read the rest of the item
    switch (item->header.kind) {
        case RR_INPUT_1:
            sassert(fwrite(&(item->variant.input_1), sizeof(item->variant.input_1), 1, newlog) == 1);
            break;
        case RR_INPUT_2:
            sassert(fwrite(&(item->variant.input_2), sizeof(item->variant.input_2), 1, newlog) == 1);
            break;
        case RR_INPUT_4:
            sassert(fwrite(&(item->variant.input_4), sizeof(item->variant.input_4), 1, newlog) == 1);
            break;
        case RR_INPUT_8:
            sassert(fwrite(&(item->variant.input_8), sizeof(item->variant.input_8), 1, newlog) == 1);
            break;
        case RR_INTERRUPT_REQUEST:
            sassert(fwrite(&(item->variant.interrupt_request),
                        sizeof(item->variant.interrupt_request), 1, newlog) == 1);
            break;
        case RR_EXIT_REQUEST:
            sassert(fwrite(&(item->variant.exit_request),
                        sizeof(item->variant.exit_request), 1, newlog) == 1);
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item->variant.call_args;
                //mz read kind first!
                sassert(fwrite(&(args->kind), sizeof(args->kind), 1, newlog) == 1);
                switch(args->kind) {
                    case RR_CALL_CPU_MEM_RW:
                        sassert(fwrite(&(args->variant.cpu_mem_rw_args),
                                    sizeof(args->variant.cpu_mem_rw_args), 1, newlog) == 1);
                        //mz buffer length in args->variant.cpu_mem_rw_args.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.cpu_mem_rw_args.buf = g_malloc(args->variant.cpu_mem_rw_args.len);
                        //mz read the buffer
                        sassert(fwrite(args->variant.cpu_mem_rw_args.buf, 1,
                                    args->variant.cpu_mem_rw_args.len, newlog) > 0);
                        break;
                    case RR_CALL_CPU_MEM_UNMAP:
                        sassert(fwrite(&(args->variant.cpu_mem_unmap),
                                    sizeof(args->variant.cpu_mem_unmap), 1, newlog) == 1);
                        sassert(fwrite(args->variant.cpu_mem_unmap.buf, 1,
                                    args->variant.cpu_mem_unmap.len, newlog) > 0);
                        //free(args->variant.cpu_mem_unmap.buf);
                        break;

                    case RR_CALL_CPU_REG_MEM_REGION:
                        sassert(fwrite(&(args->variant.cpu_mem_reg_region_args), 
                                    sizeof(args->variant.cpu_mem_reg_region_args), 1, newlog) == 1);
                        break;

                    case RR_CALL_HD_TRANSFER:
                        sassert(fwrite(&(args->variant.hd_transfer_args),
                                    sizeof(args->variant.hd_transfer_args), 1, newlog) == 1);
                        break;

                    case RR_CALL_NET_TRANSFER:
                        sassert(fwrite(&(args->variant.net_transfer_args),
                                    sizeof(args->variant.net_transfer_args), 1, newlog) == 1);
                        break;

                    case RR_CALL_HANDLE_PACKET:
                        sassert(fwrite(&(args->variant.handle_packet_args), 
                                    sizeof(args->variant.handle_packet_args), 1, newlog) == 1);
                        sassert(fwrite(args->variant.handle_packet_args.buf, 
                                    args->variant.handle_packet_args.size, 1,
                                    newlog) == 1 /*> 0*/);
                        //free(args->variant.handle_packet_args.buf);
                        break;

                    default:
                        //mz unimplemented
                        sassert(0);
                }
            }
            break;
        case RR_LAST:
        case RR_DEBUG:
            //mz nothing to read
            break;
        default:
            //mz unimplemented
            sassert(0);
    }
}

// Returns guest instr count (in old replay counting mode)
static RR_prog_point copy_entry(void) {
    // Code copied from rr_log.c.
    // Copy entry.
    RR_log_entry *item = &entry;

    //mz XXX we assume that the log is not trucated - should probably fix this.
    if (fread(&(item->header.prog_point), sizeof(RR_prog_point), 1, oldlog) != 1) {
        //mz an error occurred
        if (feof(oldlog)) {
            // replay is done - we've reached the end of file
            //mz we should never get here!
            sassert(0);
        } 
        else {
            //mz some other kind of error
            //mz XXX something more graceful, perhaps?
            sassert(0);
        }
    }
    if (item->header.prog_point.guest_instr_count > end_count) {
        // We don't want to copy this one.
        return item->header.prog_point;
    }

    //ph Fix up instruction count
    RR_prog_point original_prog_point = item->header.prog_point;
    item->header.prog_point.guest_instr_count -= actual_start_count;
    sassert(fwrite(&(item->header.prog_point), sizeof(RR_prog_point), 1, newlog) == 1);

    //mz this is more compact, as it doesn't include extra padding.
    sassert(fread(&(item->header.kind), sizeof(item->header.kind), 1, oldlog) == 1);
    sassert(fread(&(item->header.callsite_loc), sizeof(item->header.callsite_loc), 1, oldlog) == 1);
    sassert(fwrite(&(item->header.kind), sizeof(item->header.kind), 1, newlog) == 1);
    sassert(fwrite(&(item->header.callsite_loc), sizeof(item->header.callsite_loc), 1, newlog) == 1);

    //mz read the rest of the item
    switch (item->header.kind) {
        case RR_INPUT_1:
            sassert(fread(&(item->variant.input_1), sizeof(item->variant.input_1), 1, oldlog) == 1);
            sassert(fwrite(&(item->variant.input_1), sizeof(item->variant.input_1), 1, newlog) == 1);
            break;
        case RR_INPUT_2:
            sassert(fread(&(item->variant.input_2), sizeof(item->variant.input_2), 1, oldlog) == 1);
            sassert(fwrite(&(item->variant.input_2), sizeof(item->variant.input_2), 1, newlog) == 1);
            break;
        case RR_INPUT_4:
            sassert(fread(&(item->variant.input_4), sizeof(item->variant.input_4), 1, oldlog) == 1);
            sassert(fwrite(&(item->variant.input_4), sizeof(item->variant.input_4), 1, newlog) == 1);
            break;
        case RR_INPUT_8:
            sassert(fread(&(item->variant.input_8), sizeof(item->variant.input_8), 1, oldlog) == 1);
            sassert(fwrite(&(item->variant.input_8), sizeof(item->variant.input_8), 1, newlog) == 1);
            break;
        case RR_INTERRUPT_REQUEST:
            sassert(fread(&(item->variant.interrupt_request),
                        sizeof(item->variant.interrupt_request), 1, oldlog) == 1);
            sassert(fwrite(&(item->variant.interrupt_request),
                        sizeof(item->variant.interrupt_request), 1, newlog) == 1);
            break;
        case RR_EXIT_REQUEST:
            sassert(fread(&(item->variant.exit_request),
                        sizeof(item->variant.exit_request), 1, oldlog) == 1);
            sassert(fwrite(&(item->variant.exit_request),
                        sizeof(item->variant.exit_request), 1, newlog) == 1);
            break;
        case RR_SKIPPED_CALL:
            {
                RR_skipped_call_args *args = &item->variant.call_args;
                //mz read kind first!
                sassert(fread(&(args->kind), sizeof(args->kind), 1, oldlog) == 1);
                sassert(fwrite(&(args->kind), sizeof(args->kind), 1, newlog) == 1);
                switch(args->kind) {
                    case RR_CALL_CPU_MEM_RW:
                        sassert(fread(&(args->variant.cpu_mem_rw_args),
                                    sizeof(args->variant.cpu_mem_rw_args), 1, oldlog) == 1);
                        sassert(fwrite(&(args->variant.cpu_mem_rw_args),
                                    sizeof(args->variant.cpu_mem_rw_args), 1, newlog) == 1);
                        //mz buffer length in args->variant.cpu_mem_rw_args.len
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.cpu_mem_rw_args.buf = g_malloc(args->variant.cpu_mem_rw_args.len);
                        //mz read the buffer
                        sassert(fread(args->variant.cpu_mem_rw_args.buf, 1,
                                    args->variant.cpu_mem_rw_args.len, oldlog) > 0);
                        sassert(fwrite(args->variant.cpu_mem_rw_args.buf, 1,
                                    args->variant.cpu_mem_rw_args.len, newlog) > 0);
                        break;
                    case RR_CALL_CPU_MEM_UNMAP:
                        sassert(fread(&(args->variant.cpu_mem_unmap),
                                    sizeof(args->variant.cpu_mem_unmap), 1, oldlog) == 1);
                        sassert(fwrite(&(args->variant.cpu_mem_unmap),
                                    sizeof(args->variant.cpu_mem_unmap), 1, newlog) == 1);
                        args->variant.cpu_mem_unmap.buf = malloc(args->variant.cpu_mem_unmap.len);
                        sassert(fread(args->variant.cpu_mem_unmap.buf, 1,
                                    args->variant.cpu_mem_unmap.len, oldlog) > 0);
                        sassert(fwrite(args->variant.cpu_mem_unmap.buf, 1,
                                    args->variant.cpu_mem_unmap.len, newlog) > 0);
                        //free(args->variant.cpu_mem_unmap.buf);
                        break;

                    case RR_CALL_CPU_REG_MEM_REGION:
                        sassert(fread(&(args->variant.cpu_mem_reg_region_args), 
                                    sizeof(args->variant.cpu_mem_reg_region_args), 1, oldlog) == 1);
                        sassert(fwrite(&(args->variant.cpu_mem_reg_region_args), 
                                    sizeof(args->variant.cpu_mem_reg_region_args), 1, newlog) == 1);
                        break;

                    case RR_CALL_HD_TRANSFER:
                        sassert(fread(&(args->variant.hd_transfer_args),
                                    sizeof(args->variant.hd_transfer_args), 1, oldlog) == 1);
                        sassert(fwrite(&(args->variant.hd_transfer_args),
                                    sizeof(args->variant.hd_transfer_args), 1, newlog) == 1);
                        break;

                    case RR_CALL_NET_TRANSFER:
                        sassert(fread(&(args->variant.net_transfer_args),
                                    sizeof(args->variant.net_transfer_args), 1, oldlog) == 1);
                        sassert(fwrite(&(args->variant.net_transfer_args),
                                    sizeof(args->variant.net_transfer_args), 1, newlog) == 1);
                        break;

                    case RR_CALL_HANDLE_PACKET:
                        sassert(fread(&(args->variant.handle_packet_args), 
                                    sizeof(args->variant.handle_packet_args), 1, oldlog) == 1);
                        sassert(fwrite(&(args->variant.handle_packet_args), 
                                    sizeof(args->variant.handle_packet_args), 1, newlog) == 1);
                        //mz XXX HACK
                        args->old_buf_addr = (uint64_t) args->variant.handle_packet_args.buf;
                        //mz buffer length in args->variant.cpu_mem_rw_args.len 
                        //mz always allocate a new one. we free it when the item is added to the recycle list
                        args->variant.handle_packet_args.buf = 
                            malloc(args->variant.handle_packet_args.size);
                        //mz read the buffer 
                        sassert(fread(args->variant.handle_packet_args.buf, 
                                    args->variant.handle_packet_args.size, 1,
                                    oldlog) == 1 /*> 0*/);
                        sassert(fwrite(args->variant.handle_packet_args.buf, 
                                    args->variant.handle_packet_args.size, 1,
                                    newlog) == 1 /*> 0*/);
                        //free(args->variant.handle_packet_args.buf);
                        break;

                    default:
                        //mz unimplemented
                        sassert(0);
                }
            }
            break;
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
    RR_prog_point prog_point = rr_prog_point;
    printf("Ending cut-and-paste on prog point:\n");
    rr_spit_prog_point(rr_prog_point);
    prog_point.guest_instr_count -= actual_start_count;

    RR_header end;
    end.kind = RR_LAST;
    end.callsite_loc = RR_CALLSITE_LAST;
    end.prog_point = rr_prog_point;
    end.prog_point.guest_instr_count -= actual_start_count;
    sassert(fwrite(&(end.prog_point), sizeof(end.prog_point), 1, newlog) == 1);
    sassert(fwrite(&(end.kind), sizeof(end.kind), 1, newlog) == 1);
    sassert(fwrite(&(end.callsite_loc), sizeof(end.callsite_loc), 1, newlog) == 1);

    rewind(newlog);
    fwrite(&prog_point, sizeof(RR_prog_point), 1, newlog);
    fclose(newlog);

    done = true;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    uint64_t count = rr_prog_point.guest_instr_count;
    if (!snipping && count+tb->num_guest_insns > start_count) {
        sassert((oldlog = fopen(rr_nondet_log->name, "r")));
        sassert(fread(&orig_last_prog_point, sizeof(RR_prog_point), 1, oldlog) == 1);
        printf("Original ending prog point: ");
        rr_spit_prog_point(orig_last_prog_point);

        actual_start_count = count;
        printf("Saving snapshot at instr count %lu...\n", count);
        do_savevm_rr(get_monitor(), snp_name);

        printf("Beginning cut-and-paste process at prog point:\n");
        rr_spit_prog_point(rr_prog_point);
        printf("Writing entries to %s...\n", nondet_name);
        newlog = fopen(nondet_name, "w");
        sassert(newlog);
        // We'll fix this up later.
        RR_prog_point prog_point = {0, 0, 0};
        fwrite(&prog_point, sizeof(RR_prog_point), 1, newlog);

        fseek(oldlog, ftell(rr_nondet_log->fp), SEEK_SET);

        RR_log_entry *item = rr_get_queue_head();
        while (item != NULL && item->header.prog_point.guest_instr_count < end_count) {
            write_entry(item);
            item = item->next;
        }
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

        init_timer_alarm();
        rr_do_end_replay(0);
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
        int i;
        for (i = 0; i < args->nargs; i++) {
            if (0 == strncmp(args->list[i].key, "start", 5)) {
                start_count = strtoul(args->list[i].value, NULL, 10);
            } else if (0 == strncmp(args->list[i].key, "end", 3)) {
                end_count = strtoul(args->list[i].value, NULL, 10);
            } else if (0 == strncmp(args->list[i].key, "name", 4)) {
                name = args->list[i].value;
            }
        }
    }

    snprintf(nondet_name, 128, "%s-rr-nondet.log", name);
    snprintf(snp_name, 128, "%s-rr-snp", name);

    return true;
}

void uninit_plugin(void *self) {
    if (snipping && !done) end_snip();
}
