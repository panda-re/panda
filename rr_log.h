#ifndef __RR_LOG_H_
#define __RR_LOG_H_

/* Target-specific code for record and replay.
   This is mostly code that relies on things like hwaddr and
   ram_addr_t. Note that record/replay currently only works in whole-system
   mode.
*/

#include "cpu.h"
#include "rr_log_all.h"

// accessors
uint64_t rr_get_pc(void);
uint64_t rr_get_secondary(void);

// mz structure for arguments to cpu_physical_memory_rw()
typedef struct {
    hwaddr addr;
    uint8_t* buf;
    uint32_t len;
} RR_cpu_mem_rw_args;

// mz structure for arguments to cpu_register_physical_memory()
typedef struct {
    hwaddr start_addr;
    uint64_t size;
    char *name;
    uint32_t len;
    bool added;
} RR_mem_region_change_args;

// structure for arguments to cpu_physical_memory_unmap
typedef struct {
    hwaddr addr;
    uint8_t* buf;
    hwaddr len;
} RR_cpu_mem_unmap;

void rr_record_cpu_mem_rw_call(RR_callsite_id call_site, hwaddr addr,
                               const uint8_t* buf, int len, int is_write);
void rr_record_memory_region_change(RR_callsite_id call_site,
                                     hwaddr start_addr, uint64_t size,
                                     const char *name, bool added);
void rr_record_cpu_mem_unmap(RR_callsite_id call_site, hwaddr addr,
                             uint8_t* buf, hwaddr len, int is_write);

static inline void rr_cpu_physical_memory_unmap_record(hwaddr addr,
                                                       uint8_t* buf, hwaddr len,
                                                       int is_write)
{
    rr_record_cpu_mem_unmap((RR_callsite_id)rr_skipped_callsite_location, addr,
                            buf, len, is_write);
}

// mz XXX addr should be hwaddr
static inline void rr_device_mem_rw_call_record(hwaddr addr, const uint8_t* buf,
                                                int len, int is_write)
{
    rr_record_cpu_mem_rw_call((RR_callsite_id)rr_skipped_callsite_location,
                              addr, buf, len, is_write);
}

// mz XXX addr should be hwaddr
static inline void rr_mem_region_change_record(hwaddr start_addr, uint64_t size,
                                          const char *name, bool added)
{
    rr_record_memory_region_change(
        (RR_callsite_id)rr_skipped_callsite_location, start_addr, size,
        name, added);
}

// mz using uint8_t for kind and callsite_loc to control space - enums default
// to int.
// mz NOTE: make sure RR_callsite_id has at most 255 members
// mz NOTE: make sure RR_log_entry_kind has at most 255 members
typedef struct {
    RR_prog_point prog_point;
    uint8_t kind;
    uint8_t callsite_loc; // mz This is used for another sanity check
} RR_header;

// mz generic args
typedef struct {
    uint8_t kind;
    union {
        
        RR_mem_region_change_args mem_region_change_args;
        RR_cpu_mem_rw_args cpu_mem_rw_args;
        RR_cpu_mem_unmap cpu_mem_unmap;
        RR_hd_transfer_args hd_transfer_args;
        RR_net_transfer_args net_transfer_args;
        RR_handle_packet_args handle_packet_args;
    } variant;
    // mz XXX HACK
    uint64_t old_buf_addr;
} RR_skipped_call_args;

// an item in a program-point indexed record/replay log
typedef struct rr_log_entry_t {
    RR_header header;
    // mz all possible options, depending on log_entry.kind
    union {
        // if log_entry.kind == RR_INPUT_1
        uint8_t input_1;
        // if log_entry.kind == RR_INPUT_2
        uint16_t input_2;
        // if log_entry.kind == RR_INPUT_4
        uint32_t input_4;
        // if log_entry.kind == RR_INPUT_8
        uint64_t input_8;
        // if log_entry.kind == RR_INTERRUPT_REQUEST
        int32_t interrupt_request; // mz 2-bytes is enough for the interrupt
                                    // request value!
        // if log_entry.kind == RR_EXIT_REQUEST
        uint16_t exit_request;
        // if log_entry.kind == RR_SKIPPED_CALL
        RR_skipped_call_args call_args;
        // if log_entry.kind == RR_LAST
        // no variant fields
    } variant;
    struct rr_log_entry_t* next;
} RR_log_entry;

// a program-point indexed record/replay log
typedef enum { RECORD, REPLAY } RR_log_type;
typedef struct RR_log_t {
    // mz TODO this field seems redundant given existence of rr_mode
    RR_log_type type;              // record or replay
    RR_prog_point last_prog_point; // to report progress

    char* name; // file name
    FILE* fp;   // file pointer for log
    unsigned long long
        size; // for a log being opened for read, this will be the size in bytes
    uint64_t bytes_read;

    RR_log_entry current_item;
    uint8_t current_item_valid;
    uint64_t item_number;
} RR_log;

RR_log_entry* rr_get_queue_head(void);

void panda_end_replay(void);

extern RR_log_entry *rr_queue_tail;
static inline uint64_t rr_get_guest_instr_count(void) {
    assert(first_cpu);
    return first_cpu->rr_guest_instr_count;
}

//mz program execution state
static inline RR_prog_point rr_prog_point(void) {
    RR_prog_point ret = {0};
    ret.guest_instr_count = first_cpu->rr_guest_instr_count;
    return ret;
}

static inline uint64_t rr_num_instr_before_next_interrupt(void) {
    if (!rr_queue_tail) {
        return -1;
    }
    RR_log_entry last = *rr_queue_tail;
    switch (last.header.kind) {
        case RR_SKIPPED_CALL:
            if (last.header.callsite_loc != RR_CALLSITE_MAIN_LOOP_WAIT) {
                return -1;
            } // otherwise fall through
        case RR_LAST:
        case RR_INTERRUPT_REQUEST:
            return last.header.prog_point.guest_instr_count -
                rr_get_guest_instr_count();
        default:
            return -1;
    }
}


//void breakpoint_invalidate(CPUState *cpu, target_ulong pc);

#endif
