#ifndef __RR_LOG_H_
#define __RR_LOG_H_

/* Target-specific code for record and replay.
   This is mostly code that relies on things like target_phys_addr_t and
   ram_addr_t. Note that record/replay currently only works in whole-system
   mode.
*/

#include "cpu.h"
#include "targphys.h"
#include "rr_log_all.h"

// accessors
uint64_t rr_get_pc(void);
uint64_t rr_get_secondary(void);
uint64_t rr_get_guest_instr_count (void);


void rr_clear_rr_guest_instr_count(CPUState *cpu_state);

//mz structure for arguments to cpu_physical_memory_rw()
typedef struct {
    target_phys_addr_t addr;
    uint8_t *buf;
    uint32_t len;
} RR_cpu_mem_rw_args;

//mz structure for arguments to cpu_register_physical_memory()
typedef struct {
    target_phys_addr_t start_addr;
    ram_addr_t size;
    ram_addr_t phys_offset;
} RR_cpu_reg_mem_region_args;

// structure for arguments to cpu_physical_memory_unmap
typedef struct {
    target_phys_addr_t addr;
    uint8_t *buf;
    target_phys_addr_t len;
} RR_cpu_mem_unmap;

void rr_record_cpu_mem_rw_call(RR_callsite_id call_site, target_phys_addr_t addr, uint8_t *buf, int len, int is_write);
void rr_record_cpu_reg_io_mem_region(RR_callsite_id call_site, target_phys_addr_t start_addr, ram_addr_t size, ram_addr_t phys_offset);
void rr_record_cpu_mem_unmap(RR_callsite_id call_site, target_phys_addr_t addr, uint8_t *buf, target_phys_addr_t len, int is_write);

static inline void rr_cpu_physical_memory_unmap_record(target_phys_addr_t addr, uint8_t *buf, target_phys_addr_t len, int is_write) {
  rr_record_cpu_mem_unmap((RR_callsite_id) rr_skipped_callsite_location, addr, buf, len, is_write);
}

//mz XXX addr should be target_phys_addr_t
static inline void rr_device_mem_rw_call_record(target_phys_addr_t addr, uint8_t *buf, int len, int is_write) {
    rr_record_cpu_mem_rw_call((RR_callsite_id) rr_skipped_callsite_location, addr, buf, len, is_write);
}

//mz XXX addr should be target_phys_addr_t
static inline void rr_reg_mem_call_record(target_phys_addr_t start_addr, ram_addr_t size, ram_addr_t phys_offset) {
    rr_record_cpu_reg_io_mem_region((RR_callsite_id) rr_skipped_callsite_location, start_addr, size, phys_offset);
}

//mz using uint8_t for kind and callsite_loc to control space - enums default to int.
//mz NOTE: make sure RR_callsite_id has at most 255 members
//mz NOTE: make sure RR_log_entry_kind has at most 255 members
typedef struct {
    RR_prog_point prog_point;
    uint8_t kind;
    uint8_t callsite_loc;  //mz This is used for another sanity check
} RR_header;

//mz generic args
typedef struct {
    uint8_t kind;
    union {
        RR_cpu_reg_mem_region_args cpu_mem_reg_region_args;
        RR_cpu_mem_rw_args cpu_mem_rw_args;
        RR_cpu_mem_unmap cpu_mem_unmap;
        RR_hd_transfer_args hd_transfer_args;
        RR_net_transfer_args net_transfer_args;
        RR_handle_packet_args handle_packet_args;
    } variant;
    //mz XXX HACK 
  uint64_t old_buf_addr;
} RR_skipped_call_args;

// an item in a program-point indexed record/replay log
typedef struct rr_log_entry_t {
    RR_header header;
    //mz all possible options, depending on log_entry.kind
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
        uint16_t interrupt_request;         //mz 2-bytes is enough for the interrupt request value!
        // if log_entry.kind == RR_EXIT_REQUEST
        uint16_t exit_request;
        // if log_entry.kind == RR_SKIPPED_CALL
        RR_skipped_call_args call_args;
        // if log_entry.kind == RR_LAST
        // no variant fields
    } variant;
    struct rr_log_entry_t *next;
} RR_log_entry;

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

RR_log_entry *rr_get_queue_head(void);

#endif
