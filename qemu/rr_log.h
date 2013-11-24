#ifndef __RR_LOG_H_
#define __RR_LOG_H_

/* Target-specific code for record and replay.
   This is mostly code that relies on things like target_phys_addr_t and
   ram_addr_t. Note that record/replay currently only works in whole-system
   mode.
*/

// Hack to enable QEMU user mode to compile
#if !defined(CONFIG_SOFTMMU)
typedef uint32_t target_phys_addr_t;
typedef uint32_t ram_addr_t;
#endif

#include "rr_log_all.h"

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



typedef enum {
  PIRATE_HD_TRANSFER_HD_TO_IOB,
  PIRATE_HD_TRANSFER_IOB_TO_HD,
  PIRATE_HD_TRANSFER_PORT_TO_IOB,
  PIRATE_HD_TRANSFER_IOB_TO_PORT
} Pirate_hd_transfer;


static const char *pirate_hd_transfer_str[] = {
  "PIRATE_HD_TRANSFER_HD_TO_IOB",
  "PIRATE_HD_TRANSFER_IOB_TO_HD",
  "PIRATE_HD_TRANSFER_PORT_TO_IOB",
  "PIRATE_HD_TRANSFER_IOB_TO_PORT"
} Pirate_hd_transfer;


// structure for arguments to pirate_hd_transfer
typedef struct {
  Pirate_hd_transfer type;   
  uint64_t src_addr;
  uint64_t dest_addr;
  uint32_t num_bytes;
} RR_pirate_hd_transfer;

void rr_record_cpu_mem_rw_call(RR_callsite_id call_site, target_phys_addr_t addr, uint8_t *buf, int len, int is_write);
void rr_record_cpu_reg_io_mem_region(RR_callsite_id call_site, target_phys_addr_t start_addr, ram_addr_t size, ram_addr_t phys_offset);
void rr_record_cpu_mem_unmap(RR_callsite_id call_site, target_phys_addr_t addr, uint8_t *buf, target_phys_addr_t len, int is_write);

static inline void rr_cpu_physical_memory_unmap_record(target_phys_addr_t addr, uint8_t *buf, target_phys_addr_t len, int is_write) {
    rr_record_cpu_mem_unmap(rr_skipped_callsite_location, addr, buf, len, is_write);
}

//mz XXX addr should be target_phys_addr_t
static inline void rr_device_mem_rw_call_record(target_phys_addr_t addr, uint8_t *buf, int len, int is_write) {
    rr_record_cpu_mem_rw_call(rr_skipped_callsite_location, addr, buf, len, is_write);
}

//mz XXX addr should be target_phys_addr_t
static inline void rr_reg_mem_call_record(target_phys_addr_t start_addr, ram_addr_t size, ram_addr_t phys_offset) {
    rr_record_cpu_reg_io_mem_region(rr_skipped_callsite_location, start_addr, size, phys_offset);
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
        RR_pirate_hd_transfer pirate_hd_transfer_args;
    } variant;
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

#endif
