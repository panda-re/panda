#ifndef QEMU_REHOSTING_H
#define QEMU_REHOSTING_H

#include "qemu-common.h"
#include "exec/hwaddr.h"

#define NUM_IRQS        256
//#define NUM_IRQS        192             //TODO: not sure if this setting is Omnia or A9-specific? Need more flexible likely...
#define PPI(irq)        ((irq) + 16)

#define REHOSTING_MAX_CPUS     4
#define REHOSTING_DEFAULT_RAM  1024*1024*1024
#define RAM_LIMIT_GB    4

#define DEBUG_REHOSTING_MACHINE
#ifdef DEBUG_REHOSTING_MACHINE
#define RH_DBG(fmt, ...) \
do { fprintf(stderr, "rehosting_machine: " fmt "\n", ## __VA_ARGS__); } while (0)
#else
#define RH_DBG(fmt, ...) do {} while(0)
#endif

int lookup_gic(const char *cpu_model);
void parse_mem_map(char *map_str);

enum {
    MEM = 0,
    NAND,
    NAND_CONTROLLER,
    DMAC,
    CPUPERIPHS,
    MPCORE_PERIPHBASE,
    GIC_DIST,
    GIC_CPU,
    GIC_V2M,
    GIC_ITS,
    GIC_REDIST,
    UART,
    GPIO,
    GP_TIMER0,
    GP_TIMER1,
    DG_TIMER,
    CACHE_CTRL,
    FLASH,
    VIRT_MMIO,

    MEM_REGION_COUNT
};

typedef struct MemMapEntry {
    hwaddr base;
    hwaddr size;
    char* opt_fn_str;
} MemMapEntry;

typedef struct str_int_map {
    const char* entry_str;
    const int entry_val;
} str_int_map;

// TODO: figure out GIC versions for each QEMU-supported CPU
#define TABLE_CPU_TO_GIC_ENTRIES 2
const str_int_map table_cpu_to_gic [] = {

    {"cortex-a15", 2},
    {"cortex-a9", 1}
    //{"cortex-a8", 0},
    //{"cortex-m3", 0},
    //{"cortex-m4", 0},
    //{"cortex-r5", 0},

};

/* Number of virtio transports to create (0..8; limited by
 * number of available IRQ lines).
 */
//#define NUM_VIRTIO_TRANSPORTS 4
#define NUM_VIRTIO_TRANSPORTS 1

#define MAX_MEM_MAPPED_FILES 10

// https://stackoverflow.com/questions/47346133/how-to-use-a-define-inside-a-format-string
#define MAX_NAME_LEN 1000
#define STR_(X) #X
#define STR(X) STR_(X)

#endif
