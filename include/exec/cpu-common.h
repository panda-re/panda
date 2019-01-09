#ifndef CPU_COMMON_H
#define CPU_COMMON_H

/* CPU interfaces that are target independent.  */

#ifndef CONFIG_USER_ONLY
#include "exec/hwaddr.h"
#endif

#include "qemu/bswap.h"
#include "qemu/queue.h"
#include "qemu/fprintf-fn.h"

/**
 * CPUListState:
 * @cpu_fprintf: Print function.
 * @file: File to print to using @cpu_fprint.
 *
 * State commonly used for iterating over CPU models.
 */
typedef struct CPUListState {
    fprintf_function cpu_fprintf;
    FILE *file;
} CPUListState;

/* The CPU list lock nests outside tb_lock/tb_unlock.  */
void qemu_init_cpu_list(void);
void cpu_list_lock(void);
void cpu_list_unlock(void);

#if !defined(CONFIG_USER_ONLY)

enum device_endian {
    DEVICE_NATIVE_ENDIAN,
    DEVICE_BIG_ENDIAN,
    DEVICE_LITTLE_ENDIAN,
};

#if defined(HOST_WORDS_BIGENDIAN)
#define DEVICE_HOST_ENDIAN DEVICE_BIG_ENDIAN
#else
#define DEVICE_HOST_ENDIAN DEVICE_LITTLE_ENDIAN
#endif

/* address in the RAM (different from a physical address) */
#if defined(CONFIG_XEN_BACKEND)
typedef uint64_t ram_addr_t;
#  define RAM_ADDR_MAX UINT64_MAX
#  define RAM_ADDR_FMT "%" PRIx64
#else
typedef uintptr_t ram_addr_t;
#  define RAM_ADDR_MAX UINTPTR_MAX
#  define RAM_ADDR_FMT "%" PRIxPTR
#endif

extern ram_addr_t ram_size;

/* memory API */

typedef void CPUWriteMemoryFunc(void *opaque, hwaddr addr, uint32_t value);
typedef uint32_t CPUReadMemoryFunc(void *opaque, hwaddr addr);

void qemu_ram_remap(ram_addr_t addr, ram_addr_t length);
/* This should not be used by devices.  */
ram_addr_t qemu_ram_addr_from_host(void *ptr);
RAMBlock *qemu_ram_block_by_name(const char *name);
RAMBlock *qemu_ram_block_from_host(void *ptr, bool round_offset,
                                   ram_addr_t *offset);
void qemu_ram_set_idstr(RAMBlock *block, const char *name, DeviceState *dev);
void qemu_ram_unset_idstr(RAMBlock *block);
const char *qemu_ram_get_idstr(RAMBlock *rb);
size_t qemu_ram_pagesize(RAMBlock *block);
size_t qemu_ram_pagesize_largest(void);



void cpu_physical_memory_rw(hwaddr addr, uint8_t *buf,
                            int len, int is_write);
static inline void cpu_physical_memory_read(hwaddr addr,
                                            void *buf, int len)
{
    cpu_physical_memory_rw(addr, (uint8_t *) buf, len, 0);
}
static inline void cpu_physical_memory_write(hwaddr addr,
                                             const void *buf, int len)
{
    cpu_physical_memory_rw(addr, (uint8_t *)buf, len, 1);
}
void *cpu_physical_memory_map(hwaddr addr,
                              hwaddr *plen,
                              int is_write);
void cpu_physical_memory_unmap(void *buffer, hwaddr len,
                               int is_write, hwaddr access_len);
void cpu_register_map_client(QEMUBH *bh);
void cpu_unregister_map_client(QEMUBH *bh);

bool cpu_physical_memory_is_io(hwaddr phys_addr);

/* Coalesced MMIO regions are areas where write operations can be reordered.
 * This usually implies that write operations are side-effect free.  This allows
 * batching which can make a major impact on performance when using
 * virtualization.
 */
void qemu_flush_coalesced_mmio_buffer(void);

void cpu_physical_memory_write_rom(AddressSpace *as, hwaddr addr,
                                   const uint8_t *buf, int len);
void cpu_flush_icache_range(hwaddr start, int len);

extern struct MemoryRegion io_mem_rom;
extern struct MemoryRegion io_mem_notdirty;

typedef int (RAMBlockIterFunc)(const char *block_name, void *host_addr,
    ram_addr_t offset, ram_addr_t length, void *opaque);

int qemu_ram_foreach_block(RAMBlockIterFunc func, void *opaque);
int ram_block_discard_range(RAMBlock *rb, uint64_t start, size_t length);


#endif

#endif /* CPU_COMMON_H */
