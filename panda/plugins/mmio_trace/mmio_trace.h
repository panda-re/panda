#include "panda/plugin.h"
#include "panda/common.h"

// Struct instead of std::tuple for C-compatible API
typedef struct mmio_event_t {
    char access_type;
    vaddr prog_counter;
    target_ptr_t phys_addr;
    size_t size;
    uint64_t value;
} mmio_event_t;
