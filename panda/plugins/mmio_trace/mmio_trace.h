#include "panda/plugin.h"
#include "panda/common.h"

// Struct instead of std::tuple for C-compatible API
typedef struct mmio_event_t {
    char access_type;
    target_ulong phys_addr;
    int size;
    uint64_t value;
} mmio_event_t;