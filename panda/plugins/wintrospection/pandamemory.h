#ifndef __PANDA_PHYSICAL_MEMORY_H
#define __PANDA_PHYSICAL_MEMORY_H

#include <iohal/memory/physical_memory.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Use PANDA as a physical memory reader for the HAL
 *
 * \return struct PhysicalMemory*
 */
struct PhysicalMemory* create_panda_physical_memory();

#ifdef __cplusplus
}
#endif

#endif
