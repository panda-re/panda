#include "panda/plugin.h"
#include "panda/common.h"

#include <cstdlib>
#include <cstring>

#include <iohal/memory/common.h>
#include <iohal/memory/physical_memory.h>

#include "pandamemory.h"

class PandaPhysicalMemory {
private:
  pm_addr_t m_max_address;

public:
  static const uint32_t PAPM_TAG = 0x5041504d;

  PandaPhysicalMemory() { m_max_address = ram_size; }

  pm_addr_t get_max_address() { return m_max_address; }

  uint8_t get_byte(pm_addr_t addr) {
    uint8_t retval = 0;
    if (addr < m_max_address) {
      panda_physical_memory_rw(addr, &retval, 1, 0);
    }
    return retval;
  }
};

pm_addr_t get_panda_physical_memory_upper_bound(struct PhysicalMemory *pmem) {
  auto papm = (PandaPhysicalMemory *)pmem->opaque;
  return papm->get_max_address();
}

bool read_panda_physical_memory(struct PhysicalMemory *pmem, pm_addr_t addr,
                                uint8_t *buffer, uint64_t size) {
  auto papm = (PandaPhysicalMemory *)pmem->opaque;
  auto max_addr = papm->get_max_address();

  for (size_t ix = 0; ix < size; ++ix) {
    auto current_addr = addr + ix;
    if ((uintptr_t)current_addr > max_addr) {
      return false;
    }
    buffer[ix] = papm->get_byte(current_addr);
  }
  return true;
}

void free_panda_physical_memory(struct PhysicalMemory *pmem) {
  auto papm = (PandaPhysicalMemory *)pmem->opaque;
  delete papm;
  // Memset here for a few reasons:
  //  - Ensure use-after-free bugs fail early (i.e. on a null pointer deref
  //  rather
  //    than on stale data)
  //  - The caller will still have an invalid pointer to pmem, so mistakes are
  //  more
  //    likely
  std::memset(pmem, 0, sizeof(PhysicalMemory));
  std::free(pmem);
}

struct PhysicalMemory *create_panda_physical_memory() {
  // Allocate the backing physical memory object
  PandaPhysicalMemory *papm = new PandaPhysicalMemory();

  // Allocate the wrapper object
  auto pmem =
      (struct PhysicalMemory *)std::calloc(1, sizeof(struct PhysicalMemory));
  if (!pmem) {
    delete papm;
    return nullptr;
  }

  pmem->tagvalue = PandaPhysicalMemory::PAPM_TAG;
  pmem->opaque = papm;
  pmem->upper_bound = get_panda_physical_memory_upper_bound;
  pmem->read = read_panda_physical_memory;
  pmem->free = free_panda_physical_memory;

  return pmem;
}
