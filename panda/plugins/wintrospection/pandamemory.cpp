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

  PandaPhysicalMemory() {
    rcu_read_lock();
    m_max_address = panda_find_max_ram_address();
    rcu_read_unlock();
  }

  pm_addr_t get_max_address() { return m_max_address; }
};

pm_addr_t get_panda_physical_memory_upper_bound(struct PhysicalMemory *pmem) {
  auto papm = (PandaPhysicalMemory *)pmem->opaque;
  return papm->get_max_address();
}

bool read_panda_physical_memory(struct PhysicalMemory *pmem, pm_addr_t addr,
                                uint8_t *buffer, uint64_t size) {
  auto papm = (PandaPhysicalMemory *)pmem->opaque;
  auto max_addr = papm->get_max_address();

  if ((addr + size) > max_addr) {
    return false;
  }
  return 0 == panda_physical_memory_read(addr, buffer, size);
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
