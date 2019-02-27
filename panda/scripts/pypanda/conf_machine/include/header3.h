typedef struct Error Error;

typedef struct MemoryRegionIoeventfd MemoryRegionIoeventfd;

typedef enum {
    IOMMU_NONE = 0,
    IOMMU_RO   = 1,
    IOMMU_WO   = 2,
    IOMMU_RW   = 3,
} IOMMUAccessFlags;

struct MemoryListener {
    void (*begin)(MemoryListener *listener);
    void (*commit)(MemoryListener *listener);
    void (*region_add)(MemoryListener *listener, MemoryRegionSection *section);
    void (*region_del)(MemoryListener *listener, MemoryRegionSection *section);
    void (*region_nop)(MemoryListener *listener, MemoryRegionSection *section);
    void (*log_start)(MemoryListener *listener, MemoryRegionSection *section,
                      int old, int new);
    void (*log_stop)(MemoryListener *listener, MemoryRegionSection *section,
                     int old, int new);
    void (*log_sync)(MemoryListener *listener, MemoryRegionSection *section);
    void (*log_global_start)(MemoryListener *listener);
    void (*log_global_stop)(MemoryListener *listener);
    void (*eventfd_add)(MemoryListener *listener, MemoryRegionSection *section,
                        bool match_data, uint64_t data, EventNotifier *e);
    void (*eventfd_del)(MemoryListener *listener, MemoryRegionSection *section,
                        bool match_data, uint64_t data, EventNotifier *e);
    void (*coalesced_mmio_add)(MemoryListener *listener, MemoryRegionSection *section,
                               hwaddr addr, hwaddr len);
    void (*coalesced_mmio_del)(MemoryListener *listener, MemoryRegionSection *section,
                               hwaddr addr, hwaddr len);

    unsigned priority;
    AddressSpace *address_space;
    struct { struct MemoryListener *tqe_next; struct MemoryListener * *tqe_prev; } link;
    struct { struct MemoryListener *tqe_next; struct MemoryListener * *tqe_prev; } link_as;
};

struct AddrRange {
    Int128 start;
    Int128 size;
};

struct FlatRange {
    MemoryRegion *mr;
    hwaddr offset_in_region;
    AddrRange addr;
    uint8_t dirty_log_mask;
    bool romd_mode;
    bool readonly;
};

struct rcu_head {
    struct rcu_head *next;
    RCUCBFunc *func;
};

typedef void RCUCBFunc(struct rcu_head *head);

struct FlatView {
    struct rcu_head rcu;
    unsigned ref;
    FlatRange *ranges;
    unsigned nr;
    unsigned nr_allocated;
};

struct AddressSpace {

    struct rcu_head rcu;
    char *name;
    MemoryRegion *root;
    int ref_count;
    bool malloced;


    struct FlatView *current_map;

    int ioeventfd_nb;
    struct MemoryRegionIoeventfd *ioeventfds;
    struct AddressSpaceDispatch *dispatch;
    struct AddressSpaceDispatch *next_dispatch;
    MemoryListener dispatch_listener;
    struct memory_listeners_as { struct MemoryListener *tqh_first; struct MemoryListener * *tqh_last; } listeners;
    struct { struct AddressSpace *tqe_next; struct AddressSpace * *tqe_prev; } address_spaces_link;
};


struct IOMMUTLBEntry {
    AddressSpace    *target_as;
    hwaddr           iova;
    hwaddr           translated_addr;
    hwaddr           addr_mask;  /* 0xfff = 4k translation */
    IOMMUAccessFlags perm;
};

typedef enum {
    IOMMU_NOTIFIER_NONE = 0,

    IOMMU_NOTIFIER_UNMAP = 0x1,

    IOMMU_NOTIFIER_MAP = 0x2,
} IOMMUNotifierFlag;


struct IOMMUNotifier {
    void (*notify)(struct IOMMUNotifier *notifier, IOMMUTLBEntry *data);
    IOMMUNotifierFlag notifier_flags;
    struct { struct IOMMUNotifier *le_next; struct IOMMUNotifier **le_prev; } node;
};

typedef struct IOMMUNotifier IOMMUNotifier;


typedef int size_t;


struct Int128 {
    uint64_t lo;
    int64_t hi;
};

typedef uint64_t ram_addr_t;

typedef struct RAMBlockNotifier RAMBlockNotifier;

struct RAMBlock {
    struct rcu_head rcu;
    struct MemoryRegion *mr;
    uint8_t *host;
    ram_addr_t offset;
    ram_addr_t used_length;
    ram_addr_t max_length;
    void (*resized)(const char*, uint64_t length, void *host);
    uint32_t flags;
    /* Protected by iothread lock.  */
    char idstr[256];
    /* RCU-enabled, writes protected by the ramlist lock */
    struct{
	struct RAMBlock *le_next;
	struct RAMBlock **le_prev;
    } next;
    
    struct {
    	struct RAMBlockNotifier *lh_first;
    } ramblock_notifiers;
    
    int fd;
    size_t page_size;
};

struct MemoryRegion {
    Object parent_obj;

    /* All fields are private - violators will be prosecuted */

    /* The following fields should fit in a cache line */
    bool romd_mode;
    bool ram;
    bool subpage;
    bool readonly; /* For RAM regions */
    bool rom_device;
    bool flush_coalesced_mmio;
    bool global_locking;
    uint8_t dirty_log_mask;
    RAMBlock *ram_block;
    Object *owner;
    const MemoryRegionIOMMUOps *iommu_ops;

    const MemoryRegionOps *ops;
    void *opaque;
    MemoryRegion *container;
    Int128 size;
    hwaddr addr;
    void (*destructor)(MemoryRegion *mr);
    uint64_t align;
    bool terminates;
    bool ram_device;
    bool enabled;
    bool warning_printed; /* For reservations */
    uint8_t vga_logging_count;
    MemoryRegion *alias;
    hwaddr alias_offset;
    int32_t priority;
    struct subregions { struct MemoryRegion *tqh_first; struct MemoryRegion * *tqh_last; } subregions;
    struct { struct MemoryRegion *tqe_next; struct MemoryRegion * *tqe_prev; } subregions_link;
    struct coalesced_ranges { struct CoalescedMemoryRange *tqh_first; struct CoalescedMemoryRange * *tqh_last; } coalesced;
    const char *name;
    unsigned ioeventfd_nb;
    MemoryRegionIoeventfd *ioeventfds;
    struct { struct IOMMUNotifier *lh_first; } iommu_notify;
    IOMMUNotifierFlag iommu_notify_flags;
};

void memory_region_allocate_system_memory(MemoryRegion *mr, Object *owner, const char *name,uint64_t ram_size);

void memory_region_add_subregion(MemoryRegion *mr, hwaddr offset, MemoryRegion *subregion);



