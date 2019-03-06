typedef int size_t;

typedef char gchar;

typedef enum QType {
    QTYPE_NONE = 0,
    QTYPE_QNULL = 1,
    QTYPE_QINT = 2,
    QTYPE_QSTRING = 3,
    QTYPE_QDICT = 4,
    QTYPE_QLIST = 5,
    QTYPE_QFLOAT = 6,
    QTYPE_QBOOL = 7,
    QTYPE__MAX = 8,
} QType;

typedef struct QObject QObject;

struct QObject {
    QType type;
    size_t refcnt;
};


typedef struct GenericAlternate {
    QType type;
    char padding[];
} GenericAlternate;


typedef enum QapiErrorClass {
    QAPI_ERROR_CLASS_GENERICERROR = 0,
    QAPI_ERROR_CLASS_COMMANDNOTFOUND = 1,
    QAPI_ERROR_CLASS_DEVICEENCRYPTED = 2,
    QAPI_ERROR_CLASS_DEVICENOTACTIVE = 3,
    QAPI_ERROR_CLASS_DEVICENOTFOUND = 4,
    QAPI_ERROR_CLASS_KVMMISSINGCAP = 5,
    QAPI_ERROR_CLASS__MAX = 6,
} QapiErrorClass;

typedef enum ErrorClass {
    ERROR_CLASS_GENERIC_ERROR = QAPI_ERROR_CLASS_GENERICERROR,
    ERROR_CLASS_COMMAND_NOT_FOUND = QAPI_ERROR_CLASS_COMMANDNOTFOUND,
    ERROR_CLASS_DEVICE_ENCRYPTED = QAPI_ERROR_CLASS_DEVICEENCRYPTED,
    ERROR_CLASS_DEVICE_NOT_ACTIVE = QAPI_ERROR_CLASS_DEVICENOTACTIVE,
    ERROR_CLASS_DEVICE_NOT_FOUND = QAPI_ERROR_CLASS_DEVICENOTFOUND,
    ERROR_CLASS_KVM_MISSING_CAP = QAPI_ERROR_CLASS_KVMMISSINGCAP,
} ErrorClass;

typedef unsigned long gsize;

typedef struct _GString GString;

struct _GString
{
  gchar *str;
  gsize len;
  gsize allocated_len;
};


typedef struct Error Error;

struct Error
{
    char *msg;
    ErrorClass err_class;
    const char *src, *func;
    int line;
    GString *hint;
};


typedef struct GenericList {
    struct GenericList *next;
    char padding[];
} GenericList;

typedef enum VisitorType {
    VISITOR_INPUT = 1,
    VISITOR_OUTPUT = 2,
    VISITOR_CLONE = 3,
    VISITOR_DEALLOC = 4,
} VisitorType;


typedef struct Visitor Visitor;

struct Visitor
{

    void (*start_struct)(Visitor *v, const char *name, void **obj, size_t size, Error **errp);


    void (*check_struct)(Visitor *v, Error **errp);


    void (*end_struct)(Visitor *v, void **obj);



    void (*start_list)(Visitor *v, const char *name, GenericList **list,
                       size_t size, Error **errp);


    GenericList *(*next_list)(Visitor *v, GenericList *tail, size_t size);


    void (*end_list)(Visitor *v, void **list);



    void (*start_alternate)(Visitor *v, const char *name,
                            GenericAlternate **obj, size_t size,
                            bool promote_int, Error **errp);


    void (*end_alternate)(Visitor *v, void **obj);


    void (*type_int64)(Visitor *v, const char *name, int64_t *obj,
                       Error **errp);


    void (*type_uint64)(Visitor *v, const char *name, uint64_t *obj,
                        Error **errp);


    void (*type_size)(Visitor *v, const char *name, uint64_t *obj,
                      Error **errp);


    void (*type_bool)(Visitor *v, const char *name, bool *obj, Error **errp);


    void (*type_str)(Visitor *v, const char *name, char **obj, Error **errp);


    void (*type_number)(Visitor *v, const char *name, double *obj,
                        Error **errp);


    void (*type_any)(Visitor *v, const char *name, QObject **obj,
                     Error **errp);


    void (*type_null)(Visitor *v, const char *name, Error **errp);



    void (*optional)(Visitor *v, const char *name, bool *present);


    VisitorType type;


    void (*complete)(Visitor *v, void *opaque);


    void (*free)(Visitor *v);
};

typedef void (ObjectPropertyAccessor)(Object *obj,
                                      Visitor *v,
                                      const char *name,
                                      void *opaque,
                                      Error **errp);


typedef Object *(ObjectPropertyResolve)(Object *obj,
                                        void *opaque,
                                        const char *part);


typedef void (ObjectPropertyRelease)(Object *obj,
                                     const char *name,
                                     void *opaque);

typedef struct ObjectProperty
{
    gchar *name;
    gchar *type;
    gchar *description;
    ObjectPropertyAccessor *get;
    ObjectPropertyAccessor *set;
    ObjectPropertyResolve *resolve;
    ObjectPropertyRelease *release;
    void *opaque;
} ObjectProperty;


ObjectClass *cpu_class_by_name(const char *typename, const char *cpu_model);

Object *object_new(const char *typename);

const char *object_class_get_name(ObjectClass *klass);

ObjectClass *object_class_by_name(const char *typename);


ObjectProperty *object_property_find(Object *obj, const char *name, Error **errp);

void object_property_set_bool(Object *obj, bool value,const char *name, Error **errp);

bool object_property_get_bool(Object *obj, const char *name, Error **errp);

void object_property_set_int(Object *obj, int64_t value, const char *name, Error **errp);

int64_t object_property_get_int(Object *obj, const char *name,Error **errp);

void object_property_set_link(Object *obj, Object *value, const char *name, Error **errp);

Object *object_property_get_link(Object *obj, const char *name,Error **errp);

typedef enum {
    IOMMU_NONE = 0,
    IOMMU_RO   = 1,
    IOMMU_WO   = 2,
    IOMMU_RW   = 3,
} IOMMUAccessFlags;

typedef struct Int128 Int128;

struct Int128 {
    uint64_t lo;
    int64_t hi;
};

typedef struct AddrRange AddrRange;

struct AddrRange {
    Int128 start;
    Int128 size;
};

typedef void RCUCBFunc(struct rcu_head *head);

struct rcu_head {
    struct rcu_head *next;
    RCUCBFunc *func;
};







typedef int size_t;



typedef uint64_t ram_addr_t;

typedef struct RAMBlockNotifier RAMBlockNotifier;

typedef struct RAMBlock RAMBlock;

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

typedef struct MemoryRegion MemoryRegion;
typedef struct MemoryListener MemoryListener;

typedef struct MemoryRegionIoeventfd MemoryRegionIoeventfd;

typedef struct AddressSpace AddressSpace;

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

typedef struct IOMMUTLBEntry IOMMUTLBEntry;

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

typedef struct MemoryRegionIOMMUOps MemoryRegionIOMMUOps;

struct MemoryRegionIOMMUOps {
    IOMMUTLBEntry (*translate)(MemoryRegion *iommu, hwaddr addr, bool is_write);
    uint64_t (*get_min_page_size)(MemoryRegion *iommu);
    void (*notify_flag_changed)(MemoryRegion *iommu,
                                IOMMUNotifierFlag old_flags,
                                IOMMUNotifierFlag new_flags);
};

typedef void CPUWriteMemoryFunc(void *opaque, hwaddr addr, uint32_t value);
typedef uint32_t CPUReadMemoryFunc(void *opaque, hwaddr addr);

typedef struct MemoryRegionMmio MemoryRegionMmio;

struct MemoryRegionMmio {
    CPUReadMemoryFunc *read[3];
    CPUWriteMemoryFunc *write[3];
};

typedef uint32_t MemTxResult;

typedef struct MemTxAttrs {
    unsigned int unspecified:1;
    unsigned int secure:1;
    unsigned int user:1;
    unsigned int requester_id:16;
} MemTxAttrs;

enum device_endian {
    DEVICE_NATIVE_ENDIAN,
    DEVICE_BIG_ENDIAN,
    DEVICE_LITTLE_ENDIAN,
};

typedef struct MemoryRegionOps MemoryRegionOps;

struct MemoryRegionOps {
    /* Read from the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    uint64_t (*read)(void *opaque,
                     hwaddr addr,
                     unsigned size);
    /* Write to the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    void (*write)(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size);

    MemTxResult (*read_with_attrs)(void *opaque,
                                   hwaddr addr,
                                   uint64_t *data,
                                   unsigned size,
                                   MemTxAttrs attrs);
    MemTxResult (*write_with_attrs)(void *opaque,
                                    hwaddr addr,
                                    uint64_t data,
                                    unsigned size,
                                    MemTxAttrs attrs);

    enum device_endian endianness;
    /* Guest-visible constraints: */
    struct {
        /* If nonzero, specify bounds on access sizes beyond which a machine
         * check is thrown.
         */
        unsigned min_access_size;
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise unaligned
         * accesses throw machine checks.
         */
         bool unaligned;
        /*
         * If present, and returns #false, the transaction is not accepted
         * by the device (and results in machine dependent behaviour such
         * as a machine check exception).
         */
        bool (*accepts)(void *opaque, hwaddr addr,
                        unsigned size, bool is_write);
    } valid;
    /* Internal implementation constraints: */
    struct {
        /* If nonzero, specifies the minimum size implemented.  Smaller sizes
         * will be rounded upwards and a partial result will be returned.
         */
        unsigned min_access_size;
        /* If nonzero, specifies the maximum size implemented.  Larger sizes
         * will be done as a series of accesses with smaller sizes.
         */
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise all accesses
         * are converted to (possibly multiple) naturally aligned accesses.
         */
        bool unaligned;
    } impl;

    /* If .read and .write are not present, old_mmio may be used for
     * backwards compatibility with old mmio registration
     */
    const MemoryRegionMmio old_mmio;
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

typedef struct FlatRange FlatRange;

struct FlatRange {
    MemoryRegion *mr;
    hwaddr offset_in_region;
    AddrRange addr;
    uint8_t dirty_log_mask;
    bool romd_mode;
    bool readonly;
};

typedef struct FlatView FlatView;

struct FlatView {
    struct rcu_head rcu;
    unsigned ref;
    FlatRange *ranges;
    unsigned nr;
    unsigned nr_allocated;
};

typedef struct MemoryRegionSection MemoryRegionSection;

struct MemoryRegionSection {
    MemoryRegion *mr;
    AddressSpace *address_space;
    hwaddr offset_within_region;
    Int128 size;
    hwaddr offset_within_address_space;
    bool readonly;
};

typedef struct EventNotifier EventNotifier;

struct EventNotifier {



    int rfd;
    int wfd;

};

typedef struct MemoryListener MemoryListener;

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

void memory_region_allocate_system_memory(MemoryRegion *mr, Object *owner, const char *name,uint64_t ram_size);

void memory_region_add_subregion(MemoryRegion *mr, hwaddr offset, MemoryRegion *subregion);


