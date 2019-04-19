
typedef int size_t;


typedef uint64_t hwaddr;

typedef struct InterfaceImpl InterfaceImpl;
typedef struct TypeImpl TypeImpl;

struct TypeImpl;
typedef struct TypeImpl *Type;

typedef struct ObjectClass ObjectClass;
typedef struct Object Object;

typedef void (ObjectUnparent)(Object *obj);

typedef struct QemuOpt QemuOpt;
typedef struct QemuOpts QemuOpts;

typedef struct BusState BusState;
typedef struct DeviceState DeviceState;

typedef struct ObjectClass ObjectClass;

typedef struct HotplugHandler HotplugHandler;

typedef struct IRQState *qemu_irq;

typedef void (*qemu_irq_handler)(void *opaque, int n, int level);

struct IRQState {
    Object parent_obj;

    qemu_irq_handler handler;
    void *opaque;
    int n;
};

typedef struct QEMUTimerList QEMUTimerList;

typedef void QEMUTimerCB(void *opaque);

typedef struct QEMUTimer QEMUTimer;

struct QEMUTimer {
	int64_t expire_time;
	QEMUTimerList *timer_list;
	QEMUTimerCB *cb;
	void *opaque;
	QEMUTimer *next;
	int scale;
};

typedef struct {
    QEMUTimer *timer;
    qemu_irq sgi[4][16];                  // Software Generated Interrupts (SGI)
    qemu_irq ppi[4][16]; // Shared Peripheral Interrupts (SPI)
    qemu_irq spi[256];                                         // Private Peripheral Interrupts (PPI)
} machine_irqs;

enum QemuOptType {
    QEMU_OPT_STRING = 0,
    QEMU_OPT_BOOL,
    QEMU_OPT_NUMBER,
    QEMU_OPT_SIZE,
};


typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

typedef struct BusChild {
    DeviceState *child;
    int index;
    struct { struct BusChild *tqe_next; struct BusChild * *tqe_prev; } sibling;
} BusChild;


struct BusState {
    Object obj;
    DeviceState *parent;
    char *name;
    HotplugHandler *hotplug_handler;
    int max_index;
    bool realized;
    struct ChildrenHead { struct BusChild *tqh_first; struct BusChild * *tqh_last; } children;
    struct { struct BusState *le_next; struct BusState **le_prev; } sibling;
};



typedef struct NamedGPIOList NamedGPIOList;

struct NamedGPIOList {
    char *name;
    qemu_irq *in;
    int num_in;
    int num_out;
   // QLIST_ENTRY(NamedGPIOList) node;
    struct node {
        struct NamedGPIOList *le_next;
	struct NamedGPIOList **le_prev;
    };
};


typedef struct Location {

    enum { LOC_NONE, LOC_CMDLINE, LOC_FILE } kind;
    int num;
    const void *ptr;
    struct Location *prev;
} Location;


typedef struct QemuOptDesc {
    const char *name;
    enum QemuOptType type;
    const char *help;
    const char *def_value_str;
} QemuOptDesc;

typedef struct QemuOptsList {
    const char *name;
    const char *implied_opt_name;
    bool merge_lists;
    struct { struct QemuOpts *tqh_first; struct QemuOpts * *tqh_last; } head;
    QemuOptDesc desc[];
} QemuOptsList;


struct QemuOpt {
    char *name;
    char *str;

    const QemuOptDesc *desc;
    union {
        bool boolean;
        uint64_t uint;
    } value;

    QemuOpts *opts;
    struct { struct QemuOpt *tqe_next; struct QemuOpt * *tqe_prev; } next;
};

struct QemuOpts {
    char *id;
    QemuOptsList *list;
    Location loc;
    struct QemuOptHead { struct QemuOpt *tqh_first; struct QemuOpt * *tqh_last; } head;
    struct { struct QemuOpts *tqe_next; struct QemuOpts * *tqe_prev; } next;
};

struct InterfaceImpl
{
    const char *typename;
};


struct TypeImpl
{
    const char *name;

    size_t class_size;

    size_t instance_size;

    void (*class_init)(ObjectClass *klass, void *data);
    void (*class_base_init)(ObjectClass *klass, void *data);
    void (*class_finalize)(ObjectClass *klass, void *data);

    void *class_data;

    void (*instance_init)(Object *obj);
    void (*instance_post_init)(Object *obj);
    void (*instance_finalize)(Object *obj);

    bool abstract;

    const char *parent;
    TypeImpl *parent_type;

    ObjectClass *class;

    int num_interfaces;
    InterfaceImpl interfaces[32];
};

typedef unsigned long gsize;

typedef struct _GHashTable GHashTable;

typedef struct _GSList GSList;
typedef void* gpointer;

gpointer g_malloc0 (gsize n_bytes);

struct _GSList
{
  gpointer data;
  GSList *next;
};

const char *bios_name;

typedef void (ObjectFree)(void *obj);

struct ObjectClass
{
    Type type;
    GSList *interfaces;

    const char *object_cast_cache[4];
    const char *class_cast_cache[4];

    ObjectUnparent *unparent;

    GHashTable *properties;
};


DeviceState *sysbus_create_varargs(const char *name, hwaddr addr, qemu_irq irq, ...);


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

Error **error_abort;
Error **error_fatal;

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

typedef enum {
    IOMMU_NONE = 0,
    IOMMU_RO   = 1,
    IOMMU_WO   = 2,
    IOMMU_RW   = 3,
} IOMMUAccessFlags;

typedef enum {
    IF_DEFAULT = -1,            /* for use with drive_add() only */
    /*
     * IF_NONE must be zero, because we want MachineClass member
     * block_default_type to default-initialize to IF_NONE
     */
    IF_NONE = 0,
    IF_IDE, IF_SCSI, IF_FLOPPY, IF_PFLASH, IF_MTD, IF_SD, IF_VIRTIO, IF_XEN,
    IF_COUNT
} BlockInterfaceType;

typedef struct DriveInfo DriveInfo;

int lookup_gic(const char *cpu_model);

void error_report(const char *fmt, ...);

void exit(int status);

enum {
    QEMU_PSCI_CONDUIT_DISABLED = 0,
    QEMU_PSCI_CONDUIT_SMC = 1,
    QEMU_PSCI_CONDUIT_HVC = 2,
};

DriveInfo *drive_get(BlockInterfaceType type, int bus, int unit);

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


typedef struct MigrationStats MigrationStats;

typedef enum MigrationStatus {
    MIGRATION_STATUS_NONE = 0,
    MIGRATION_STATUS_SETUP = 1,
    MIGRATION_STATUS_CANCELLING = 2,
    MIGRATION_STATUS_CANCELLED = 3,
    MIGRATION_STATUS_ACTIVE = 4,
    MIGRATION_STATUS_POSTCOPY_ACTIVE = 5,
    MIGRATION_STATUS_COMPLETED = 6,
    MIGRATION_STATUS_FAILED = 7,
    MIGRATION_STATUS_COLO = 8,
    MIGRATION_STATUS__MAX = 9,
} MigrationStatus;

typedef struct XBZRLECacheStats XBZRLECacheStats;

struct XBZRLECacheStats {
    int64_t cache_size;
    int64_t bytes;
    int64_t pages;
    int64_t cache_miss;
    double cache_miss_rate;
    int64_t overflow;
};

typedef struct MigrationInfo MigrationInfo;

struct MigrationInfo {
    bool has_status;
    MigrationStatus status;
    bool has_ram;
    MigrationStats *ram;
    bool has_disk;
    MigrationStats *disk;
    bool has_xbzrle_cache;
    XBZRLECacheStats *xbzrle_cache;
    bool has_total_time;
    int64_t total_time;
    bool has_expected_downtime;
    int64_t expected_downtime;
    bool has_downtime;
    int64_t downtime;
    bool has_setup_time;
    int64_t setup_time;
    bool has_cpu_throttle_percentage;
    int64_t cpu_throttle_percentage;
    bool has_error_desc;
    char *error_desc;
};

MemoryRegion *get_system_memory(void);

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

void memory_region_init_ram_from_file(MemoryRegion *mr,
                                      struct Object *owner,
                                      const char *name,
                                      uint64_t size,
                                      bool share,
                                      const char *path,
                                      Error **errp);


void create_one_flash(const char *name, hwaddr flashbase,
                             hwaddr flashsize, const char *file,
                             MemoryRegion *sysmem);



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


typedef enum {
    ARM_ENDIANNESS_UNKNOWN = 0,
    ARM_ENDIANNESS_LE,
    ARM_ENDIANNESS_BE8,
    ARM_ENDIANNESS_BE32,
} arm_endianness;

typedef struct Notifier Notifier;

struct Notifier
{
    void (*notify)(Notifier *notifier, void *data);
    struct { struct Notifier *le_next; struct Notifier **le_prev; } node;
};

typedef struct ARMCPU ARMCPU;

typedef struct {
    Notifier notifier; /* actual notifier */
    ARMCPU *cpu; /* handle to the first cpu object */
} ArmLoadKernelNotifier;

struct arm_boot_info {
    uint64_t ram_size;
    const char *kernel_filename;
    const char *kernel_cmdline;
    const char *initrd_filename;
    const char *dtb_filename;
    hwaddr loader_start;
    /* multicore boards that use the default secondary core boot functions
     * need to put the address of the secondary boot code, the boot reg,
     * and the GIC address in the next 3 values, respectively. boards that
     * have their own boot functions can use these values as they want.
     */
    hwaddr smp_loader_start;
    hwaddr smp_bootreg_addr;
    hwaddr gic_cpu_if_addr;
    int nb_cpus;
    int board_id;
    /* ARM machines that support the ARM Security Extensions use this field to
     * control whether Linux is booted as secure(true) or non-secure(false).
     */
    bool secure_boot;
    int (*atag_board)(const struct arm_boot_info *info, void *p);
    /* multicore boards that use the default secondary core boot functions
     * can ignore these two function calls. If the default functions won't
     * work, then write_secondary_boot() should write a suitable blob of
     * code mimicking the secondary CPU startup process used by the board's
     * boot loader/boot ROM code, and secondary_cpu_reset_hook() should
     * perform any necessary CPU reset handling and set the PC for the
     * secondary CPUs to point at this boot blob.
     */
    void (*write_secondary_boot)(ARMCPU *cpu,
                                 const struct arm_boot_info *info);
    void (*secondary_cpu_reset_hook)(ARMCPU *cpu,
                                     const struct arm_boot_info *info);
    /* if a board is able to create a dtb without a dtb file then it
     * sets get_dtb. This will only be used if no dtb file is provided
     * by the user. On success, sets *size to the length of the created
     * dtb, and returns a pointer to it. (The caller must free this memory
     * with g_free() when it has finished with it.) On failure, returns NULL.
     */
    void *(*get_dtb)(const struct arm_boot_info *info, int *size);
    /* if a board needs to be able to modify a device tree provided by
     * the user it should implement this hook.
     */
    void (*modify_dtb)(const struct arm_boot_info *info, void *fdt);
    /* machine init done notifier executing arm_load_dtb */
    ArmLoadKernelNotifier load_kernel_notifier;
    /* Used internally by arm_boot.c */
    int is_linux;
    hwaddr initrd_start;
    hwaddr initrd_size;
    hwaddr entry;

    /* Boot firmware has been loaded, typically at address 0, with -bios or
     * -pflash. It also implies that fw_cfg_find() will succeed.
     */
    bool firmware_loaded;

    /* Address at which board specific loader/setup code exists. If enabled,
     * this code-blob will run before anything else. It must return to the
     * caller via the link register. There is no stack set up. Enabled by
     * defining write_board_setup, which is responsible for loading the blob
     * to the specified address.
     */
    hwaddr board_setup_addr;
    void (*write_board_setup)(ARMCPU *cpu,
                              const struct arm_boot_info *info);

    /* If set, the board specific loader/setup blob will be run from secure
     * mode, regardless of secure_boot. The blob becomes responsible for
     * changing to non-secure state if implementing a non-secure boot
     */
    bool secure_board_setup;

    arm_endianness endianness;
};


typedef struct MemMapEntry {
	hwaddr base;
	hwaddr size;
	char* opt_fn_str;
} MemMapEntry;


void parse_mem_map(char *map_str);

MemMapEntry dev_mem_map[MEM_REGION_COUNT];
MemMapEntry file_mem_map[10];

const int irqmap[384];

int smp_cpus;

typedef struct RehostingBoardInfo {
    struct arm_boot_info bootinfo;
    const char *cpu_model;
    const MemMapEntry *dev_mem_map;
    const MemMapEntry *file_mem_map;
    const int *irqmap;
    int smp_cpus;
    void *fdt;
    int fdt_size;
    uint32_t clock_phandle;
    uint32_t gic_phandle;
    uint32_t v2m_phandle;
    bool using_psci;
} RehostingBoardInfo;

void create_internal_gic(RehostingBoardInfo *vbi, machine_irqs *irqs, int gic_version);
void create_external_gic(RehostingBoardInfo *vbi, machine_irqs *irqs, int gic_version, bool secure);
void create_virtio_devices(RehostingBoardInfo *vbi, qemu_irq *pic);

typedef struct AccelState {
    /*< private >*/
    Object parent_obj;
} AccelState;

typedef struct MachineState MachineState;

struct MachineState {
    /*< private >*/
    Object parent_obj;
    Notifier sysbus_notifier;

    /*< public >*/

    char *accel;
    bool kernel_irqchip_allowed;
    bool kernel_irqchip_required;
    bool kernel_irqchip_split;
    int kvm_shadow_mem;
    char *dtb;
    char *dumpdtb;
    int phandle_start;
    char *dt_compatible;
    bool dump_guest_core;
    bool mem_merge;
    bool usb;
    bool usb_disabled;
    bool igd_gfx_passthru;
    char *firmware;
    bool iommu;
    bool suppress_vmdesc;
    bool enforce_config_section;
    bool enable_graphics;
	
    int board_id;
    char *mem_map_str;

    ram_addr_t ram_size;
    ram_addr_t maxram_size;
    uint64_t   ram_slots;
    const char *boot_order;
    char *kernel_filename;
    char *kernel_cmdline;
    char *initrd_filename;
    const char *cpu_model;
    AccelState *accelerator;
};




/**
 * Object:
 *
 * The base for all objects.  The first member of this object is a pointer to
 * a #ObjectClass.  Since C guarantees that the first member of a structure
 * always begins at byte 0 of that structure, as long as any sub-object places
 * its parent as the first member, we can cast directly to a #Object.
 *
 * As a result, #Object contains a reference to the objects type as its
 * first member.  This allows identification of the real type of the object at
 * run time.
 */
struct Object
{
    /*< private >*/
    void* klass; //ObjectClass *klass;
    void* free; //ObjectFree *free;
    void* properties; //GHashTable *properties;
    uint32_t ref;
    void* parent;
};


/**
 * DeviceState:
 * @realized: Indicates whether the device has been fully constructed.
 *
 * This structure should not be accessed directly.  We declare it here
 * so that it can be embedded in individual device state structures.
 */
struct DeviceState {
    /*< private >*/
    struct Object parent_obj;
    /*< public >*/
    
    const char *id;
    bool realized;
    bool pending_deleted_event;
    void* opts; //QemuOpts *opts;
    int hotplugged;
    void* parent_bus; //BusState *parent_bus;
    void* gpios; //QLIST_HEAD(, NamedGPIOList) gpios;
    void* child_bus; //QLIST_HEAD(, BusState) child_bus;
    int num_child_bus;
    int instance_id_alias;
    int alias_required_for_version;
};


typedef struct {
  int __flags[8];			/* XXX - long might give better alignment */
  long __mask;			/* must have size >= sizeof(sigset_t) */
//#if (_SETJMP_SAVES_REGS == 0)
// _PROTOTYPE(void (*__pc),(void));	/* program counter */
//  void *__sp;			/* stack pointer */
//  void *__lb;			/* local base (ACKspeak for frame pointer) */
//#else
  void *__regs[16];		/* size is machine dependent */
//#endif
} jmp_buf[1];
typedef jmp_buf sigjmp_buf;

struct QemuMutex {
	pthread_mutex_t lock;
};

typedef struct icount_decr_u16 {
    uint16_t low;
    uint16_t high;
} icount_decr_u16;
typedef struct QemuMutex QemuMutex;
typedef uint64_t vaddr;
#define TB_JMP_CACHE_BITS 12
#define TB_JMP_CACHE_SIZE 4096 // 1<<12
/**
 * CPUState:
 * @cpu_index: CPU index (informative).
 * @nr_cores: Number of cores within this CPU package.
 * @nr_threads: Number of threads within this CPU.
 * @numa_node: NUMA node this CPU is belonging to.
 * @host_tid: Host thread ID.
 * @running: #true if CPU is currently running (lockless).
 * @has_waiter: #true if a CPU is currently waiting for the cpu_exec_end;
 * valid under cpu_list_lock.
 * @created: Indicates whether the CPU thread has been successfully created.
 * @interrupt_request: Indicates a pending interrupt request.
 * @halted: Nonzero if the CPU is in suspended state.
 * @stop: Indicates a pending stop request.
 * @stopped: Indicates the CPU has been artificially stopped.
 * @unplug: Indicates a pending CPU unplug request.
 * @crash_occurred: Indicates the OS reported a crash (panic) for this CPU
 * @tcg_exit_req: Set to force TCG to stop executing linked TBs for this
 *           CPU and return to its top level loop.
 * @singlestep_enabled: Flags for single-stepping.
 * @icount_extra: Instructions until next timer event.
 * @icount_decr: Number of cycles left, with interrupt flag in high bit.
 * This allows a single read-compare-cbranch-write sequence to test
 * for both decrementer underflow and exceptions.
 * @can_do_io: Nonzero if memory-mapped IO is safe. Deterministic execution
 * requires that IO only be performed on the last instruction of a TB
 * so that interrupts take effect immediately.
 * @cpu_ases: Pointer to array of CPUAddressSpaces (which define the
 *            AddressSpaces this CPU has)
 * @num_ases: number of CPUAddressSpaces in @cpu_ases
 * @as: Pointer to the first AddressSpace, for the convenience of targets which
 *      only have a single AddressSpace
 * @env_ptr: Pointer to subclass-specific CPUArchState field.
 * @gdb_regs: Additional GDB registers.
 * @gdb_num_regs: Number of total registers accessible to GDB.
 * @gdb_num_g_regs: Number of registers in GDB 'g' packets.
 * @next_cpu: Next CPU sharing TB cache.
 * @opaque: User data.
 * @mem_io_pc: Host Program Counter at which the memory was accessed.
 * @mem_io_vaddr: Target virtual address at which the memory was accessed.
 * @kvm_fd: vCPU file descriptor for KVM.
 * @work_mutex: Lock to prevent multiple access to queued_work_*.
 * @queued_work_first: First asynchronous work pending.
 * @trace_dstate: Dynamic tracing state of events for this vCPU (bitmask).
 *
 * State of one CPU core or thread.
 */
	struct CPUState {
	    /*< private >*/
//	    struct DeviceState parent_obj; //DeviceState parent_obj;
	    /*< public >*/
/*
	    int nr_cores;
	    int nr_threads;
	    int numa_node;

	    void* thread; //struct QemuThread *thread;
//	#ifdef _WIN32
//	    HANDLE hThread;
//	#endif
	    int thread_id;
	    uint32_t host_tid;
	    bool running, has_waiter;
	    struct QemuCond *halt_cond;
	    bool thread_kicked;
	    bool created;
	    bool stop;
	    bool stopped;
	    bool unplug;
	    bool crash_occurred;
	    bool exit_request;
	    uint32_t interrupt_request;
	    int singlestep_enabled;
	    int64_t icount_extra;
	    sigjmp_buf jmp_env;

	    QemuMutex work_mutex;
	    struct qemu_work_item *queued_work_first, *queued_work_last;

	    void* cpu_ases; //CPUAddressSpace *cpu_ases;
	    int num_ases;
	    void* as; //AddressSpace *as;
	    void* memory; //MemoryRegion *memory;
*/
		char values[472];
	    CPUX86State *env_ptr; // CPUArchState *env_ptr; /* CPUArchState */
		char values2[32924];
		
	    /* Writes protected by tb_lock, reads not thread-safe  */ 
/*
	    void* tb_jmp_cache[TB_JMP_CACHE_SIZE]; //struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];
	    struct GDBRegisterState *gdb_regs;
	    int gdb_num_regs;
	    int gdb_num_g_regs;
	    void* node; //QTAILQ_ENTRY(CPUState) node;

*/	    /* ice debug support */
/*	    void* breakpoints; //QTAILQ_HEAD(breakpoints_head, CPUBreakpoint) breakpoints;

	    void* watchpoints; //QTAILQ_HEAD(watchpoints_head, CPUWatchpoint) watchpoints;
	    void* watchpoint_hit; //CPUWatchpoint *watchpoint_hit;
	    bool watchpoints_disabled;

	    void *opaque;
*/
	    /* In order to avoid passing too many arguments to the MMIO helpers,
	     * we store some rarely used information in the CPU context.
	     */
/*	    uintptr_t mem_io_pc;
	    vaddr mem_io_vaddr;

	    int kvm_fd;
	    bool kvm_vcpu_dirty;
	    struct KVMState *kvm_state;
	    struct kvm_run *kvm_run;

*/	    /*
	     * Used for events with 'vcpu' and *without* the 'disabled' properties.
	     * Dynamically allocated based on bitmap requried to hold up to
	     * trace_get_vcpu_event_count() entries.
	     */
/*	    unsigned long *trace_dstate;

*/	    /* TODO Move common fields from CPUArchState here. */
//	    int cpu_index; /* used by alpha TCG */
//	    uint32_t halted; /* used by alpha, cris, ppc TCG */
//	    union {
//		uint32_t u32;
//		icount_decr_u16 u16;
//	    } icount_decr;
//	    uint32_t can_do_io;
//	    int32_t exception_index; /* used by m68k TCG */
	    uint64_t rr_guest_instr_count;
	    uint64_t panda_guest_pc;

	    // Used for rr reverse debugging
//	    uint8_t reverse_flags;
//	    uint64_t last_gdb_instr; // Instruction count from which we last sent a GDB command
//	    uint64_t last_bp_hit_instr; // Last bp observed during this checkpoint run
//	    uint64_t temp_rr_bp_instr; // Saved bp. Used by rstep/rcont, which disables bp to move forward, then restores on next tb in cpu-exec.c

	    /* Used to keep track of an outstanding cpu throttle thread for migration
	     * autoconverge
	     */
//	    bool throttle_thread_scheduled;

	    /* Note that this is accessed at the start of every TB via a negative
	       offset from AREG0.  Leave this field at the end so as to make the
	       (absolute value) offset as small as possible.  This reduces code
	       size, especially for hosts without large memory offsets.  */
//	    uint32_t tcg_exit_req;

//	    bool hax_vcpu_dirty;
//	    void* hax_vcpu; //struct hax_vcpu_state *hax_vcpu;
	};
typedef struct CPUState CPUState;

typedef uint64_t ram_addr_t;
typedef ram_addr_t tb_page_addr_t;
struct TranslationBlock {
    target_ulong pc;   /* simulated PC corresponding to this block (EIP + CS base) */
    target_ulong cs_base; /* CS base for this block */
    uint32_t flags; /* flags defining in which context the code was generated */
    uint16_t size;      /* size of target code for this block (1 <=
                           size <= TARGET_PAGE_SIZE) */
    uint16_t icount;
    uint32_t cflags;    /* compile flags */
#define CF_COUNT_MASK  0x7fff
#define CF_LAST_IO     0x8000 /* Last insn may be an IO access.  */
#define CF_NOCACHE     0x10000 /* To be freed after execution */
#define CF_USE_ICOUNT  0x20000
#define CF_IGNORE_ICOUNT 0x40000 /* Do not generate icount code */

    uint16_t invalid;

    void *tc_ptr;    /* pointer to the translated code */
    uint8_t *tc_search;  /* pointer to search data */
    /* original tb when cflags has CF_NOCACHE */
    struct TranslationBlock *orig_tb;
    /* first and second physical page containing code. The lower bit
       of the pointer tells the index in page_next[] */
    struct TranslationBlock *page_next[2];
    tb_page_addr_t page_addr[2];

    /* The following data are used to directly call another TB from
     * the code of this one. This can be done either by emitting direct or
     * indirect native jump instructions. These jumps are reset so that the TB
     * just continue its execution. The TB can be linked to another one by
     * setting one of the jump targets (or patching the jump instruction). Only
     * two of such jumps are supported.
     */
    uint16_t jmp_reset_offset[2]; /* offset of original jump target */
#define TB_JMP_RESET_OFFSET_INVALID 0xffff /* indicates no jump generated */
//#ifdef USE_DIRECT_JUMP
    uint16_t jmp_insn_offset[2]; /* offset of native jump instruction */
//#else
    uintptr_t jmp_target_addr[2]; /* target address for indirect jump */
//#endif
    /* Each TB has an assosiated circular list of TBs jumping to this one.
     * jmp_list_first points to the first TB jumping to this one.
     * jmp_list_next is used to point to the next TB in a list.
     * Since each TB can have two jumps, it can participate in two lists.
     * jmp_list_first and jmp_list_next are 4-byte aligned pointers to a
     * TranslationBlock structure, but the two least significant bits of
     * them are used to encode which data field of the pointed TB should
     * be used to traverse the list further from that TB:
     * 0 => jmp_list_next[0], 1 => jmp_list_next[1], 2 => jmp_list_first.
     * In other words, 0/1 tells which jump is used in the pointed TB,
     * and 2 means that this is a pointer back to the target TB of this list.
     */
    uintptr_t jmp_list_next[2];
    uintptr_t jmp_list_first;

//#ifdef CONFIG_LLVM
    /* pointer to LLVM translated code */
    struct TCGLLVMContext *tcg_llvm_context;
//#ifdef __cplusplus
    void* llvm_function; //Function *llvm_function;
//#else
//    struct Function *llvm_function;
//#endif
    uint8_t *llvm_tc_ptr;
    uint8_t *llvm_tc_end;
    struct TranslationBlock* llvm_tb_next[2];
//#endif

};
typedef struct TranslationBlock TranslationBlock;
typedef target_ulong target_long;

struct MonitorDef {
	const char *name;
	int offset;
	target_long (*get_value)(void  *md, int val);
	int type;
};

typedef struct MonitorDef Monitor;
