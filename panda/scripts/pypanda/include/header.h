
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

typedef struct _GHashTable GHashTable;

typedef struct _GSList GSList;
typedef void* gpointer;


struct _GSList
{
  gpointer data;
  GSList *next;
};


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

