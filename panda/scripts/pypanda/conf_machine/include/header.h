
typedef uint64_t hwaddr;



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


struct Object {
   ObjectClass *klass;
   ObjectFree *free;
   GHashTable *properties;
   uint32_t ref;
   Object *parent;
}


struct DeviceState {

    Object parent_obj;


    const char *id;
    bool realized;
    bool pending_deleted_event;
    QemuOpts *opts;
    int hotplugged;
    BusState *parent_bus;
    struct { struct NamedGPIOList *lh_first; } gpios;
    struct { struct BusState *lh_first; } child_bus;
    int num_child_bus;
    int instance_id_alias;
    int alias_required_for_version;
};

DeviceState *sysbus_create_varargs(const char *name,
                                 hwaddr addr, ...);


