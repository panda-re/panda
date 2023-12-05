enum QType {QTYPE_NONE, QTYPE_QNULL, QTYPE_QINT, QTYPE_QSTRING, QTYPE_QDICT, QTYPE_QLIST, QTYPE_QFLOAT, QTYPE_QBOOL, QTYPE__MAX};
typedef enum QType QType;

struct QObject;
struct QDictEntry;
struct QDict;

typedef struct QObject QObject;
struct QObject {
    enum QType                      type;
    size_t                     refcnt;
};

typedef struct QDictEntry QDictEntry;
struct QDictEntry {
    char *key;
    struct QObject *value;
    struct {
        struct QDictEntry *le_next;
        struct QDictEntry **le_prev;
    } next;
};

typedef struct QDict QDict;

struct QDict {
    struct QObject base;
    size_t size;
    struct {
        struct QDictEntry *lh_first;
    } table[512];
};

typedef enum ErrorClass {
    ERROR_CLASS_GENERIC_ERROR,// = QAPI_ERROR_CLASS_GENERICERROR,
    ERROR_CLASS_COMMAND_NOT_FOUND,// = QAPI_ERROR_CLASS_COMMANDNOTFOUND,
    ERROR_CLASS_DEVICE_ENCRYPTED,// = QAPI_ERROR_CLASS_DEVICEENCRYPTED,
    ERROR_CLASS_DEVICE_NOT_ACTIVE,// = QAPI_ERROR_CLASS_DEVICENOTACTIVE,
    ERROR_CLASS_DEVICE_NOT_FOUND,// = QAPI_ERROR_CLASS_DEVICENOTFOUND,
    ERROR_CLASS_KVM_MISSING_CAP,// = QAPI_ERROR_CLASS_KVMMISSINGCAP,
} ErrorClass;

// XXX GSTRING
struct Error 
{ 
    char *msg; 
    ErrorClass err_class; 
    const char *src, *func; 
    int line; 
    //GString *hint; 
    void *hint; 
}; 

typedef struct Error Error;