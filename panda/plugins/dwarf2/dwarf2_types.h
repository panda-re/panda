
typedef void (*dwarfTypeCB)(CPUState *env, target_ulong buf, LocType loc_t, target_ulong buf_len, const char *astnodename);

struct DwarfTypeInfo;
typedef struct {
    DwarfTypeInfo *type;
    target_ulong dec_line;
    std::string nodename;
} DwarfVarType;
