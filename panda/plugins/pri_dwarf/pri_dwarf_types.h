
#include <libdwarf/libdwarf.h>

typedef void (*dwarfTypeCB)(target_ulong buf, LocType loc_t, target_ulong buf_len, const char *astnodename);

typedef struct DwarfVarType {
    Dwarf_Debug dbg;
    Dwarf_Die var_die;
} DwarfVarType;
