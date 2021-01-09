#ifndef __DYNAMIC_SYMBOLS_INT_FNS_H__
#define __DYNAMIC_SYMBOLS_INT_FNS_H__

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
#define MAX_PATH_LEN 4096
struct symbol {
    target_ulong address;
    char name[MAX_PATH_LEN]; 
    char section[MAX_PATH_LEN]; 
};

struct symbol resolve_symbol(CPUState* cpu, target_ulong asid, char* section_name, char* symbol);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
void update_symbols_in_space(CPUState* cpu);
#endif
