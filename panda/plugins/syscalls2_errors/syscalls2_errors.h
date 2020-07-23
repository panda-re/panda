#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
//#include "syscalls2/syscalls2_int_fns.h"
#include "syscalls2/syscalls2_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
void catch_all_sys_return(CPUState*, target_ulong, const syscall_info_t*, const syscall_ctx_t*);


// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

typedef void (*on_get_error_t)(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *ctx, target_ulong sys_errorno, const char* sys_error_description);


// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

PPP_PROT_REG_CB(on_get_error)
PPP_CB_BOILERPLATE(on_get_error)
