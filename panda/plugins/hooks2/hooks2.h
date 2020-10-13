#ifndef __HOOKS2_H
#define __HOOKS2_H


extern "C" {

#include "hooks2_ppp.h"


// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
int add_hooks2(
    hooks2_func_t hook,
    void *cb_data,
    bool is_kernel,
    const char *procname,
    const char *libname,
    target_ulong trace_start,
    target_ulong trace_stop,
    target_ulong range_begin,
    target_ulong range_end);

void enable_hooks2(int id);
void disable_hooks2(int id);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#define ADD_HOOKS2_ALWAYS(hook, cb_data, procname, libname) \
    ADD_HOOKS2(hook, cb_data, false, procname, libname, 0, 0, 0, 0)

#define ADD_HOOKS2_SINGLE_INSN(hook, cb_data, procname, libname, pc) \
    ADD_HOOKS2(hook, cb_data, false, procname, libname, pc, pc, 0, 0)

#define ADD_HOOKS2(...)                                                 \
    ({                                                                  \
        dlerror();                                                      \
        void *op = panda_get_plugin_by_name("hooks2");                  \
        if (!op) {                                                      \
            printf("Couldn't add hooks2s plugin\n");                    \
            assert (op);                                                \
        }                                                               \
        _add_hooks2_t func =                                            \
            (_add_hooks2_t) dlsym(op, "add_hooks2");                    \
        assert (func != 0);                                             \
        func(__VA_ARGS__);                                              \
    })

#define DISABLE_HOOKS2(...)                                             \
    ({                                                                  \
        dlerror();                                                      \
        void *op = panda_get_plugin_by_name("hooks2");                  \
        if (!op) {                                                      \
            printf("Couldn't add hooks2s plugin\n");                    \
            assert (op);                                                \
        }                                                               \
        _disable_hooks2_t func =                                        \
            (_disable_hooks2_t) dlsym(op, "disable_hooks2");            \
        assert(func != 0);                                              \
        func(__VA_ARGS__);                                              \
    })

#define ENABLE_HOOKS2(...)                                              \
    ({                                                                  \
        dlerror();                                                      \
        void *op = panda_get_plugin_by_name("hooks2");                  \
        if (!op) {                                                      \
            printf("Couldn't add hooks2s plugin\n");                    \
            assert (op);                                                \
        }                                                               \
        _enable_hooks2_t func =                                         \
            (_enable_hooks2_t) dlsym(op, "enable_hooks2");              \
        assert(func != 0);                                              \
        func(__VA_ARGS__);                                              \
    })

}

#endif /* __HOOKS2_H */
