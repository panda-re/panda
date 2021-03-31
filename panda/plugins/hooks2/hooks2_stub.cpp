/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Michael Bel            bellma@ornl.gov
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

/* This is a stub for systems that aren't ARM or X86. */

#include "panda/plugin.h"


#include "hooks2.h"

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);

PPP_PROT_REG_CB(on_process_start);
PPP_PROT_REG_CB(on_process_end);
PPP_PROT_REG_CB(on_thread_start);
PPP_PROT_REG_CB(on_thread_end);
PPP_PROT_REG_CB(on_thread_end);
PPP_PROT_REG_CB(on_mmap_updated);

}


PPP_CB_BOILERPLATE(on_process_start);
PPP_CB_BOILERPLATE(on_process_end);
PPP_CB_BOILERPLATE(on_thread_start);
PPP_CB_BOILERPLATE(on_thread_end);
PPP_CB_BOILERPLATE(on_mmap_updated);

int
add_hooks2(
    hooks2_func_t hook,
    void *cb_data,
    bool is_kernel,
    const char *procname,
    const char *libname,
    target_ulong trace_start,
    target_ulong trace_stop,
    target_ulong range_begin,
    target_ulong range_end)
{
    (void)hook;
    (void)cb_data;
    (void)is_kernel;
    (void)procname;
    (void)libname;
    (void)trace_start;
    (void)trace_stop;
    (void)range_begin;
    (void)range_end;
    assert(NULL && "hooks2 does not support for this platform");
    return 0;
}

void
enable_hooks2(int id)
{
    (void)id;
    return;
}

void
disable_hooks2(int id)
{
    (void)id;
    return;
}

bool
init_plugin(void *self)
{
    (void)self;
    assert(NULL && "hooks2 does not support for this platform");
    return false;
}

void uninit_plugin(void *self) {
    (void)self;
}
