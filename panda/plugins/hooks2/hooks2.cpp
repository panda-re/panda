/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Michael Bel            bellma@ornl.gov
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <list>
#include <string>
#include <map>
#include <memory>
#include <unordered_set>
#include <sstream>

#include "panda/plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"


#include "hooks2.h"

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

#if defined(TARGET_ARM) || defined(TARGET_I386) || defined(TARGET_X86_64)

extern "C" {
PPP_PROT_REG_CB(on_prog_start);
PPP_PROT_REG_CB(on_prog_end);
}

PPP_CB_BOILERPLATE(on_prog_start);
PPP_CB_BOILERPLATE(on_prog_end);


struct HashableOsiThread {
    target_pid_t pid;
    target_pid_t tid;

    bool operator==(const HashableOsiThread &p) const
    {
         return pid == p.pid && tid == p.tid;
    }
};

template<> struct std::hash<HashableOsiThread>
{
    inline size_t operator()(const HashableOsiThread &thread) const
    {
        std::hash<int> hasher;
        return (hasher(thread.pid) ^ hasher(thread.tid));
    }
};


struct callback_info {
    panda_cb_type type;
    panda_cb cb;
};

struct hook_cfg {
    bool is_kernel;
    std::shared_ptr<std::string> procname;
    std::shared_ptr<std::string> libname;
    target_ulong trace_start;
    target_ulong trace_stop;
    target_ulong range_begin;
    target_ulong range_end;
    hooks2_func_t hook_func;
    void *cb_data;

    int index;
    bool active;
    bool enabled;
};

struct active_trace {
    std::shared_ptr<struct hook_cfg> cfg;
    std::unordered_set<HashableOsiThread> active_threads;
    bool resolved;
    target_ulong resolved_trace_start;
    target_ulong resolved_trace_stop;
    target_ulong resolved_range_begin;
    target_ulong resolved_range_end;
};

struct global_hooks2_data {
    /* Configuration */
    bool disable_chaining;
    std::list<std::shared_ptr<struct hook_cfg> > hook_cfg;
    int hook_idx;

    /* Dynamic */
    struct callback_info cb_tracing;
    struct callback_info cb_pend_procname;
    struct callback_info cb_asid_changed;

    void *self;
    std::list< std::shared_ptr<struct hook_cfg> > kernel_traces;
    std::map<target_ulong, std::list< std::shared_ptr<struct active_trace> >> map_active_utraces;

    std::map<target_pid_t, std::string> pid_map;
};

static struct global_hooks2_data plugin;


static void
register_callback(struct callback_info &cb)
{
    panda_register_callback(plugin.self, cb.type, cb.cb);
}

static void
enable_callback(struct callback_info &cb)
{
    if (!panda_is_callback_enabled(plugin.self, cb.type, cb.cb)) {
        panda_enable_callback(plugin.self, cb.type, cb.cb);
    }
}

static void
disable_callback(struct callback_info &cb)
{
    if (panda_is_callback_enabled(plugin.self, cb.type, cb.cb)) {
        panda_disable_callback(plugin.self, cb.type, cb.cb);
    }
}

static bool
traces_empty()
{
    for (auto &element : plugin.map_active_utraces) {
        if (!element.second.empty())
            return false;
    }
    return true;
}

static bool
in_range(TranslationBlock *tb, target_ulong value)
{
    return ((value >= tb->pc) && (value < (tb->pc + tb->size)));
}

static void
handle_userspace_traces(
    CPUState *cpu,
    TranslationBlock *tb,
    std::shared_ptr<struct active_trace> &trace)
{

    OsiThread *pThread = get_current_thread(cpu);
    if (pThread == NULL)
        return;

    HashableOsiThread thread;
    thread.pid = pThread->pid;
    thread.tid = pThread->tid;
    free_osithread(pThread);

    if (!trace->cfg->enabled) {
        trace->active_threads.erase(thread);
        return;
    }

    bool active = true;
    auto search = trace->active_threads.find(thread);
    if (search == trace->active_threads.end()) {
        active = false;
    }

    if (!active) {
        if (in_range(tb, trace->resolved_trace_start)) {
            trace->active_threads.insert(thread);
            active = true;
        }
    }

    if (active) {
        if ((tb->pc >= trace->resolved_range_begin) &&
            (tb->pc <= trace->resolved_range_end)) {

            trace->cfg->hook_func(cpu, tb, trace->cfg->cb_data);
        }

        if (in_range(tb, trace->resolved_trace_stop)) {
            trace->active_threads.erase(thread);
        }
    }
}

static void
handle_kernel_traces(
    CPUState *cpu,
    TranslationBlock *tb,
    std::shared_ptr<struct hook_cfg> &cfg)
{
    if (!cfg->enabled) {
        cfg->active = false;
        return;
    }

    if (!cfg->active) {
        if (in_range(tb, cfg->trace_start)) {
            cfg->active = true;
        }
    }

    if (cfg->active) {
        if ((tb->pc >= cfg->range_begin) &&
            (tb->pc <= cfg->range_end)) {

            cfg->hook_func(cpu, tb, cfg->cb_data);
        }

        if (in_range(tb, cfg->trace_stop)) {
            cfg->active = false;
        }
    }
}


static bool
update_active_userspace_traces(CPUState *cpu)
{
    bool changed = false;

    OsiProc *proc = get_current_process(cpu);
    if (!proc)
        return changed;

    target_ulong asid = panda_current_asid(cpu);

    auto &trace_list = plugin.map_active_utraces[asid];

    if (!trace_list.empty()) {
        bool needs_update = false;
        for (auto &trace : trace_list) {
            if (trace->cfg->procname != NULL) {
                if (*trace->cfg->procname != proc->name) {
                    needs_update = true;
                }
            }
        }
        if (!needs_update) {
            /* This list is up-to-date. */
            free_osiproc(proc);
            return changed;
        }

        /* It's out-of-date, so we will rebuild it. */
        trace_list.clear();
        changed = true;
    }

    for (auto &cfg: plugin.hook_cfg) {
        if (cfg->is_kernel)
            continue;
        if (cfg->procname) {
            if ((!proc->name) || (*cfg->procname != proc->name))
                continue;
        }

        std::shared_ptr<struct active_trace> trace = std::make_shared<struct active_trace>();

        trace->cfg = cfg;
        trace->resolved = false;
        trace_list.push_back(trace);
        changed = true;
    }

    free_osiproc(proc);
    return changed;
}

static void
update_active_userspace_libs(CPUState *cpu)
{
    target_ulong asid = panda_current_asid(cpu);
    auto trace_list = plugin.map_active_utraces[asid];

    bool do_get_mappings = false;
    for (auto &trace: trace_list) {
        if (trace->cfg->libname) {
            do_get_mappings = true;
            trace->resolved = false;
        } else {
            trace->resolved = true;
            trace->resolved_trace_start = trace->cfg->trace_start;
            trace->resolved_trace_stop = trace->cfg->trace_stop;
            trace->resolved_range_begin = trace->cfg->range_begin;
            trace->resolved_range_end = trace->cfg->range_end;
        }
    }

    if (!do_get_mappings) {
        return;
    }

    OsiProc *current = get_current_process(cpu);
    if (!current)
        return;

    GArray *ms = get_mappings(cpu, current);
    if (!ms) {
        free_osiproc(current);
        return;
    }

    for (auto &trace: trace_list) {
        if (!trace->cfg->libname)
            continue;

        OsiModule *m_text = NULL;

        for (int i = 0; i < ms->len; i++) {
            OsiModule *m = &g_array_index(ms, OsiModule, i);
            if (m->name && (*trace->cfg->libname == m->name)) {
                if (!m_text || (m->base < m_text->base)) {
                    m_text = m;
                }
            }
        }

        if (m_text) {
            trace->resolved = true;
            trace->resolved_trace_start = m_text->base + trace->cfg->trace_start;
            trace->resolved_trace_stop = m_text->base + trace->cfg->trace_stop;
            trace->resolved_range_begin = m_text->base + trace->cfg->range_begin;
            trace->resolved_range_end = std::min(
                m_text->base + m_text->size,
                m_text->base + trace->cfg->range_end);
        }
    }

    free_osiproc(current);
    g_array_free(ms, true);
}


static void
cb_tracing_before_block_exec(CPUState *cpu, TranslationBlock *tb)
{
    if (panda_in_kernel(cpu)) {
        for (auto &trace_ptr : plugin.kernel_traces) {
            handle_kernel_traces(cpu, tb, trace_ptr);
        }
    } else {
        auto trace_list = plugin.map_active_utraces.find(panda_current_asid(cpu));
        if (trace_list != plugin.map_active_utraces.end()) {
            for (auto &trace_ptr : trace_list->second) {
                handle_userspace_traces(cpu, tb, trace_ptr);
            }
        }
    }
}


static void
on_progname_change(CPUState* cpu)
{
    OsiProc *current = get_current_process(cpu);
    if (current) {
        bool is_new = false;

        auto it = plugin.pid_map.find(current->pid);
        if (it == plugin.pid_map.end()) {
            is_new = true;
        } else if (it->second != current->name) {
            is_new = true;
        }

        if (is_new) {
            plugin.pid_map[current->pid] = std::string(current->name);
            PPP_RUN_CB(on_prog_start, cpu, current);
        }

        free_osiproc(current);
    }


    if (update_active_userspace_traces(cpu)) {
        update_active_userspace_libs(cpu);
    }

    if (!plugin.kernel_traces.size()) {
        auto search = plugin.map_active_utraces.find(panda_current_asid(cpu));
        if (search == plugin.map_active_utraces.end()) {
            disable_callback(plugin.cb_tracing);
        } else if (search->second.size()) {
            enable_callback(plugin.cb_tracing);
        } else {
            disable_callback(plugin.cb_tracing);
        }
    }

    if (traces_empty()) {
        plugin.map_active_utraces.clear();
        disable_callback(plugin.cb_asid_changed);
    } else {
        printf("Enabling callback\n");
        enable_callback(plugin.cb_asid_changed);
    }
}

static void
cb_pending_procname_after_block_exec(
    CPUState *cpu,
    TranslationBlock *tb,
    uint8_t exit_code)
{
    if (exit_code)
        return;

    if (panda_in_kernel(cpu))
        return;

    on_progname_change(cpu);
    disable_callback(plugin.cb_pend_procname);
}


static bool
cb_asid_changed(
    CPUState *env,
    target_ulong old_asid,
    target_ulong new_asid)
{
    if (old_asid == new_asid){
        printf("old_asid,new_asid=0x%08x\n", (int)new_asid);
        return false;
    }

    printf("asid=0x%08x\n", (int)new_asid);
    auto search = plugin.map_active_utraces.find(new_asid);
    if (search == plugin.map_active_utraces.end()) {
        printf("0x%08x\n", (int)new_asid);
        enable_callback(plugin.cb_pend_procname);
    } else {
        if (search->second.size()) {
            enable_callback(plugin.cb_tracing);
        } else if (!plugin.kernel_traces.size()) {
            disable_callback(plugin.cb_tracing);
        }
    }
    return false;
}

static void
on_sys_brk_enter(
    CPUState* cpu,
    target_ulong pc,
    target_ulong brk)
{
    (void)pc;
    (void)brk;

    on_progname_change(cpu);
}

static void
on_mmap_return(
    CPUState* cpu,
    target_ulong pc,
    target_ulong arg0,
    target_ulong arg1,
    target_ulong arg2,
    target_ulong arg3,
    target_ulong arg4,
    target_ulong arg5)
{
    (void)pc;
    (void)arg0;
    (void)arg1;
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;

    update_active_userspace_libs(cpu);
}

static void
on_sys_munmap_return(
    CPUState* cpu,
    target_ulong pc,
    target_ulong addr,
    uint32_t len)
{
    (void)pc;
    (void)addr;
    (void)len;

    update_active_userspace_libs(cpu);
}

static void
on_sys_exit_enter(
    CPUState* cpu,
    target_ulong pc,
    int32_t error_code)
{
    (void)pc;

    OsiProc *current = get_current_process(cpu);
    if (current) {
        PPP_RUN_CB(on_prog_end, cpu, current, error_code);
        plugin.pid_map.erase(current->pid);
        free_osiproc(current);
    }

    target_ulong asid = panda_current_asid(cpu);
    plugin.map_active_utraces.erase(asid);

    if (!plugin.kernel_traces.size()) {
        disable_callback(plugin.cb_tracing);
    }

    if (traces_empty()) {
        plugin.map_active_utraces.clear();
        disable_callback(plugin.cb_asid_changed);
    }
}


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
    std::shared_ptr<struct hook_cfg> cfg = std::make_shared<struct hook_cfg>();

    if (procname)
        cfg->procname = std::make_shared<std::string>(procname);
    else
        cfg->procname = NULL;

    if (libname)
        cfg->libname = std::make_shared<std::string>(libname);
    else
        cfg->libname = NULL;

    cfg->hook_func = hook;
    cfg->cb_data = cb_data;
    cfg->is_kernel = is_kernel;
    cfg->trace_start = trace_start;
    cfg->trace_stop = trace_stop;
    cfg->range_begin = range_begin;
    cfg->range_end = range_end;
    cfg->enabled = true;
    cfg->index = plugin.hook_idx++;
    plugin.hook_cfg.push_back(cfg);

    if (is_kernel) {
        plugin.kernel_traces.push_back(cfg);
        enable_callback(plugin.cb_tracing);
    } else if (!cfg->procname) {
        enable_callback(plugin.cb_asid_changed);
    }

    return cfg->index;
}

void
enable_hooks2(int id)
{
    for (auto &cfg: plugin.hook_cfg) {
        if (cfg->index == id)
            cfg->enabled = true;
    }
}

void
disable_hooks2(int id)
{
    for (auto &cfg: plugin.hook_cfg) {
        if (cfg->index == id)
            cfg->enabled = false;
    }
}

bool
init_plugin(void *self)
{
    panda_require("osi");
    panda_require("syscalls2");

    assert(init_osi_api());
    assert(init_syscalls2_api());

    plugin.self = self;
    plugin.hook_idx = 0;

    plugin.cb_asid_changed.cb.asid_changed = cb_asid_changed;
    plugin.cb_asid_changed.type = PANDA_CB_ASID_CHANGED;

    plugin.cb_pend_procname.cb.after_block_exec = cb_pending_procname_after_block_exec;
    plugin.cb_pend_procname.type = PANDA_CB_AFTER_BLOCK_EXEC;

    plugin.cb_tracing.cb.before_block_exec = cb_tracing_before_block_exec;
    plugin.cb_tracing.type = PANDA_CB_BEFORE_BLOCK_EXEC;

    register_callback(plugin.cb_asid_changed);
    register_callback(plugin.cb_pend_procname);
    register_callback(plugin.cb_tracing);
    disable_callback(plugin.cb_asid_changed);
    disable_callback(plugin.cb_pend_procname);
    disable_callback(plugin.cb_tracing);

    PPP_REG_CB("syscalls2", on_sys_brk_enter, on_sys_brk_enter);

#if defined(TARGET_X86_64)
    PPP_REG_CB("syscalls2", on_sys_mmap_return, on_mmap_return);
#elif defined(TARGET_I386)
    PPP_REG_CB("syscalls2", on_sys_mmap_pgoff_return, on_mmap_return);
#else
    PPP_REG_CB("syscalls2", on_do_mmap2_return, on_mmap_return);
#endif

    PPP_REG_CB("syscalls2", on_sys_munmap_return, on_sys_munmap_return);
    PPP_REG_CB("syscalls2", on_sys_exit_enter, on_sys_exit_enter);
    PPP_REG_CB("syscalls2", on_sys_exit_group_enter, on_sys_exit_enter);

    return true;
}

void
uninit_plugin(void *self) {
    disable_callback(plugin.cb_asid_changed);
    disable_callback(plugin.cb_pend_procname);
    disable_callback(plugin.cb_tracing);

    plugin.self = NULL;
    plugin.hook_cfg.clear();
    plugin.kernel_traces.clear();
    plugin.map_active_utraces.clear();
}

#else

bool
init_plugin(void *self)
{
    (void)self;
    return false;
}

void
uninit_plugin(void *self)
{
    (void)self;
}

#endif
