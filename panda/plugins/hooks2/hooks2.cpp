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

#define MAX_PATHNAME 256

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);

PPP_PROT_REG_CB(on_process_start);
PPP_PROT_REG_CB(on_process_end);
PPP_PROT_REG_CB(on_thread_start);
PPP_PROT_REG_CB(on_thread_end);

}

PPP_CB_BOILERPLATE(on_process_start);
PPP_CB_BOILERPLATE(on_process_end);
PPP_CB_BOILERPLATE(on_thread_start);
PPP_CB_BOILERPLATE(on_thread_end);

enum ThreadStartType {
    NEW_THREAD,
    FORK,
    EXECVE,
    SYS_BRK,
    ASID_CHANGE,
};

/* The hashable OSI thread allows us to store threads in a set */
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

struct process_info {
    std::string name;
    std::unordered_set<HashableOsiThread> threads;
    target_ulong asid;
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

    std::map<target_pid_t, std::shared_ptr<process_info> > map_running_procs;
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

static void
read_string(CPUState *cpu, target_ulong addr, char *buffer)
{
    bool done = false;
    int idx = 0;

    while (!done) {
        panda_virtual_memory_read(
            cpu,
            addr,
            (uint8_t *)(buffer + idx),
            32);
        for (int j = 0; j < 32; j++) {
            if (buffer[idx] == 0) {
                done = true;
                break;
            } else if (idx >= MAX_PATHNAME) {
                buffer[idx - 1] = 0;
                done = true;
                break;
            }
            idx++;
        }
    }
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
update_active_userspace_traces(
    CPUState *cpu,
    target_ulong asid)
{
    bool changed = false;

    OsiProc *proc = get_current_process(cpu);
    if (!proc)
        return changed;

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
update_active_userspace_libs(CPUState *cpu, target_ulong asid)
{
    auto it = plugin.map_active_utraces.find(asid);
    if (it == plugin.map_active_utraces.end()) {
        return;
    }

    auto trace_list = it->second;

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
        auto it = plugin.map_active_utraces.find(panda_current_asid(cpu));
        if (it != plugin.map_active_utraces.end()) {
            for (auto &trace_ptr : it->second) {
                handle_userspace_traces(cpu, tb, trace_ptr);
            }
        }
    }
}


static void
on_process_start_internal(
    CPUState* cpu,
    const char *procname,
    target_ulong asid,
    target_pid_t pid)
{
    PPP_RUN_CB(
        on_process_start,
        cpu,
        procname,
        asid,
        pid);

    if (!asid)
        return;

    if (update_active_userspace_traces(cpu, asid)) {
        update_active_userspace_libs(cpu, asid);
    }

    if (!plugin.kernel_traces.size()) {
        auto search = plugin.map_active_utraces.find(asid);
        if (search == plugin.map_active_utraces.end()) {
            disable_callback(plugin.cb_tracing);
        } else if (search->second.size()) {
            enable_callback(plugin.cb_tracing);
        } else {
            disable_callback(plugin.cb_tracing);
        }
    }
}


static void
on_process_end_internal(
    CPUState* cpu,
    const char *procname,
    target_ulong asid,
    target_pid_t pid)
{
    PPP_RUN_CB(
        on_process_end,
        cpu,
        procname,
        asid,
        pid);

    if (!asid)
        return;

    auto it = plugin.map_active_utraces.find(asid);
    if (it != plugin.map_active_utraces.end()) {
        auto trace_list = it->second;
        trace_list.clear();
        plugin.map_active_utraces.erase(it);
    }

    if (!plugin.kernel_traces.size()) {
        disable_callback(plugin.cb_tracing);
    }
}


static void
on_thread_end_internal(
    CPUState* cpu,
    const char *procname,
    target_ulong asid,
    target_pid_t pid,
    target_pid_t tid)
{
    PPP_RUN_CB(
        on_thread_end,
        cpu,
        procname,
        asid,
        pid,
        tid);

    if (!asid)
        return;

    HashableOsiThread thread;
    thread.pid = pid;
    thread.tid = tid;

    auto it = plugin.map_active_utraces.find(asid);
    if (it != plugin.map_active_utraces.end()) {
        auto trace_list = it->second;

        for (auto &trace : trace_list) {
            trace->active_threads.erase(thread);
        }
    }
}


static void
on_thread_start_internal(
    CPUState* cpu,
    const char *procname,
    target_ulong asid,
    target_pid_t pid,
    target_pid_t tid)
{
    PPP_RUN_CB(
        on_thread_start,
        cpu,
        procname,
        asid,
        pid,
        tid);
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

    update_active_userspace_libs(cpu, panda_current_asid(cpu));
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

    update_active_userspace_libs(cpu, panda_current_asid(cpu));
}

static void
on_start_thread_or_proc(
    CPUState* cpu,
    ThreadStartType type,
    target_pid_t pidtid,
    target_ulong asid,
    const char *procname)
{
    HashableOsiThread thread;
    bool is_new_proc = false;
    bool is_new_thread = false;

    OsiThread *pThread = get_current_thread(cpu);
    if (pThread == NULL)
        return;

    if (type == NEW_THREAD) {
        //printf("new thread: %d,%d\n", pThread->pid, pidtid);
        thread.pid = pThread->pid;
        thread.tid = pidtid;
    } else if (type == FORK) {
        thread.pid = pidtid;
        thread.tid = pidtid;
    } else { /* execve() or brk() or asid_change */
        thread.pid = pThread->pid;
        thread.tid = pThread->tid;
    }

    free_osithread(pThread);

    std::shared_ptr<process_info> info = NULL;

    if (type != NEW_THREAD) {
        auto it = plugin.map_running_procs.find(thread.pid);
        if (it != plugin.map_running_procs.end()) {
            info = it->second;

            if (info->name == procname) {
                if(info->asid == asid) {
                    /* The process info is identical so skip it. */
                    return;
                } else {
                    /* ASID is different so update. */
                    info->asid = asid;
                }
            } else {
                /* We are replacing this process.*/
                on_process_end_internal(
                    cpu,
                    info->name.c_str(),
                    info->asid,
                    thread.pid);
                plugin.map_running_procs.erase(it);
            }
        } else {
            info = std::make_shared<process_info>();
            plugin.map_running_procs[thread.pid] = info;
        }

        is_new_proc = true;
    } else {
        auto it = plugin.map_running_procs.find(thread.pid);
        if (it != plugin.map_running_procs.end()) {
            info = it->second;
        } else {
            //printf("  did not find pid %d \n", pThread->pid);
            info = std::make_shared<process_info>();
            plugin.map_running_procs[thread.pid] = info;
            is_new_proc = true;
        }
        is_new_thread = true;
    }

    info->name = std::string(procname);
    info->asid = asid;
    info->threads.insert(thread);

    if (is_new_proc) {
        on_process_start_internal(
            cpu,
            procname,
            asid,
            thread.pid);
    }

    if (is_new_thread) {
        on_thread_start_internal(
            cpu,
            procname,
            asid,
            thread.pid,
            thread.tid);
    }
}


static void
on_sys_brk_enter(
    CPUState* cpu,
    target_ulong pc,
    target_ulong brk)
{
    (void)pc;
    (void)brk;

    OsiProc *proc = get_current_process(cpu);
    if (!proc) {
        return;
    }

    on_start_thread_or_proc(
        cpu,
        SYS_BRK,
        -1,
        panda_current_asid(cpu),
        proc->name);
}


/* The argument order is architecture dependent. For most common arch's, the
   first 3 args are the same. Arg4/5 (ctid or tls) may be swapped. */
static void
on_sys_clone_return(
    CPUState* cpu,
    target_ulong pc,
    target_ulong flags,
    target_ulong child_stack,
    target_ulong ptr_ptid,
    target_ulong arg4,
    target_ulong arg5)
{
    ThreadStartType type;
    target_ulong asid;

    (void)pc;
    (void)child_stack;
    (void)ptr_ptid;
    (void)arg4;
    (void)arg5;

    if (flags & CLONE_VFORK) {
        /* vfork -- will call execve() immediately so we don't
           track the process. */
        return;
    }

    target_ulong thread_mask = CLONE_VM | CLONE_THREAD;
    if ((flags & thread_mask) == thread_mask) {
        type = NEW_THREAD;
        asid = panda_current_asid(cpu);
    } else {
        type = FORK;
        asid = 0;
    }

    target_long ret = get_syscall_retval(cpu);

    OsiProc *proc = get_current_process(cpu);
    if (!proc)
        return;

    if (ret == 0) {
        OsiThread *pThread = get_current_thread(cpu);
        printf("retval for sys_clone() is 0!!\n");
        printf("  %d,%d,%d,%d\n",
               (int)proc->pid,
               (int)ret,
               (int)pThread->pid,
               (int)pThread->tid);
    }

    on_start_thread_or_proc(
        cpu,
        type,
        ret,
        asid,
        proc->name);

    free_osiproc(proc);
}

static void
on_sys_fork_return(CPUState *cpu, target_ulong pc)
{
    on_sys_clone_return(cpu, pc, 0, 0, 0, 0, 0);
}

static void
on_sys_vfork_return(CPUState *cpu, target_ulong pc)
{
    (void)cpu;
    (void)pc;

    /* vfork will call execve() immediately so we don't
       track the process for now. */
    return;
}

static void
on_sys_execve_enter(
    CPUState *cpu,
    target_ulong pc,
    target_ulong filename,
    target_ulong argv,
    target_ulong envp)
{
    char procname[MAX_PATHNAME];

    (void)pc;
    (void)argv;
    (void)envp;

    read_string(cpu, filename, procname);

    on_start_thread_or_proc(
        cpu,
        EXECVE,
        -1,
        0,
        procname);
}

static void
on_sys_execveat_enter(
    CPUState *cpu,
    target_ulong pc,
    int32_t dfd,
    target_ulong filename,
    target_ulong argv,
    target_ulong envp,
    int32_t flags)
{
    char procname[MAX_PATHNAME];

    (void)pc;
    (void)dfd;
    (void)flags;
    (void)argv;
    (void)envp;

    read_string(cpu, filename, procname);

    on_start_thread_or_proc(
        cpu,
        EXECVE,
        -1,
        0,
        procname);
}


static void
on_sys_exit_enter_common(
    CPUState* cpu,
    target_ulong pc,
    int32_t error_code,
    bool exit_group)
{
    (void)pc;

    HashableOsiThread thread;

    OsiThread *pThread = get_current_thread(cpu);
    if (!pThread) {
        return;
    }

    OsiProc *proc = get_current_process(cpu);
    if (!proc) {
        free_osithread(pThread);
        return;
    }

    thread.pid = pThread->pid;
    thread.tid = pThread->tid;

    /*printf("sys_exit_common: pid=%d, tid=%d, group=%d\n",
           thread.pid,
           thread.tid,
           (int)exit_group);*/

     auto it = plugin.map_running_procs.find(thread.pid);
     if (it != plugin.map_running_procs.end()) {
         auto info = it->second;

         if (!exit_group) {
             info->threads.erase(thread);
         }

         if (thread.pid != thread.tid) {
             on_thread_end_internal(
                 cpu,
                 info->name.c_str(),
                 info->asid,
                 thread.pid,
                 thread.tid);
         }

         if (exit_group || info->threads.empty()) {
             on_process_end_internal(
                 cpu,
                 info->name.c_str(),
                 info->asid,
                 thread.pid);
             plugin.map_running_procs.erase(it);
         }
     } else {
         on_process_end_internal(
             cpu,
             proc->name,
             panda_current_asid(cpu),
             thread.pid);
     }

     free_osithread(pThread);
     free_osiproc(proc);
}


static void
on_sys_exit_enter(
    CPUState* cpu,
    target_ulong pc,
    int32_t error_code)
{
    on_sys_exit_enter_common(cpu, pc, error_code, false);
}

static void
on_sys_exit_group_enter(
    CPUState* cpu,
    target_ulong pc,
    int32_t error_code)
{
    on_sys_exit_enter_common(cpu, pc, error_code, true);
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

    disable_callback(plugin.cb_pend_procname);

    OsiProc *proc = get_current_process(cpu);
    if (!proc)
        return;

    on_start_thread_or_proc(
        cpu,
        ASID_CHANGE,
        -1,
        panda_current_asid(cpu),
        proc->name);
}


static bool
cb_asid_changed(
    CPUState *env,
    target_ulong old_asid,
    target_ulong new_asid)
{
    if (old_asid == new_asid){
        return false;
    }

    auto search = plugin.map_active_utraces.find(new_asid);
    if (search == plugin.map_active_utraces.end()) {
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
    enable_callback(plugin.cb_asid_changed);
    disable_callback(plugin.cb_pend_procname);
    disable_callback(plugin.cb_tracing);

#if defined(TARGET_X86_64)
    PPP_REG_CB("syscalls2", on_sys_mmap_return, on_mmap_return);
#elif defined(TARGET_I386)
    PPP_REG_CB("syscalls2", on_sys_mmap_pgoff_return, on_mmap_return);
#else
    PPP_REG_CB("syscalls2", on_do_mmap2_return, on_mmap_return);
#endif

    PPP_REG_CB("syscalls2", on_sys_munmap_return, on_sys_munmap_return);

    PPP_REG_CB("syscalls2", on_sys_brk_enter, on_sys_brk_enter);
    PPP_REG_CB("syscalls2", on_sys_execve_enter, on_sys_execve_enter);
    PPP_REG_CB("syscalls2", on_sys_execveat_enter, on_sys_execveat_enter);
    PPP_REG_CB("syscalls2", on_sys_clone_return, on_sys_clone_return);
    PPP_REG_CB("syscalls2", on_sys_fork_return, on_sys_fork_return);
    PPP_REG_CB("syscalls2", on_sys_vfork_return, on_sys_vfork_return);
    PPP_REG_CB("syscalls2", on_sys_exit_enter, on_sys_exit_enter);
    PPP_REG_CB("syscalls2", on_sys_exit_group_enter, on_sys_exit_group_enter);

    return true;
}

void uninit_plugin(void *self) {
    disable_callback(plugin.cb_asid_changed);
    disable_callback(plugin.cb_pend_procname);
    disable_callback(plugin.cb_tracing);

    plugin.self = NULL;
    plugin.hook_cfg.clear();
    plugin.kernel_traces.clear();
    plugin.map_active_utraces.clear();
}
