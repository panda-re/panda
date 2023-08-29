/*!
 * @file osi_linux.cpp
 * @brief PANDA Operating System Introspection for Linux.
 *
 * @author Manolis Stamatogiannakis <manolis.stamatogiannakis@vu.nl>
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <map>
#include <unordered_set>
#include <glib.h>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "osi/osi_types.h"
#include "osi/os_intro.h"
#include "utils/kernelinfo/kernelinfo.h"
#include "osi_linux.h"
#include "syscalls2/syscalls_ext_typedefs.h"
#include "hooks/hooks_int_fns.h"
#include "proc_start_linux/proc_start_linux.h"
#include "proc_start_linux/proc_start_linux_ppp.h"

#include "default_profile.h"
#include "kernel_2_4_x_profile.h"
#include "kernelinfo_downloader.h"
#include "endian_helpers.h"

#include "panda/tcg-utils.h"
#include "osi/osi_ext.h"

#define KERNEL_CONF "/" TARGET_NAME "-softmmu/panda/plugins/osi_linux/kernelinfo.conf"

const uint32_t MAPPING_TYPE_FILE    = 1 << 0;
const uint32_t MAPPING_TYPE_HEAP    = 1 << 1;
const uint32_t MAPPING_TYPE_STACK   = 1 << 2;
const uint32_t MAPPING_TYPE_UNKNOWN = 1 << 3;
const uint32_t MAPPING_TYPE_ALL     = (1 << 4) - 1;

#ifdef TARGET_MIPS
#include "hw_proc_id/hw_proc_id_ext.h"
#endif

/*
 * Functions interfacing with QEMU/PANDA should be linked as C.
 * C++ function name mangling breaks linkage.
 */
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
#include "osi_linux_int_fns.h"
}
void on_first_syscall(CPUState *cpu, target_ulong pc, target_ulong callno);

void on_get_processes(CPUState *env, GArray **out);
void on_get_process_handles(CPUState *env, GArray **out);
void on_get_current_process(CPUState *env, OsiProc **out_p);
void on_get_current_process_handle(CPUState *env, OsiProcHandle **out_p);
void on_get_process(CPUState *, const OsiProcHandle *, OsiProc **);
void on_get_mappings(CPUState *env, OsiProc *p, GArray **out);
void on_get_file_mappings(CPUState *env, OsiProc *p, GArray **out);
void on_get_heap_mappings(CPUState *env, OsiProc *p, GArray **out);
void on_get_stack_mappings(CPUState *env, OsiProc *p, GArray **out);
void on_get_unknown_mappings(CPUState *env, OsiProc *p, GArray **out);
void on_get_mapping_by_addr(CPUState *env, OsiProc *p, const target_ptr_t addr, OsiModule **out);
void on_get_mapping_base_address_by_name(CPUState *env, OsiProc *p, const char *name, target_ptr_t *base_address);
void on_has_mapping_prefix(CPUState *env, OsiProc *p, const char *prefix, bool *found);
void on_get_current_thread(CPUState *env, OsiThread *t);

void init_per_cpu_offsets(CPUState *cpu);
struct kernelinfo ki;
struct KernelProfile const *kernel_profile;

extern const char *qemu_file;
static bool osi_initialized;
static bool first_osi_check = true;

/* ******************************************************************
 Helpers
****************************************************************** */

/**
 * @brief Resolves a file struct and returns its full pathname.
 */
static char *get_file_name(CPUState *env, target_ptr_t file_struct) {
    char *name = NULL;
    target_ptr_t file_dentry, file_mnt;

    // Read addresses for dentry, vfsmnt structs.
    file_dentry = get_file_dentry(env, file_struct);
    file_mnt = get_file_mnt(env, file_struct);
   OG_printf("(struct dentry *) file_dentry at " TARGET_FMT_lx "\n", file_dentry);
   OG_printf("(struct vfsmount *) file_mnt at " TARGET_FMT_lx "\n", file_mnt);

    if (unlikely(file_dentry == (target_ptr_t)NULL || file_mnt == (target_ptr_t)NULL)) {
        LOG_INFO("failure resolving file struct " TARGET_PTR_FMT "/" TARGET_PTR_FMT, file_dentry, file_mnt);
        return NULL;
    }

    char *s1, *s2;
    s1 = read_vfsmount_name(env, file_mnt);
    s2 = read_dentry_name(env, file_dentry);
    OG_printf("S1=%s, S2=%s\n", s1, s2);
    name = g_strconcat(s1, s2, NULL);
    g_free(s1);
    g_free(s2);

    return name;
}

static uint64_t get_file_position(CPUState *env, target_ptr_t file_struct) {
    return get_file_pos(env, file_struct);
}

static target_ptr_t get_file_struct_ptr(CPUState *env, target_ptr_t task_struct, int fd) {
    target_ptr_t files = get_files(env, task_struct);
    target_ptr_t fds = kernel_profile->get_files_fds(env, files);
    target_ptr_t fd_file = 0;
    // fds is a flat array with struct file pointers.
    // fds+fd*sizeof(target_ptr_t) is the address of the nth pointer that we need to read
    OG_printf("(struct files_struct*) files at " TARGET_FMT_lx \
           ", (struct file *(*)[32])fds at " TARGET_FMT_lx "\n", files, fds);

    auto err = struct_get(env, &fd_file, fds, fd*sizeof(target_ptr_t));
    if (err != struct_get_ret_t::SUCCESS) {
      LOG_ERROR("Unable to load file descriptor details");
    }
    fixupendian(fd_file);
    return fd_file;
}

/**
 * @brief Resolves a file struct and returns its full pathname.
 */
static char *get_fd_name(CPUState *env, target_ptr_t task_struct, int fd) {
    target_ptr_t fd_file = get_file_struct_ptr(env, task_struct, fd);
    if (fd_file == (target_ptr_t)NULL) return NULL;
    OG_printf("Get FDs[%d] name from " TARGET_FMT_lx "\n", fd, fd_file);
    return get_file_name(env, fd_file);
}

/**
 * @brief Retrieves the current offset of a file descriptor.
 */
static uint64_t get_fd_pos(CPUState *env, target_ptr_t task_struct, int fd) {
    target_ptr_t fd_file = get_file_struct_ptr(env, task_struct, fd);
    if (fd_file == (target_ptr_t)NULL) return ((uint64_t) INVALID_FILE_POS);
    return get_file_position(env, fd_file);
}

/**
 * @brief Fills an OsiProcHandle struct.
 */
static void fill_osiprochandle(CPUState *cpu, OsiProcHandle *h,
        target_ptr_t task_addr) {
    struct_get_ret_t UNUSED(err);

    // h->asid = taskd->mm->pgd (some kernel tasks are expected to return error)
    err = struct_get(cpu, &h->asid, task_addr, {ki.task.mm_offset, ki.mm.pgd_offset});

    // Convert asid to physical to be able to compare it with the pgd register.
    h->asid = panda_virt_to_phys(cpu, h->asid);
    h->taskd = kernel_profile->get_group_leader(cpu, task_addr);
}

/**
 * @brief Fills an OsiProc struct. Any existing contents are overwritten.
 */
void fill_osiproc(CPUState *cpu, OsiProc *p, target_ptr_t task_addr) {
    struct_get_ret_t UNUSED(err);
    memset(p, 0, sizeof(OsiProc));

    // p->asid = taskd->mm->pgd (some kernel tasks are expected to return error)
    err = struct_get(cpu, &p->asid, task_addr, {ki.task.mm_offset, ki.mm.pgd_offset});

    // p->ppid = taskd->real_parent->pid
    err = struct_get(cpu, &p->ppid, task_addr,
                     {ki.task.real_parent_offset, ki.task.tgid_offset});

    // Convert asid to physical to be able to compare it with the pgd register.
    p->asid = p->asid ? panda_virt_to_phys(cpu, p->asid) : (target_ulong) NULL;
    p->taskd = kernel_profile->get_group_leader(cpu, task_addr);

    p->name = get_name(cpu, task_addr, p->name);
    p->pid = get_tgid(cpu, task_addr);
    //p->ppid = get_real_parent_pid(cpu, task_addr);
    p->pages = NULL;  // OsiPage - TODO

    //if kernel version is < 3.17
    if(ki.version.a < 3 || (ki.version.a == 3 && ki.version.b < 17)) {
        uint64_t tmp = get_start_time(cpu, task_addr);

        //if there's an endianness mismatch
        #if defined(TARGET_WORDS_BIGENDIAN) != defined(HOST_WORDS_BIGENDIAN)
            //convert the most significant half into nanoseconds, then add the rest of the nanoseconds
            p->create_time = (((tmp & 0xFFFFFFFF00000000) >> 32) * 1000000000) + (tmp & 0x00000000FFFFFFFF);
        #else
            //convert the least significant half into nanoseconds, then add the rest of the nanoseconds
            p->create_time = ((tmp & 0x00000000FFFFFFFF) * 1000000000) + ((tmp & 0xFFFFFFFF00000000) >> 32);
        #endif
       
    } else {
        p->create_time = get_start_time(cpu, task_addr);
    }
}

/**
 * @brief Fills an OsiModule struct.
 * Returns true if the struct was filled (module type of m matches one of the
 *   requested mapping types.
 */
static bool fill_osimodule(CPUState *env, OsiModule *m, target_ptr_t vma_addr,
        uint32_t mapping_type) {

    target_ulong vma_start, vma_end;
    target_ptr_t vma_vm_file;
    target_ptr_t vma_dentry;
    target_ptr_t mm_addr, start_brk, brk, start_stack;
    bool populated = false;

    static uint64_t last_instr_count;
    static target_ptr_t last_dentry;
    static char *last_file;
    static char *last_name;

    memset(m, 0, sizeof(OsiModule));

    vma_start = get_vma_start(env, vma_addr);
    vma_end = get_vma_end(env, vma_addr);
    vma_vm_file = get_vma_vm_file(env, vma_addr);

    if (vma_vm_file != (target_ptr_t)NULL) {
        // Memory area is mapped from a file.
        if((mapping_type & MAPPING_TYPE_FILE) != 0) {
            populated = true;
            vma_dentry = get_vma_dentry(env, vma_addr);

            if((env->rr_guest_instr_count == last_instr_count) &&
                    (vma_dentry == last_dentry)) {
                m->file = g_strdup(last_file);
                m->name = g_strdup(last_name);
            } else {
                m->file = read_dentry_name(env, vma_dentry);
                m->name = g_strrstr(m->file, "/");
                if (m->name != NULL) m->name = g_strdup(m->name + 1);

                // Save the results from calling read_dentry_name
                // Next request may be able to reuse these
                last_instr_count = env->rr_guest_instr_count;
                last_dentry = vma_dentry;
                last_file = m->file;
                last_name = m->name;
            }

            // Get offset in pages, then *= with PAGE_SIZE to translate into bytes
            get_vma_pgoff(env, vma_addr, &m->offset);
            m->offset *= 4096; // PAGE_SIZE XXX should specify this size in OSI profiles.
        }
    } else {  // Other memory areas.
        mm_addr = get_vma_vm_mm(env, vma_addr);
        start_brk = get_mm_start_brk(env, mm_addr);
        brk = get_mm_brk(env, mm_addr);
        start_stack = get_mm_start_stack(env, mm_addr);

        if (vma_start <= start_brk && vma_end >= brk) {
            if((mapping_type & MAPPING_TYPE_HEAP) != 0) {
                populated = true;
                m->name = g_strdup("[heap]");
            }
        } else if (vma_start <= start_stack && vma_end >= start_stack) {
            if((mapping_type & MAPPING_TYPE_STACK) != 0) {
                populated = true;
                m->name = g_strdup("[stack]");
            }
        } else if((mapping_type & MAPPING_TYPE_UNKNOWN) != 0) {
            populated = true;
            m->name = g_strdup("[???]");
        }
    }

    if(populated) {
        // Fill everything but m->name, m->file & m->offset.
        m->modd = vma_addr;
        m->base = vma_start;
        m->size = vma_end - vma_start;
        m->flags = get_vma_flags(env, vma_addr);
    }

    return populated;
}

/**
 * @brief Fills an OsiThread struct. Any existing contents are overwritten.
 */
void fill_osithread(CPUState *env, OsiThread *t,
                           target_ptr_t task_addr) {
    memset(t, 0, sizeof(*t));
    t->tid = get_pid(env, task_addr);
    t->pid = get_tgid(env, task_addr);
}

/* ******************************************************************
 Initialization logic
****************************************************************** */
/**
 * @brief When necessary, after the first syscall ensure we can read current task
 */

void on_first_syscall(CPUState *cpu, target_ulong pc, target_ulong callno) {
    // Make sure we can now read current. Note this isn't like all the other on_...
    // functions that are registered as OSI callbacks
    /*
    if (can_read_current(cpu) == false) {
      printf("Failed to read at first syscall. Retrying...\n");
      return;
    }
    */
    assert(can_read_current(cpu) && "Couldn't find current task struct at first syscall");
    if (!osi_initialized)
      LOG_INFO(PLUGIN_NAME " initialization complete.");
    osi_initialized=true;
    PPP_REMOVE_CB("syscalls2", on_all_sys_enter, on_first_syscall);
}

/**
 * @brief Test to see if we can read the current task struct
 */
inline bool can_read_current(CPUState *cpu) {
    target_ptr_t ts = kernel_profile->get_current_task_struct(cpu);
    return 0x0 != ts;
}

#ifdef TARGET_MIPS
// on MIPS, we need to get the value of r28 from the kernel before
// we can read the current task struct. If osi_guest_is_ready is called
// before r28 is set we won't check until the first syscall. This
// significantly increases the number of instructions we need to
// wait before we can read the current task struct. Instead, we
// wait until r28 is set and then proceed on MIPS. The intended use case
// (on boot) should work fine because r28 will be set immediately and then
// won't check again until the first syscall.
bool r28_set = false;
inline void check_cache_r28(CPUState *cpu);
#endif

/**
 * @brief Check if we've successfully initialized OSI for the guest.
 * Returns true if introspection is available.
 *
 * If introspection is unavailable at the first check, this will register a PPP-style
 * callback with syscalls2 to try reinitializing at the first syscall.
 *
 * If that fails, then we raise an assertion because OSI has really failed.
 */
bool osi_guest_is_ready(CPUState *cpu, void** ret) {

    if (osi_initialized) { // If osi_initialized is set, the guest must be ready
      return true;      // or, if it isn't, the user wants an assertion error
    }


    // If it's the very first time, try reading current, if we can't
    // wait until first sycall and try again
    if (first_osi_check) {
        #ifdef TARGET_MIPS
        if (!get_id(cpu)){
            // If we're on MIPS, we need to wait until r28 is set before
            // moving to a syscall strategy
            if (!id_is_initialized()){
                *ret = NULL;
                return false;
            }
        }
        #endif
        first_osi_check = false;

        init_per_cpu_offsets(cpu); // Formerly in _machine_init callback, but now it will work with loading OSI after init and snapshots

        // Try to load current, if it works, return true
        if (can_read_current(cpu)) {
            // Disable on_first_syscall PPP callback because we're all set
            PPP_REMOVE_CB("syscalls2", on_all_sys_enter, on_first_syscall); // XXX may be disabled?
            LOG_INFO(PLUGIN_NAME " initialization complete.");
            osi_initialized=true;
            return true;
        }

        // We can't read the current task right now. This isn't a surprise,
        // it could be happening because we're in boot.
        // Wait until on_first_syscall runs, everything should work then
        LOG_INFO(PLUGIN_NAME " cannot find current task struct. Deferring OSI initialization until first syscall.");

        PPP_REG_CB("syscalls2", on_all_sys_enter, on_first_syscall);
    }
    // Not yet initialized, just set the caller's result buffer to NULL
    *ret = NULL;
    return false;
}

/* ******************************************************************
 PPP Callbacks
****************************************************************** */

/**
 * @brief PPP callback to retrieve process list from the running OS.
 *
 */
void on_get_processes(CPUState *env, GArray **out) {
    if (!osi_guest_is_ready(env, (void**)out)) return;
    // instantiate and call function from get_process_info template
    get_process_info<>(env, out, fill_osiproc, free_osiproc_contents);
}

/**
 * @brief PPP callback to retrieve process handles from the running OS.
 */
void on_get_process_handles(CPUState *env, GArray **out) {
    if (!osi_guest_is_ready(env, (void**)out)) return;

    // instantiate and call function from get_process_info template
    get_process_info<>(env, out, fill_osiprochandle, free_osiprochandle_contents);
}

/**
 * @brief PPP callback to retrieve info about the currently running process.
 */
void on_get_current_process(CPUState *env, OsiProc **out) {
    if (!osi_guest_is_ready(env, (void**)out)) return;

    static target_ptr_t last_ts = 0x0;
    static target_ptr_t cached_taskd = 0x0;
    static target_ptr_t cached_asid = 0x0;
    static char *cached_name = (char *)g_malloc0(ki.task.comm_size);
    static target_ptr_t cached_pid = -1;
    static target_ptr_t cached_ppid = -1;
    static void *cached_comm_ptr = NULL;
    static uint64_t cached_start_time = 0;
    // OsiPage - TODO

    OsiProc *p = NULL;
    target_ptr_t ts = kernel_profile->get_current_task_struct(env);
    if (0x0 != ts) {
        p = (OsiProc *)g_malloc(sizeof(*p));
        if ((ts != last_ts) || (NULL == cached_comm_ptr) ||
            (0 != strncmp((char *)cached_comm_ptr, cached_name,
                          ki.task.comm_size))) {
            last_ts = ts;
            fill_osiproc(env, p, ts);

            // update the cache
            cached_taskd = p->taskd;
            cached_asid = p->asid;
            memset(cached_name, 0, ki.task.comm_size);
            strncpy(cached_name, p->name, ki.task.comm_size);
            cached_pid = p->pid;
            cached_ppid = p->ppid;
	    cached_start_time = p->create_time;
            cached_comm_ptr = panda_map_virt_to_host(
                env, ts + ki.task.comm_offset, ki.task.comm_size);
        } else {
            p->taskd = cached_taskd;
            p->asid = cached_asid;
            p->name = g_strdup(cached_name);
            p->pid = cached_pid;
            p->ppid = cached_ppid;
            p->pages = NULL;
	    p->create_time = cached_start_time;
        }
    }
    *out = p;
}

/**
 * @brief PPP callback to the handle of the currently running process.
 */
void on_get_current_process_handle(CPUState *env, OsiProcHandle **out) {
    if (!osi_guest_is_ready(env, (void**)out)) return;

    OsiProcHandle *p = NULL;
    target_ptr_t ts = kernel_profile->get_current_task_struct(env);
    if (ts) {
        p = (OsiProcHandle *)g_malloc(sizeof(OsiProcHandle));
        fill_osiprochandle(env, p, ts);
    }
    *out = p;
}

/**
 * @brief PPP callback to retrieve info about a running process using its
 * handle.
 */
void on_get_process(CPUState *env, const OsiProcHandle *h, OsiProc **out) {
    if (!osi_guest_is_ready(env, (void**)out)) return;

    OsiProc *p = NULL;
    if (h != NULL && h->taskd != (target_ptr_t)NULL) {
        p = (OsiProc *)g_malloc(sizeof(OsiProc));
        fill_osiproc(env, p, h->taskd);
    }
    *out = p;
}

/**
 * @brief PPP callback to retrieve memory details about a running process.
 * Return value is a pointer to a static memory address, which will be
 * overwritten the next time this function is called.
 */
void on_get_proc_mem(CPUState *env, const OsiProc *p, OsiProcMem **out) {
    if (!osi_guest_is_ready(env, (void**)out)) return;

    static OsiProcMem pm;

    if ((p != nullptr) && (p->taskd != 0)) {
        target_ptr_t vma_addr = get_vma_first(env, p->taskd);
        if(vma_addr != 0) {
            target_ptr_t mm_addr = get_vma_vm_mm(env, vma_addr);
            if(mm_addr != 0) {
                pm.start_brk = get_mm_start_brk(env, mm_addr);
                if(pm.start_brk != 0) {
                    pm.brk = get_mm_brk(env, mm_addr);
                    if(pm.brk != 0) {
                        *out = &pm;
                        return;
                    }
                }
            }
        }
    }

    *out = nullptr;
}

/**
 * @brief Get all mappings that match one of the specified mapping types.
 */
static void get_mappings(CPUState *env, OsiProc *p, GArray **out,
        uint32_t mapping_type) {
    if (!osi_guest_is_ready(env, (void**)out)) return;

    OsiModule m;
    target_ptr_t vma_first, vma_current;

    // Read the module info for the process.
    vma_first = vma_current = get_vma_first(env, p->taskd);
    if (vma_current == (target_ptr_t)NULL) goto error0;

    if (*out == NULL) {
        // g_array_sized_new() args: zero_term, clear, element_sz, reserved_sz
        *out = g_array_sized_new(false, false, sizeof(OsiModule), 128);
        g_array_set_clear_func(*out, (GDestroyNotify)free_osimodule_contents);
    }

    do {
        if(fill_osimodule(env, &m, vma_current, mapping_type)) {
            g_array_append_val(*out, m);
        }
        vma_current = get_vma_next(env, vma_current);
    } while(vma_current != (target_ptr_t)NULL && vma_current != vma_first);

    return;

error0:
    if(*out != NULL) {
        g_array_free(*out, true);
    }
    *out = NULL;
    return;
}


/**
 * @brief PPP callback to retrieve OsiModules from the running OS.
 *
 * Current implementation returns all the memory areas mapped by the
 * process and the files they were mapped from. Libraries that have
 * many mappings will appear multiple times.
 *
 * @todo Remove duplicates from results.
 */
void on_get_mappings(CPUState *env, OsiProc *p, GArray **out) {
    get_mappings(env, p, out, MAPPING_TYPE_ALL);
}

/**
 * @brief PPP callback to retrieve OsiModules backed by files from 
 * the running OS.
 */
void on_get_file_mappings(CPUState *env, OsiProc *p, GArray **out) {
    get_mappings(env, p, out, MAPPING_TYPE_FILE);
}

/**
 * @brief PPP callback to retrieve heap OsiModules from the running OS.
 */
void on_get_heap_mappings(CPUState *env, OsiProc *p, GArray **out) {
    get_mappings(env, p, out, MAPPING_TYPE_HEAP);
}

/**
 * @brief PPP callback to retrieve stack OsiModules from the running OS.
 */
void on_get_stack_mappings(CPUState *env, OsiProc *p, GArray **out) {
    get_mappings(env, p, out, MAPPING_TYPE_STACK);
}

/**
 * @brief PPP callback to retrieve unknown OsiModules from the running OS.
 */
void on_get_unknown_mappings(CPUState *env, OsiProc *p, GArray **out) {
    get_mappings(env, p, out, MAPPING_TYPE_UNKNOWN);
}

/**
 * @brief PPP callback to retrieve OsiModule for a specific virtual memory
 * address from the running OS.
 */
void on_get_mapping_by_addr(CPUState *env, OsiProc *p, const target_ptr_t addr,
        OsiModule **out) {
    if (!osi_guest_is_ready(env, (void**)out)) return;

    // Read the module info for the process.
    target_ptr_t vma_first = get_vma_first(env, p->taskd);
    target_ptr_t vma_current = vma_first;

    if (vma_current != (target_ptr_t)NULL) {
        do {
            target_ptr_t vma_start = get_vma_start(env, vma_current);
            if(addr >= vma_start) {
                target_ptr_t vma_end = get_vma_end(env, vma_current);
                if(addr < vma_end) {
                    *out = static_cast<OsiModule *>(g_malloc(sizeof(**out)));
                    assert(fill_osimodule(env, *out, vma_current,
                        MAPPING_TYPE_ALL));
                    return;
                }
            }
            vma_current = get_vma_next(env, vma_current);
        } while(vma_current != (target_ptr_t)NULL && vma_current != vma_first);
    }

    *out = nullptr;
}

/**
 * @brief PPP callback that returns true if a modules is loaded whose name
 * begins with prefix.
 */
void on_has_mapping_prefix(CPUState *env, OsiProc *p, const char *prefix,
        bool *found) {

    void *_out;
    *found = false;
    if (!osi_guest_is_ready(env, &_out)) {
        return;
    }

    const size_t prefix_len = strlen(prefix);

    // Read the module info for the process.
    target_ptr_t vma_first = get_vma_first(env, p->taskd);
    target_ptr_t vma_current = vma_first;
    target_ptr_t vma_previous_dentry = 0;

    if (vma_current != (target_ptr_t)NULL) {
        do {
            target_ptr_t vma_vm_file = get_vma_vm_file(env, vma_current);
            if (vma_vm_file != (target_ptr_t)NULL) {
                // Memory area is mapped from a file.
                target_ptr_t vma_dentry = get_vma_dentry(env, vma_current);
                if(vma_dentry != vma_previous_dentry) {
                    char *file = read_dentry_name(env, vma_dentry);
                    char *mapping_name = g_strrstr(file, "/");
                    if(mapping_name != NULL) {
                        *found = strncmp(prefix, ++mapping_name,
                            prefix_len) == 0;
                    }
                    g_free(file);
                    if(*found) {
                        return;
                    }
                    vma_previous_dentry = vma_dentry;
                }
            }
            vma_current = get_vma_next(env, vma_current);
        } while(vma_current != (target_ptr_t)NULL && vma_current != vma_first);
    }
}

/**
 * @brief PPP callback that returns the base address for the requested module.
 */
void on_get_mapping_base_address_by_name(CPUState *env, OsiProc *p, const char *name, target_ptr_t *base_address) {
    void *_out;
    if (!osi_guest_is_ready(env, &_out)) {
        *base_address = 0;
        return;
    }

    bool found = false;

    // Read the module info for the process.
    target_ptr_t vma_first = get_vma_first(env, p->taskd);
    target_ptr_t vma_current = vma_first;
    target_ptr_t vma_previous_dentry = 0;

    if (vma_current != (target_ptr_t)NULL) {
        do {
            target_ptr_t vma_vm_file = get_vma_vm_file(env, vma_current);
            if (vma_vm_file != (target_ptr_t)NULL) {
                // Memory area is mapped from a file.
                target_ptr_t vma_dentry = get_vma_dentry(env, vma_current);
                if(vma_dentry != vma_previous_dentry) {
                    char *file = read_dentry_name(env, vma_dentry);
                    char *mapping_name = g_strrstr(file, "/");
                    if(mapping_name != NULL) {
                        found = g_strcmp0(name, ++mapping_name) == 0;
                    }
                    g_free(file);
                    if(found) {
                        *base_address = get_vma_start(env, vma_current);
                        return;
                    }
                    vma_previous_dentry = vma_dentry;
                }
            }
            vma_current = get_vma_next(env, vma_current);
        } while(vma_current != (target_ptr_t)NULL && vma_current != vma_first);
    }

    *base_address = 0;
    return;
}



/**
 * @brief PPP callback to retrieve current thread.
 */
void on_get_current_thread(CPUState *env, OsiThread **out) {
    static target_ptr_t last_ts = 0x0;
    static target_pid_t cached_tid = 0;
    static target_pid_t cached_pid = 0;

    if (!osi_guest_is_ready(env, (void**)out)) return;

    OsiThread *t = NULL;
    target_ptr_t ts = kernel_profile->get_current_task_struct(env);
    if (0x0 != ts) {
        t = (OsiThread *)g_malloc(sizeof(OsiThread));
        if (last_ts != ts) {
            fill_osithread(env, t, ts);
            cached_tid = t->tid;
            cached_pid = t->pid;
        } else {
            t->tid = cached_tid;
            t->pid = cached_pid;
        }
    }

    *out = t;
}

/**
 * @brief PPP callback to retrieve the process pid from a handle.
 */
void on_get_process_pid(CPUState *env, const OsiProcHandle *h, target_pid_t *pid) {
    if (!osi_guest_is_ready(env, (void**)pid)) return;

    if (h->taskd == NULL || h->taskd == (target_ptr_t)-1) {
        *pid = (target_pid_t)-1;
    } else {
        *pid = get_tgid(env, h->taskd);
    }
}

/**
 * @brief PPP callback to retrieve the process parent pid from a handle.
 */
void on_get_process_ppid(CPUState *cpu, const OsiProcHandle *h, target_pid_t *ppid) {
    struct_get_ret_t UNUSED(err);
    if (!osi_guest_is_ready(cpu, (void**)ppid)) return;

    if (h->taskd == (target_ptr_t)-1) {
        *ppid = (target_pid_t)-1;
    } else {
        // ppid = taskd->real_parent->pid
        err = struct_get(cpu, ppid, h->taskd,
                         {ki.task.real_parent_offset, ki.task.pid_offset});
        if (err != struct_get_ret_t::SUCCESS) {
            *ppid = (target_pid_t)-1;
        }
    }
}

/* ******************************************************************
 osi_linux extra API
****************************************************************** */

char *osi_linux_fd_to_filename(CPUState *env, OsiProc *p, int fd) {
    char *filename = NULL;
    target_ptr_t ts_current;
    //const char *err = NULL;

    if (p == NULL) {
        //err = "Null OsiProc argument";
        goto end;
    }

    ts_current = p->taskd;
    if (ts_current == 0) {
        //err = "can't get task";
        goto end;
    }

    filename = get_fd_name(env, ts_current, fd);
    if (unlikely(filename == NULL)) {
        //err = "can't get filename";
        goto end;
    }

    filename = g_strchug(filename);
    if (unlikely(g_strcmp0(filename, "") == 0)) {
        //err = "filename is empty";
        g_free(filename);
        filename = NULL;
        goto end;
    }

end:
    //if (unlikely(err != NULL)) {
    //    LOG_ERROR("%s -- (pid=%d, fd=%d)", err, (int)p->pid, fd);
    //}
    return filename;
}


target_ptr_t ext_get_file_dentry(CPUState *env, target_ptr_t file_struct) {
	return get_file_dentry(env, file_struct);
} 

target_ptr_t ext_get_file_struct_ptr(CPUState *env, target_ptr_t task_struct, int fd) {
	return get_file_struct_ptr(env, task_struct, fd);
}


unsigned long long  osi_linux_fd_to_pos(CPUState *env, OsiProc *p, int fd) {
    //    target_ulong asid = panda_current_asid(env);
    target_ptr_t ts_current = 0;
    ts_current = p->taskd;
    if (ts_current == 0) return INVALID_FILE_POS;
    return get_fd_pos(env, ts_current, fd);
}



/* ******************************************************************
 Testing functions
****************************************************************** */
#if defined(OSI_LINUX_TEST)
/**
 * @brief Tests the osi_linux functionality by directly calling the
 * respective introspection functions. For testing the functions via
 * their callbacks, use the osi_test plugin.
 */
int osi_linux_test(CPUState *env, target_ulong oldval, target_ulong newval) {
    static uint32_t asid_change_count = 0;
    GArray *ps = NULL;

    on_get_processes(env, &ps);
    assert(ps != NULL && ps->len > 0 && "no processes retrieved");

#if PANDA_LOG_LEVEL >= PANDA_LOG_INFO
    char mode = panda_in_kernel(env) ? 'K' : 'U';
    LOG_INFO("--- START(%c) %06u ------------------------------------------", mode, asid_change_count);
    for (uint32_t i = 0; i < ps->len; i++) {
        OsiProc *p = &g_array_index(ps, OsiProc, i);
        LOG_INFO(TARGET_PID_FMT ":" TARGET_PID_FMT ":%s:" TARGET_PTR_FMT ":" TARGET_PTR_FMT,
                 p->pid, p->ppid, p->name, p->asid, p->taskd);
#if defined(OSI_LINUX_TEST_MODULES)
        GArray *ms = NULL;
        on_get_mappings(env, p, &ms);
        if (ms != NULL) {
            for (uint32_t j = 0; j < ms->len; j++) {
                OsiModule *m = &g_array_index(ms, OsiModule, j);
                LOG_INFO("\t" TARGET_PTR_FMT ":%04up:%s:%s", m->base, NPAGES(m->size), m->name, m->file);
            }
            g_array_free(ms, true);
        }
#endif
#if defined(OSI_LINUX_TEST_MODULES) && defined(OSI_LINUX_TEST_FDNAME)
        if (ms != NULL) {
            LOG_INFO("\t------------------------");
        }
#endif
#if defined(OSI_LINUX_TEST_FDNAME)
        for (uint32_t fd=0; fd<16; fd++) {
            char *s = get_fd_name(env, ps->proc[i].offset, fd);
            LOG_INFO("\tfd%d -> %s", fd, s);
            g_free(s);
        }
#endif
    }
    LOG_INFO("--- END(%c)  %06u ------------------------------------------", mode, asid_change_count);
#endif // PANDA_LOG_LEVEL >= PANDA_LOG_INFO

    g_array_free(ps, true);
    asid_change_count++;
    return 0;
}
#endif // OSI_LINUX_TEST

/* ******************************************************************
 Plugin Initialization/Cleanup
****************************************************************** */
/**
 * @brief Updates any per-cpu offsets we need for introspection.
 * This allows kernel profiles to be independent of boot-time configuration.
 * If ki.task.per_cpu_offsets_addr is set to 0, the values of the per-cpu
 * offsets in the profile will not be updated.
 *
 * Currently the only per-cpu offset we use in osi_linux is
 * ki.task.per_cpu_offset_0_addr.
 */
void init_per_cpu_offsets(CPUState *cpu) {
    // old kernel - no per-cpu offsets to update
    if (PROFILE_KVER_LE(ki, 2, 4, 254)) {
        return;
    }

    // skip update because there's no per_cpu_offsets_addr
    if (ki.task.per_cpu_offsets_addr == 0) {
        LOG_INFO("Using profile-provided value for ki.task.per_cpu_offset_0_addr: "
                 TARGET_PTR_FMT, (target_ptr_t)ki.task.per_cpu_offset_0_addr);
        return;
    }

    // skip update because of failure to read from per_cpu_offsets_addr
    target_ptr_t per_cpu_offset_0_addr;
    auto r = struct_get(cpu, &per_cpu_offset_0_addr, ki.task.per_cpu_offsets_addr,
                        0*sizeof(target_ptr_t));
    if (r != struct_get_ret_t::SUCCESS) {
        LOG_ERROR("Unable to update value of ki.task.per_cpu_offset_0_addr.");
        assert(false);
        return;
    }

    ki.task.per_cpu_offset_0_addr = per_cpu_offset_0_addr;
    LOG_INFO("Updated value for ki.task.per_cpu_offset_0_addr: "
             TARGET_PTR_FMT, (target_ptr_t)ki.task.per_cpu_offset_0_addr);
}

/**
 * @brief After guest has restored snapshot, reset so we can redo
 * initialization
 */
void restore_after_snapshot(CPUState* cpu) {
    LOG_INFO("Snapshot loaded. Re-initializing");

    // By setting these, we'll redo our init logic which determines
    // if OSI is ready at the first time it's used, otherwise 
    // it runs at the first syscall (and asserts if it fails)
    osi_initialized=false;
    first_osi_check = true;
    PPP_REG_CB("syscalls2", on_all_sys_enter, on_first_syscall);
}

/**
 * @brief Initializes plugin.
 */
bool init_plugin(void *self) {
    // Register callbacks to the PANDA core.
#if defined(TARGET_I386) || defined(TARGET_ARM) || defined(TARGET_MIPS)
    {
        // Whenever we load a snapshot, we need to find cpu offsets again
        // (particularly if KASLR is enabled) and we also may need to re-initialize
        // OSI on the first guest syscall after the revert.
        panda_cb pcb = { .after_loadvm = restore_after_snapshot };
        panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

        // Register hooks in the kernel to provide task switch notifications.
        assert(init_osi_api());
    }

#if defined(TARGET_MIPS) // 32 or 64 bit
        panda_require("hw_proc_id");
        assert(init_hw_proc_id_api());
#endif

#if defined(OSI_LINUX_TEST)
    {
        panda_cb pcb = { .asid_changed = osi_linux_test };
        panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    }
#endif

    // Read the name of the kernel configuration to use.
    panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);
    char *kconf_file = g_strdup(panda_parse_string_opt(plugin_args, "kconf_file", NULL, "file containing kernel configuration information"));
    char *kconf_group = g_strdup(panda_parse_string_opt(plugin_args, "kconf_group", NULL, "kernel profile to use"));
    osi_initialized = panda_parse_bool_opt(plugin_args, "load_now", "Raise a fatal error if OSI cannot be initialized immediately");
    panda_free_args(plugin_args);

    if (!kconf_file) {
        // Search build dir and installed location for kernelinfo.conf
        gchar *progname = realpath(qemu_file, NULL);
        gchar *progdir = NULL;
        if(progname != NULL) {
            progdir = g_path_get_dirname(progname);
        }
        gchar *kconffile_canon = NULL;

        if (kconffile_canon == NULL && progdir != NULL) {  // from build dir
            if (kconf_file != NULL) g_free(kconf_file);
            kconf_file = g_build_filename(progdir, "panda", "plugins", "osi_linux", "kernelinfo.conf", NULL);
            LOG_INFO("Looking for kconf_file attempt %u: %s", 1, kconf_file);
            kconffile_canon = realpath(kconf_file, NULL);
        }
        if (kconffile_canon == NULL) {  // from etc dir (installed location)
            if (kconf_file != NULL) g_free(kconf_file);
            kconf_file = g_build_filename(CONFIG_QEMU_CONFDIR, "osi_linux", "kernelinfo.conf", NULL);
            LOG_INFO("Looking for kconf_file attempt %u: %s", 2, kconf_file);
            kconffile_canon = realpath(kconf_file, NULL);
        }
        if (kconffile_canon == NULL) { // from PANDA_DIR
            if (kconf_file != NULL) g_free(kconf_file);
            const char* panda_dir = g_getenv("PANDA_DIR");
            kconf_file = g_strdup_printf("%s%s", panda_dir, KERNEL_CONF);
            kconffile_canon = realpath(kconf_file, NULL);
        }

        g_free(progdir);
        free(progname);
        assert(kconffile_canon != NULL && "Could not find default kernelinfo.conf file");
        free(kconffile_canon);
    }

    if (!kconf_group) {
        kconf_group = g_strdup_printf("%s:%d", panda_os_variant, panda_os_bits);
    }


    // Load kernel offsets.
    if (read_kernelinfo(kconf_file, kconf_group, &ki) != 0) {
        LOG_ERROR("Failed to read group %s from %s.", kconf_group, kconf_file);
        if (download_kernelinfo(kconf_file, kconf_group) == 0) {
            LOG_INFO("Downloaded file from panda-re.mit.edu");
            if (read_kernelinfo(kconf_file, kconf_group, &ki) != 0) {
                LOG_ERROR("Downloaded file didn't contain correct group");
                goto error;
            }
        }else{
            LOG_ERROR("Download failed. No such file.");
            // Log all valid groups in your kconf file - user might've just specified the argument wrong
            printf("Valid kconf_groups in %s:\n", kconf_file);
            list_kernelinfo_groups(kconf_file);
            printf("\n");
            goto error;
        }
    }
    LOG_INFO("Read kernel info from group \"%s\" of file \"%s\".", kconf_group, kconf_file);
    g_free(kconf_file);
    g_free(kconf_group);

    if (PROFILE_KVER_LE(ki, 2, 4, 254)) {
        kernel_profile = &KERNEL24X_PROFILE;
    } else {
        kernel_profile = &DEFAULT_PROFILE;
    }

    PPP_REG_CB("osi", on_get_processes, on_get_processes);
    PPP_REG_CB("osi", on_get_process_handles, on_get_process_handles);
    PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
    PPP_REG_CB("osi", on_get_current_process_handle, on_get_current_process_handle);
    PPP_REG_CB("osi", on_get_process, on_get_process);
    PPP_REG_CB("osi", on_get_proc_mem, on_get_proc_mem);
    PPP_REG_CB("osi", on_get_mappings, on_get_mappings);
    PPP_REG_CB("osi", on_get_file_mappings, on_get_file_mappings);
    PPP_REG_CB("osi", on_get_heap_mappings, on_get_heap_mappings);
    PPP_REG_CB("osi", on_get_stack_mappings, on_get_stack_mappings);
    PPP_REG_CB("osi", on_get_unknown_mappings, on_get_unknown_mappings);
    PPP_REG_CB("osi", on_get_mapping_by_addr, on_get_mapping_by_addr);
    PPP_REG_CB("osi", on_get_mapping_base_address_by_name,
        on_get_mapping_base_address_by_name);
    PPP_REG_CB("osi", on_has_mapping_prefix, on_has_mapping_prefix);
    PPP_REG_CB("osi", on_get_current_thread, on_get_current_thread);
    PPP_REG_CB("osi", on_get_process_pid, on_get_process_pid);
    PPP_REG_CB("osi", on_get_process_ppid, on_get_process_ppid);

    // By default, we'll request syscalls2 to load on first syscall
    panda_require("syscalls2");

    
    if (0x0 != ki.task.switch_task_hook_addr) {
        void* hooks = panda_get_plugin_by_name("hooks");
        if (hooks == NULL){
            panda_require("hooks");
            hooks = panda_get_plugin_by_name("hooks");
        }
        if (hooks != NULL){
            void (*dlsym_add_hook)(struct hook*) = (void(*)(struct hook*)) dlsym(hooks, "add_hook");
            if ((void*)dlsym_add_hook == NULL) {
                printf("couldn't load add_hook from hooks\n");
                return false;
            }
            struct hook h;
            h.addr = ki.task.switch_task_hook_addr;
            h.asid = 0;
            h.type = PANDA_CB_START_BLOCK_EXEC;
            h.cb.start_block_exec = [](CPUState *cpu, TranslationBlock *tb, hook *){    
                bool** out=0;
                if (osi_guest_is_ready(cpu, (void**)out)){
                    notify_task_change(cpu); 
                }
            };
            h.km = MODE_ANY;
            h.enabled = true;
            dlsym_add_hook(&h);
        }
    }

    panda_require("proc_start_linux");
    // Setup exec task change notifications.
    PPP_REG_CB("proc_start_linux", on_rec_auxv, [](CPUState *cpu, TranslationBlock *tb, struct auxv_values *vals){
                bool** out=0;
                if (osi_guest_is_ready(cpu, (void**)out)){
                    notify_task_change(cpu); 
                } });

    return true;
#else
    fprintf(stderr, PLUGIN_NAME "Unsupported guest architecture\n");
    goto error;
#endif

error:
    return false;
}

/**
 * @brief Plugin cleanup.
 */
void uninit_plugin(void *self) {
    // if we don't clear tb's when this exits we have TBs which can call
    // into our exited plugin.
    panda_do_flush_tb();
#if defined(TARGET_I386) || defined(TARGET_ARM)
    // Nothing to do...
#endif
    osi_initialized=false;
    return;
}

/* vim:set tabstop=4 softtabstop=4 expandtab: */
