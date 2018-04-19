/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
#define __STDC_FORMAT_MACROS

#include "qemu/atomic.h"
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include <cstdio>
#include <cstdlib>

extern "C" {

#include "osi/osi_types.h"
#include "osi/os_intro.h"

#if defined(TARGET_I386) && !defined(TARGET_X86_64)

#include "qemu/rcu.h"
#include "qemu/rcu_queue.h"

#include "exec/address-spaces.h"

bool init_plugin(void *);
void uninit_plugin(void *);
void on_get_current_process(CPUState *cpu, OsiProc **out_p);
void on_get_processes(CPUState *cpu, OsiProcs **out_ps);
void on_get_libraries(CPUState *cpu, OsiProc *p, OsiModules **out_ms);
void on_free_osiproc(OsiProc *p);
void on_free_osiprocs(OsiProcs *ps);
void on_free_osimodules(OsiModules *ms);

#define KMODE_FS           0x030          // Segment number of FS in kernel mode
#define KPCR_CURTHREAD_OFF (0x120 + 0x04) // _KPCR.PrcbData.CurrentThread
#define KDBG_PSLML         0x48  // _KDDEBUGGER_DATA64.PsLoadedModuleList
#define KTHREAD_KPROC_OFF  0x22c // _KTHREAD.Process
#define EPROC_LINKS_OFF    0x0a0 // _EPROCESS.ActiveProcessLinks
#define EPROC_DTB_OFF      0x018 // _EPROCESS.Pcb.DirectoryTableBase
#define EPROC_PID_OFF      0x09c // _EPROCESS.UniqueProcessId
#define EPROC_PPID_OFF     0x1c8 // _EPROCESS.InheritedFromUniqueProcessId
#define EPROC_NAME_OFF     0x1fc // _EPROCESS.ImageFileName
#define EPROC_TYPE_OFF     0x000 // _EPROCESS.Pcb.Header.Type
#define EPROC_SIZE_OFF     0x002 // _EPROCESS.Pcb.Header.Size
#define EPROC_TYPE          0x03 // Value of Type
#define EPROC_SIZE          0x1b // Value of Size
#define EPROC_PEB_OFF      0x1b0 // _EPROCESS.Peb
#define PEB_LDR_OFF        0x00c // _PEB.Ldr
#define PEB_LDR_MEM_LINKS_OFF  0x14 // _PEB_LDR_DATA.InMemoryOrderModuleList
#define PEB_LDR_LOAD_LINKS_OFF 0x0c // _PEB_LDR_DATA.InLoadOrderModuleList
#define LDR_MEM_LINKS_OFF  0x008 // _LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks
#define LDR_LOAD_LINKS_OFF 0x000 // _LDR_DATA_TABLE_ENTRY.InLoadOrderLinks
#define LDR_BASE_OFF       0x018 // _LDR_DATA_TABLE_ENTRY.DllBase
#define LDR_SIZE_OFF       0x020 // _LDR_DATA_TABLE_ENTRY.SizeOfImage
#define LDR_BASENAME_OFF   0x02c // _LDR_DATA_TABLE_ENTRY.BaseDllName
#define LDR_FILENAME_OFF   0x024 // _LDR_DATA_TABLE_ENTRY.FullDllName

// Size of a guest pointer. Note that this can't just be target_ulong since
// a 32-bit OS will run on x86_64-softmmu
#define PTR uint32_t

static inline char * make_pagedstr() {
    char *m = strdup("(paged)");
    assert(m);
    return m;
}

// Gets a unicode string. Does its own mem allocation.
// Output is a null-terminated UTF8 string
char * get_unicode_str(CPUState *cpu, PTR ustr) {
    uint16_t size = 0;
    PTR str_ptr = 0;
    if (-1 == panda_virtual_memory_rw(cpu, ustr, (uint8_t *)&size, 2, false)) {
        return make_pagedstr();
    }

    // Clamp size
    if (size > 1024) size = 1024;
    if (-1 == panda_virtual_memory_rw(cpu, ustr+4, (uint8_t *)&str_ptr, 4, false)) {
        return make_pagedstr();
    }

    gchar *in_str = (gchar *)g_malloc0(size);
    if (-1 == panda_virtual_memory_rw(cpu, str_ptr, (uint8_t *)in_str, size, false)) {
        g_free(in_str);
        return make_pagedstr();
    }

    gsize bytes_written = 0;
    gchar *out_str = g_convert(in_str, size,
            "UTF-8", "UTF-16LE", NULL, &bytes_written, NULL);

    // An abundance of caution: we copy it over to something allocated
    // with our own malloc. In the future we need to provide a way for
    // someone else to free the memory allocated in here...
    char *ret = (char *)malloc(bytes_written+1);
    memcpy(ret, out_str, bytes_written+1);
    g_free(in_str);
    g_free(out_str);
    return ret;
}

// Process introspection
static PTR get_next_proc(CPUState *cpu, PTR eproc) {
    PTR next;
    if (-1 == panda_virtual_memory_rw(cpu, eproc+EPROC_LINKS_OFF, (uint8_t *)&next, sizeof(PTR), false))
        return 0;
    next -= EPROC_LINKS_OFF;
    return next;
}

static PTR get_pid(CPUState *cpu, PTR eproc) {
    PTR pid;
    panda_virtual_memory_rw(cpu, eproc+EPROC_PID_OFF, (uint8_t *)&pid, sizeof(PTR), false);
    return pid;
}

static PTR get_ppid(CPUState *cpu, PTR eproc) {
    PTR ppid;
    panda_virtual_memory_rw(cpu, eproc+EPROC_PPID_OFF, (uint8_t *)&ppid, sizeof(PTR), false);
    return ppid;
}

static PTR get_dtb(CPUState *cpu, PTR eproc) {
    PTR dtb;
    panda_virtual_memory_rw(cpu, eproc+EPROC_DTB_OFF, (uint8_t *)&dtb, sizeof(PTR), false);
    return dtb;
}

// *must* be called on a buffer of size 17 or greater
static void get_procname(CPUState *cpu, PTR eproc, char *name) {
    panda_virtual_memory_rw(cpu, eproc+EPROC_NAME_OFF, (uint8_t *)name, 16, false);
    name[16] = '\0';
}

static PTR get_kpcr(CPUState *cpu) {
    // Windows 2000 has a fixed location for the KPCR
    return 0xFFDFF000;
}

// Loaded module list
static PTR lml;

static PTR get_loaded_module_list(CPUState *cpu) {

    if(lml) return lml;

    MemoryRegion *mr = memory_region_find(get_system_memory(), 0x2000000, 1).mr;

    rcu_read_lock();
    char *host_ptr = (char *)qemu_map_ram_ptr(mr->ram_block, 0);
    unsigned char *s;
    bool found=false;
    uint32_t i;

    // Locate the KDDEBUGGER_DATA64 structure
    for(i=0; i<mr->size-0x208; i++) {
        s = ((unsigned char *) host_ptr) + i;
	if(s[8] == '\0' && s[9] == '\0' && s[10] == '\0' && s[11] == '\0' &&
	    s[12] == '\0' && s[13] == '\0' && s[14] == '\0' && s[15] == '\0' &&
	    s[16] == 'K' && s[17] == 'D' && s[18] == 'B' && s[19] == 'G') {
            found=true;
	    break;
	}
    }

    // Ensure the structure was located
    assert(found);

    // Store the virtual address of the loaded module list so we don't need
    // to repeat this work
    memcpy(&lml, s+KDBG_PSLML, sizeof(lml));

    rcu_read_unlock();
    return lml;
}

static bool is_valid_process(CPUState *cpu, PTR eproc) {
    uint8_t type;
    uint8_t size;

    if(eproc == 0) return false;

    panda_virtual_memory_rw(cpu, eproc+EPROC_TYPE_OFF, (uint8_t *)&type, 1, false);
    panda_virtual_memory_rw(cpu, eproc+EPROC_SIZE_OFF, (uint8_t *)&size, 1, false);

    return (type == EPROC_TYPE && size == EPROC_SIZE) &&
        get_next_proc(cpu, eproc);
}

static PTR get_current_proc(CPUState *cpu) {
    PTR thread, proc;
    PTR kpcr = get_kpcr(cpu);

    // Read KPCR->CurrentThread->Process
    if (-1 == panda_virtual_memory_rw(cpu, kpcr+KPCR_CURTHREAD_OFF, (uint8_t *)&thread, sizeof(PTR), false)) return 0;
    if (-1 == panda_virtual_memory_rw(cpu, thread+KTHREAD_KPROC_OFF, (uint8_t *)&proc, sizeof(PTR), false)) return 0;

    // Sometimes, proc == 0 here.  Is there a better way to do this?

    return is_valid_process(cpu, proc) ? proc : 0;
}

// Module stuff
static const char *get_mod_basename(CPUState *cpu, PTR mod) {
    return get_unicode_str(cpu, mod+LDR_BASENAME_OFF);
}

static const char *get_mod_filename(CPUState *cpu, PTR mod) {
    return get_unicode_str(cpu, mod+LDR_FILENAME_OFF);
}

static PTR get_mod_base(CPUState *cpu, PTR mod) {
    PTR base;
    panda_virtual_memory_rw(cpu, mod+LDR_BASE_OFF, (uint8_t *)&base, sizeof(PTR), false);
    return base;
}

static PTR get_mod_size(CPUState *cpu, PTR mod) {
    uint32_t size;
    panda_virtual_memory_rw(cpu, mod+LDR_SIZE_OFF, (uint8_t *)&size, sizeof(uint32_t), false);
    return size;
}

static PTR get_next_mod(CPUState *cpu, PTR mod) {
    PTR next;
    if (-1 == panda_virtual_memory_rw(cpu, mod+LDR_LOAD_LINKS_OFF, (uint8_t *)&next, sizeof(PTR), false))
        return 0;
    next -= LDR_LOAD_LINKS_OFF;
    return next;
}

static void fill_osiproc(CPUState *cpu, OsiProc *p, PTR eproc) {
    p->offset = eproc;
    char *name = (char *)malloc(17);
    get_procname(cpu, eproc, name);
    p->name = name;
    p->asid = get_dtb(cpu, eproc);
    p->pages = NULL;
    p->pid = get_pid(cpu, eproc);
    p->ppid = get_ppid(cpu, eproc);
}

static void fill_osimod(CPUState *cpu, OsiModule *m, PTR mod, bool ignore_basename) {
    m->offset = mod;
    m->file = (char *)get_mod_filename(cpu, mod);
    m->base = get_mod_base(cpu, mod);
    m->size = get_mod_size(cpu, mod);
    m->name = ignore_basename ? strdup("-") : (char *)get_mod_basename(cpu, mod);
    assert(m->name);
}

static void add_proc(CPUState *cpu, OsiProcs *ps, PTR eproc) {
    static uint32_t capacity = 16;
    if (ps->proc == NULL) {
        ps->proc = (OsiProc *)malloc(sizeof(OsiProc) * capacity);
    }
    else if (ps->num == capacity) {
        capacity *= 2;
        ps->proc = (OsiProc *)realloc(ps->proc, sizeof(OsiProc) * capacity);
    }

    OsiProc *p = &ps->proc[ps->num++];
    fill_osiproc(cpu, p, eproc);
}

static void add_mod(CPUState *cpu, OsiModules *ms, PTR mod, bool ignore_basename) {
    static uint32_t capacity = 16;
    if (ms->module == NULL) {
        ms->module = (OsiModule *)malloc(sizeof(OsiModule) * capacity);
    }
    else if (ms->num == capacity) {
        capacity *= 2;
        ms->module = (OsiModule *)realloc(ms->module, sizeof(OsiModule) * capacity);
    }

    OsiModule *p = &ms->module [ms->num++];
    fill_osimod(cpu, p, mod, ignore_basename);
}

void on_get_current_process(CPUState *cpu, OsiProc **out_p) {
    PTR eproc = get_current_proc(cpu);
    if(eproc) {
        OsiProc *p = (OsiProc *) malloc(sizeof(OsiProc));
        fill_osiproc(cpu, p, eproc);
        *out_p = p;
    } else {
        *out_p = NULL;
    }
}

void on_get_processes(CPUState *cpu, OsiProcs **out_ps) {
    PTR first = get_current_proc(cpu);
    if(first == NULL) {
        *out_ps = NULL;
        return;
    }
    PTR first_pid = get_pid(cpu, first);
    PTR current = first;

    if (first_pid == 0) { // Idle proc, don't try
        *out_ps = NULL;
        return;
    }

    OsiProcs *ps = (OsiProcs *)malloc(sizeof(OsiProcs));
    ps->num = 0;
    ps->proc = NULL;

    do {
        // One of these will be the loop head,
        // which we don't want to include
        if (is_valid_process(cpu, current)) {
            add_proc(cpu, ps, current);
        }

        current = get_next_proc(cpu, current);
        if (!current) break;
    } while (current != first);

    *out_ps = ps;
}

void on_get_libraries(CPUState *cpu, OsiProc *p, OsiModules **out_ms) {
    // Find the process we're interested in
    PTR eproc = get_current_proc(cpu);
    if (!eproc) {
        *out_ms = NULL; return;
    }

    bool found = false;
    PTR first_proc = eproc;
    do {
        if (eproc == p->offset) {
            found = true;
            break;
        }
        eproc = get_next_proc(cpu, eproc);
        if (!eproc) break;
    } while (eproc != first_proc);

    if (!found) {
        *out_ms = NULL; return;
    }

    PTR peb = 0, ldr = 0, first_mod = 0;
    // PEB->Ldr->InMemoryOrderModuleList
    if (-1 == panda_virtual_memory_rw(cpu, eproc+EPROC_PEB_OFF, (uint8_t *)&peb, sizeof(PTR), false) ||
        -1 == panda_virtual_memory_rw(cpu, peb+PEB_LDR_OFF, (uint8_t *)&ldr, sizeof(PTR), false) ||
        -1 == panda_virtual_memory_rw(cpu, ldr+PEB_LDR_MEM_LINKS_OFF, (uint8_t *)&first_mod, sizeof(PTR), false)) {
        *out_ms = NULL; return;
    }

    OsiModules *ms = (OsiModules *)malloc(sizeof(OsiModules));
    ms->num = 0;
    ms->module = NULL;

    PTR current_mod = first_mod;
    while(true) {
        PTR next_mod = get_next_mod(cpu, current_mod);
        if(next_mod == first_mod) break;
        add_mod(cpu, ms, current_mod, true);
        current_mod = next_mod;
        if (!current_mod) break;
    }

    *out_ms = ms;
    return;
}

void on_get_modules(CPUState *cpu, OsiModules **out_ms) {
    PTR lml = get_loaded_module_list(cpu);

    PTR PsLoadedModuleList;

    // Dbg.PsLoadedModuleList
    if (-1 == panda_virtual_memory_rw(cpu, lml, (uint8_t *)&PsLoadedModuleList, sizeof(PTR), false)) {
        *out_ms = NULL;
        return;
    }

    OsiModules *ms = (OsiModules *)malloc(sizeof(OsiModules));
    ms->num = 0;
    ms->module = NULL;
    PTR current_mod = PsLoadedModuleList;

    while(true) {
        PTR next_mod = get_next_mod(cpu, current_mod);
        if(next_mod == PsLoadedModuleList) break;
        add_mod(cpu, ms, current_mod, false);
        current_mod = next_mod;
        if (!current_mod) break;
    }

    *out_ms = ms;
}

void on_free_osiproc(OsiProc *p) {
    if (!p) return;
    free(p->name);
    free(p);
}

void on_free_osiprocs(OsiProcs *ps) {
    if(!ps) return;
    if(ps->proc) {
        for(uint32_t i = 0; i < ps->num; i++) {
            free(ps->proc[i].name);
        }
        free(ps->proc);
    }
    free(ps);
}

void on_free_osimodules(OsiModules *ms) {
    if(!ms) return;
    if(ms->module) {
        for(uint32_t i = 0; i < ms->num; i++) {
            free(ms->module[i].file);
            free(ms->module[i].name);
        }
        free(ms->module);
    }
    free(ms);
}

#endif

bool init_plugin(void *self) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
    PPP_REG_CB("osi", on_get_processes, on_get_processes);
    PPP_REG_CB("osi", on_get_libraries, on_get_libraries);
    PPP_REG_CB("osi", on_get_modules, on_get_modules);
    PPP_REG_CB("osi", on_free_osiproc, on_free_osiproc);
    PPP_REG_CB("osi", on_free_osiprocs, on_free_osiprocs);
    PPP_REG_CB("osi", on_free_osimodules, on_free_osimodules);
    return true;
#else
    return false;
#endif

}

void uninit_plugin(void *self) { }

}
