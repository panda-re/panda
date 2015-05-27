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

#include <distorm.h>
namespace distorm {
#include <mnemonics.h>
}

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "../osi/osi_types.h"
#include "../osi/os_intro.h"

bool init_plugin(void *);
void uninit_plugin(void *);
void on_get_current_process(CPUState *env, OsiProc **out_p);
void on_get_processes(CPUState *env, OsiProcs **out_ps);
void on_get_libraries(CPUState *env, OsiProc *p, OsiModules **out_ms);
void on_free_osiproc(OsiProc *p);
void on_free_osiprocs(OsiProcs *ps);
void on_free_osimodules(OsiModules *ms);

}

#include <stdio.h>
#include <stdlib.h>

#ifdef TARGET_I386

// Code should work for other versions of Windows once these constants
// are redefined. Possibly we should move them to a config file?
#define KMODE_FS           0x030 // Segment number of FS in kernel mode
#define KPCR_CURTHREAD_OFF 0x124 // _KPCR.PrcbData.CurrentThread
#define KTHREAD_KPROC_OFF  0x150 // _KTHREAD.Process
#define EPROC_LINKS_OFF    0x0b8 // _EPROCESS.ActiveProcessLinks
#define EPROC_DTB_OFF      0x018 // _EPROCESS.Pcb.DirectoryTableBase
#define EPROC_PID_OFF      0x0b4 // _EPROCESS.UniqueProcessId
#define EPROC_PPID_OFF     0x140 // _EPROCESS.InheritedFromUniqueProcessId
#define EPROC_NAME_OFF     0x16c // _EPROCESS.ImageFileName
#define EPROC_TYPE_OFF     0x000 // _EPROCESS.Pcb.Header.Type
#define EPROC_SIZE_OFF     0x002 // _EPROCESS.Pcb.Header.Size
#define EPROC_TYPE          0x03 // Value of Type
#define EPROC_SIZE          0x26 // Value of Size
#define EPROC_PEB_OFF      0x1a8 // _EPROCESS.Peb
#define PEB_LDR_OFF        0x00c // _PEB.Ldr
#define PEB_LDR_MEM_LINKS_OFF  0x14 // _PEB_LDR_DATA.InMemoryOrderModuleLinks
#define LDR_MEM_LINKS_OFF  0x008 // _LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks
#define LDR_BASE_OFF       0x018 // _LDR_DATA_TABLE_ENTRY.DllBase
#define LDR_SIZE_OFF       0x020 // _LDR_DATA_TABLE_ENTRY.SizeOfImage
#define LDR_BASENAME_OFF   0x02c // _LDR_DATA_TABLE_ENTRY.BaseDllName
#define LDR_FILENAME_OFF   0x024 // _LDR_DATA_TABLE_ENTRY.FullDllName

// Size of a guest pointer. Note that this can't just be target_ulong since
// a 32-bit OS will run on x86_64-softmmu
#define PTR uint32_t

static inline char * make_pagedstr() {
    char *m = (char *)malloc(8);
    strcpy(m, "(paged)");
    return m;
}

// Gets a unicode string. Does its own mem allocation.
// Output is a null-terminated UTF8 string
char * get_unicode_str(CPUState *env, PTR ustr) {
    uint16_t size = 0;
    PTR str_ptr = 0;
    if (-1 == panda_virtual_memory_rw(env, ustr, (uint8_t *)&size, 2, false)) {
        return make_pagedstr();
    }
    // Clamp size
    if (size > 1024) size = 1024;
    if (-1 == panda_virtual_memory_rw(env, ustr+4, (uint8_t *)&str_ptr, 4, false)) {
        return make_pagedstr();
    }
    gchar *in_str = (gchar *)g_malloc0(size);
    if (-1 == panda_virtual_memory_rw(env, str_ptr, (uint8_t *)in_str, size, false)) {
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
static PTR get_next_proc(CPUState *env, PTR eproc) {
    PTR next;
    if (-1 == panda_virtual_memory_rw(env, eproc+EPROC_LINKS_OFF, (uint8_t *)&next, sizeof(PTR), false)) 
        return 0;
    next -= EPROC_LINKS_OFF;
    return next;
}

static PTR get_pid(CPUState *env, PTR eproc) {
    PTR pid;
    panda_virtual_memory_rw(env, eproc+EPROC_PID_OFF, (uint8_t *)&pid, sizeof(PTR), false);
    return pid;
}

static PTR get_ppid(CPUState *env, PTR eproc) {
    PTR ppid;
    panda_virtual_memory_rw(env, eproc+EPROC_PPID_OFF, (uint8_t *)&ppid, sizeof(PTR), false);
    return ppid;
}

static PTR get_dtb(CPUState *env, PTR eproc) {
    PTR dtb;
    panda_virtual_memory_rw(env, eproc+EPROC_DTB_OFF, (uint8_t *)&dtb, sizeof(PTR), false);
    return dtb;
}

// *must* be called on a buffer of size 16 or greater
static void get_procname(CPUState *env, PTR eproc, char *name) {
    panda_virtual_memory_rw(env, eproc+EPROC_NAME_OFF, (uint8_t *)name, 15, false);
    name[15] = '\0';
}

// XXX: this will have to change for 64-bit
static PTR get_current_proc(CPUState *env) {
    // Read the kernel-mode FS segment base
    uint32_t e1, e2;
    uint32_t fs_base, thread, proc;

    // Read out the two 32-bit ints that make up a segment descriptor
    panda_virtual_memory_rw(env, env->gdt.base + KMODE_FS, (uint8_t *)&e1, sizeof(PTR), false);
    panda_virtual_memory_rw(env, env->gdt.base + KMODE_FS + 4, (uint8_t *)&e2, sizeof(PTR), false);
    
    // Turn wacky segment into base
    fs_base = (e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000);

    // Read KPCR->CurrentThread->Process
    panda_virtual_memory_rw(env, fs_base+KPCR_CURTHREAD_OFF, (uint8_t *)&thread, sizeof(PTR), false);
    panda_virtual_memory_rw(env, thread+KTHREAD_KPROC_OFF, (uint8_t *)&proc, sizeof(PTR), false);

    return proc;
}

static bool is_valid_process(CPUState *env, PTR eproc) {
    uint8_t type;
    uint8_t size;
    
    panda_virtual_memory_rw(env, eproc+EPROC_TYPE_OFF, (uint8_t *)&type, 1, false);
    panda_virtual_memory_rw(env, eproc+EPROC_SIZE_OFF, (uint8_t *)&size, 1, false);

    return (type == EPROC_TYPE && size == EPROC_SIZE);
}

// Module stuff
static const char *get_mod_basename(CPUState *env, PTR mod) {
    return get_unicode_str(env, mod+LDR_BASENAME_OFF);
}

static const char *get_mod_filename(CPUState *env, PTR mod) {
    return get_unicode_str(env, mod+LDR_FILENAME_OFF);
}

static PTR get_mod_base(CPUState *env, PTR mod) {
    PTR base;
    panda_virtual_memory_rw(env, mod+LDR_BASE_OFF, (uint8_t *)&base, sizeof(PTR), false);
    return base;
}

static PTR get_mod_size(CPUState *env, PTR mod) {
    uint32_t size;
    panda_virtual_memory_rw(env, mod+LDR_SIZE_OFF, (uint8_t *)&size, sizeof(uint32_t), false);
    return size;
}

static PTR get_next_mod(CPUState *env, PTR mod) {
    PTR next;
    if (-1 == panda_virtual_memory_rw(env, mod+LDR_MEM_LINKS_OFF, (uint8_t *)&next, sizeof(PTR), false))
        return 0;
    next -= LDR_MEM_LINKS_OFF;
    return next;
}

static void fill_osiproc(CPUState *env, OsiProc *p, PTR eproc) {
    p->offset = eproc;
    char *name = (char *)malloc(16);
    get_procname(env, eproc, name);
    p->name = name;
    p->asid = get_dtb(env, eproc);
    p->pages = NULL;
    p->pid = get_pid(env, eproc);
    p->ppid = get_ppid(env, eproc);
}

static void fill_osimod(CPUState *env, OsiModule *m, PTR mod) {
    m->offset = mod;
    m->file = (char *)get_mod_filename(env, mod);
    m->base = get_mod_base(env, mod);
    m->size = get_mod_size(env, mod);
    m->name = (char *)get_mod_basename(env, mod);
}

static void add_proc(CPUState *env, OsiProcs *ps, PTR eproc) {
    static uint32_t capacity = 16;
    if (ps->proc == NULL) {
        ps->proc = (OsiProc *)malloc(sizeof(OsiProc) * capacity);
    }
    else if (ps->num == capacity) {
        capacity *= 2;
        ps->proc = (OsiProc *)realloc(ps->proc, sizeof(OsiProc) * capacity);
    }

    OsiProc *p = &ps->proc[ps->num++];
    fill_osiproc(env, p, eproc);
}

static void add_mod(CPUState *env, OsiModules *ms, PTR mod) {
    static uint32_t capacity = 16;
    if (ms->module == NULL) {
        ms->module = (OsiModule *)malloc(sizeof(OsiModule) * capacity);
    }
    else if (ms->num == capacity) {
        capacity *= 2;
        ms->module = (OsiModule *)realloc(ms->module, sizeof(OsiModule) * capacity);
    }

    OsiModule *p = &ms->module [ms->num++];
    fill_osimod(env, p, mod);
}

void on_get_current_process(CPUState *env, OsiProc **out_p) {
    OsiProc *p = (OsiProc *) malloc(sizeof(OsiProc));
    PTR eproc = get_current_proc(env);
    fill_osiproc(env, p, eproc);
    *out_p = p;
}

void on_get_processes(CPUState *env, OsiProcs **out_ps) {
    PTR first = get_current_proc(env);
    PTR first_pid = get_pid(env, first);
    PTR current = first;

    if (first_pid == 0) { // Idle proc, don't try
        out_ps = NULL;
        return;
    }

    OsiProcs *ps = (OsiProcs *)malloc(sizeof(OsiProcs));
    ps->num = 0;
    ps->proc = NULL;

    do {
        // One of these will be the loop head,
        // which we don't want to include
        if (is_valid_process(env, current)) {
            add_proc(env, ps, current);
        }

        current = get_next_proc(env, current);
        if (!current) break;
    } while (current != first);

    *out_ps = ps;
}

void on_get_libraries(CPUState *env, OsiProc *p, OsiModules **out_ms) {
    // Find the process we're interested in
    PTR eproc = get_current_proc(env);
    bool found = false;
    PTR first_proc = eproc;
    do {
        if (eproc == p->offset) {
            found = true;
            break;
        }
        eproc = get_next_proc(env, eproc);
        if (!eproc) break;
    } while (eproc != first_proc);

    if (!found) {
        *out_ms = NULL; return;
    }

    OsiModules *ms = (OsiModules *)malloc(sizeof(OsiModules));
    ms->num = 0;
    ms->module = NULL;
    PTR peb = 0, ldr = 0;
    // PEB->Ldr->InMemoryOrderModuleList
    if (-1 == panda_virtual_memory_rw(env, eproc+EPROC_PEB_OFF, (uint8_t *)&peb, sizeof(PTR), false) ||
        -1 == panda_virtual_memory_rw(env, peb+PEB_LDR_OFF, (uint8_t *)&ldr, sizeof(PTR), false)) {
        *out_ms = NULL; return;
    }

    // Fake "first mod": the address of where the list list head would
    // be if it were a LDR_DATA_TABLE_ENTRY
    PTR first_mod = ldr+PEB_LDR_MEM_LINKS_OFF-LDR_MEM_LINKS_OFF;
    PTR current_mod = get_next_mod(env, first_mod);
    // We want while loop here -- we are starting at the head,
    // which is not a valid module
    while (current_mod != first_mod) {
        add_mod(env, ms, current_mod);
        current_mod = get_next_mod(env, current_mod);
        if (!current_mod) break;
    }

    *out_ms = ms;
    return;
}

void on_free_osiproc(OsiProc *p) {
    if (!p) return;
    free(p->name);
    free(p);
}

void on_free_osiprocs(OsiProcs *ps) {
    if (!ps) return;
    for(uint32_t i = 0; i < ps->num; i++) {
        free(ps->proc[i].name);
    }
    if(ps->proc) free(ps->proc);
    free(ps);
}

void on_free_osimodules(OsiModules *ms) {
    if (!ms) return;
    for(uint32_t i = 0; i < ms->num; i++) {
        free(ms->module[i].file);
        free(ms->module[i].name);
    }
    if (ms->module) free(ms->module);
    free(ms);
}

#endif

bool init_plugin(void *self) {
    panda_require("osi");
#ifdef TARGET_I386
    PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
    PPP_REG_CB("osi", on_get_processes, on_get_processes);
    PPP_REG_CB("osi", on_get_libraries, on_get_libraries);
    PPP_REG_CB("osi", on_free_osiproc, on_free_osiproc);
    PPP_REG_CB("osi", on_free_osiprocs, on_free_osiprocs);
    PPP_REG_CB("osi", on_free_osimodules, on_free_osimodules);
#endif
    return true;
}

void uninit_plugin(void *self) { }
