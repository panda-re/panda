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

}

#include <stdio.h>
#include <stdlib.h>

#ifdef TARGET_I386

// Code should work for other versions of Windows once these constants
// are redefined. Possibly we should move them to a config file?
#define KMODE_FS           0x030
#define KPCR_CURTHREAD_OFF 0x124
#define KTHREAD_KPROC_OFF  0x150
#define EPROC_LINKS_OFF    0x0b8
#define EPROC_DTB_OFF      0x018
#define EPROC_PID_OFF      0x0b4
#define EPROC_PPID_OFF     0x140
#define EPROC_NAME_OFF     0x16c
#define EPROC_TYPE_OFF     0x000
#define EPROC_SIZE_OFF     0x002
#define EPROC_TYPE          0x03
#define EPROC_SIZE          0x26

static uint32_t get_pid(CPUState *env, target_ulong eproc) {
    uint32_t pid;
    panda_virtual_memory_rw(env, eproc+EPROC_PID_OFF, (uint8_t *)&pid, 4, false);
    return pid;
}

static uint32_t get_ppid(CPUState *env, target_ulong eproc) {
    uint32_t ppid;
    panda_virtual_memory_rw(env, eproc+EPROC_PPID_OFF, (uint8_t *)&ppid, 4, false);
    return ppid;
}

static uint32_t get_dtb(CPUState *env, target_ulong eproc) {
    uint32_t dtb;
    panda_virtual_memory_rw(env, eproc+EPROC_DTB_OFF, (uint8_t *)&dtb, 4, false);
    return dtb;
}

static uint32_t get_next_proc(CPUState *env, target_ulong eproc) {
    uint32_t next;
    panda_virtual_memory_rw(env, eproc+EPROC_LINKS_OFF, (uint8_t *)&next, 4, false);
    next -= EPROC_LINKS_OFF;
    return next;
}

// *must* be called on a buffer of size 17 or greater
static void get_procname(CPUState *env, target_ulong eproc, char *name) {
    panda_virtual_memory_rw(env, eproc+EPROC_NAME_OFF, (uint8_t *)name, 16, false);
    name[16] = '\0';
}

static uint32_t get_current_proc(CPUState *env) {
    // Read the kernel-mode FS segment base
    uint32_t e1, e2;
    uint32_t fs_base, thread, proc;

    // Read out the two 32-bit ints that make up a segment descriptor
    panda_virtual_memory_rw(env, env->gdt.base + KMODE_FS, (uint8_t *)&e1, 4, false);
    panda_virtual_memory_rw(env, env->gdt.base + KMODE_FS + 4, (uint8_t *)&e2, 4, false);
    
    // Turn wacky segment into base
    fs_base = (e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000);

    // Read KPCR->CurrentThread->Process
    panda_virtual_memory_rw(env, fs_base+KPCR_CURTHREAD_OFF, (uint8_t *)&thread, 4, false);
    panda_virtual_memory_rw(env, thread+KTHREAD_KPROC_OFF, (uint8_t *)&proc, 4, false);

    return proc;
}

static void fill_osiproc(CPUState *env, OsiProc *p, uint32_t eproc) {
    char *name = (char *)malloc(17);
    get_procname(env, eproc, name);
    p->name = name;
    p->asid = get_dtb(env, eproc);
    p->pages = NULL;
    p->pid = get_pid(env, eproc);
    p->ppid = get_ppid(env, eproc);
}

static bool is_valid_process(CPUState *env, uint32_t eproc) {
    uint8_t type;
    uint8_t size;
    
    panda_virtual_memory_rw(env, eproc+EPROC_TYPE_OFF, (uint8_t *)&type, 1, false);
    panda_virtual_memory_rw(env, eproc+EPROC_SIZE_OFF, (uint8_t *)&size, 1, false);

    return (type == EPROC_TYPE && size == EPROC_SIZE);
}

static void add_proc(CPUState *env, OsiProcs *ps, uint32_t eproc) {
    static uint32_t capacity = 16;
    if (ps->proc == NULL) {
        ps->proc = (OsiProc *)malloc(sizeof(OsiProc) * capacity);
    }
    else if (ps->num == capacity) {
        capacity *= 2;
        ps->proc = (OsiProc *)malloc(sizeof(OsiProc) * capacity);
    }

    OsiProc *p = &ps->proc[ps->num++];
    fill_osiproc(env, p, eproc);
}

void on_get_current_process(CPUState *env, OsiProc **out_p) {
    OsiProc *p = (OsiProc *) malloc(sizeof(OsiProc));
    uint32_t eproc = get_current_proc(env);
    fill_osiproc(env, p, eproc);
    *out_p = p;
}

void on_get_processes(CPUState *env, OsiProcs **out_ps) {
    uint32_t first = get_current_proc(env);
    uint32_t current = first;

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
    } while (current != first);

    *out_ps = ps;
}
#endif

bool init_plugin(void *self) {
#ifdef TARGET_I386
    PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
    PPP_REG_CB("osi", on_get_processes, on_get_processes);
#endif
    return true;
}

void uninit_plugin(void *self) { }
