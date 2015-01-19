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

#include "panda_common.h"
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

/*
 * This code should work for other versions of the linux kernel 
 * if you redefine these offsets. 
 * Offsets derived from task_struct_offset_finder kernel module tool.
 */
#define TASKS_OFF          212 // Tasks field which points to the list_head for this proc
#define PID_OFF            292 // PID
#define TGID_OFF           296 // TGID
#define REAL_PARENT_OFF    304 // Pointer to real parent process task_struct
#define PARENT_OFF         308 // Pointer to parent process (recipient of SIGCHLD)
#define COMM_OFF           516 // Executable name excluding path

#define MAX_TASK_COMM_LEN  16   // Max length of the comm field in task_struct
#define PAGE_SIZE          8192 // Used to find thread_info struct from esp

// mm struct offset (ptr to mm)
#define MM_OFF 240
// and, within mm struct, cr3 is here
#define PGD_OFF 36

// Size of a guest pointer. Note that this can't just be target_ulong since
// a 32-bit OS will run on x86_64-softmmu
#define PTR uint32_t

static PTR get_next_proc(CPUState *env, PTR task_addr) {
    PTR next;
        if (-1 == panda_virtual_memory_rw(env, task_addr+TASKS_OFF, (uint8_t *)&next, sizeof(PTR), false)) 
        return 0;
    // tasks is a struct list_head, with struct list_head *next, *prev fields.
    // *next is [0] so this is our ptr to the 'tasks' field of the next proc
    // Subtract the offset again to get the base of the next proc
    return next - TASKS_OFF;
}

static PTR get_pid(CPUState *env, PTR task_addr) {
    PTR pid = 0;
    panda_virtual_memory_rw(env, task_addr+PID_OFF, (uint8_t *)&pid, sizeof(pid), false);
    return pid;
}

static PTR get_ppid(CPUState *env, PTR task_addr) {
    PTR parent_addr = 0;
    // Assumes that we want parent and not real_parent - change if necessary
    panda_virtual_memory_rw(env, task_addr+PARENT_OFF, (uint8_t *)&parent_addr, sizeof(parent_addr), false);
    return get_pid(env, parent_addr);
}

// must be called on buffer of size MAX_TASK_COMM_LEN+1
static void get_procname(CPUState *env, PTR task_addr, char *name) {
    panda_virtual_memory_rw(env, task_addr+COMM_OFF, (uint8_t *)name, MAX_TASK_COMM_LEN, false);
    name[MAX_TASK_COMM_LEN+1] = '\0';
}

// Process introspection
static void fill_osiproc(CPUState *env, OsiProc *p, PTR task_addr) {
    p->offset = 0; // Not quite relevant for linux
    char *name = (char *)calloc(1, MAX_TASK_COMM_LEN+1);
    get_procname(env, task_addr, name);
    p->name = name;
    //printf("p->name: %s\n", p->name);

    p->pages = NULL;
    p->pid = get_pid(env, task_addr);
    //printf("p->pid: %d\n", p->pid);
    p->ppid = get_ppid(env, task_addr);
    //printf("p->ppid: %d\n", p->ppid);
    
    target_ulong mm;
    panda_virtual_memory_rw(env, task_addr + MM_OFF, (uint8_t *) &mm, sizeof(target_ulong), false);    
    target_ulong asid;  
    panda_virtual_memory_rw(env, mm + PGD_OFF, (uint8_t *) &asid, sizeof(target_ulong), false);
    p->asid = asid;
    p->asid = asid & (~0xc0000000);

}

static void add_proc(CPUState *env, OsiProcs *ps, PTR task_addr) {
    static uint32_t capacity = 16;
    if (ps->proc == NULL) {
        ps->proc = (OsiProc *)malloc(sizeof(OsiProc) * capacity);
    }
    else if (ps->num == capacity) {
        capacity *= 2;
        ps->proc = (OsiProc *)realloc(ps->proc, sizeof(OsiProc) * capacity);
    }

    OsiProc *p = &ps->proc[ps->num++];
    fill_osiproc(env, p, task_addr);
}

PTR get_thread_info_addr(CPUState *env) {
    int esp = env->regs[R_ESP];     
    return esp & ~(PAGE_SIZE - 1);
}


#define KMODE_FS 0xd8

PTR get_task(CPUState *env) {
    uint32_t e1, e2;
    uint32_t fs_base;

    // Read out the two 32-bit ints that make up a segment descriptor                                                                                                                                                                                                                                    
    panda_virtual_memory_rw(env, env->gdt.base + KMODE_FS, (uint8_t *)&e1, 4, false);
    panda_virtual_memory_rw(env, env->gdt.base + KMODE_FS + 4, (uint8_t *)&e2, 4, false);
    // Turn wacky segment into base                                         
    fs_base = (e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000);
    // the rest of this comes from peering at in_asm trace thx to qemu.
    uint32_t fsplus = fs_base + 0xc147cf0c;
    uint32_t eax, eax_2;
    panda_virtual_memory_rw(env, fsplus,      (uint8_t *)&eax, 4, false);
    panda_virtual_memory_rw(env, eax+0x148,   (uint8_t *)&eax_2, 4, false);
    return eax_2;
}



static PTR get_current_proc(CPUState *env) {
    /*
    // First find the thread_info struct
    PTR thread_info_addr = get_thread_info_addr(env);   
    // the task_struct *task is at thread_info[0], so just deref thread_info_addr
    PTR task_struct_addr = panda_virtual_memory_rw(env, thread_info_addr, (uint8_t *)&task_struct_addr, sizeof(task_struct_addr), false);
    */
    PTR task_struct_addr = get_task(env);
    return task_struct_addr;
}


    

void on_get_current_process(CPUState *env, OsiProc **out_p) {
    OsiProc *p = (OsiProc *) malloc(sizeof(OsiProc));
    PTR task_struct_addr = get_current_proc(env);
    fill_osiproc(env, p, task_struct_addr);
    *out_p = p;
}

void on_get_processes(CPUState *env, OsiProcs **out_ps) {
    PTR first = get_current_proc(env);
    //PTR first_pid = get_pid(env, first);
    PTR current = first;

    OsiProcs *ps = (OsiProcs *)malloc(sizeof(OsiProcs));
    ps->num = 0;
    ps->proc = NULL;

    do {
        add_proc(env, ps, current);
        current = get_next_proc(env, current);
        if (!current) break;
    } while (current != first);

    *out_ps = ps;
}

void on_get_libraries(CPUState *env, OsiProc *p, OsiModules **out_ms) {
    //TODO 
    *out_ms = NULL;
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

    // this plugin absolutely requires osi
    panda_require("osi");


#ifdef TARGET_I386
    PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
    PPP_REG_CB("osi", on_get_processes, on_get_processes);
    PPP_REG_CB("osi", on_get_libraries, on_get_libraries);
    PPP_REG_CB("osi", on_free_osiproc, on_free_osiproc);
    PPP_REG_CB("osi", on_free_osiprocs, on_free_osiprocs);
    PPP_REG_CB("osi", on_free_osimodules, on_free_osimodules);
    return true;
#endif
    return false;
}

void uninit_plugin(void *self) { }
