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
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/panda_addr.h"
extern "C" {

//#include "config.h"
#include "rr_log.h"
#include "qemu-common.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "loaded.h"
#include "pandalog.h"
#include "panda_common.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

// this provides the fd resolution magic
#include "../osi_linux/osi_linux_ext.h"

#include "../syscalls2/gen_syscalls_ext_typedefs.h"
#include "panda_plugin_plugin.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <dwarf.h>
#include <libdwarf.h>

}

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

// prototype for register-this-callabck
PPP_PROT_REG_CB(on_library_load);
}

// This creates the global for this call back fn (on_library_load)
PPP_CB_BOILERPLATE(on_library_load)

#include <map>
#define MAX_FILENAME 256
std::map <target_ulong, OsiProc> running_procs;

void die(const char* fmt, ...) {
    va_list args;
    
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

target_ulong monitored_asid = 0;


uint32_t guest_strncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        uint8_t c;
        panda_virtual_memory_rw(env, guest_addr+i, &c, 1, 0);
        buf[i] = c;
        if (c==0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}

#if defined(TARGET_I386)
void linux_mmap_pgoff_return(CPUState *env,target_ulong pc,uint32_t addr,uint32_t len,uint32_t prot,uint32_t flags,uint32_t fd,uint32_t pgoff) {
    target_ulong asid = panda_current_asid(env);
    if (running_procs.count(asid) == 0) {
        //printf ("linux_mmap_pgoff_enter for asid=0x%x fd=%d -- dont know about that asid.  discarding \n", (unsigned int) asid, (int) fd);
        return;
    }
    if ((int32_t) fd == -1){
        //printf ("linux_mmap_pgoff_enter for asid=0x%x fd=%d flags=%x -- not valid fd . . . \n", (unsigned int) asid, (int) fd, flags);
        return;
    }
    OsiProc proc = running_procs[asid];        
    char *filename = osi_linux_fd_to_filename(env, &proc, fd);
    //uint64_t pos = osi_linux_fd_to_pos(env, &proc, fd);
    // if a filename exists and permission is executable
    // TODO: fix this magic constant of 0x04 for PROT_EXEC could be different on different linux distros
    if (filename != NULL && ((prot & 0x04) == 0x04)) {
        printf ("linux_mmap_pgoff(fd=%d filename=[%s] len=%d prot=%x flags=%x pgoff=%d)=%x\n", (int) fd, filename, len, prot, flags, pgoff, EAX);        
        PPP_RUN_CB(on_library_load, env, pc, filename, EAX)

    }
}
void linux_open_enter(CPUState *env, target_ulong pc, target_ulong filename, int32_t flags, int32_t mode) {
    char the_filename[MAX_FILENAME];
    guest_strncpy(env, the_filename, MAX_FILENAME, filename);    
    printf ("linux_open_enter asid=0x%x filename=[%s]\n", (unsigned int) panda_current_asid(env), the_filename);
}
#endif

// get current process before each bb execs
// which will probably help us actually know the current process
int osi_foo(CPUState *env, TranslationBlock *tb) {

    if (panda_in_kernel(env)) {

        OsiProc *p = get_current_process(env);      

        //some sanity checks on what we think the current process is
        // this means we didnt find current task
        if (p->offset == 0) return 0;
        // or the name
        if (p->name == 0) return 0;
        // this is just not ok
        if (((int) p->pid) == -1) return 0;
        uint32_t n = strnlen(p->name, 32);
        // name is one char?
        if (n<2) return 0;
        uint32_t np = 0;
        for (uint32_t i=0; i<n; i++) {
            np += (isprint(p->name[i]) != 0);
        }
        // name doesnt consist of solely printable characters
        //        printf ("np=%d n=%d\n", np, n);
        if (np != n) return 0;
        target_ulong asid = panda_current_asid(env);
        if (running_procs.count(asid) == 0) {
            printf ("adding asid=0x%x to running procs.  cmd=[%s]  task=0x%x\n", (unsigned int)  asid, p->name, (unsigned int) p->offset);
        }
        running_procs[asid] = *p;
    }
    
    return 0;
}
bool init_plugin(void *self) {
    //panda_arg_list *args = panda_get_args("loaded");

    panda_require("osi_linux");
    assert(init_osi_linux_api());
    panda_require("osi");
    assert(init_osi_api());
    panda_require("syscalls2");

#if defined(TARGET_I386)
    {
        panda_cb pcb;
        pcb.before_block_exec = osi_foo;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    }
    
    PPP_REG_CB("syscalls2", on_sys_mmap_pgoff_return, linux_mmap_pgoff_return);
#else
    fprintf(stderr, "The loaded plugin is not currently supported on this platform.\n");
    return false;
#endif
    return true;
}

void uninit_plugin(void *self) { }
