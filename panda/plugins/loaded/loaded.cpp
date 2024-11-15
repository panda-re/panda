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

#include <cstdio>
#include <map>
#include <memory>
#include <sys/mman.h>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "loaded.h"

extern "C" {
#include "panda/rr/rr_log.h"
#include "panda/plog.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

// this provides the fd resolution magic
#include "osi_linux/osi_linux_ext.h"

#include "syscalls2/syscalls_ext_typedefs.h"

}

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

// prototype for register-this-callabck
PPP_PROT_REG_CB(on_library_load);
// This creates the global for this call back fn (on_library_load)
PPP_CB_BOILERPLATE(on_library_load)

bool debug = false;

#define MAX_FILENAME 256
std::map <target_ulong, OsiProc> running_procs;

void die(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

uint32_t guest_strncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        uint8_t c = 0;
        panda_virtual_memory_rw(cpu, guest_addr+i, &c, 1, 0);
        buf[i] = c;
        if (c==0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
// 125 long sys_mprotect ['unsigned long start', ' size_t len', 'unsigned long prot']
void linux_mprotect_return(CPUState* cpu,target_ulong pc,uint32_t start,uint32_t len,uint32_t prot) {
    if (debug) {
        printf("[loaded] mprotect()\n");
    }
}
// 90 long sys_old_mmap ['struct mmap_arg_struct __user *arg']
void linux_old_mmap_return(CPUState *cpu, target_ulong pc, uint32_t arg_ptr) {
    if (debug) {
        printf("[loaded] old mmap()\n");
    }
}

void linux_mmap_pgoff_return(CPUState *cpu,target_ulong pc,uint32_t addr,uint32_t len,uint32_t prot,uint32_t flags,uint32_t fd,uint32_t pgoff) {
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    target_ulong asid = panda_current_asid(cpu);
    if (running_procs.count(asid) == 0) {
        //printf ("linux_mmap_pgoff_enter for asid=0x%x fd=%d -- dont know about that asid.  discarding \n", (unsigned int) asid, (int) fd);
        return;
    }
    if ((int32_t) fd == -1){
        //printf ("linux_mmap_pgoff_enter for asid=0x%x fd=%d flags=%x -- not valid fd . . . \n", (unsigned int) asid, (int) fd, flags);
        return;
    }
    OsiProc proc = running_procs[asid];
    char *filename = osi_linux_fd_to_filename(cpu, &proc, fd);
    // gets us offset into the file.  could be useful
    // uint64_t pos = osi_linux_fd_to_pos(env, &proc, fd);
    // if a filename exists and permission is executable
    if (filename != NULL && ((prot & PROT_EXEC) == PROT_EXEC)) {
        if (debug) {
            printf ("[loaded] linux_mmap_pgoff(fd=%d filename=[%s] "
                    "len=%d prot=%x flags=%x "
                    "pgoff=%d)=" TARGET_FMT_lx "\n", (int) fd,
                    filename, len, prot, flags, pgoff, env->regs[R_EAX]);
        }
        PPP_RUN_CB(on_library_load, cpu, pc, filename, env->regs[R_EAX], len);
    } else if ((prot & PROT_EXEC) == PROT_EXEC) {
        printf("[loaded] mapped executable section without a filename!\n");
        printf ("[loaded] linux_mmap_pgoff(fd=%d "
                "len=%d prot=%x flags=%x "
                "pgoff=%d)=" TARGET_FMT_lx "\n", (int) fd,
                len, prot, flags, pgoff, env->regs[R_EAX]);
    }
}

#elif defined(TARGET_I386) && defined(TARGET_X86_64)
void linux_mprotect_return(CPUState* cpu, target_ulong pc, 
                            uint64_t start, uint32_t len, 
                            uint64_t prot) {
    if (debug) {
        printf("[loaded] mprotect() on x86-64\n");
    }
}
// https://man7.org/linux/man-pages/man2/mmap.2.html
// https://github.com/panda-re/panda/blob/dev/panda/plugins/syscalls2/generated/syscalls_ext_typedefs_x64.h#L7405-L7412
void linux_mmap_return(CPUState *cpu, target_ulong pc,
                        uint64_t addr, uint64_t len, uint64_t prot, 
                        uint64_t flags, uint64_t fd, uint64_t offset) {

    if (debug) {
        printf("linux_mmap_return 64-bit is called\n");
    }
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    target_ulong asid = panda_current_asid(cpu);
    if (running_procs.count(asid) == 0) {
        return;
    }
    if ((int32_t) fd == -1) {
        return;
    }
    if (debug) {
        printf("linux_mmap_return 64-bit is called, with OK fd and non-zero running proc\n");
    }

    OsiProc proc = running_procs[asid];
    char * filename = osi_linux_fd_to_filename(cpu, &proc, fd);
    // TODO: Brendan, will this offset help us? I feel like there is a difference
    // mmap is just an offset and mmap_pgoff is an offset of pages? These I do NOT think are the same!!!! 
    // YES!!! SEE FILE_TAINT LIBRARY
    // gets us offset into the file, could be useful, how would we update the callback?
    // It is unused, I need to comment out...
    // uint64_t pos = osi_linux_fd_to_pos(cpu, &proc, fd);
    // if a filename exists and permission is executable
    if (filename != NULL && ((prot & PROT_EXEC) == PROT_EXEC)) {
        if (debug) {
            printf("[loaded] linux_mmap(fd=%lu filename=[%s] len=%lu prot=%lx flags=%lx pgoff=%lu)=%lx\n", 
                   fd, filename, len, prot, flags, offset, (unsigned long) env->regs[R_EAX]);
        }
        PPP_RUN_CB(on_library_load, cpu, pc, filename, env->regs[R_EAX], len);
    }
    else if ((prot & PROT_EXEC) == PROT_EXEC) {
        printf("[loaded] mapped executable section without a filename!\n");
        printf("[loaded] linux_mmap(fd=%lu len=%lu prot=%lx flags=%lx pgoff=%lu)=%lx\n", 
               fd, len, prot, flags, offset, (unsigned long) env->regs[R_EAX]);
    }
    else {
        if (debug) {
            if (filename == NULL) {
                printf("[loaded] I got a null file name\n");
            }
            else {
                printf("[loaded] It seems like filename %s was null, OR PROT_EXEC was not there\n", filename);
            }
        }
    }
}
#endif

// get current process before each bb execs
// which will probably help us actually know the current process
void osi_foo(CPUState *cpu, TranslationBlock *tb) {

    if (panda_in_kernel(cpu)) {

        std::unique_ptr<OsiProc, decltype(free_osiproc)*> p { get_current_process(cpu), free_osiproc };

        //some sanity checks on what we think the current process is
        // we couldn't find the current task
        if (!p) return;
        // this means we didnt find current task
        if (p->taskd == 0) return;
        // or the name
        if (p->name == 0) return;
        // this is just not ok
        if (((int) p->pid) == -1) return;
        uint32_t n = strnlen(p->name, 32);
        // name is one char?
        if (n<2) return;
        uint32_t np = 0;
        for (uint32_t i=0; i<n; i++) {
            np += (isprint(p->name[i]) != 0);
        }
        // name doesnt consist of solely printable characters
        //        printf ("np=%d n=%d\n", np, n);
        if (np != n) return;
        target_ulong asid = panda_current_asid(cpu);
        if (running_procs.count(asid) == 0) {
            printf ("adding asid=0x%x to running procs.  cmd=[%s]  task=0x%x\n", (unsigned int)  asid, p->name, (unsigned int) p->taskd);
        }
        running_procs[asid] = *p;
    }

    return;
}
bool init_plugin(void *self) {
    panda_require("osi");
    assert(init_osi_api());
    panda_require("osi_linux");
    assert(init_osi_linux_api());
    panda_require("syscalls2");
    panda_arg_list *args = panda_get_args("loaded");
    debug = panda_parse_bool_opt(args, "debug", "enable debug output");

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    {
        panda_cb pcb;
        pcb.before_block_exec = osi_foo;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    }

    PPP_REG_CB("syscalls2", on_sys_mmap_pgoff_return, linux_mmap_pgoff_return);
    // don't use these at them moment
    // PPP_REG_CB("syscalls2", on_sys_old_mmap_return, linux_old_mmap_return);
    // PPP_REG_CB("syscalls2", on_sys_mprotect_return, linux_mprotect_return);
    printf("The loaded plugin is supported on i386\n");
#elif defined(TARGET_I386) && defined(TARGET_X86_64)
    {
        panda_cb pcb;
        pcb.before_block_exec = osi_foo;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    }
    // Tell Plugin 'syscall2', that if a systemcall 'mmap' occurs, then run the code in ;'linux_mmap_return'
    // https://www.linuxquestions.org/questions/linux-general-1/difference-between-mmap2-syscall-and-mmap_pgoff-syscall-for-32-bit-linux-4175622986/
    PPP_REG_CB("syscalls2", on_sys_mmap_return, linux_mmap_return);
    PPP_REG_CB("syscalls2", on_sys_mprotect_return, linux_mprotect_return);
    printf("The loaded plugin is supported on  x86-64\n");
#else
    fprintf(stderr, "The loaded plugin is not currently supported on this platform.\n");
    return false;
#endif
    return true;
}

void uninit_plugin(void *self) { }
