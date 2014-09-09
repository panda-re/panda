extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "syscallents.h"
}

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <strings.h>
#include <errno.h>
#include <iostream>
#include <fstream>

/*
 * Functions interfacing with QEMU/PANDA should be linked as C.
 * C++ function name mangling breaks linkage.
 */
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

/*
 * Error handling macros.
 */
#define WARN_ON_ERROR(cond, txt) if (cond) {\
    char s[512];\
    bzero(&s, 512);\
    snprintf(s, 512, "@[%s] %s", __PRETTY_FUNCTION__, txt);\
    if (errno == 0) fprintf(stderr, "%s\n", s);\
    else perror(s);\
}
#define EXIT_ON_ERROR(cond, txt) if (cond) {\
    char s[512];\
    bzero(&s, 512);\
    snprintf(s, 512, "@[%s] %s", __PRETTY_FUNCTION__, txt);\
    if (errno == 0) fprintf(stderr, "%s\n", s);\
    else perror(s);\
    exit(1);\
}
#define ERRNO_CLEAR errno = 0


#define PLUGIN_NAME "panda_prov_tracer"
#define DLNAME_LEN 256
#define PROV_TRACER_DEFAULT_OUT "prov_tracer.txt"

/*
 *	--------------------
 *	Panda API Cheatsheet
 *	--------------------
 *	
 *	void panda_register_callback(void *plugin, PANDA_CB_USER_AFTER_SYSCALL, panda_cb cb);
 *	int panda_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write);
 *	target_phys_addr_t panda_virt_to_phys(CPUState *env, target_ulong addr);
 *	int panda_virtual_memory_rw(CPUState *env, target_ulong addr, uint8_t *buf, int len, int is_write);
 *
 *	Formats (from cpu.h):
 *	TARGET_FMT_lx
 *	TARGET_FMT_ld
 *	TARGET_FMT_lu
 */


#if defined(TARGET_I386)
void *syscalls_dl;
struct syscall_entry *syscalls;
FILE *ptout;

/* 
	http://www.tldp.org/LDP/tlk/ds/ds.html

	thread_info struct starts on %ESP & 0xffffe000 (8k stack).
	Its first element is a pointer to a task_struct struct.

	task_struct contains the pid/gid of the running process, however their exact 
        location is kernel-specific. I.e. it will be different depending of the flags
	set during kernel compilation.


*/

int before_block_exec_cb(CPUState *env, TranslationBlock *tb) {
	//ptout << std::hex << env->regs[R_ESP] << ":" << (0xffffe000 & env->regs[R_ESP]) <<  std::endl;
	return 0;
}

//
bool ins_translate_callback(CPUState *env, target_ulong pc) {
    opcode_t sysenter[] = OP_SYSENTER;
    unsigned char buf[2];

    cpu_memory_rw_debug(env, pc, buf, 2, 0);
    if TEST_OP(sysenter, buf) return true;

    return false;
}

int ins_exec_callback(CPUState *env, target_ulong pc) {
    unsigned char buf[2];

    cpu_memory_rw_debug(env, pc, buf, 2, 0);

    fprintf(ptout,
        "opcode=%#04x %#04x\n",
        buf[0], buf[1]);

    int syscall_nr = env->regs[R_EAX];
    // On Windows and Linux, the system call id is in EAX
    fprintf(ptout,
        "PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx "\n",
        pc, syscall_nr);

    if (syscalls[syscall_nr].nr != SYSCALL_OTHER) {
        fprintf(ptout, "%s\n", syscalls[syscall_nr].name);
    }

    /*
    fprintf(ptout,
        "GETPID=" TARGET_FMT_lx " READ=" TARGET_FMT_lx "\n",
        SYS_getpid, __NR_read);

    fprintf(ptout,
        "GETPID=%u READ=%u\n",
        SYS_getpid, __NR_read);

    #if defined(LINUX32_GUEST)
    if (env->regs[R_EAX] == 20) {
        fprintf(ptout, "getpid\n");
    }
    else if (env->regs[R_EAX] == 3) {
        fprintf(ptout, "read\n");
    }
    else {
        fprintf(ptout, "other\n");
    }
    #endif
    */
    return 0;
}

#endif

bool init_plugin(void *self) {
    int i;
    panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);

#if defined(TARGET_I386)
    // i386-specific settings
    char *guest_os = NULL;
#endif

    // handle plugin arguments
    if (plugin_args != NULL ) {
        for (i=0; i<plugin_args->nargs; i++) {
            panda_arg a = plugin_args->list[i];

#if defined(TARGET_I386)
            // i386-specific arguments
            if (0 == strcmp(a.key, "guest")) {
                ERRNO_CLEAR;
                guest_os = strdup(a.value);
                EXIT_ON_ERROR(guest_os == NULL, "strdup");
            }
#else
            // arguments available to all targets
            if (1 == 0) { }
#endif
            else {
                fprintf(stderr, "Unknown PANDA plugin argument: %s=%s.\n", a.key, a.value);
            }
        }
        panda_free_args(plugin_args);
    }



#if defined(TARGET_I386)
    // load syscall entries
    int n;
    char syscalls_dlname[DLNAME_LEN];
    ERRNO_CLEAR;
    n = snprintf(syscalls_dlname, DLNAME_LEN, "%s_syscallents_%s.so", PLUGIN_NAME, guest_os);
    EXIT_ON_ERROR(!(n > -1 && n < DLNAME_LEN), "snprintf failed");
    syscalls_dl = dlopen(syscalls_dlname, RTLD_NOW);
    EXIT_ON_ERROR(syscalls_dl == NULL, dlerror());
    syscalls = (struct syscall_entry *)dlsym(syscalls_dl, "syscalls");
    EXIT_ON_ERROR(syscalls == NULL, dlerror());

    // open output file
    ptout = fopen(PROV_TRACER_DEFAULT_OUT, "w");    
    if(ptout == NULL) return false;
    panda_cb pcb;

    //pcb.before_block_exec = before_block_exec_cb;
    //panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.insn_translate = ins_translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec = ins_exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    return true;
#else
    std::cerr << "WARN: Target not supported for panda_prov_tracer plugin." << std::endl;
    return false;
#endif
}

void uninit_plugin(void *self) {
#if defined(TARGET_I386)
    int n;

    ERRNO_CLEAR;
    n = dlclose(syscalls_dl);
    WARN_ON_ERROR(n != 0, dlerror());
	n = fclose(ptout);
    WARN_ON_ERROR(n != 0, "fclose failed");
#endif
}

