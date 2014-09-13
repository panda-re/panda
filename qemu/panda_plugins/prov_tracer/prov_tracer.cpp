#include <distorm.h>
namespace distorm {
#include <mnemonics.h>
}

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
#include <sstream>


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
_DecodeType distorm_dt = Decode32Bits;

/* 
	http://www.tldp.org/LDP/tlk/ds/ds.html

	thread_info struct starts on %ESP & 0xffffe000 (8k stack).
	Its first element is a pointer to a task_struct struct.

	task_struct contains the pid/gid of the running process, however their exact 
        location is kernel-specific. I.e. it will be different depending of the flags
	set during kernel compilation.


    http://wiki.osdev.org/SYSENTER
*/

/*
static inline char *syscall2str() {

    %eax
    %ebx, %ecx, %edx, %esi, %edi, %ebp
    std::stringstream ss;

}
*/



static inline bool in_kernelspace(CPUState *env) {
#if defined(TARGET_I386)
    // check the Current Privillege Level in the flags register
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    // check for supervisor mode in the Current Program Status register
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
    return false;
#endif
}


int before_block_exec_cb(CPUState *env, TranslationBlock *tb) {
	//ptout << std::hex << env->regs[R_ESP] << ":" << (0xffffe000 & env->regs[R_ESP]) <<  std::endl;
	return 0;
}

//
bool ins_translate_callback(CPUState *env, target_ulong pc) {
    unsigned char buf[2];
    opcode_t sysenter[] = OP_SYSENTER;
    opcode_t sysexit[] = OP_SYSEXIT;

    cpu_memory_rw_debug(env, pc, buf, 2, 0);

    _DInst decodedInstructions[1];
    unsigned int decodedInstructionsCount = 0;
    _DecodeType dt = Decode32Bits;

    _CodeInfo ci;
    ci.code = buf;
    ci.codeLen = sizeof(buf);
    ci.codeOffset = 0;
    ci.dt = dt;
    ci.features = DF_NONE;
    distorm_decompose(&ci, decodedInstructions, 1, &decodedInstructionsCount);

    for (int i=0; i<decodedInstructionsCount; i++) {
        if (decodedInstructions[i].flags == FLAG_NOT_DECODABLE) {
            fprintf(ptout, "?");
        }
        else if (decodedInstructions[i].opcode == distorm::I_SYSENTER) {
            fprintf(ptout, "!");
        }
        else {
            fprintf(ptout, "*");
        }
    }
    fprintf(ptout, "\n");


    if TEST_OP(sysenter, buf) return true;
    else if TEST_OP(sysexit, buf) return true;
    else return false;
}

int ins_exec_callback(CPUState *env, target_ulong pc) {
    unsigned char buf[2];
    opcode_t sysenter[] = OP_SYSENTER;
    opcode_t sysexit[] = OP_SYSEXIT;

    cpu_memory_rw_debug(env, pc, buf, 2, 0);

    if TEST_OP(sysenter, buf) {
        unsigned int syscall_nr = env->regs[R_EAX];

        // On Windows and Linux, the system call id is in EAX
        // On Linux, the PC will point to the same location for each syscall:
        //  At kernel initialization time the routine sysenter_setup() is called. It
        //  sets up a non-writable page and writes code for the sysenter instruction
        //  if the CPU supports that, and for the classical int 0x80 otherwise.
        //  Thus, the C library can use the fastest type of system call by jumping
        //  to a fixed address in the vsyscall page.
        //  (http://www.win.tue.nl/~aeb/linux/lk/lk-4.html)
        //
        fprintf(ptout,
            "*%s PC=" TARGET_FMT_lx ", SYSCALL=" TARGET_FMT_lx " (%s)\n",
            in_kernelspace(env) ? "k" : "u",
            pc,
            syscall_nr,
            syscalls[syscall_nr].name
        );
    }
    else if TEST_OP(sysexit, buf) {
        fprintf(ptout,
            "#%s PC=" TARGET_FMT_lx "\n",
            in_kernelspace(env) ? "k" : "u",
            pc
        );
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

    // set Distorm decode mode
    if (strstr(guest_os, "64")) { distorm_dt = Decode64Bits; }
    else { distorm_dt = Decode64Bits; }

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

