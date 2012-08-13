/*
 * Instrumentation for syscalls in linux-user/syscall.c
 */

#include "linux-user-syscall.h"
#include "tcg.h"
#include "tcg-llvm.h"

#ifdef CONFIG_LLVM_TRACE
extern FILE *funclog;
#endif

int infd = -1;
int outfd = -1;

/*
 * Kind of a hacky way to see if the file being opened is something we're
 * interested in.  For now, we are working under the assumption that a program
 * will open/read one file of interest, and open/write the other file of
 * interest.  So we assume that files that are opened from /etc and /lib aren't
 * of interest. /proc and openssl.cnf also aren't interesting, from looking at
 * openssl.
 */
#ifdef CONFIG_LLVM_TRACE
void inst_open(int ret, void *p, int flags){
    const char *file = path(p);
    if (ret > 0){
        if((strncmp(file, "/etc", 4) != 0)
                && (strncmp(file, "/lib", 4) != 0)
                && (strncmp(file, "/proc", 5) != 0)
                && (strstr(file, "openssl.cnf") == 0)){
            printf("open %s for ", file);
            if ((flags & (O_RDONLY | O_WRONLY)) == O_RDONLY){
                printf("read\n");
                infd = ret;
            }
            if (flags & O_WRONLY){
                printf("write\n");
                outfd = ret;
            }
        }
    }
}

void inst_read(int fd, int ret, void *p){
    if (ret > 0 && fd == infd){
        // log the address and size of a buffer to be tainted
        fprintf(funclog, "taint,read,%ld,%ld\n", (uintptr_t)p,
            (unsigned long)ret);
        printf("taint,read,%ld,%ld\n", (uintptr_t)p, (unsigned long)ret);
    }
}

void inst_write(int fd, int ret, void *p){
    if (ret > 0 && fd == outfd){
        // log the address and size of a buffer to be checked for taint
        fprintf(funclog, "taint,write,%ld,%ld\n", (uintptr_t)p,
            (unsigned long)ret);
        printf("taint,write,%ld,%ld\n", (uintptr_t)p, (unsigned long)ret);
    }
}
#endif // CONFIG_LLVM_TRACE

void inst_exit_group(void){
    if (tcg_llvm_ctx) {
#ifdef CONFIG_LLVM_TRACE
        if (execute_llvm && trace_llvm){
            //write module to file before exiting
            tcg_llvm_write_module(tcg_llvm_ctx);
        }
#endif
        tcg_llvm_close(tcg_llvm_ctx);
        tcg_llvm_ctx = NULL;
    }
}

