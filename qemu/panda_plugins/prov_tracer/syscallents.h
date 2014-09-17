#ifndef __SYSCALLENTS_H__
#define __SYSCALLENTS_H__

#define SYSCALL_MAXARGS 6
#define SYSCALL_STRSAMPLE_LEN 128

enum prov_tracer_syscall {
    SYSCALL_OTHER = -1,
    SYSCALL_READ = 0,
    SYSCALL_WRITE,
    SYSCALL_OPEN,
    SYSCALL_CLOSE,
    SYSCALL_STAT,
    SYSCALL_FSTAT,
    SYSCALL_LSTAT,
    SYSCALL_POLL,
    SYSCALL_LSEEK,
    SYSCALL_MMAP
};

enum syscall_argtype {
    SYSCALL_ARG_INT,
    SYSCALL_ARG_PTR,
    SYSCALL_ARG_STR
};

struct syscall_entry {
    enum prov_tracer_syscall nr;
    const char *name;
    int nargs;
    enum syscall_argtype args[SYSCALL_MAXARGS];
};

#endif
