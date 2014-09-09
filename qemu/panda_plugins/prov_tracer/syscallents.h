
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

#define SYSCALL_MAXARGS 6
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


#if defined(TARGET_I386)
typedef const unsigned char opcode_t;
#define OP_SYSENTER { 0x0f, 0x34 }
#define TEST_OP(o0, o1) (o0[0] == o1[0] && o0[1] == o1[1])
#endif
