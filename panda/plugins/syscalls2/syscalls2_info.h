#ifndef SYSCALL_INFO_H
#define SYSCALL_INFO_H

typedef enum {
    SYSCALL_ARG_CHAR_STAR,
    SYSCALL_ARG_POINTER,
    SYSCALL_ARG_4BYTE,
    SYSCALL_ARG_4SIGNED,
    SYSCALL_ARG_8BYTE,
    SYSCALL_ARG_2BYTE
} syscall_argtype_t;

typedef struct {
    int no;
    const char *name;
    int nargs;
    syscall_argtype_t *argt;
    uint8_t *argsz;
} syscall_info_t;

#ifdef __cplusplus
extern "C" {
#endif
// dynamically loads system call information
int load_syscall_info(void);
#ifdef __cplusplus
}
#endif

#endif
