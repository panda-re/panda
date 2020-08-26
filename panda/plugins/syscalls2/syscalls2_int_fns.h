#pragma once

// returns information about the syscall with the specified number
const syscall_info_t *get_syscall_info(uint32_t callno);

// returns meta-information about the syscalls of the guest os
const syscall_meta_t *get_syscall_meta(void);

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// returns the system call return value, hiding arch-specific details
target_long get_syscall_retval(CPUState *cpu);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
