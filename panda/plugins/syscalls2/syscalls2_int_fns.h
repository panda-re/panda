#pragma once

// returns information about the syscall with the specified number
const syscall_info_t *get_syscall_info(uint32_t callno);

// returns meta-information about the syscalls of the guest os
const syscall_meta_t *get_syscall_meta(void);

// returns the system call return value, hiding arch-specific details
target_long get_syscall_retval(CPUState *cpu);

