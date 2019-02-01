#pragma once

#include "kernel_profile.h"

target_ptr_t kernel24x_get_current_task_struct(CPUState *cpu);
target_ptr_t kernel24x_get_files_fds(CPUState *cpu, target_ptr_t files);

const KernelProfile KERNEL24X_PROFILE = {
    .get_current_task_struct = &kernel24x_get_current_task_struct,
    .get_files_fds = &kernel24x_get_files_fds
};
