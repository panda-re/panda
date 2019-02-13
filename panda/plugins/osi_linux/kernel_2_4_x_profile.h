#pragma once

#include "kernel_profile.h"

target_ptr_t kernel24x_get_current_task_struct(CPUState *cpu);
target_ptr_t kernel24x_get_task_struct_next(CPUState *cpu, target_ptr_t ts);
target_ptr_t kernel24x_get_group_leader(CPUState *cpu, target_ptr_t ts);
target_ptr_t kernel24x_get_files_fds(CPUState *cpu, target_ptr_t files);

const KernelProfile KERNEL24X_PROFILE = {
    .get_current_task_struct = &kernel24x_get_current_task_struct,
    .get_task_struct_next = &kernel24x_get_task_struct_next,
    .get_group_leader = &kernel24x_get_group_leader,
    .get_files_fds = &kernel24x_get_files_fds
};
