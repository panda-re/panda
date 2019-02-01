#pragma once

#include "kernel_profile.h"

target_ptr_t default_get_current_task_struct(CPUState *cpu);
target_ptr_t default_get_file_fds(CPUState *cpu, target_ptr_t files);

const KernelProfile DEFAULT_PROFILE = {
    .get_current_task_struct = &default_get_current_task_struct,
    .get_files_fds = &default_get_file_fds
};
