#pragma once

#include "kernel_profile.h"

void default_get_current_process(CPUState *cpu, OsiProc **proc);
void default_get_current_thread(CPUState *cpu, OsiThread **thr);

target_ptr_t default_get_file_fds(CPUState *cpu, target_ptr_t files);

const KernelProfile DEFAULT_PROFILE = {
	.get_current_process = &default_get_current_process,
	.get_current_thread = &default_get_current_thread,
    .get_files_fds = &default_get_file_fds
};
