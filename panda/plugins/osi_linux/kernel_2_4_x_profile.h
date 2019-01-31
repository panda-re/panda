#pragma once

#include "kernel_profile.h"

void kernel24x_get_current_process(CPUState *cpu, OsiProc **proc);
void kernel24x_get_current_thread(CPUState *cpu, OsiThread **thr);
target_ptr_t kernel24x_get_files_fds(CPUState *cpu, target_ptr_t files);

const KernelProfile KERNEL24X_PROFILE = {
	.get_current_process = &kernel24x_get_current_process,
	.get_current_thread = &kernel24x_get_current_thread,
    .get_files_fds = &kernel24x_get_files_fds
};
