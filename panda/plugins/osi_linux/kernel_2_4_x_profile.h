#pragma once

#include "kernel_profile.h"

void kernel24x_get_current_process(CPUState *cpu, OsiProc **proc);
void kernel24x_get_current_thread(CPUState *cpu, OsiThread **thr);

const KernelProfile KERNEL24X_PROFILE = {
	.get_current_process = &kernel24x_get_current_process,
	.get_current_thread = &kernel24x_get_current_thread
};
