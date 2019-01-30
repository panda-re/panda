#pragma once

#include "kernel_profile.h"

void default_get_current_process(CPUState *cpu, OsiProc **proc);
void default_get_current_thread(CPUState *cpu, OsiThread **thr);

const KernelProfile DEFAULT_PROFILE = {
	.get_current_process = &default_get_current_process,
	.get_current_thread = &default_get_current_thread
};
