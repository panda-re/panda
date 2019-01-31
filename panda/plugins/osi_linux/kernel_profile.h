#pragma once

#include "panda/plugin.h"
#include "osi/osi_types.h"

struct KernelProfile
{
	void (*get_current_process)(CPUState *cpu, OsiProc **proc);
	void (*get_current_thread)(CPUState *cpu, OsiThread **thr);

    target_ptr_t (*get_files_fds)(CPUState *cpu, target_ptr_t files);
};
