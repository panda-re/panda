#include "osi_linux.h"
#include "kernel_2_4_x_profile.h"

target_ptr_t kernel24x_get_current_task_struct(CPUState *cpu)
{
	target_ptr_t kernel_esp = panda_current_sp(cpu);
	if (false == panda_in_kernel(cpu)) {
	  // INT 80h pushes 20 bytes - we are emulating that here if not in kernel mode.
	  kernel_esp -= 20;
	}
	target_ptr_t ts = kernel_esp & THREADINFO_MASK;
	return ts;
}

/**
 * @brief Retrieves the array of file structs from the files struct.
 * The n-th element of the array corresponds to the n-th open fd.
 */
IMPLEMENT_OFFSET_GET(get_files_fds, files_struct, target_ptr_t, ki.fs.fd_offset, 0)

target_ptr_t kernel24x_get_files_fds(CPUState *cpu, target_ptr_t files)
{
	return get_files_fds(cpu, files);
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab: */
