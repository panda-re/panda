#include "osi_linux.h"
#include "default_profile.h"

target_ptr_t default_get_current_task_struct(CPUState *cpu)
{
	target_ptr_t kernel_esp = panda_current_sp(cpu);
	target_ptr_t ts = get_task_struct(cpu, (kernel_esp & THREADINFO_MASK));
	return ts;
}

/**
 * @brief Retrieves the array of file structs from the files struct.
 * The n-th element of the array corresponds to the n-th open fd.
 */
IMPLEMENT_OFFSET_GET2L(get_files_fds, files_struct, target_ptr_t, ki.fs.fdt_offset, target_ptr_t, ki.fs.fd_offset, 0);

target_ptr_t default_get_file_fds(CPUState *cpu, target_ptr_t files)
{
	return get_files_fds(cpu, files);
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab: */
