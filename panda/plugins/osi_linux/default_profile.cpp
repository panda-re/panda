#include "osi_linux.h"
#include "default_profile.h"


/**
 * @brief Retrieves the task_struct address using per cpu information.
 */
target_ptr_t default_get_current_task_struct(CPUState *cpu)
{
    struct_get_ret_t err;
    target_ptr_t current_task_addr;
    target_ptr_t ts; // Returned task struct
#ifdef TARGET_ARM
    // Read banked R13 for SVC mode to get the kernel SP (1=>SVC bank from target/arm/internals.h)
    unsigned long kernel_sp =  ((CPUARMState*)cpu->env_ptr)->banked_r13[1];

    // XXX: This should use THREADINFO_MASK but that's hardcoded and wrong for my test system
    target_ptr_t task_thread_info = kernel_sp & ~(0x2000 -1);

    current_task_addr=task_thread_info+0xC;
#else
    current_task_addr = ki.task.current_task_addr;
#endif
    if (current_task_addr ==(target_ptr_t)NULL) {
        printf("[OSI PROFILE] current task is NULL\n");
        return (target_ptr_t)NULL;
    }
    err = struct_get(cpu, &ts, current_task_addr, ki.task.per_cpu_offset_0_addr);
    if (err != struct_get_ret_t::SUCCESS) {
        printf("[OSI_PROFILE] failed to get current task struct\n");
        return (target_ptr_t)NULL;
    }
    return ts;
}

/**
 * @brief Retrieves the address of the following task_struct in the process list.
 */
target_ptr_t default_get_task_struct_next(CPUState *cpu, target_ptr_t task_struct)
{
    struct_get_ret_t err;
    target_ptr_t tasks;
    err = struct_get(cpu, &tasks, task_struct, ki.task.tasks_offset);
    if (err != struct_get_ret_t::SUCCESS) {
        printf("[OSI PROFILE] failed to get next task\n");
        return (target_ptr_t)NULL;
    }
    return tasks-ki.task.tasks_offset;
}

/**
 * @brief Retrieves the thread group leader address from task_struct.
 */
target_ptr_t default_get_group_leader(CPUState *cpu, target_ptr_t ts)
{
    struct_get_ret_t err;
    target_ptr_t group_leader;

    err = struct_get(cpu, &group_leader, ts, ki.task.group_leader_offset);
    if (err != struct_get_ret_t::SUCCESS) {
        printf("[OSI PROFILE] failed to get group leader for task\n");
        return (target_ptr_t)NULL;
    }
    return group_leader;
}

/**
 * @brief Retrieves the array of file structs from the files struct.
 * The n-th element of the array corresponds to the n-th open fd.
 */
target_ptr_t default_get_file_fds(CPUState *cpu, target_ptr_t files)
{
    struct_get_ret_t err;
    target_ptr_t files_fds;
    err = struct_get(cpu, &files_fds, files, {ki.fs.fdt_offset, ki.fs.fd_offset});
    if (err != struct_get_ret_t::SUCCESS) {
        LOG_ERROR("Failed to retrieve file structs (error code: %d)", err);
        return (target_ptr_t)NULL;
    }
    return files_fds;
}

/* vim:set tabstop=4 softtabstop=4 expandtab: */
