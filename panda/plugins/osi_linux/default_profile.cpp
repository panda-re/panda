#include "osi_linux.h"
#include "default_profile.h"

#ifdef TARGET_MIPS
extern target_ulong last_r28;
#endif

/**
 * @brief Retrieves the task_struct address using per cpu information.
 */
target_ptr_t default_get_current_task_struct(CPUState *cpu)
{
    struct_get_ret_t err;
    target_ptr_t current_task_addr;
    target_ptr_t ts;
#ifdef TARGET_ARM
    target_ptr_t kernel_sp = panda_current_ksp(cpu);

    // XXX: This should use THREADINFO_MASK but that's hardcoded and wrong for my test system
    // We need to expose that as a part of the OSI config - See issue #651
    target_ptr_t task_thread_info = kernel_sp & ~(0x2000 -1);

    current_task_addr=task_thread_info+0xC;
#elif defined(TARGET_MIPS)
    // __current_thread_info is stored in KERNEL r28
    // userspace clobbers it but kernel restores (somewhow?)
    // First field of struct is task - no offset needed
    current_task_addr=last_r28;

#else // x86/64
    current_task_addr = ki.task.current_task_addr;
#endif
    err = struct_get(cpu, &ts, current_task_addr, ki.task.per_cpu_offset_0_addr);
    assert(err == struct_get_ret_t::SUCCESS && "failed to get current task struct");
    fixupendian(ts);
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
    fixupendian(tasks);
    assert(err == struct_get_ret_t::SUCCESS && "failed to get next task");
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
    fixupendian(group_leader);
    assert(err == struct_get_ret_t::SUCCESS && "failed to get group leader for task");
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
    fixupendian(files_fds);
    return files_fds;
}

/* vim:set tabstop=4 softtabstop=4 expandtab: */
