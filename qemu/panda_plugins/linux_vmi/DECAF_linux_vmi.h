/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with this program; if not, write to the Free 
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA 02111-1307 USA
**/

/**
 * Based off of the original read_linux from TEMU but reimplemented here
 * @author Lok
**/
#ifndef DECAF_LINUX_VMI_H
#define DECAF_LINUX_VMI_H

//#include "DECAF_main.h"
#include "qemu-common.h"
#include "linux_vmi_types.h"
#include "panda_wrapper.h"
/* THREE EXAMPLES of equivalent functions what the macro generates
gpid_t DECAF_get_pid(CPUState* env, gva_t task_struct_addr)
{
  gpid_t pid;

  if (DECAF_read_mem(env, addr + task_struct_pid_offset, sizeof(gpid_t), &pid) != 0)
  {
    return (-1);
  }

  return pid;
}

target_long DECAF_get_tgid (CPUState* env, gva_t task_struct_addr)
{
  target_long tgid;
  if (DECAF_read_mem(env, task_struct_addr + task_struct_tgid_offset, sizeof(target_long), & tgid) != 0)
  {
    return (-1);
  }
  return (tgid);
}

gva_t DECAF_get_group_leader (CPUState* env, gva_t task_struct_addr)
{
  gva_t gl;
  if (DECAF_read_mem(env, task_struct_addr + task_struct_tgid_offset, sizeof(gva_t), &gl) != 0)
  {
    return (-1);
  }
  return (gl);
}
*/
#define IMPLEMENT_OFFSET_GETTER(_retType, _name, _paramName, _offset, _defaultRetValue) \
  extern int _offset;                                                                   \
  static inline _retType _name(CPUState* env, gva_t _paramName)                         \
  {                                                                                     \
    _retType _t;                                                                        \
    if (DECAF_read_mem(env, _paramName + _offset, &_t, sizeof(_retType)) != 0)          \
    {                                                                                   \
      return (_defaultRetValue);                                                        \
    }                                                                                   \
                                                                                        \
    return (_t);                                                                        \
  }


/**
 * Takes in the address of a task_struct and retrieves and returns the stack field
 * Returns -1 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(target_long, DECAF_get_stack, task_struct_addr, task_struct_stack_offset, -1)

/**
 * Takes in the address of a task_struct and retrieves and returns the pid field
 * Returns -1 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gpid_t, DECAF_get_pid, task_struct_addr, task_struct_pid_offset, -1)

/**
 * Takes in the address of a task_struct and retrieves and returns the tgid field
 * Returns -1 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(target_long, DECAF_get_tgid, task_struct_addr, task_struct_tgid_offset, -1)

/**
 * Takes in the address of a task_struct and returns the group_leader field - which is a pointer
 * Returns 0 (NULL) if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_group_leader, task_struct_addr, task_struct_group_leader_offset, 0)

/**
 * Takes in the address of a task_struct and returns the thread_group field - which is a pointer
 * Returns 0 (NULL) if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_thread_group, task_struct_addr, task_struct_thread_group_offset, 0)

/**
 * Takes in the address of a cred struct and returns the uid field
 * Returns -1 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(target_long, DECAF_get_cred_uid, cred_addr, cred_uid_offset, -1)

/**
 * Takes in the address of a cred struct and returns the gid field
 * Returns -1 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(target_long, DECAF_get_cred_gid, cred_addr, cred_gid_offset, -1)

/**
 * Takes in the address of a cred struct and returns the euid field
 * Returns -1 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(target_long, DECAF_get_cred_euid, cred_addr, cred_euid_offset, -1)

/**
 * Takes in the address of a cred struct and returns the egid field
 * Returns -1 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(target_long, DECAF_get_cred_egid, cred_addr, cred_egid_offset, -1)

/**
 * Takes in the address of a task_struct and returns the mm field - which is a pointer
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_mm, task_struct_addr, task_struct_mm_offset, 0)

/**
 * Takes in the address of a mm_struct and returns the start_brk field - which is an address
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_start_brk, mm_struct_addr, mm_struct_start_brk_offset, 0)

/**
 * Takes in the address of a mm_struct and returns the brk field - which is an address
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_brk, mm_struct_addr, mm_struct_brk_offset, 0)

/**
 * Takes in the address of a mm_struct and returns the start_brk field - which is an address
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_start_stack, mm_struct_addr, mm_struct_start_stack_offset, 0)

/**
 * Takes in the address of vm_area_struct and returns the vm_next field - which is a pointer
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_next_mmap, vma_addr, vm_area_struct_vm_next_offset, 0)

/**
 * Takes in the address of vm_area_struct and returns the vm_file field - which is a pointer
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_vm_file, vma_addr, vm_area_struct_vm_file_offset, 0)

/**
 * Takes in the address of vm_area_struct and returns the vm_flags field
 * Returns 0 if unsuccessful - i.e. no flags are set
 */
IMPLEMENT_OFFSET_GETTER(target_ulong, DECAF_get_vm_flags, vma_addr, vm_area_struct_vm_flags_offset, 0)

/**
 * Takes in the address of vm_area_struct and returns the vm_start field - which is an address
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_vm_start, vma_addr, vm_area_struct_vm_start_offset, 0)

/**
 * Takes in the address of vm_area_struct and returns the vm_end field - which is an address
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_vm_end, vma_addr, vm_area_struct_vm_end_offset, 0)

/**
 * Takes in the address of a dentry struct and returns the d_parent field - which is a pointer
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_dentry_d_parent, dentry_addr, dentry_d_parent_offset, 0)

/**
 * Takes in the address of a task_struct and returns the real_cred field - which is a pointer
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_real_cred, task_struct_addr, task_struct_real_cred_offset, 0)

/**
 * Takes in the address of a task_struct and returns the cred field - which is a pointer
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_cred, task_struct_addr, task_struct_cred_offset, 0)

/**
 * Takes in the address of a task_struct and returns the real_parent field - which is a pointer
 * Returns 0 if unsuccessful
 */
IMPLEMENT_OFFSET_GETTER(gva_t, DECAF_get_real_parent, task_struct_addr, task_struct_real_parent_offset, 0)






/* ONE EXAMPLE
 *
IMPLEMENT_2LEVEL_GETTER(int, DECAF_get_uid, task_struct_addr, gva_t, DECAF_get_cred, 0, DECAF_get_cred_uid, -1)

int DECAF_get_uid(CPUState* env, gva_t task_struct_addr)
{
  gva_t t;
  t = DECAF_get_cred(env, task_struct_addr);
  if ( t == 0 )
  {
    return (-1);
  }

  return (get_cred_uid(t));
}
*/
#define IMPLEMENT_2LEVEL_GETTER(_retType, _name, _paramName, _1stStageRetType, _1stStageName, _1stStageRetErr, _2ndStageName, _defaultRetVal)   \
  static inline _retType _name(CPUState* env, gva_t _paramName) \
  {                                                             \
      _1stStageRetType _t;                                      \
      _t =_1stStageName(env, _paramName);                       \
      if (_t == _1stStageRetErr)                 \
      {                                          \
        return (_defaultRetVal);                 \
      }                                          \
      return (_2ndStageName(env, _t));           \
  }


/**
 * Takes in the address of a task_struct and returns the uid associated with it. This is done by
 * first obtaining the cred struct as pointed to by the cred field and then returning uid field of that
 * Returns -1 if not successful
 */
IMPLEMENT_2LEVEL_GETTER(target_long, DECAF_get_uid, task_struct_addr, gva_t, DECAF_get_cred, 0, DECAF_get_cred_uid, -1)

/**
 * Takes in the address of a task_struct and returns the gid associated with it. This is done by
 * first obtaining the cred struct as pointed to by the cred field and then returning gid field of that
 * Returns -1 if not successful
 */
IMPLEMENT_2LEVEL_GETTER(target_long, DECAF_get_gid, task_struct_addr, gva_t, DECAF_get_cred, 0, DECAF_get_cred_gid, -1)

/**
 * Takes in the address of a task_struct and returns the euid associated with it. This is done by
 * first obtaining the cred struct as pointed to by the cred field and then returning euid field of that
 * Returns -1 if not successful
 */
IMPLEMENT_2LEVEL_GETTER(target_long, DECAF_get_euid, task_struct_addr, gva_t, DECAF_get_cred, 0, DECAF_get_cred_euid, -1)

/**
 * Takes in the address of a task_struct and returns the egid associated with it. This is done by
 * first obtaining the cred struct as pointed to by the cred field and then returning egid field of that
 * Returns -1 if not successful
 */
IMPLEMENT_2LEVEL_GETTER(target_long, DECAF_get_egid, task_struct_addr, gva_t, DECAF_get_cred, 0, DECAF_get_cred_egid, -1)

/**
 * Takes in the address of a task_struct and returns the group-leader's pid associated with it. This is done by
 * first obtaining the group-leader (a task_struct) as pointed to by the group_leader field and then
 * then returning pid field of that
 * Returns -1 if not successful
 */
IMPLEMENT_2LEVEL_GETTER(target_long, DECAF_get_group_leader_pid, task_struct_addr, gva_t, DECAF_get_group_leader, 0, DECAF_get_pid, -1)

/**
 * Takes in the address of a task_struct and returns the group-leader's pid associated with it. This is done by
 * first obtaining the parent (a task_struct) as pointed to by the parent field and then
 * then returning pid field of that
 * Returns -1 if not successful
 */
IMPLEMENT_2LEVEL_GETTER(target_long, DECAF_get_parent_pid, task_struct_addr, gva_t, DECAF_get_real_parent, 0, DECAF_get_pid, -1)


/**
 * Looks for the current task_struct (the one associated with the current ThreadInfo)
 * in the current kernel stack. Keep in mind that the task_struct is a THREAD task_struct
 * which CAN be different from the process's task_struct. 
**/
gva_t DECAF_get_current_task_struct(CPUState* env);

/**
 * Takes in a task struct and returns the a pointer to the next one
**/
gva_t DECAF_get_next_task_struct(CPUState* env, gva_t task_struct_addr);

/** 
 * Takes in a task struct and returns the previous one
**/
gva_t DECAF_get_prev_task_struct(CPUState* env, gva_t addr);

/**
 * Returns the task_struct associated with the current process. 
 * By process, I mean the thread group leader. So this function
 * Basically calls DECAF_get_group_leader(DECAF_get_current_task_struct(env))
**/
gva_t DECAF_get_current_process(CPUState* env);

/**
 * Returns the pgd field of the task struct passed in
**/
target_asid_t DECAF_get_pgd(CPUState* env, gva_t task_struct_addr);

/**
 * Gets the COMM name from the task struct and copies it into the buffer
 * with size.
**/
DECAF_errno_t DECAF_get_name(CPUState* env, gva_t task_struct_addr, char *buf, int size);

/**
 * Gets the argv[0] (cmdline) name from the task struct and copies it into the buffer
 * with size.
**/
DECAF_errno_t DECAF_get_arg_name(CPUState* env, gva_t task_struct_addr, char *buf, int size);

/**
 * Get the first mmap entry from the task struct
**/ 
gva_t DECAF_get_first_mmap(CPUState* env, gva_t task_struct_addr);

/**
 * Get the iname from the dentry object and copy it into the name buffer of size
**/
void DECAF_get_dentry_iname(CPUState* env, gva_t dentry_addr, char* name, int size);

/**
 * Get the dname from the dentry object and copy it into the name buffer of size
**/
void DECAF_get_dentry_dname(CPUState* env, gva_t dentry_addr, char *name, int size);

/**
 * Get the full iname path from the dentry object and copy it into the name buffer of size
**/
void DECAF_get_dentry_full_iname_path(CPUState* env, gva_t dentry_addr, char* name, int size);

/**
 * Get the full dname path from the dentry object and copy it into the name buffer of size
**/
void DECAF_get_dentry_full_dname_path(CPUState* env, gva_t dentry_addr, char* name, int size, gva_t vfsmnt);

/**
 * Get the iname for the module from the vma object and copy it into the name buffer of size
 * Uses the dentry functions.
**/
void DECAF_get_mod_iname(CPUState* env, gva_t vma_addr, char* name, int size);

/**
 * Get the dname for the module from the vma object and copy it into the name buffer of size
 * Uses the dentry functions.
**/
void DECAF_get_mod_dname(CPUState* env, gva_t vma_addr, char* name, int size);

/**
 * Get the full iname path from the vma object and copy it into the name buffer of size
 * Uses the dentry functions.
**/
void DECAF_get_mod_full_iname(CPUState* env, gva_t vma_addr, char* name, int size);

/**
 * Get the full dname path from the vma object and copy it into the name buffer of size
 * Uses the dentry functions.
**/
void DECAF_get_mod_full_dname(CPUState* env, gva_t vma_addr, char* name, int size);

/**
 * Initialize all of the offsets by reading it from the configuration file
 * Returns the number of offets read or -1 if error
**/
int DECAF_linux_vmi_init(void);

/**
 * Initialize all of the offsets by reading it from a pattern string.
 * Returns the number of offets read or -1 if error
**/
int DECAF_linux_vmi_init_with_string(const char* pattern);
#endif
