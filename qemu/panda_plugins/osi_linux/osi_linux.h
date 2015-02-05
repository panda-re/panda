/*!
 * @file osi_linux.h
 * @brief Definitions for the implementation of Linux OSI.
 *
 * This header file is not meant to be used by plugins building
 * upon the functionality of Linux OSI.
 * For <a href="https://github.com/moyix/panda/blob/master/docs/ppp.md">Plugin-Plugin</a>
 * interactions, `osi_linux_ext.h` should be used.
 *
 * The offset getter macros have been based off the code from
 * linux_vmi plugin and TEMU's read_linux.
 *
 *
 * @author Manolis Stamatogiannakis <manolis.stamatogiannakis@vu.nl>
 * @copyright   This work is licensed under the terms of the GNU GPL, version 2.
 *              See the COPYING file in the top-level directory. 
 */
#ifndef OSI_LINUX_H
#define OSI_LINUX_H

// For byte array reversal.
#define PLUGIN_NAME "osi_linux"
#define DEFAULT_KERNELINFO_GROUP "debian-3.2.63-i686"

/**
 * @brief Pointer type of the guest VM.
 *
 * @note This definition implies that the guest VM pointer size matches the
 * size of unsigned long of the target processor. This is a reasonable 
 * assumption to make -- at least in the context of a research prototype.
 */
#define PTR target_ulong

/**
 * @brief Page size used by the kernel. Used to calculate THREADINFO_MASK.
 */
#define PAGE_SIZE 4096

/**
 * @brief Returns the number of pages required to store n bytes.
 */
#define NPAGES(n) ((n) >> 12)

/**
 * @brief Mask to apply on ESP to get the thread_info address.
 *
 * The value should be either ~8191 or ~4095, depending on the
 * size of the stack used by the kernel.
 *
 * @see Understanding the Linux Kernel 3rd ed., pp85.
 * @todo Check if this value can be read from kernelinfo.conf.
 */
#define THREADINFO_MASK (~(PAGE_SIZE + PAGE_SIZE - 1))

/**
 * @brief The offset in the linear address space of a process
 * where the kernel lives.
 */
#define PAGE_OFFSET 0xc0000000

/**
 * @brief Platform specific macro for retrieving ESP.
 */
#if defined(TARGET_I386)
#define _ESP	(env->regs[R_ESP])
#elif defined(TARGET_ARM)
#define _ESP	(env->regs[13])
#else
#error	"_ESP macro not defined for target architecture."
#endif

/**
 * @brief Platform specific macro for retrieving the page directory address.
 */
#if defined(TARGET_I386)
#define _PGD    (env->cr[3])
#elif defined(TARGET_ARM)
#define _PGD    (env->cp15.c2_base0 & env->cp15.c2_base_mask)
#else
#error	"_PGD macro not defined for target architecture."
#endif

/**
 * @brief Platform specific macro for getting the current privillege level.
 */
#if defined(TARGET_I386)
/* check the Current Privillege Level in the flags register */
#define _IN_KERNEL ((env->hflags & HF_CPL_MASK) == 0)
#elif defined(TARGET_ARM)
/* check for supervisor mode in the Current Program Status register */
#define _IN_KERNEL ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC)
#else
#error  "_IN_KERNEL macro not defined for target architecture."
#endif

#define LOG_ERR(fmt, args...) fprintf(stderr, "ERROR(%s:%s): " fmt "\n", __FILE__, __func__, ## args)
#define LOG_INFO(fmt, args...) fprintf(stderr, "INFO(%s:%s): " fmt "\n", __FILE__, __func__, ## args)

extern struct kernelinfo ki;
extern int panda_memory_errors;

/**
 * @brief IMPLEMENT_OFFSET_GET is a macro for generating uniform
 * inlines for retrieving data based on a location+offset.
 */
#define IMPLEMENT_OFFSET_GET(_name, _paramName, _retType, _offset, _errorRetValue)                        \
static inline _retType _name(CPUState* env, PTR _paramName) {                                             \
  _retType _t;                                                                                            \
  if (-1 == panda_virtual_memory_rw(env, _paramName + _offset, (uint8_t *)&_t, sizeof(_retType), 0)) { \
    panda_memory_errors++;                                                                                \
    return (_errorRetValue);                                                                              \
  }                                                                                                       \
  return (_t);                                                                                            \
}

/**
 * @brief IMPLEMENT_OFFSET_GET is a macro for generating uniform
 * inlines for retrieving data based on a *(location+offset1) + offset2.
 */
#define IMPLEMENT_OFFSET_GET2L(_name, _paramName, _retType1, _offset1, _retType2, _offset2, _errorRetValue)   \
static inline _retType2 _name(CPUState* env, PTR _paramName) {                                                \
  _retType1 _t1;                                                                                              \
  _retType2 _t2;                                                                                              \
  if (-1 == panda_virtual_memory_rw(env, _paramName + _offset1, (uint8_t *)&_t1, sizeof(_retType1), 0)) {  \
    panda_memory_errors++;                                                                                    \
    return (_errorRetValue);                                                                                  \
  }                                                                                                           \
  if (-1 == panda_virtual_memory_rw(env, _t1 + _offset2, (uint8_t *)&_t2, sizeof(_retType2), 0)) {         \
    panda_memory_errors++;                                                                                    \
    return (_errorRetValue);                                                                                  \
  }                                                                                                           \
  return (_t2);                                                                                               \
}



/* ******************************************************************
 Offset getters are defined below. Only the getters used by the
 plugin have been defined. See kernelinfo.conf to see what additional
 getters can be added.
****************************************************************** */

/**
 * @brief Retrieves the task_struct address using the thread_info address.
 */
IMPLEMENT_OFFSET_GET(get_task_struct, thread_info_addr, PTR, ki.task.task_offset, 0)

/**
 * @brief Retrieves the thread group address from task_struct.
 * If the thread group address points back to itself, then the task_struct
 * corresponds to a process.
 */
IMPLEMENT_OFFSET_GET(get_thread_group, task_struct, PTR, ki.task.thread_group_offset, 0)

/**
 * @brief Retrieves the tasks address from a task_struct.
 * This is used to iterate the process list.
 */
IMPLEMENT_OFFSET_GET(get_tasks, task_struct, PTR, ki.task.tasks_offset, 0)

/**
 * @brief Retrieves the pid from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_pid, task_struct, int, ki.task.pid_offset, 0)

/**
 * @brief Retrieves the address of the stack from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_stack, task_struct, PTR, ki.task.stack_offset, 0)

/**
 * @brief Retrieves the original parent pid from task_struct.
 */
IMPLEMENT_OFFSET_GET2L(get_real_parent_pid, task_struct, PTR, ki.task.real_parent_offset, int, ki.task.pid_offset, -1)

/**
 * @brief Retrieves the current parent pid (that will receive SIGCHLD, SIGWAIT) from task_struct.
 */
IMPLEMENT_OFFSET_GET2L(get_parent_pid, task_struct, PTR, ki.task.parent_offset, int, ki.task.pid_offset, -1)

/**
 * @brief Retrieves the address of the page directory from a task_struct.
 */
IMPLEMENT_OFFSET_GET2L(get_pgd, task_struct, PTR, ki.task.mm_offset, PTR, ki.mm.pgd_offset, 0)


/**
 * @brief Retrieves the address of the mm_struct from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_mm, task_struct, PTR, ki.task.mm_offset, 0)

/**
 * @brief Retrieves the address of the mm_struct from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_mm_start_brk, mm_struct, PTR, ki.mm.start_brk_offset, 0)

/**
 * @brief Retrieves the address of the mm_struct from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_mm_brk, mm_struct, PTR, ki.mm.brk_offset, 0)

/**
 * @brief Retrieves the address of the mm_struct from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_mm_start_stack, mm_struct, PTR, ki.mm.start_stack_offset, 0)

/**
 * @brief Retrieves the address of the first vm_area_struct of the task.
 */
IMPLEMENT_OFFSET_GET2L(get_vma_first, task_struct, PTR, ki.task.mm_offset, PTR, ki.mm.mmap_offset, 0)

/**
 * @brief Retrieves the address of the following vm_area_struct.
 * This is used to iterate the mmap list.
 */
IMPLEMENT_OFFSET_GET(get_vma_next, vma_struct, PTR, ki.vma.vm_next_offset, 0)

/**
 * @brief Retrieves the of the mm_struct where this vm_area_struct belongs to.
 */
IMPLEMENT_OFFSET_GET(get_vma_vm_mm, vma_struct, PTR, ki.vma.vm_mm_offset, 0)

/**
 * @todo Retrieves the address of the following vm_area_struct.
 */
IMPLEMENT_OFFSET_GET(get_vma_start, vma_struct, target_ulong, ki.vma.vm_start_offset, 0)

/**
 * @todo Retrieves the address of the following vm_area_struct.
 */
IMPLEMENT_OFFSET_GET(get_vma_end, vma_struct, target_ulong, ki.vma.vm_end_offset, 0)

/**
 * @todo Retrieves the address of the following vm_area_struct.
 */
IMPLEMENT_OFFSET_GET(get_vma_flags, vma_struct, target_ulong, ki.vma.vm_flags_offset, 0)

/**
 * @brief Retrieves the address of the mm_struct from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_vma_vm_file, vma_struct, PTR, ki.vma.vm_file_offset, 0)

/**
 * @brief Retrieves the dentry associated with a vma_struct.
 *
 * @note Old DECAF code used different code, depending on whether ki.fs.f_dentry_offset was available.
 * It is assumed here that the offset is always available (can't think why it shouldn't be).
 * From Linux 2.6.20 onwards, f_dentry is a pseudo-member of the file struct.
 *
 * @see https://github.com/torvalds/linux/commit/0f7fc9e4d03987fe29f6dd4aa67e4c56eb7ecb05
 */
IMPLEMENT_OFFSET_GET2L(get_vma_dentry, vma_struct, PTR, ki.vma.vm_file_offset, PTR, ki.fs.f_dentry_offset, 0)

/**
 * @brief Retrieves the vfsmount dentry associated with a vma_struct.
 */
//IMPLEMENT_OFFSET_GET2L(get_vma_vfsmount_dentry, vma_struct, PTR, ki.vma.vm_file_offset, PTR, ki.fs.f_dentry_offset, 0)

// TODO: temp names
//IMPLEMENT_OFFSET_GET2L(get_dentry1, vma_struct, PTR, ki.vma.vm_file_offset, PTR, ki.fs.f_path_offset+0000, 0)

/* ******************************************************************
 Slightly more complex inlines that can't be implemented as simple
 offset getters.
****************************************************************** */

/**
 * @brief Size of the qstr kernel struct. Used to resolve dentry struct to names.
 *
 *  Because the struct is simple with no conditionally defined members,
 *  we choose to not use kernel offsets read from kernelinfo.conf to retrieve it.
 *
 * @code{.c}
 *  struct qstr {
 *    unsigned int hash;
 *    unsigned int len;
 *    const unsigned char *name;
 *  };
 * @endcode
 */
#define _SIZEOF_QSTR (2*sizeof(target_uint) + sizeof(PTR))

/**
 * @brief Retrieves the name of the file associated with a dentry struct.
 *
 * @note The old DECAF code used to check dentry.d_iname. This unecessary complicated
 * the implementation. dentry.d_iname is merely a buffer. When used, dentry.d_name->name
 * will merely point to this buffer instead of a dynamically allocated buffer.
 */
static inline char *read_dentry_name(CPUState *env, PTR dentry, char *name, int recurse) {
  PTR dentry_current;
  uint8_t d_name[_SIZEOF_QSTR];
  int err;

  // current path component
  char *pcomp = NULL;
  target_uint pcomp_length = 0;
  unsigned int pcomp_capacity = 32;

  // all path components read so far
  char **pcomps = NULL;
  unsigned int pcomps_idx = 0;
  unsigned int pcomps_capacity = 16;

  // for reversing pcomps
  char **pcomps_start, **pcomps_end;

  pcomp = (char *)g_malloc(pcomp_capacity * sizeof(char));
  pcomps = (char **)g_malloc(pcomps_capacity * sizeof(char *));
  do {
    dentry_current = dentry;

    // read d_name qstr
    err = panda_virtual_memory_rw(env, dentry_current + ki.fs.d_name_offset, d_name, _SIZEOF_QSTR, 0);
    if (-1 == err) goto error;

    // read component
    pcomp_length = *(target_uint *)(d_name + sizeof(target_uint)) + 1;
    if (pcomp_capacity < pcomp_length) {
      pcomp_capacity = pcomp_length;
      pcomp = (char *)g_realloc(pcomp, pcomp_capacity * sizeof(char));
    }
    err = panda_virtual_memory_rw(env, *(PTR *)(d_name + 2*sizeof(target_uint)), (uint8_t *)pcomp, pcomp_length*sizeof(char), 0);
    if (-1 == err) goto error;

    // copy component
    if (pcomps_idx == pcomps_capacity - 1) { // -1 leaves room for NULL termination
      pcomps_capacity *= 2;
      pcomps = (char **)g_realloc(pcomps, pcomps_capacity * sizeof(char *));
    }
    pcomps[pcomps_idx++] = g_strdup(pcomp);

    // read the parent dentry
    err = panda_virtual_memory_rw(env, dentry_current + ki.fs.d_parent_offset, (uint8_t *)&dentry, sizeof(PTR), 0);
    if (-1 == err) goto error;
  } while (recurse && (dentry != dentry_current));

  // reverse components order
  g_free(pcomp);
  pcomps_start = pcomps;
  pcomps_end = &pcomps[pcomps_idx - 1];
  while (pcomps_start < pcomps_end) {
    pcomp = *pcomps_start;
    *pcomps_start = *pcomps_end;
    *pcomps_end = pcomp;
    pcomps_start++;
    pcomps_end--;
  }

  // join components and return
  g_free(name);
  pcomps[pcomps_idx] = NULL;      // NULL terminate vector
  if (dentry == dentry_current) { // Eliminate root directory.
    pcomps[0][0] = '\0';
  }
  name = g_strjoinv("/", pcomps);
  g_strfreev(pcomps);

  return name;

error:
  LOG_INFO("Error reading d_entry.");
  panda_memory_errors++;

  g_free(name);
  pcomps[pcomps_idx] = NULL;
  g_free(pcomp);
  g_strfreev(pcomps);

  return NULL;
}

/**
 * @brief Retrieves the command name from a task_struct.
 *
 * @note task.comm is a fixed length array.
 * This means that we don't have to account for the terminating '\0'.
 */
static inline char *get_name(CPUState *env, PTR task_struct, char *name) {
  if (name == NULL) { name = (char *)g_malloc0(ki.task.comm_size * sizeof(char)); }
  else { name = (char *)g_realloc(name, ki.task.comm_size * sizeof(char)); }
  if (-1 == panda_virtual_memory_rw(env, task_struct + ki.task.comm_offset, (uint8_t *)name, ki.task.comm_size * sizeof(char), 0)) {
    panda_memory_errors++;
    strncpy(name, "N/A", ki.task.comm_size*sizeof(char));
  }
  return name;
}

/**
 * @brief Retrieves the address of the following task_struct in the process list.
 */
static inline PTR get_task_struct_next(CPUState *env, PTR task_struct) {
  PTR tasks = get_tasks(env, task_struct);

  if (!tasks) return (PTR)NULL;
  else return tasks-ki.task.tasks_offset;
}

#endif
