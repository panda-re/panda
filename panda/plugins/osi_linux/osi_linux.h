/*!
 * @file osi_linux.h
 * @brief Definitions for the implementation of Linux OSI.
 *
 * This header file is not meant to be used by plugins building
 * upon the functionality of Linux OSI.
 * For <a href="https://github.com/panda-re/panda/blob/master/panda/docs/manual.md#plugin-plugin-interaction">Plugin-Plugin</a>
 * interactions, `osi_linux_ext.h` should be used.
 *
 * The offset getter macros have been based off the code from
 * linux_vmi plugin and TEMU's read_linux.
 *
 *
 * @author Manolis Stamatogiannakis <manolis.stamatogiannakis@vu.nl>
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#pragma once
#include "panda/plugin.h"
#include "osi/osi_types.h"
#include "utils/kernelinfo/kernelinfo.h"
#include "osi_linux_debug.h"

extern struct kernelinfo ki;

/**
 * @brief IMPLEMENT_OFFSET_GET is a macro for generating uniform
 * inlines for retrieving data based on a location+offset.
 *
 * @deprecated Directly returning a value complicates error handling
 * and doesn't work for arrays or simple structs.
 * Use IMPLEMENT_OFFSET_GETN instead.
 */
#define IMPLEMENT_OFFSET_GET(_name, _paramName, _retType, _offset, _errorRetValue) \
static inline _retType _name(CPUState* env, target_ptr_t _paramName) { \
	_retType _t; \
	if (-1 == panda_virtual_memory_rw(env, _paramName + _offset, (uint8_t *)&_t, sizeof(_retType), 0)) { \
		return (_errorRetValue); \
	} \
	return (_t); \
}

/**
 * @brief IMPLEMENT_OFFSET_GET2L is a macro for generating uniform
 * inlines for retrieving data based on a *(location+offset1) + offset2.
 *
 * @deprecated Directly returning a value complicates error handling
 * and doesn't work for arrays or simple structs.
 * Use IMPLEMENT_OFFSET_GET2LN instead.
 */
#define IMPLEMENT_OFFSET_GET2L(_name, _paramName, _retType1, _offset1, _retType2, _offset2, _errorRetValue) \
static inline _retType2 _name(CPUState* env, target_ptr_t _paramName) { \
	_retType1 _t1; \
	_retType2 _t2; \
	if (-1 == panda_virtual_memory_rw(env, _paramName + _offset1, (uint8_t *)&_t1, sizeof(_retType1), 0)) { \
		return (_errorRetValue); \
	} \
	if (-1 == panda_virtual_memory_rw(env, _t1 + _offset2, (uint8_t *)&_t2, sizeof(_retType2), 0)) { \
		return (_errorRetValue); \
	} \
	return (_t2); \
}

#define OG_AUTOSIZE 0
#define OG_SUCCESS 0
#define OG_ERROR_MEMORY -1
#define OG_ERROR_DEREF -2
#define OG_printf(...)
//#define OG_printf(...) printf(__VA_ARGS__)

/**
 * @brief IMPLEMENT_OFFSET_GETN is a macro for generating uniform
 * inlines for retrieving data based on a location+offset.
 * It provides better error handling than IMPLEMENT_OFFSET_GET and is not
 * limited to retrieving only primitive types.
 */
#define IMPLEMENT_OFFSET_GETN(_funcName, _paramName, _retType, _retName, _retSize, _offset) \
static inline int _funcName(CPUState* env, target_ptr_t _paramName, _retType* _retName) { \
	size_t ret_size = ((_retSize) == OG_AUTOSIZE) ? sizeof(_retType) : (_retSize); \
	OG_printf(#_funcName ":1:" TARGET_PTR_FMT ":%d\n", _paramName, _offset); \
	OG_printf(#_funcName ":2:" TARGET_PTR_FMT ":%zu\n", _paramName + _offset, ret_size); \
	if (-1 == panda_virtual_memory_rw(env, _paramName + _offset, (uint8_t *)_retName, ret_size, 0)) { \
		return OG_ERROR_MEMORY; \
	} \
	OG_printf(#_funcName ":3:ok\n"); \
	return OG_SUCCESS; \
}

/**
 * @brief IMPLEMENT_OFFSET_GET2LN is an improved macro for generating uniform
 * inlines for retrieving data based on a *(location+offset1) + offset2.
 * It provides better error handling than IMPLEMENT_OFFSET_GET2L and is not
 * limited to retrieving only primitive types.
 */
#define IMPLEMENT_OFFSET_GET2LN(_funcName, _paramName, _retType, _retName, _retSize, _offset1, _offset2) \
static inline int _funcName(CPUState* env, target_ptr_t _paramName, _retType* _retName) { \
	target_ptr_t _p1; \
	size_t ret_size = ((_retSize) == OG_AUTOSIZE) ? sizeof(_retType) : (_retSize); \
	OG_printf(#_funcName ":1:" TARGET_PTR_FMT ":%d\n", _paramName, _offset1); \
	OG_printf(#_funcName ":2:" TARGET_PTR_FMT ":%zu\n", _paramName + _offset1, sizeof(target_ptr_t)); \
	if (-1 == panda_virtual_memory_rw(env, _paramName + _offset1, (uint8_t *)&_p1, sizeof(target_ptr_t), 0)) { \
		return OG_ERROR_MEMORY; \
	} \
	OG_printf(#_funcName ":3:" TARGET_PTR_FMT ":%d\n", _p1, _offset2); \
	if (_p1 == (target_ptr_t)NULL) { \
		return OG_ERROR_DEREF; \
	} \
	OG_printf(#_funcName ":4:" TARGET_PTR_FMT ":%zu\n", _p1 + _offset2, ret_size); \
	if (-1 == panda_virtual_memory_rw(env, _p1 + _offset2, (uint8_t *)_retName, ret_size, 0)) { \
		return OG_ERROR_MEMORY; \
	} \
	OG_printf(#_funcName ":5:ok\n"); \
	return OG_SUCCESS; \
}



/* ******************************************************************
 Offset getters are defined below. Only the getters used by the
 plugin have been defined. See kernelinfo.conf to see what additional
 getters can be added.
****************************************************************** */

/**
 * @brief Retrieves the thread group address from task_struct.
 * If the thread group address points back to itself, then the task_struct
 * corresponds to a process.
 */
IMPLEMENT_OFFSET_GET(get_thread_group, task_struct, target_ptr_t, ki.task.thread_group_offset, 0)

/**
 * @brief Retrieves the tasks address from a task_struct.
 * This is used to iterate the process list.
 */
IMPLEMENT_OFFSET_GET(get_tasks, task_struct, target_ptr_t, ki.task.tasks_offset, 0)

/**
 * @brief Retrieves the pid from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_pid, task_struct, int, ki.task.pid_offset, 0)

/**
 * @brief Retrieves the tgid from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_tgid, task_struct, int, ki.task.tgid_offset, 0)

/**
 * @brief Retrieves the address of the stack from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_stack, task_struct, target_ptr_t, ki.task.stack_offset, 0)

/**
 * @brief Retrieves the original parent pid from task_struct.
 */
IMPLEMENT_OFFSET_GET2L(get_real_parent_pid, task_struct, target_ptr_t, ki.task.real_parent_offset, int, ki.task.pid_offset, -1)

/**
 * @brief Retrieves the current parent pid (that will receive SIGCHLD, SIGWAIT) from task_struct.
 */
IMPLEMENT_OFFSET_GET2L(get_parent_pid, task_struct, target_ptr_t, ki.task.parent_offset, int, ki.task.pid_offset, -1)

/**
 * @brief Retrieves the address of the page directory from a task_struct.
 */
IMPLEMENT_OFFSET_GET2L(get_pgd, task_struct, target_ptr_t, ki.task.mm_offset, target_ptr_t, ki.mm.pgd_offset, 0)

/**
 * @brief Retrieves the address of the mm_struct from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_mm, task_struct, target_ptr_t, ki.task.mm_offset, 0)

/**
 * @brief Retrieves the address of the mm_struct from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_mm_start_brk, mm_struct, target_ptr_t, ki.mm.start_brk_offset, 0)

/**
 * @brief Retrieves the address of the mm_struct from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_mm_brk, mm_struct, target_ptr_t, ki.mm.brk_offset, 0)

/**
 * @brief Retrieves the address of the mm_struct from a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_mm_start_stack, mm_struct, target_ptr_t, ki.mm.start_stack_offset, 0)

/**
 * @brief Retrieves the address of the first vm_area_struct of the task.
 */
IMPLEMENT_OFFSET_GET2L(get_vma_first, task_struct, target_ptr_t, ki.task.mm_offset, target_ptr_t, ki.mm.mmap_offset, 0)

/**
 * @brief Retrieves the address of the following vm_area_struct.
 * This is used to iterate the mmap list.
 */
IMPLEMENT_OFFSET_GET(get_vma_next, vma_struct, target_ptr_t, ki.vma.vm_next_offset, 0)

/**
 * @brief Retrieves the of the mm_struct where this vm_area_struct belongs to.
 */
IMPLEMENT_OFFSET_GET(get_vma_vm_mm, vma_struct, target_ptr_t, ki.vma.vm_mm_offset, 0)

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
IMPLEMENT_OFFSET_GET(get_vma_vm_file, vma_struct, target_ptr_t, ki.vma.vm_file_offset, 0)

/**
 * @brief Retrieves the dentry associated with a vma_struct.
 *
 * XXX: Convert uses of this to the single level getter of f_path_dentry_offset.
 * Operating on file structs vs vma structs, will help to share code between
 * mm resolution and fd resolution.
 */
IMPLEMENT_OFFSET_GET2L(get_vma_dentry, vma_struct, target_ptr_t, ki.vma.vm_file_offset, target_ptr_t, ki.fs.f_path_dentry_offset, 0)

/**
 * @brief Retrieves the vfsmount dentry associated with a vma_struct.
 *
 * XXX: Reading the vfsmount dentry is required to get the full pathname of files not located in the root fs.
 * This hasn't been implemented yet...
 */
IMPLEMENT_OFFSET_GET2L(get_vma_vfsmount_dentry, vma_struct, target_ptr_t, ki.vma.vm_file_offset, target_ptr_t, ki.fs.f_path_dentry_offset, 0)

/**
 * @brief Retrieves the address of the files struct associated with a task_struct.
 */
IMPLEMENT_OFFSET_GET(get_files, task_struct, target_ptr_t, ki.task.files_offset, 0)

/**
 * @brief Retrieves the dentry struct associated with a file struct.
 */
IMPLEMENT_OFFSET_GET(get_file_dentry, file_struct, target_ptr_t, ki.fs.f_path_dentry_offset, 0)

/**
 * @brief Retrieves the vfsmount struct associated with a file struct.
 */
IMPLEMENT_OFFSET_GET(get_file_mnt, file_struct, target_ptr_t, ki.fs.f_path_mnt_offset, 0)

IMPLEMENT_OFFSET_GET(get_file_pos, file_struct, target_ptr_t, ki.fs.f_pos_offset, 0)

/**
 * @brief Retrieves the mnt_parent vfsmount struct associated with a vfsmount struct.
 */
IMPLEMENT_OFFSET_GETN(get_vfsmount_parent, vfsmount, target_ptr_t, vfsmount_parent, OG_AUTOSIZE, ki.path.mnt_parent_offset)

/**
 * @brief Retrieves the dentry struct associated with a vfsmount struct.
 */
IMPLEMENT_OFFSET_GETN(get_vfsmount_dentry, vfsmount, target_ptr_t, vfsmount_dentry, OG_AUTOSIZE, ki.path.mnt_mountpoint_offset)

/**
 * @brief Retrieves the mnt_root dentry struct associated with a vfsmount struct.
 */
IMPLEMENT_OFFSET_GETN(get_vfsmount_root_dentry, vfsmount, target_ptr_t, root_dentry, OG_AUTOSIZE, ki.path.mnt_root_offset)

/**
 * @brief Retrieves the qstr for a dentry.
 */
IMPLEMENT_OFFSET_GETN(get_dentry_name, dentry, uint8_t, dname_qstr, ki.qstr.size*sizeof(uint8_t), ki.path.d_name_offset)

/**
 * @brief Retrieves the dynamic name function for a dentry.
 */
IMPLEMENT_OFFSET_GET2LN(get_dentry_dname, dentry, target_ptr_t, dname_funcp, OG_AUTOSIZE, ki.path.d_op_offset, ki.path.d_dname_offset)

/**
 * @brief Retrieves the parent of a dentry.
 */
IMPLEMENT_OFFSET_GETN(get_dentry_parent, dentry, target_ptr_t, dentry_parent, OG_AUTOSIZE, ki.path.d_parent_offset)

/* ******************************************************************
 Slightly more complex inlines that can't be implemented as simple
 offset getters.
****************************************************************** */
/**
 * @brief Retrieves the n-th file struct from an fd file array. (pp 479)
 */
static inline target_ptr_t get_fd_file(CPUState *env, target_ptr_t fd_file_array, int n) {
	target_ptr_t fd_file, fd_file_ptr;

	// Compute address of the pointer to the file struct of the n-th fd.
	fd_file_ptr = fd_file_array+n*sizeof(target_ptr_t);

	// Read address of the file struct.
	if (-1 == panda_virtual_memory_rw(env, fd_file_ptr, (uint8_t *)&fd_file, sizeof(target_ptr_t), 0)) {
		return (target_ptr_t)NULL;
	}

	return fd_file_ptr;
}

/**
 * @brief Retrieves the name of the file associated with a dentry struct.
 *
 * The function traverses all the path components it meets until it
 * reaches a mount point. 
 *
 * @note We can always use dentry.d_name->name and ignore dentry.d_iname.
 * When the latter is used, the former will be set to point to it.
 */
static inline char *read_dentry_name(CPUState *env, target_ptr_t dentry) {
	char *name = NULL;

	// current path component
	char *pcomp = NULL;
	uint32_t pcomp_length = 0;
	uint32_t pcomp_capacity = 0;

	// all path components read so far
	char **pcomps = NULL;
	uint32_t pcomps_idx = 0;
	uint32_t pcomps_capacity = 0;

	// for reversing pcomps
	char **pcomps_start, **pcomps_end;

	target_ptr_t current_dentry_parent = dentry;
	target_ptr_t current_dentry = (target_ptr_t)NULL;
	uint8_t *d_name = (uint8_t *)g_malloc(ki.qstr.size * sizeof(uint8_t));
	while (current_dentry_parent != current_dentry) {
		int og_err1, og_err2;
		current_dentry = current_dentry_parent;
		//printf("1#%lx\n", (uintptr_t)(current_dentry + ki.path.d_name_offset));

		// read dentry d_parent and d_name
		memset(d_name, 0, ki.qstr.size * sizeof(uint8_t));
		og_err1 = get_dentry_name(env, current_dentry, d_name);
		og_err2 = get_dentry_parent(env, current_dentry, &current_dentry_parent);
		//HEXDUMP(d_name, ki.path.qstr_size, current_dentry + ki.path.d_name_offset);
		if (OG_SUCCESS != og_err1 || OG_SUCCESS != og_err2) {
			break;
		}

		// read d_dname function pointer - indicates a dynamic name
		target_ptr_t d_dname;
		og_err1 = get_dentry_dname(env, current_dentry, &d_dname);
		if (OG_SUCCESS != og_err1) {
			// static name
			d_dname = (target_ptr_t)NULL;
		}

		// read component
		pcomp_length = *(uint32_t *)(d_name + sizeof(uint32_t)) + 1; // increment pcomp_length to include the string terminator
		if (pcomp_capacity < pcomp_length) {
			pcomp_capacity = pcomp_length + 16;
			pcomp = (char *)g_realloc(pcomp, pcomp_capacity * sizeof(char));
		}
		og_err1 = panda_virtual_memory_rw(env, *(target_ptr_t *)(d_name + ki.qstr.name_offset), (uint8_t *)pcomp, pcomp_length*sizeof(char), 0);
		//printf("2#%lx\n", (uintptr_t)*(target_ptr_t *)(d_name + 2*sizeof(uint32_t)));
		//printf("3#%s\n", pcomp);
		if (-1 == og_err1) {
			break;
		}

		// use the empty string for "/" components (mountpoints?)
		if (pcomp[0] == '/' && pcomp[1] == '\0') {
			pcomp[0] = '\0';
		}

		// copy component
		if (pcomps_idx + 1 >= pcomps_capacity) { // +1 accounts for the terminating NULL
			pcomps_capacity += 16;
			pcomps = (char **)g_realloc(pcomps, pcomps_capacity * sizeof(char *));
		}
		if (d_dname == (target_ptr_t)NULL) {
			// static name
			pcomps[pcomps_idx++] = g_strdup(pcomp);
		}
		else {
			// XXX: full reconstruction of dynamic names in not currently supported
			pcomps[pcomps_idx++] = g_strdup(pcomp);
		}
	}

	// reverse components order and join them
	g_free(d_name);
	g_free(pcomp);
	if (pcomps != NULL) {
		pcomps_start = pcomps;
		pcomps_end = &pcomps[pcomps_idx - 1];
		while (pcomps_start < pcomps_end) {
			pcomp = *pcomps_start;
			*pcomps_start = *pcomps_end;
			*pcomps_end = pcomp;
			pcomps_start++;
			pcomps_end--;
		}
		pcomps[pcomps_idx] = NULL; // NULL terminate vector
		name = g_strjoinv("/", pcomps);
		g_strfreev(pcomps);
	}

#if defined(OSI_LINUX_FDNDEBUG)
	if (name == NULL) {
		LOG_WARN("Error reading d_entry.");
	}
#endif
	return name;
}

/**
 * @brief Retrieves the name of the file associated with a dentry struct.
 *
 * The function traverses all the mount points to the root mount.
 */
static inline char *read_vfsmount_name(CPUState *env, target_ptr_t vfsmount) {
	char *name = NULL;

	// current path component
	char *pcomp = NULL;

	// all path components read so far
	char **pcomps = NULL;
	uint32_t pcomps_idx = 0;
	uint32_t pcomps_capacity = 0;

	target_ptr_t current_vfsmount_parent = vfsmount;
	target_ptr_t current_vfsmount = (target_ptr_t)NULL;
	while(current_vfsmount != current_vfsmount_parent) {
		int og_err0, og_err1;
		target_ptr_t current_vfsmount_dentry;
		//int og_err2;
		//target_ptr_t root_dentry;
		current_vfsmount = current_vfsmount_parent;

		// retrieve vfsmount members
		og_err0 = get_vfsmount_dentry(env, current_vfsmount, &current_vfsmount_dentry);
		og_err1 = get_vfsmount_parent(env, current_vfsmount, &current_vfsmount_parent);
		//printf("###D:%d:" TARGET_PTR_FMT ":" TARGET_PTR_FMT "\n", og_err0, current_vfsmount, current_vfsmount_dentry);
		//printf("###R:%d:" TARGET_PTR_FMT ":" TARGET_PTR_FMT "\n", og_err2, current_vfsmount, root_dentry);
		//og_err2 = get_vfsmount_root_dentry(env, current_vfsmount, &root_dentry);
		//printf("###P:%d:" TARGET_PTR_FMT ":" TARGET_PTR_FMT "\n", og_err1, current_vfsmount, current_vfsmount_parent);

		// check whether we should break out
		if (OG_SUCCESS != og_err0 || OG_SUCCESS != og_err1) {
			break;
		}
		if (current_vfsmount_dentry == (target_ptr_t)NULL) {
			break;
		}

		// read and copy component
		pcomp = read_dentry_name(env, current_vfsmount_dentry);
		//printf("###S:%s\n", pcomp);

		// this may hapen it seems
		if (pcomp == NULL) {
			continue;
		}

		if (pcomps_idx + 1 >= pcomps_capacity) { // +1 accounts for the terminating NULL
			pcomps_capacity += 16;
			pcomps = (char **)g_realloc(pcomps, pcomps_capacity * sizeof(char *));
		}
		pcomps[pcomps_idx++] = pcomp;
	}

	// reverse components order and join them
	if (pcomps != NULL) {
		char **pcomps_start = pcomps;
		char **pcomps_end = &pcomps[pcomps_idx - 1];
		while (pcomps_start < pcomps_end) {
			pcomp = *pcomps_start;
			*pcomps_start = *pcomps_end;
			*pcomps_end = pcomp;
			pcomps_start++;
			pcomps_end--;
		}
		pcomps[pcomps_idx] = NULL;			// NULL terminate vector
		name = g_strjoinv("", pcomps);		// slashes are included in pcomps
		g_strfreev(pcomps);
	}

	//printf("###F:%s\n", name);
	return name;
}

/**
 * @brief Retrieves the command name from a task_struct.
 *
 * @note task.comm is a fixed length array.
 * This means that we don't have to account for the terminating '\0'.
 */
static inline char *get_name(CPUState *env, target_ptr_t task_struct, char *name) {
	if (name == NULL) { name = (char *)g_malloc0(ki.task.comm_size * sizeof(char)); }
	else { name = (char *)g_realloc(name, ki.task.comm_size * sizeof(char)); }
	if (-1 == panda_virtual_memory_rw(env, task_struct + ki.task.comm_offset, (uint8_t *)name, ki.task.comm_size * sizeof(char), 0)) {
		strncpy(name, "N/A", ki.task.comm_size*sizeof(char));
	}
	return name;
}

void fill_osiproc(CPUState *env, OsiProc *p, target_ptr_t task_addr);
void fill_osithread(CPUState *env, OsiThread *t, target_ptr_t task_addr);

/* vim:set tabstop=4 softtabstop=4 noexpandtab: */
