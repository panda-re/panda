/*!
 * @file kernelinfo_read.c
 * @brief Reads kernel information (struct offsets and such) from key-value config files.
 *
 * @see https://developer.gnome.org/glib/stable/glib-Key-value-file-parser.html
 *
 * @author Manolis Stamatogiannakis <manolis.stamatogiannakis@vu.nl>
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "cpu.h"
#include "kernelinfo.h"	/* must come after cpu.h, glib.h */

#define ERRLOG_OUT stderr
#define ERRLOG(fmt, args...) fprintf(ERRLOG_OUT, "ERROR(%s:%s): " fmt "\n", basename(__FILE__), __func__, ## args)

/*!
 * @brief Convenience wrapper for reading `int` values from keyfile and handling any errors.
 */
#define READ_INFO_INT(mname, errp, errcount) (ki->mname) = g_key_file_get_integer(keyfile, group_real, #mname, &err); \
	if (err != NULL) { errcount++; g_error_free(errp); errp = NULL; ERRLOG("Couldn't read " #mname "."); }

/*!
 * @brief Convenience wrapper for reading unsigned 64bit values from keyfile and handling any errors.
 */
#define READ_INFO_UINT64(mname, errp, errcount) (ki->mname) = g_key_file_get_uint64(keyfile, group_real, #mname, &err); \
	if (err != NULL) { errcount++; g_error_free(errp); errp = NULL; }

/*!
 * @brief Convenience wrapper for reading string values from keyfile and handling any errors.
 */
#define READ_INFO_STRING(mname, errp, errcount) (ki->mname) = g_key_file_get_string(keyfile, group_real, #mname, &err); \
	if (err != NULL) { errcount++; g_error_free(errp); errp = NULL; }

/*! Reads kernel information (struct offsets and such) from the specified file.
 *
 * Each file may contain several contain information for many different kernels
 * in groups. A specific group can be chosen with \p group.
 *
 * \param file The name of the kernel information file. When `NULL` the default #DEFAULT_KERNELINFO_FILE is used.
 * \param group The name of the group to use from the kernel information file. When `NULL`, the first group is used.
 * \param ki A structure used to read the kernel information.
 * \return 0 for success. -1 for failure.
 */
int read_kernelinfo(gchar const *file, gchar const *group, struct kernelinfo *ki) {
	GError *err = NULL;
	GKeyFile *keyfile;
	gchar *group_real = NULL;
	int err_task = 0, err_mm = 0, err_cred = 0, err_vma = 0, err_fs = 0, err_misc = 0;
	uint64 init_addr = 0;

	/* open file */
	memset(ki, '\0', sizeof(struct kernelinfo));
	keyfile = g_key_file_new();
	g_key_file_load_from_file (keyfile, (file != NULL ? file : DEFAULT_KERNELINFO_FILE), G_KEY_FILE_NONE, &err);
	if (err != NULL) goto error;

	/* get group */
	if (group != NULL) group_real = g_strdup(group);
	else group_real = g_key_file_get_start_group(keyfile);
	if (!g_key_file_has_group(keyfile, group_real)) goto error;

	/* read task information */
	READ_INFO_INT(task.task_offset, err, err_fs);
	READ_INFO_INT(task.tasks_offset, err, err_task);
	READ_INFO_INT(task.size, err, err_task);
	//READ_INFO_INT(task.list_offset, err, err_task);
	READ_INFO_INT(task.pid_offset, err, err_task);
	READ_INFO_INT(task.tgid_offset, err, err_task);
	READ_INFO_INT(task.group_leader_offset, err, err_task);
	READ_INFO_INT(task.thread_group_offset, err, err_task);
	READ_INFO_INT(task.real_parent_offset, err, err_task);
	READ_INFO_INT(task.parent_offset, err, err_task);
	READ_INFO_INT(task.mm_offset, err, err_task);
	READ_INFO_INT(task.stack_offset, err, err_task);
	READ_INFO_INT(task.real_cred_offset, err, err_task);
	READ_INFO_INT(task.cred_offset, err, err_task);
	READ_INFO_INT(task.comm_offset, err, err_task);
	READ_INFO_INT(task.comm_size, err, err_task);
	READ_INFO_INT(task.files_offset, err, err_task);

	/* init_task address is always read as uint64 and then cast to (target-specific) target_ulong */
	init_addr = g_key_file_get_uint64(keyfile, group_real, "task.init_addr", &err);
	if (err != NULL) { err_task++; g_error_free(err); err = NULL; ERRLOG("Couldn't read task.init_addr."); }
	else { ki->task.init_addr = (target_ulong)init_addr; }

	/* read cred information */
	READ_INFO_INT(cred.uid_offset, err, err_cred);
	READ_INFO_INT(cred.gid_offset, err, err_cred);
	READ_INFO_INT(cred.euid_offset, err, err_cred);
	READ_INFO_INT(cred.egid_offset, err, err_cred);

	/* read mm information */
	READ_INFO_INT(mm.mmap_offset, err, err_mm);
	READ_INFO_INT(mm.pgd_offset, err, err_mm);
	READ_INFO_INT(mm.arg_start_offset, err, err_mm);
	READ_INFO_INT(mm.start_brk_offset, err, err_mm);
	READ_INFO_INT(mm.brk_offset, err, err_mm);
	READ_INFO_INT(mm.start_stack_offset, err, err_mm);

	/* read vma information */
	READ_INFO_INT(vma.vm_mm_offset, err, err_vma);
	READ_INFO_INT(vma.vm_start_offset, err, err_vma);
	READ_INFO_INT(vma.vm_end_offset, err, err_vma);
	READ_INFO_INT(vma.vm_next_offset, err, err_vma);
	READ_INFO_INT(vma.vm_file_offset, err, err_vma);
	READ_INFO_INT(vma.vm_flags_offset, err, err_vma);

	/* read fs information */
	READ_INFO_INT(fs.f_path_dentry_offset, err, err_fs);
	READ_INFO_INT(fs.f_path_mnt_offset, err, err_fs);
    READ_INFO_INT(fs.f_pos_offset, err, err_fs);
	READ_INFO_INT(fs.mnt_parent_offset, err, err_fs);
	READ_INFO_INT(fs.mnt_mountpoint_offset, err, err_fs);
	READ_INFO_INT(fs.mnt_root_offset, err, err_fs);
	READ_INFO_INT(fs.d_name_offset, err, err_fs);
	READ_INFO_INT(fs.d_iname_offset, err, err_fs);
	READ_INFO_INT(fs.d_parent_offset, err, err_fs);
	READ_INFO_INT(fs.fdt_offset, err, err_fs);
	READ_INFO_INT(fs.fdtab_offset, err, err_fs);
	READ_INFO_INT(fs.fd_offset, err, err_fs);

	/* read kernel full name */
	READ_INFO_STRING(name, err, err_misc);

	/* check the sum of errors */
	if (err_task + err_cred + err_mm + err_vma + err_fs + err_misc == 0) {
		g_key_file_free(keyfile);
		g_free(group_real);
		return 0;
	}

	error:
		g_key_file_free(keyfile);
		g_free(group_real);
		g_free(ki->name);
		return -1;
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
