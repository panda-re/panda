#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/utsname.h>

typedef unsigned long uintptr_t;

#define MAX_MEMBER_NAME 31
static char *cp_memb(const char *s)
{
	static char memb[MAX_MEMBER_NAME+1];
	int i;
	for (i = 0; i < MAX_MEMBER_NAME && s[i] != '\0'; i++) {
		memb[i] = s[i] == '.' ? '_' : s[i];
	}
	memb[i] = 0;
	return memb;
}

#define PRINT_OFFSET(structp, memb, cfgname) \
	printk(KERN_INFO cfgname ".%s_offset = %d\n",\
			cp_memb(#memb),\
			(int)((void *)&(structp->memb) - (void *)structp))

#define PRINT_SIZE(structv, cfgmemb, cfgname) printk(KERN_INFO cfgname "." cfgmemb " = %lu\n", (unsigned long)(sizeof(structv)))

static int __init kernelinfo24_init(void)
{
	struct file file__s;
	struct files_struct files_struct__s;
	struct dentry dentry__s;
	struct vfsmount vfsmount__s;
	struct qstr qstr__s;

	struct task_struct *task_struct__p;
	struct file *file__p;
	struct files_struct *files_struct__p;
	struct dentry *dentry__p;
	struct vfsmount *vfsmount__p;
	struct qstr *qstr__p;

	task_struct__p = &init_task;
	file__p = &file__s;
	files_struct__p = &files_struct__s;
	dentry__p = &dentry__s;
	vfsmount__p = &vfsmount__s;
	qstr__p = &qstr__s;

	printk(KERN_INFO "---KERNELINFO-BEGIN---\n");
	printk(KERN_INFO "name = %s|%s|%s\n", system_utsname.release,
			system_utsname.version, system_utsname.machine);
	printk(KERN_INFO "version.a = %d\n", LINUX_VERSION_CODE >> 16);
	printk(KERN_INFO "version.b = %d\n", (LINUX_VERSION_CODE >> 8) & 0xFF);
	printk(KERN_INFO "version.c = %d\n", LINUX_VERSION_CODE & 0xFF);

	printk(KERN_INFO "task.init_addr = %llu\n", (u64)(uintptr_t)(task_struct__p));
	printk(KERN_INFO "#task.init_addr = 0x%08llX\n",
			(u64)(uintptr_t)(task_struct__p));

	PRINT_SIZE(init_task, "size", "task");
	PRINT_OFFSET(task_struct__p, pid, "task");
	PRINT_OFFSET(task_struct__p, tgid, "task");
	PRINT_OFFSET(task_struct__p, comm, "task");
	PRINT_SIZE(task_struct__p->comm, "comm_size", "task");
	PRINT_OFFSET(task_struct__p, files, "task");

	PRINT_OFFSET(file__p, f_dentry, "fs");
	PRINT_OFFSET(file__p, f_vfsmnt, "fs");
	PRINT_OFFSET(file__p, f_pos, "fs");
	PRINT_OFFSET(files_struct__p, fd, "fs");

	PRINT_SIZE(dentry__s.d_name, "qstr_size", "path");
	// need to add qstr name offset
	PRINT_OFFSET(dentry__p, d_name, "path");
	PRINT_OFFSET(dentry__p, d_iname, "path");
	PRINT_OFFSET(dentry__p, d_parent, "path");
	PRINT_OFFSET(dentry__p, d_op, "path");
	PRINT_OFFSET(dentry__p, d_name, "path");
	PRINT_OFFSET(vfsmount__p, mnt_root, "path");
	PRINT_OFFSET(vfsmount__p, mnt_parent, "path");
	PRINT_OFFSET(vfsmount__p, mnt_mountpoint, "path");

	printk(KERN_INFO "---KERNELINFO-END---\n");

	return -1;
}

static void __exit kernelinfo24_exit(void)
{
}

module_init(kernelinfo24_init);
module_exit(kernelinfo24_exit);

/* vim:set tabstop=4 softtabstop=4 noexpandtab: */
