#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#define INT_FMT     "       %d, "
#define SIZET_FMT    "       %zu, "

int init_module(void)
{
    struct vm_area_struct vma;
    struct file filestruct;
    struct dentry dentrystr;
    struct cred credstruct;
    struct thread_info ti;

    printk(KERN_INFO "\n"
        "    {  \"%s %s\", /* entry name */\n"
/* 0*/  "       0x%08lX, /* task struct root */\n"
        SIZET_FMT "/* size of task_struct */\n"
        INT_FMT "/* offset of task_struct list */\n"
        INT_FMT "/* offset of pid */\n"
        INT_FMT "/* offset of tgid */\n"
/* 5*/  INT_FMT "/* offset of group_leader */\n"
        INT_FMT "/* offset of thread_group */\n"
        INT_FMT "/* offset of real_parent */\n"
        INT_FMT "/* offset of mm */\n"
        INT_FMT "/* offset of stack */\n"
/*10*/  INT_FMT "/* offset of real_cred */\n"
        INT_FMT "/* offset of cred */\n"
        INT_FMT "/* offset of uid cred */\n"
        INT_FMT "/* offset of gid cred */\n"
        INT_FMT "/* offset of euid cred */\n"
/*15*/  INT_FMT "/* offset of egid cred */\n"
        INT_FMT "/* offset of pgd in mm */\n"
        INT_FMT "/* offset of arg_start in mm */\n"
        INT_FMT "/* offset of start_brk in mm */\n"
        INT_FMT "/* offset of brk in mm */\n"
/*20*/  INT_FMT "/* offset of start_stack in mm */\n",

        utsname()->version, utsname()->machine,
/* 0*/  (long)&init_task,
        sizeof(init_task),
        (int)((void *)&init_task.tasks - (void *)&init_task),
        (int)((void *)&init_task.pid - (void *)&init_task),
        (int)((void *)&init_task.tgid - (void *)&init_task),
/* 5*/  (int)((void *)&init_task.group_leader - (void *)&init_task),
        (int)((void *)&init_task.thread_group - (void *)&init_task),
        (int)((void *)&init_task.real_parent - (void *)&init_task),
        (int)((void *)&init_task.mm - (void *)&init_task),
        (int)((void *)&init_task.stack - (void *)&init_task),
/*10*/  (int)((void *)&init_task.real_cred - (void *)&init_task),
        (int)((void *)&init_task.cred - (void *)&init_task),
        (int)((void *)&credstruct.uid - (void *)&credstruct),
        (int)((void *)&credstruct.gid - (void *)&credstruct),
        (int)((void *)&credstruct.euid - (void *)&credstruct),
/*15*/  (int)((void *)&credstruct.egid - (void *)&credstruct),
        (int)((void *)&init_task.mm->pgd - (void *)init_task.mm),
        (int)((void *)&init_task.mm->arg_start - (void *)init_task.mm),
        (int)((void *)&init_task.mm->start_brk - (void *)init_task.mm),
        (int)((void *)&init_task.mm->brk - (void *)init_task.mm),
/*20*/  (int)((void *)&init_task.mm->start_stack - (void *)init_task.mm)
    );

    /* Break printing in two parts (printk buffer is limited). */
    printk(KERN_INFO "\n"
        INT_FMT "/* offset of comm */\n"
        SIZET_FMT "/* size of comm */\n"
        INT_FMT "/* offset of vm_start in vma */\n"
        INT_FMT "/* offset of vm_end in vma */\n"
/*25*/  INT_FMT "/* offset of vm_next in vma */\n"
        INT_FMT "/* offset of vm_file in vma */\n"
        INT_FMT "/* offset of vm_flags in vma */\n"
        INT_FMT "/* offset of dentry in file */\n"
        INT_FMT "/* offset of d_name in dentry */\n"
/*30*/  INT_FMT "/* offset of d_iname in dentry */\n"
        INT_FMT "/* offset of d_parent in dentry */\n"
        INT_FMT "/* offset of task in thread_info */\n"
        "    },\n",

       (int)((void *)&init_task.comm - (void *)&init_task),
       sizeof(init_task.comm),
       (int)((void *)&vma.vm_start - (void *)&vma),
       (int)((void *)&vma.vm_end - (void *)&vma),
/*25*/ (int)((void *)&vma.vm_next - (void *)&vma),
       (int)((void *)&vma.vm_file - (void *)&vma),
       (int)((void *)&vma.vm_flags - (void *)&vma),
       (int)((void *)&filestruct.f_dentry - (void *)&filestruct),
       (int)((void *)&dentrystr.d_name - (void *)&dentrystr),
/*30*/ (int)((void *)&dentrystr.d_iname - (void *)&dentrystr),
       (int)((void *)&dentrystr.d_parent - (void *)&dentrystr),
       (int)((void *)&ti.task - (void *)&ti)
    );
    printk(KERN_INFO "Information module registered.\n");

    /* Return a failure. We only want to print the info. */
    return -1;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Information module removed.\n");
}

MODULE_LICENSE("GPL");

