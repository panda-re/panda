static int __init goldfish_audio_init(void)
{
  int ret;

  struct vm_area_struct vma;
  struct file filestruct;
  struct dentry dentrystr;
  struct cred credstruct;
  struct thread_info ti;

  printk(KERN_INFO
      "    {  \"%s\", /* entry name */\n"
      "       0x%08lX, /* task struct root */\n"
      "       %d, /* size of task_struct */\n"
      "       %d, /* offset of task_struct list */\n"
      "       %d, /* offset of pid */\n"
      "       %d, /* offset of tgid */\n"
      "       %d, /* offset of group_leader */\n"
      "       %d, /* offset of thread_group */\n"
      "       %d, /* offset of real_parent */\n"
      "       %d, /* offset of mm */\n"
      "       %d, /* offset of stack */\n"
      "       %d, /* offset of real_cred */\n"
      "       %d, /* offset of cred */\n"
      "       %d, /* offset of uid cred */\n"
      "       %d, /* offset of gid cred */\n"
      "       %d, /* offset of euid cred */\n"
      "       %d, /* offset of egid cred */\n"
      "       %d, /* offset of pgd in mm */\n"
      "       %d, /* offset of arg_start in mm */\n"
      "       %d, /* offset of start_brk in mm */\n"
      "       %d, /* offset of brk in mm */\n"
      "       %d, /* offset of start_stack in mm */\n",

      "Android-x86 Gingerbread",
      (long)&init_task,
      sizeof(init_task),
      (int)&init_task.tasks - (int)&init_task,
      (int)&init_task.pid - (int)&init_task,
      (int)&init_task.tgid - (int)&init_task,
      (int)&init_task.group_leader - (int)&init_task,
      (int)&init_task.thread_group - (int)&init_task,
      (int)&init_task.real_parent - (int)&init_task,
      (int)&init_task.mm - (int)&init_task,
      (int)&init_task.stack - (int)&init_task,
      (int)&init_task.real_cred - (int)&init_task,
      (int)&init_task.cred - (int)&init_task,
      (int)&credstruct.uid - (int)&credstruct,
      (int)&credstruct.gid - (int)&credstruct,
      (int)&credstruct.euid - (int)&credstruct,
      (int)&credstruct.egid - (int)&credstruct,
      (int)&init_task.mm->pgd - (int)init_task.mm,
      (int)&init_task.mm->arg_start - (int)init_task.mm,
      (int)&init_task.mm->start_brk - (int)init_task.mm,
      (int)&init_task.mm->brk - (int)init_task.mm,
      (int)&init_task.mm->start_stack - (int)init_task.mm
  );

  printk(KERN_INFO
      "       %d, /* offset of comm */\n"
      "       %d, /* size of comm */\n"
      "       %d, /* offset of vm_start in vma */\n"
      "       %d, /* offset of vm_end in vma */\n"
      "       %d, /* offset of vm_next in vma */\n"
      "       %d, /* offset of vm_file in vma */\n"
      "       %d, /* offset of vm_flags in vma */\n"
      "       %d, /* offset of dentry in file */\n"
      "       %d, /* offset of d_name in dentry */\n"
      "       %d, /* offset of d_iname in dentry */\n"
      "       %d, /* offset of d_parent in dentry */\n"
      "       %d, /* offset of task in thread_info */\n"
      "    },\n",

      (int)&init_task.comm - (int)&init_task,
      sizeof(init_task.comm),
      (int)&vma.vm_start - (int)&vma,
      (int)&vma.vm_end - (int)&vma,
      (int)&vma.vm_next - (int)&vma,
      (int)&vma.vm_file - (int)&vma,
      (int)&vma.vm_flags - (int)&vma,
      (int)&filestruct.f_dentry - (int)&filestruct,
      (int)&dentrystr.d_name - (int)&dentrystr,
      (int)&dentrystr.d_iname - (int)&dentrystr,
      (int)&dentrystr.d_parent - (int)&dentrystr,
      (int)&ti.task - (int)&ti
    );


  ret = platform_driver_register(&goldfish_audio_driver);
  if (ret < 0)
  {
    printk("platform_driver_register returned %d\n", ret);
    return ret;
  }

  return ret;
}
