switch( env->regs[7] ){

// 0 long sys_restart_syscall ['void']
case 0 :
record_syscall("sys_restart_syscall");
finish_syscall();
break;
// 1 long sys_exit ['int error_code']
case 1 :
record_syscall("sys_exit");
log_32(env->regs[0], "int error_code");
finish_syscall();
break;
// 2 unsigned long fork ['void']
case 2 :
record_syscall("fork");
finish_syscall();
break;
// 3 long sys_read ['unsigned int fd', ' char __user *buf', ' size_t count']
case 3 :
record_syscall("sys_read");
log_32(env->regs[0], "unsigned int fd");
log_pointer(env->regs[1], " char __user *buf");
log_32(env->regs[2], " size_t count");
finish_syscall();
break;
// 4 long sys_write ['unsigned int fd', ' const char __user *buf', 'size_t count']
case 4 :
record_syscall("sys_write");
log_32(env->regs[0], "unsigned int fd");
log_pointer(env->regs[1], " const char __user *buf");
log_32(env->regs[2], "size_t count");
finish_syscall();
break;
// 5 long sys_open ['const char __user *filename', 'int flags', ' int mode']
case 5 :
record_syscall("sys_open");
log_string(env->regs[0], "const char __user *filename");
log_32(env->regs[1], "int flags");
log_32(env->regs[2], " int mode");
finish_syscall();
break;
// 6 long sys_close ['unsigned int fd']
case 6 :
record_syscall("sys_close");
log_32(env->regs[0], "unsigned int fd");
finish_syscall();
break;
// 8 long sys_creat ['const char __user *pathname', ' int mode']
case 8 :
record_syscall("sys_creat");
log_string(env->regs[0], "const char __user *pathname");
log_32(env->regs[1], " int mode");
finish_syscall();
break;
// 9 long sys_link ['const char __user *oldname', 'const char __user *newname']
case 9 :
record_syscall("sys_link");
log_string(env->regs[0], "const char __user *oldname");
log_string(env->regs[1], "const char __user *newname");
finish_syscall();
break;
// 10 long sys_unlink ['const char __user *pathname']
case 10 :
record_syscall("sys_unlink");
log_string(env->regs[0], "const char __user *pathname");
finish_syscall();
break;
// 11 unsigned long execve ['const char *filename', ' char *const argv[]', ' char *const envp[]']
case 11 :
record_syscall("execve");
log_string(env->regs[0], "const char *filename");
log_pointer(env->regs[1], " char *const argv[]");
log_pointer(env->regs[2], " char *const envp[]");
finish_syscall();
break;
// 12 long sys_chdir ['const char __user *filename']
case 12 :
record_syscall("sys_chdir");
log_string(env->regs[0], "const char __user *filename");
finish_syscall();
break;
// 14 long sys_mknod ['const char __user *filename', ' int mode', 'unsigned dev']
case 14 :
record_syscall("sys_mknod");
log_string(env->regs[0], "const char __user *filename");
log_32(env->regs[1], " int mode");
log_32(env->regs[2], "unsigned dev");
finish_syscall();
break;
// 15 long sys_chmod ['const char __user *filename', ' mode_t mode']
case 15 :
record_syscall("sys_chmod");
log_string(env->regs[0], "const char __user *filename");
log_32(env->regs[1], " mode_t mode");
finish_syscall();
break;
// 16 long sys_lchown16 ['const char __user *filename', 'old_uid_t user', ' old_gid_t group']
case 16 :
record_syscall("sys_lchown16");
log_string(env->regs[0], "const char __user *filename");
log_32(env->regs[1], "old_uid_t user");
log_32(env->regs[2], " old_gid_t group");
finish_syscall();
break;
// 19 long sys_lseek ['unsigned int fd', ' off_t offset', 'unsigned int origin']
case 19 :
record_syscall("sys_lseek");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], " off_t offset");
log_32(env->regs[2], "unsigned int origin");
finish_syscall();
break;
// 20 long sys_getpid ['void']
case 20 :
record_syscall("sys_getpid");
finish_syscall();
break;
// 21 long sys_mount ['char __user *dev_name', ' char __user *dir_name', 'char __user *type', ' unsigned long flags', 'void __user *data']
case 21 :
record_syscall("sys_mount");
log_string(env->regs[0], "char __user *dev_name");
log_string(env->regs[1], " char __user *dir_name");
log_string(env->regs[2], "char __user *type");
log_32(env->regs[3], " unsigned long flags");
log_pointer(env->regs[4], "void __user *data");
finish_syscall();
break;
// 23 long sys_setuid16 ['old_uid_t uid']
case 23 :
record_syscall("sys_setuid16");
log_32(env->regs[0], "old_uid_t uid");
finish_syscall();
break;
// 24 long sys_getuid16 ['void']
case 24 :
record_syscall("sys_getuid16");
finish_syscall();
break;
// 26 long sys_ptrace ['long request', ' long pid', ' long addr', ' long data']
case 26 :
record_syscall("sys_ptrace");
log_32(env->regs[0], "long request");
log_32(env->regs[1], " long pid");
log_32(env->regs[2], " long addr");
log_32(env->regs[3], " long data");
finish_syscall();
break;
// 29 long sys_pause ['void']
case 29 :
record_syscall("sys_pause");
finish_syscall();
break;
// 33 long sys_access ['const char __user *filename', ' int mode']
case 33 :
record_syscall("sys_access");
log_string(env->regs[0], "const char __user *filename");
log_32(env->regs[1], " int mode");
finish_syscall();
break;
// 34 long sys_nice ['int increment']
case 34 :
record_syscall("sys_nice");
log_32(env->regs[0], "int increment");
finish_syscall();
break;
// 36 long sys_sync ['void']
case 36 :
record_syscall("sys_sync");
finish_syscall();
break;
// 37 long sys_kill ['int pid', ' int sig']
case 37 :
record_syscall("sys_kill");
log_32(env->regs[0], "int pid");
log_32(env->regs[1], " int sig");
finish_syscall();
break;
// 38 long sys_rename ['const char __user *oldname', 'const char __user *newname']
case 38 :
record_syscall("sys_rename");
log_string(env->regs[0], "const char __user *oldname");
log_string(env->regs[1], "const char __user *newname");
finish_syscall();
break;
// 39 long sys_mkdir ['const char __user *pathname', ' int mode']
case 39 :
record_syscall("sys_mkdir");
log_string(env->regs[0], "const char __user *pathname");
log_32(env->regs[1], " int mode");
finish_syscall();
break;
// 40 long sys_rmdir ['const char __user *pathname']
case 40 :
record_syscall("sys_rmdir");
log_string(env->regs[0], "const char __user *pathname");
finish_syscall();
break;
// 41 long sys_dup ['unsigned int fildes']
case 41 :
record_syscall("sys_dup");
log_32(env->regs[0], "unsigned int fildes");
finish_syscall();
break;
// 42 long sys_pipe ['int __user *']
case 42 :
record_syscall("sys_pipe");
log_pointer(env->regs[0], "int __user *");
finish_syscall();
break;
// 43 long sys_times ['struct tms __user *tbuf']
case 43 :
record_syscall("sys_times");
log_pointer(env->regs[0], "struct tms __user *tbuf");
finish_syscall();
break;
// 45 long sys_brk ['unsigned long brk']
case 45 :
record_syscall("sys_brk");
log_32(env->regs[0], "unsigned long brk");
finish_syscall();
break;
// 46 long sys_setgid16 ['old_gid_t gid']
case 46 :
record_syscall("sys_setgid16");
log_32(env->regs[0], "old_gid_t gid");
finish_syscall();
break;
// 47 long sys_getgid16 ['void']
case 47 :
record_syscall("sys_getgid16");
finish_syscall();
break;
// 49 long sys_geteuid16 ['void']
case 49 :
record_syscall("sys_geteuid16");
finish_syscall();
break;
// 50 long sys_getegid16 ['void']
case 50 :
record_syscall("sys_getegid16");
finish_syscall();
break;
// 51 long sys_acct ['const char __user *name']
case 51 :
record_syscall("sys_acct");
log_string(env->regs[0], "const char __user *name");
finish_syscall();
break;
// 52 long sys_umount ['char __user *name', ' int flags']
case 52 :
record_syscall("sys_umount");
log_string(env->regs[0], "char __user *name");
log_32(env->regs[1], " int flags");
finish_syscall();
break;
// 54 long sys_ioctl ['unsigned int fd', ' unsigned int cmd', 'unsigned long arg']
case 54 :
record_syscall("sys_ioctl");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], " unsigned int cmd");
log_32(env->regs[2], "unsigned long arg");
finish_syscall();
break;
// 55 long sys_fcntl ['unsigned int fd', ' unsigned int cmd', ' unsigned long arg']
case 55 :
record_syscall("sys_fcntl");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], " unsigned int cmd");
log_32(env->regs[2], " unsigned long arg");
finish_syscall();
break;
// 57 long sys_setpgid ['pid_t pid', ' pid_t pgid']
case 57 :
record_syscall("sys_setpgid");
log_32(env->regs[0], "pid_t pid");
log_32(env->regs[1], " pid_t pgid");
finish_syscall();
break;
// 60 long sys_umask ['int mask']
case 60 :
record_syscall("sys_umask");
log_32(env->regs[0], "int mask");
finish_syscall();
break;
// 61 long sys_chroot ['const char __user *filename']
case 61 :
record_syscall("sys_chroot");
log_string(env->regs[0], "const char __user *filename");
finish_syscall();
break;
// 62 long sys_ustat ['unsigned dev', ' struct ustat __user *ubuf']
case 62 :
record_syscall("sys_ustat");
log_32(env->regs[0], "unsigned dev");
log_pointer(env->regs[1], " struct ustat __user *ubuf");
finish_syscall();
break;
// 63 long sys_dup2 ['unsigned int oldfd', ' unsigned int newfd']
case 63 :
record_syscall("sys_dup2");
log_32(env->regs[0], "unsigned int oldfd");
log_32(env->regs[1], " unsigned int newfd");
finish_syscall();
break;
// 64 long sys_getppid ['void']
case 64 :
record_syscall("sys_getppid");
finish_syscall();
break;
// 65 long sys_getpgrp ['void']
case 65 :
record_syscall("sys_getpgrp");
finish_syscall();
break;
// 66 long sys_setsid ['void']
case 66 :
record_syscall("sys_setsid");
finish_syscall();
break;
// 67 int sigaction ['int sig', ' const struct old_sigaction __user *act', ' struct old_sigaction __user *oact']
case 67 :
record_syscall("sigaction");
log_32(env->regs[0], "int sig");
log_pointer(env->regs[1], " const struct old_sigaction __user *act");
log_pointer(env->regs[2], " struct old_sigaction __user *oact");
finish_syscall();
break;
// 70 long sys_setreuid16 ['old_uid_t ruid', ' old_uid_t euid']
case 70 :
record_syscall("sys_setreuid16");
log_32(env->regs[0], "old_uid_t ruid");
log_32(env->regs[1], " old_uid_t euid");
finish_syscall();
break;
// 71 long sys_setregid16 ['old_gid_t rgid', ' old_gid_t egid']
case 71 :
record_syscall("sys_setregid16");
log_32(env->regs[0], "old_gid_t rgid");
log_32(env->regs[1], " old_gid_t egid");
finish_syscall();
break;
// 72 long sigsuspend ['int restart', ' unsigned long oldmask', ' old_sigset_t mask']
case 72 :
record_syscall("sigsuspend");
log_32(env->regs[0], "int restart");
log_32(env->regs[1], " unsigned long oldmask");
log_32(env->regs[2], " old_sigset_t mask");
finish_syscall();
break;
// 73 long sys_sigpending ['old_sigset_t __user *set']
case 73 :
record_syscall("sys_sigpending");
log_pointer(env->regs[0], "old_sigset_t __user *set");
finish_syscall();
break;
// 74 long sys_sethostname ['char __user *name', ' int len']
case 74 :
record_syscall("sys_sethostname");
log_string(env->regs[0], "char __user *name");
log_32(env->regs[1], " int len");
finish_syscall();
break;
// 75 long sys_setrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
case 75 :
record_syscall("sys_setrlimit");
log_32(env->regs[0], "unsigned int resource");
log_pointer(env->regs[1], "struct rlimit __user *rlim");
finish_syscall();
break;
// 77 long sys_getrusage ['int who', ' struct rusage __user *ru']
case 77 :
record_syscall("sys_getrusage");
log_32(env->regs[0], "int who");
log_pointer(env->regs[1], " struct rusage __user *ru");
finish_syscall();
break;
// 78 long sys_gettimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
case 78 :
record_syscall("sys_gettimeofday");
log_pointer(env->regs[0], "struct timeval __user *tv");
log_pointer(env->regs[1], "struct timezone __user *tz");
finish_syscall();
break;
// 79 long sys_settimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
case 79 :
record_syscall("sys_settimeofday");
log_pointer(env->regs[0], "struct timeval __user *tv");
log_pointer(env->regs[1], "struct timezone __user *tz");
finish_syscall();
break;
// 80 long sys_getgroups16 ['int gidsetsize', ' old_gid_t __user *grouplist']
case 80 :
record_syscall("sys_getgroups16");
log_32(env->regs[0], "int gidsetsize");
log_pointer(env->regs[1], " old_gid_t __user *grouplist");
finish_syscall();
break;
// 81 long sys_setgroups16 ['int gidsetsize', ' old_gid_t __user *grouplist']
case 81 :
record_syscall("sys_setgroups16");
log_32(env->regs[0], "int gidsetsize");
log_pointer(env->regs[1], " old_gid_t __user *grouplist");
finish_syscall();
break;
// 83 long sys_symlink ['const char __user *old', ' const char __user *new']
case 83 :
record_syscall("sys_symlink");
log_string(env->regs[0], "const char __user *old");
log_string(env->regs[1], " const char __user *new");
finish_syscall();
break;
// 85 long sys_readlink ['const char __user *path', 'char __user *buf', ' int bufsiz']
case 85 :
record_syscall("sys_readlink");
log_string(env->regs[0], "const char __user *path");
log_pointer(env->regs[1], "char __user *buf");
log_32(env->regs[2], " int bufsiz");
finish_syscall();
break;
// 86 long sys_uselib ['const char __user *library']
case 86 :
record_syscall("sys_uselib");
log_string(env->regs[0], "const char __user *library");
finish_syscall();
break;
// 87 long sys_swapon ['const char __user *specialfile', ' int swap_flags']
case 87 :
record_syscall("sys_swapon");
log_string(env->regs[0], "const char __user *specialfile");
log_32(env->regs[1], " int swap_flags");
finish_syscall();
break;
// 88 long sys_reboot ['int magic1', ' int magic2', ' unsigned int cmd', 'void __user *arg']
case 88 :
record_syscall("sys_reboot");
log_32(env->regs[0], "int magic1");
log_32(env->regs[1], " int magic2");
log_32(env->regs[2], " unsigned int cmd");
log_pointer(env->regs[3], "void __user *arg");
finish_syscall();
break;
// 91 long sys_munmap ['unsigned long addr', ' size_t len']
case 91 :
record_syscall("sys_munmap");
log_32(env->regs[0], "unsigned long addr");
log_32(env->regs[1], " size_t len");
finish_syscall();
break;
// 92 long sys_truncate ['const char __user *path', 'unsigned long length']
case 92 :
record_syscall("sys_truncate");
log_string(env->regs[0], "const char __user *path");
log_32(env->regs[1], "unsigned long length");
finish_syscall();
break;
// 93 long sys_ftruncate ['unsigned int fd', ' unsigned long length']
case 93 :
record_syscall("sys_ftruncate");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], " unsigned long length");
finish_syscall();
break;
// 94 long sys_fchmod ['unsigned int fd', ' mode_t mode']
case 94 :
record_syscall("sys_fchmod");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], " mode_t mode");
finish_syscall();
break;
// 95 long sys_fchown16 ['unsigned int fd', ' old_uid_t user', ' old_gid_t group']
case 95 :
record_syscall("sys_fchown16");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], " old_uid_t user");
log_32(env->regs[2], " old_gid_t group");
finish_syscall();
break;
// 96 long sys_getpriority ['int which', ' int who']
case 96 :
record_syscall("sys_getpriority");
log_32(env->regs[0], "int which");
log_32(env->regs[1], " int who");
finish_syscall();
break;
// 97 long sys_setpriority ['int which', ' int who', ' int niceval']
case 97 :
record_syscall("sys_setpriority");
log_32(env->regs[0], "int which");
log_32(env->regs[1], " int who");
log_32(env->regs[2], " int niceval");
finish_syscall();
break;
// 99 long sys_statfs ['const char __user * path', 'struct statfs __user *buf']
case 99 :
record_syscall("sys_statfs");
log_string(env->regs[0], "const char __user * path");
log_pointer(env->regs[1], "struct statfs __user *buf");
finish_syscall();
break;
// 100 long sys_fstatfs ['unsigned int fd', ' struct statfs __user *buf']
case 100 :
record_syscall("sys_fstatfs");
log_32(env->regs[0], "unsigned int fd");
log_pointer(env->regs[1], " struct statfs __user *buf");
finish_syscall();
break;
// 103 long sys_syslog ['int type', ' char __user *buf', ' int len']
case 103 :
record_syscall("sys_syslog");
log_32(env->regs[0], "int type");
log_pointer(env->regs[1], " char __user *buf");
log_32(env->regs[2], " int len");
finish_syscall();
break;
// 104 long sys_setitimer ['int which', 'struct itimerval __user *value', 'struct itimerval __user *ovalue']
case 104 :
record_syscall("sys_setitimer");
log_32(env->regs[0], "int which");
log_pointer(env->regs[1], "struct itimerval __user *value");
log_pointer(env->regs[2], "struct itimerval __user *ovalue");
finish_syscall();
break;
// 105 long sys_getitimer ['int which', ' struct itimerval __user *value']
case 105 :
record_syscall("sys_getitimer");
log_32(env->regs[0], "int which");
log_pointer(env->regs[1], " struct itimerval __user *value");
finish_syscall();
break;
// 106 long sys_newstat ['char __user *filename', 'struct stat __user *statbuf']
case 106 :
record_syscall("sys_newstat");
log_string(env->regs[0], "char __user *filename");
log_pointer(env->regs[1], "struct stat __user *statbuf");
finish_syscall();
break;
// 107 long sys_newlstat ['char __user *filename', 'struct stat __user *statbuf']
case 107 :
record_syscall("sys_newlstat");
log_string(env->regs[0], "char __user *filename");
log_pointer(env->regs[1], "struct stat __user *statbuf");
finish_syscall();
break;
// 108 long sys_newfstat ['unsigned int fd', ' struct stat __user *statbuf']
case 108 :
record_syscall("sys_newfstat");
log_32(env->regs[0], "unsigned int fd");
log_pointer(env->regs[1], " struct stat __user *statbuf");
finish_syscall();
break;
// 111 long sys_vhangup ['void']
case 111 :
record_syscall("sys_vhangup");
finish_syscall();
break;
// 114 long sys_wait4 ['pid_t pid', ' int __user *stat_addr', 'int options', ' struct rusage __user *ru']
case 114 :
record_syscall("sys_wait4");
log_32(env->regs[0], "pid_t pid");
log_pointer(env->regs[1], " int __user *stat_addr");
log_32(env->regs[2], "int options");
log_pointer(env->regs[3], " struct rusage __user *ru");
finish_syscall();
break;
// 115 long sys_swapoff ['const char __user *specialfile']
case 115 :
record_syscall("sys_swapoff");
log_string(env->regs[0], "const char __user *specialfile");
finish_syscall();
break;
// 116 long sys_sysinfo ['struct sysinfo __user *info']
case 116 :
record_syscall("sys_sysinfo");
log_pointer(env->regs[0], "struct sysinfo __user *info");
finish_syscall();
break;
// 118 long sys_fsync ['unsigned int fd']
case 118 :
record_syscall("sys_fsync");
log_32(env->regs[0], "unsigned int fd");
finish_syscall();
break;
// 119 int sigreturn ['void']
case 119 :
record_syscall("sigreturn");
finish_syscall();
break;
// 120 unsigned long clone ['int (*fn)(void *)', ' void *child_stack', ' int flags', ' void *arg', ' ...']
case 120 :
record_syscall("clone");
log_pointer(env->regs[0], "int (*fn)(void *)");
log_pointer(env->regs[1], " void *child_stack");
log_32(env->regs[2], " int flags");
log_pointer(env->regs[3], " void *arg");
log_pointer(env->regs[4], " ...");
finish_syscall();
break;
// 121 long sys_setdomainname ['char __user *name', ' int len']
case 121 :
record_syscall("sys_setdomainname");
log_string(env->regs[0], "char __user *name");
log_32(env->regs[1], " int len");
finish_syscall();
break;
// 122 long sys_newuname ['struct new_utsname __user *name']
case 122 :
record_syscall("sys_newuname");
log_pointer(env->regs[0], "struct new_utsname __user *name");
finish_syscall();
break;
// 124 long sys_adjtimex ['struct timex __user *txc_p']
case 124 :
record_syscall("sys_adjtimex");
log_pointer(env->regs[0], "struct timex __user *txc_p");
finish_syscall();
break;
// 125 long sys_mprotect ['unsigned long start', ' size_t len', 'unsigned long prot']
case 125 :
record_syscall("sys_mprotect");
log_32(env->regs[0], "unsigned long start");
log_32(env->regs[1], " size_t len");
log_32(env->regs[2], "unsigned long prot");
finish_syscall();
break;
// 126 long sys_sigprocmask ['int how', ' old_sigset_t __user *set', 'old_sigset_t __user *oset']
case 126 :
record_syscall("sys_sigprocmask");
log_32(env->regs[0], "int how");
log_pointer(env->regs[1], " old_sigset_t __user *set");
log_pointer(env->regs[2], "old_sigset_t __user *oset");
finish_syscall();
break;
// 128 long sys_init_module ['void __user *umod', ' unsigned long len', 'const char __user *uargs']
case 128 :
record_syscall("sys_init_module");
log_pointer(env->regs[0], "void __user *umod");
log_32(env->regs[1], " unsigned long len");
log_string(env->regs[2], "const char __user *uargs");
finish_syscall();
break;
// 129 long sys_delete_module ['const char __user *name_user', 'unsigned int flags']
case 129 :
record_syscall("sys_delete_module");
log_string(env->regs[0], "const char __user *name_user");
log_32(env->regs[1], "unsigned int flags");
finish_syscall();
break;
// 131 long sys_quotactl ['unsigned int cmd', ' const char __user *special', 'qid_t id', ' void __user *addr']
case 131 :
record_syscall("sys_quotactl");
log_32(env->regs[0], "unsigned int cmd");
log_string(env->regs[1], " const char __user *special");
log_32(env->regs[2], "qid_t id");
log_pointer(env->regs[3], " void __user *addr");
finish_syscall();
break;
// 132 long sys_getpgid ['pid_t pid']
case 132 :
record_syscall("sys_getpgid");
log_32(env->regs[0], "pid_t pid");
finish_syscall();
break;
// 133 long sys_fchdir ['unsigned int fd']
case 133 :
record_syscall("sys_fchdir");
log_32(env->regs[0], "unsigned int fd");
finish_syscall();
break;
// 134 long sys_bdflush ['int func', ' long data']
case 134 :
record_syscall("sys_bdflush");
log_32(env->regs[0], "int func");
log_32(env->regs[1], " long data");
finish_syscall();
break;
// 135 long sys_sysfs ['int option', 'unsigned long arg1', ' unsigned long arg2']
case 135 :
record_syscall("sys_sysfs");
log_32(env->regs[0], "int option");
log_32(env->regs[1], "unsigned long arg1");
log_32(env->regs[2], " unsigned long arg2");
finish_syscall();
break;
// 136 long sys_personality ['u_long personality']
case 136 :
record_syscall("sys_personality");
log_32(env->regs[0], "u_long personality");
finish_syscall();
break;
// 138 long sys_setfsuid16 ['old_uid_t uid']
case 138 :
record_syscall("sys_setfsuid16");
log_32(env->regs[0], "old_uid_t uid");
finish_syscall();
break;
// 139 long sys_setfsgid16 ['old_gid_t gid']
case 139 :
record_syscall("sys_setfsgid16");
log_32(env->regs[0], "old_gid_t gid");
finish_syscall();
break;
// 140 long sys_llseek ['unsigned int fd', ' unsigned long offset_high', 'unsigned long offset_low', ' loff_t __user *result', 'unsigned int origin']
case 140 :
record_syscall("sys_llseek");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], " unsigned long offset_high");
log_32(env->regs[2], "unsigned long offset_low");
log_pointer(env->regs[3], " loff_t __user *result");
log_32(env->regs[4], "unsigned int origin");
finish_syscall();
break;
// 141 long sys_getdents ['unsigned int fd', 'struct linux_dirent __user *dirent', 'unsigned int count']
case 141 :
record_syscall("sys_getdents");
log_32(env->regs[0], "unsigned int fd");
log_pointer(env->regs[1], "struct linux_dirent __user *dirent");
log_32(env->regs[2], "unsigned int count");
finish_syscall();
break;
// 142 long sys_select ['int n', ' fd_set __user *inp', ' fd_set __user *outp', 'fd_set __user *exp', ' struct timeval __user *tvp']
case 142 :
record_syscall("sys_select");
log_32(env->regs[0], "int n");
log_pointer(env->regs[1], " fd_set __user *inp");
log_pointer(env->regs[2], " fd_set __user *outp");
log_pointer(env->regs[3], "fd_set __user *exp");
log_pointer(env->regs[4], " struct timeval __user *tvp");
finish_syscall();
break;
// 143 long sys_flock ['unsigned int fd', ' unsigned int cmd']
case 143 :
record_syscall("sys_flock");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], " unsigned int cmd");
finish_syscall();
break;
// 144 long sys_msync ['unsigned long start', ' size_t len', ' int flags']
case 144 :
record_syscall("sys_msync");
log_32(env->regs[0], "unsigned long start");
log_32(env->regs[1], " size_t len");
log_32(env->regs[2], " int flags");
finish_syscall();
break;
// 145 long sys_readv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
case 145 :
record_syscall("sys_readv");
log_32(env->regs[0], "unsigned long fd");
log_pointer(env->regs[1], "const struct iovec __user *vec");
log_32(env->regs[2], "unsigned long vlen");
finish_syscall();
break;
// 146 long sys_writev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
case 146 :
record_syscall("sys_writev");
log_32(env->regs[0], "unsigned long fd");
log_pointer(env->regs[1], "const struct iovec __user *vec");
log_32(env->regs[2], "unsigned long vlen");
finish_syscall();
break;
// 147 long sys_getsid ['pid_t pid']
case 147 :
record_syscall("sys_getsid");
log_32(env->regs[0], "pid_t pid");
finish_syscall();
break;
// 148 long sys_fdatasync ['unsigned int fd']
case 148 :
record_syscall("sys_fdatasync");
log_32(env->regs[0], "unsigned int fd");
finish_syscall();
break;
// 149 long sys_sysctl ['struct __sysctl_args __user *args']
case 149 :
record_syscall("sys_sysctl");
log_pointer(env->regs[0], "struct __sysctl_args __user *args");
finish_syscall();
break;
// 150 long sys_mlock ['unsigned long start', ' size_t len']
case 150 :
record_syscall("sys_mlock");
log_32(env->regs[0], "unsigned long start");
log_32(env->regs[1], " size_t len");
finish_syscall();
break;
// 151 long sys_munlock ['unsigned long start', ' size_t len']
case 151 :
record_syscall("sys_munlock");
log_32(env->regs[0], "unsigned long start");
log_32(env->regs[1], " size_t len");
finish_syscall();
break;
// 152 long sys_mlockall ['int flags']
case 152 :
record_syscall("sys_mlockall");
log_32(env->regs[0], "int flags");
finish_syscall();
break;
// 153 long sys_munlockall ['void']
case 153 :
record_syscall("sys_munlockall");
finish_syscall();
break;
// 154 long sys_sched_setparam ['pid_t pid', 'struct sched_param __user *param']
case 154 :
record_syscall("sys_sched_setparam");
log_32(env->regs[0], "pid_t pid");
log_pointer(env->regs[1], "struct sched_param __user *param");
finish_syscall();
break;
// 155 long sys_sched_getparam ['pid_t pid', 'struct sched_param __user *param']
case 155 :
record_syscall("sys_sched_getparam");
log_32(env->regs[0], "pid_t pid");
log_pointer(env->regs[1], "struct sched_param __user *param");
finish_syscall();
break;
// 156 long sys_sched_setscheduler ['pid_t pid', ' int policy', 'struct sched_param __user *param']
case 156 :
record_syscall("sys_sched_setscheduler");
log_32(env->regs[0], "pid_t pid");
log_32(env->regs[1], " int policy");
log_pointer(env->regs[2], "struct sched_param __user *param");
finish_syscall();
break;
// 157 long sys_sched_getscheduler ['pid_t pid']
case 157 :
record_syscall("sys_sched_getscheduler");
log_32(env->regs[0], "pid_t pid");
finish_syscall();
break;
// 158 long sys_sched_yield ['void']
case 158 :
record_syscall("sys_sched_yield");
finish_syscall();
break;
// 159 long sys_sched_get_priority_max ['int policy']
case 159 :
record_syscall("sys_sched_get_priority_max");
log_32(env->regs[0], "int policy");
finish_syscall();
break;
// 160 long sys_sched_get_priority_min ['int policy']
case 160 :
record_syscall("sys_sched_get_priority_min");
log_32(env->regs[0], "int policy");
finish_syscall();
break;
// 161 long sys_sched_rr_get_interval ['pid_t pid', 'struct timespec __user *interval']
case 161 :
record_syscall("sys_sched_rr_get_interval");
log_32(env->regs[0], "pid_t pid");
log_pointer(env->regs[1], "struct timespec __user *interval");
finish_syscall();
break;
// 162 long sys_nanosleep ['struct timespec __user *rqtp', ' struct timespec __user *rmtp']
case 162 :
record_syscall("sys_nanosleep");
log_pointer(env->regs[0], "struct timespec __user *rqtp");
log_pointer(env->regs[1], " struct timespec __user *rmtp");
finish_syscall();
break;
// 163 unsigned long arm_mremap ['unsigned long addr', ' unsigned long old_len', ' unsigned long new_len', ' unsigned long flags', ' unsigned long new_addr']
case 163 :
record_syscall("arm_mremap");
log_32(env->regs[0], "unsigned long addr");
log_32(env->regs[1], " unsigned long old_len");
log_32(env->regs[2], " unsigned long new_len");
log_32(env->regs[3], " unsigned long flags");
log_32(env->regs[4], " unsigned long new_addr");
finish_syscall();
break;
// 164 long sys_setresuid16 ['old_uid_t ruid', ' old_uid_t euid', ' old_uid_t suid']
case 164 :
record_syscall("sys_setresuid16");
log_32(env->regs[0], "old_uid_t ruid");
log_32(env->regs[1], " old_uid_t euid");
log_32(env->regs[2], " old_uid_t suid");
finish_syscall();
break;
// 165 long sys_getresuid16 ['old_uid_t __user *ruid', 'old_uid_t __user *euid', ' old_uid_t __user *suid']
case 165 :
record_syscall("sys_getresuid16");
log_pointer(env->regs[0], "old_uid_t __user *ruid");
log_pointer(env->regs[1], "old_uid_t __user *euid");
log_pointer(env->regs[2], " old_uid_t __user *suid");
finish_syscall();
break;
// 168 long sys_poll ['struct pollfd __user *ufds', ' unsigned int nfds', 'long timeout']
case 168 :
record_syscall("sys_poll");
log_pointer(env->regs[0], "struct pollfd __user *ufds");
log_32(env->regs[1], " unsigned int nfds");
log_32(env->regs[2], "long timeout");
finish_syscall();
break;
// 169 long sys_nfsservctl ['int cmd', 'struct nfsctl_arg __user *arg', 'void __user *res']
case 169 :
record_syscall("sys_nfsservctl");
log_32(env->regs[0], "int cmd");
log_pointer(env->regs[1], "struct nfsctl_arg __user *arg");
log_pointer(env->regs[2], "void __user *res");
finish_syscall();
break;
// 170 long sys_setresgid16 ['old_gid_t rgid', ' old_gid_t egid', ' old_gid_t sgid']
case 170 :
record_syscall("sys_setresgid16");
log_32(env->regs[0], "old_gid_t rgid");
log_32(env->regs[1], " old_gid_t egid");
log_32(env->regs[2], " old_gid_t sgid");
finish_syscall();
break;
// 171 long sys_getresgid16 ['old_gid_t __user *rgid', 'old_gid_t __user *egid', ' old_gid_t __user *sgid']
case 171 :
record_syscall("sys_getresgid16");
log_pointer(env->regs[0], "old_gid_t __user *rgid");
log_pointer(env->regs[1], "old_gid_t __user *egid");
log_pointer(env->regs[2], " old_gid_t __user *sgid");
finish_syscall();
break;
// 172 long sys_prctl ['int option', ' unsigned long arg2', ' unsigned long arg3', 'unsigned long arg4', ' unsigned long arg5']
case 172 :
record_syscall("sys_prctl");
log_32(env->regs[0], "int option");
log_32(env->regs[1], " unsigned long arg2");
log_32(env->regs[2], " unsigned long arg3");
log_32(env->regs[3], "unsigned long arg4");
log_32(env->regs[4], " unsigned long arg5");
finish_syscall();
break;
// 173 int sigreturn ['void']
case 173 :
record_syscall("sigreturn");
finish_syscall();
break;
// 174 long rt_sigaction ['int sig', ' const struct sigaction __user * act', ' struct sigaction __user * oact', '  size_t sigsetsize']
case 174 :
record_syscall("rt_sigaction");
log_32(env->regs[0], "int sig");
log_pointer(env->regs[1], " const struct sigaction __user * act");
log_pointer(env->regs[2], " struct sigaction __user * oact");
log_32(env->regs[3], "  size_t sigsetsize");
finish_syscall();
break;
// 175 long sys_rt_sigprocmask ['int how', ' sigset_t __user *set', 'sigset_t __user *oset', ' size_t sigsetsize']
case 175 :
record_syscall("sys_rt_sigprocmask");
log_32(env->regs[0], "int how");
log_pointer(env->regs[1], " sigset_t __user *set");
log_pointer(env->regs[2], "sigset_t __user *oset");
log_32(env->regs[3], " size_t sigsetsize");
finish_syscall();
break;
// 176 long sys_rt_sigpending ['sigset_t __user *set', ' size_t sigsetsize']
case 176 :
record_syscall("sys_rt_sigpending");
log_pointer(env->regs[0], "sigset_t __user *set");
log_32(env->regs[1], " size_t sigsetsize");
finish_syscall();
break;
// 177 long sys_rt_sigtimedwait ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct timespec __user *uts', 'size_t sigsetsize']
case 177 :
record_syscall("sys_rt_sigtimedwait");
log_pointer(env->regs[0], "const sigset_t __user *uthese");
log_pointer(env->regs[1], "siginfo_t __user *uinfo");
log_pointer(env->regs[2], "const struct timespec __user *uts");
log_32(env->regs[3], "size_t sigsetsize");
finish_syscall();
break;
// 178 long sys_rt_sigqueueinfo ['int pid', ' int sig', ' siginfo_t __user *uinfo']
case 178 :
record_syscall("sys_rt_sigqueueinfo");
log_32(env->regs[0], "int pid");
log_32(env->regs[1], " int sig");
log_pointer(env->regs[2], " siginfo_t __user *uinfo");
finish_syscall();
break;
// 179 int sys_rt_sigsuspend ['sigset_t __user *unewset', ' size_t sigsetsize']
case 179 :
record_syscall("sys_rt_sigsuspend");
log_pointer(env->regs[0], "sigset_t __user *unewset");
log_32(env->regs[1], " size_t sigsetsize");
finish_syscall();
break;
// 180 long sys_pread64 ['unsigned int fd', ' char __user *buf', 'size_t count', ' loff_t pos']
case 180 :
record_syscall("sys_pread64");
log_32(env->regs[0], "unsigned int fd");
log_pointer(env->regs[1], " char __user *buf");
log_32(env->regs[2], "size_t count");
// skipping arg for alignment
log_64(env->regs[4], env->regs[5], " loff_t pos");
finish_syscall();
break;
// 181 long sys_pwrite64 ['unsigned int fd', ' const char __user *buf', 'size_t count', ' loff_t pos']
case 181 :
record_syscall("sys_pwrite64");
log_32(env->regs[0], "unsigned int fd");
log_pointer(env->regs[1], " const char __user *buf");
log_32(env->regs[2], "size_t count");
// skipping arg for alignment
log_64(env->regs[4], env->regs[5], " loff_t pos");
finish_syscall();
break;
// 182 long sys_chown16 ['const char __user *filename', 'old_uid_t user', ' old_gid_t group']
case 182 :
record_syscall("sys_chown16");
log_string(env->regs[0], "const char __user *filename");
log_32(env->regs[1], "old_uid_t user");
log_32(env->regs[2], " old_gid_t group");
finish_syscall();
break;
// 183 long sys_getcwd ['char __user *buf', ' unsigned long size']
case 183 :
record_syscall("sys_getcwd");
log_pointer(env->regs[0], "char __user *buf");
log_32(env->regs[1], " unsigned long size");
finish_syscall();
break;
// 184 long sys_capget ['cap_user_header_t header', 'cap_user_data_t dataptr']
case 184 :
record_syscall("sys_capget");
log_pointer(env->regs[0], "cap_user_header_t header");
log_pointer(env->regs[1], "cap_user_data_t dataptr");
finish_syscall();
break;
// 185 long sys_capset ['cap_user_header_t header', 'const cap_user_data_t data']
case 185 :
record_syscall("sys_capset");
log_pointer(env->regs[0], "cap_user_header_t header");
log_pointer(env->regs[1], "const cap_user_data_t data");
finish_syscall();
break;
// 186 int do_sigaltstack ['const stack_t __user *uss', ' stack_t __user *uoss']
case 186 :
record_syscall("do_sigaltstack");
log_pointer(env->regs[0], "const stack_t __user *uss");
log_pointer(env->regs[1], " stack_t __user *uoss");
finish_syscall();
break;
// 187 long sys_sendfile ['int out_fd', ' int in_fd', 'off_t __user *offset', ' size_t count']
case 187 :
record_syscall("sys_sendfile");
log_32(env->regs[0], "int out_fd");
log_32(env->regs[1], " int in_fd");
log_pointer(env->regs[2], "off_t __user *offset");
log_32(env->regs[3], " size_t count");
finish_syscall();
break;
// 190 unsigned long vfork ['void']
case 190 :
record_syscall("vfork");
finish_syscall();
break;
// 191 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
case 191 :
record_syscall("sys_getrlimit");
log_32(env->regs[0], "unsigned int resource");
log_pointer(env->regs[1], "struct rlimit __user *rlim");
finish_syscall();
break;
// 192 long do_mmap2 ['unsigned long addr', ' unsigned long len', ' unsigned long prot', ' unsigned long flags', ' unsigned long fd', ' unsigned long pgoff']
case 192 :
record_syscall("do_mmap2");
log_32(env->regs[0], "unsigned long addr");
log_32(env->regs[1], " unsigned long len");
log_32(env->regs[2], " unsigned long prot");
log_32(env->regs[3], " unsigned long flags");
log_32(env->regs[4], " unsigned long fd");
log_32(env->regs[5], " unsigned long pgoff");
finish_syscall();
break;
// 193 long sys_truncate64 ['const char __user *path', ' loff_t length']
case 193 :
record_syscall("sys_truncate64");
log_string(env->regs[0], "const char __user *path");
// skipping arg for alignment
log_64(env->regs[2], env->regs[3], " loff_t length");
finish_syscall();
break;
// 194 long sys_ftruncate64 ['unsigned int fd', ' loff_t length']
case 194 :
record_syscall("sys_ftruncate64");
log_32(env->regs[0], "unsigned int fd");
// skipping arg for alignment
log_64(env->regs[2], env->regs[3], " loff_t length");
finish_syscall();
break;
// 195 long sys_stat64 ['char __user *filename', 'struct stat64 __user *statbuf']
case 195 :
record_syscall("sys_stat64");
log_string(env->regs[0], "char __user *filename");
log_pointer(env->regs[1], "struct stat64 __user *statbuf");
finish_syscall();
break;
// 196 long sys_lstat64 ['char __user *filename', 'struct stat64 __user *statbuf']
case 196 :
record_syscall("sys_lstat64");
log_string(env->regs[0], "char __user *filename");
log_pointer(env->regs[1], "struct stat64 __user *statbuf");
finish_syscall();
break;
// 197 long sys_fstat64 ['unsigned long fd', ' struct stat64 __user *statbuf']
case 197 :
record_syscall("sys_fstat64");
log_32(env->regs[0], "unsigned long fd");
log_pointer(env->regs[1], " struct stat64 __user *statbuf");
finish_syscall();
break;
// 198 long sys_lchown ['const char __user *filename', 'uid_t user', ' gid_t group']
case 198 :
record_syscall("sys_lchown");
log_string(env->regs[0], "const char __user *filename");
log_32(env->regs[1], "uid_t user");
log_32(env->regs[2], " gid_t group");
finish_syscall();
break;
// 199 long sys_getuid ['void']
case 199 :
record_syscall("sys_getuid");
finish_syscall();
break;
// 200 long sys_getgid ['void']
case 200 :
record_syscall("sys_getgid");
finish_syscall();
break;
// 201 long sys_geteuid ['void']
case 201 :
record_syscall("sys_geteuid");
finish_syscall();
break;
// 202 long sys_getegid ['void']
case 202 :
record_syscall("sys_getegid");
finish_syscall();
break;
// 203 long sys_setreuid ['uid_t ruid', ' uid_t euid']
case 203 :
record_syscall("sys_setreuid");
log_32(env->regs[0], "uid_t ruid");
log_32(env->regs[1], " uid_t euid");
finish_syscall();
break;
// 204 long sys_setregid ['gid_t rgid', ' gid_t egid']
case 204 :
record_syscall("sys_setregid");
log_32(env->regs[0], "gid_t rgid");
log_32(env->regs[1], " gid_t egid");
finish_syscall();
break;
// 205 long sys_getgroups ['int gidsetsize', ' gid_t __user *grouplist']
case 205 :
record_syscall("sys_getgroups");
log_32(env->regs[0], "int gidsetsize");
log_pointer(env->regs[1], " gid_t __user *grouplist");
finish_syscall();
break;
// 206 long sys_setgroups ['int gidsetsize', ' gid_t __user *grouplist']
case 206 :
record_syscall("sys_setgroups");
log_32(env->regs[0], "int gidsetsize");
log_pointer(env->regs[1], " gid_t __user *grouplist");
finish_syscall();
break;
// 207 long sys_fchown ['unsigned int fd', ' uid_t user', ' gid_t group']
case 207 :
record_syscall("sys_fchown");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], " uid_t user");
log_32(env->regs[2], " gid_t group");
finish_syscall();
break;
// 208 long sys_setresuid ['uid_t ruid', ' uid_t euid', ' uid_t suid']
case 208 :
record_syscall("sys_setresuid");
log_32(env->regs[0], "uid_t ruid");
log_32(env->regs[1], " uid_t euid");
log_32(env->regs[2], " uid_t suid");
finish_syscall();
break;
// 209 long sys_getresuid ['uid_t __user *ruid', ' uid_t __user *euid', ' uid_t __user *suid']
case 209 :
record_syscall("sys_getresuid");
log_pointer(env->regs[0], "uid_t __user *ruid");
log_pointer(env->regs[1], " uid_t __user *euid");
log_pointer(env->regs[2], " uid_t __user *suid");
finish_syscall();
break;
// 210 long sys_setresgid ['gid_t rgid', ' gid_t egid', ' gid_t sgid']
case 210 :
record_syscall("sys_setresgid");
log_32(env->regs[0], "gid_t rgid");
log_32(env->regs[1], " gid_t egid");
log_32(env->regs[2], " gid_t sgid");
finish_syscall();
break;
// 211 long sys_getresgid ['gid_t __user *rgid', ' gid_t __user *egid', ' gid_t __user *sgid']
case 211 :
record_syscall("sys_getresgid");
log_pointer(env->regs[0], "gid_t __user *rgid");
log_pointer(env->regs[1], " gid_t __user *egid");
log_pointer(env->regs[2], " gid_t __user *sgid");
finish_syscall();
break;
// 212 long sys_chown ['const char __user *filename', 'uid_t user', ' gid_t group']
case 212 :
record_syscall("sys_chown");
log_string(env->regs[0], "const char __user *filename");
log_32(env->regs[1], "uid_t user");
log_32(env->regs[2], " gid_t group");
finish_syscall();
break;
// 213 long sys_setuid ['uid_t uid']
case 213 :
record_syscall("sys_setuid");
log_32(env->regs[0], "uid_t uid");
finish_syscall();
break;
// 214 long sys_setgid ['gid_t gid']
case 214 :
record_syscall("sys_setgid");
log_32(env->regs[0], "gid_t gid");
finish_syscall();
break;
// 215 long sys_setfsuid ['uid_t uid']
case 215 :
record_syscall("sys_setfsuid");
log_32(env->regs[0], "uid_t uid");
finish_syscall();
break;
// 216 long sys_setfsgid ['gid_t gid']
case 216 :
record_syscall("sys_setfsgid");
log_32(env->regs[0], "gid_t gid");
finish_syscall();
break;
// 217 long sys_getdents64 ['unsigned int fd', 'struct linux_dirent64 __user *dirent', 'unsigned int count']
case 217 :
record_syscall("sys_getdents64");
log_32(env->regs[0], "unsigned int fd");
log_pointer(env->regs[1], "struct linux_dirent64 __user *dirent");
log_32(env->regs[2], "unsigned int count");
finish_syscall();
break;
// 218 long sys_pivot_root ['const char __user *new_root', 'const char __user *put_old']
case 218 :
record_syscall("sys_pivot_root");
log_string(env->regs[0], "const char __user *new_root");
log_string(env->regs[1], "const char __user *put_old");
finish_syscall();
break;
// 219 long sys_mincore ['unsigned long start', ' size_t len', 'unsigned char __user * vec']
case 219 :
record_syscall("sys_mincore");
log_32(env->regs[0], "unsigned long start");
log_32(env->regs[1], " size_t len");
log_string(env->regs[2], "unsigned char __user * vec");
finish_syscall();
break;
// 220 long sys_madvise ['unsigned long start', ' size_t len', ' int behavior']
case 220 :
record_syscall("sys_madvise");
log_32(env->regs[0], "unsigned long start");
log_32(env->regs[1], " size_t len");
log_32(env->regs[2], " int behavior");
finish_syscall();
break;
// 221 long sys_fcntl64 ['unsigned int fd', 'unsigned int cmd', ' unsigned long arg']
case 221 :
record_syscall("sys_fcntl64");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], "unsigned int cmd");
log_32(env->regs[2], " unsigned long arg");
finish_syscall();
break;
// 224 long sys_gettid ['void']
case 224 :
record_syscall("sys_gettid");
finish_syscall();
break;
// 225 long sys_readahead ['int fd', ' loff_t offset', ' size_t count']
case 225 :
record_syscall("sys_readahead");
log_32(env->regs[0], "int fd");
// skipping arg for alignment
log_64(env->regs[2], env->regs[3], " loff_t offset");
log_32(env->regs[4], " size_t count");
finish_syscall();
break;
// 226 long sys_setxattr ['const char __user *path', ' const char __user *name', 'const void __user *value', ' size_t size', ' int flags']
case 226 :
record_syscall("sys_setxattr");
log_string(env->regs[0], "const char __user *path");
log_string(env->regs[1], " const char __user *name");
log_pointer(env->regs[2], "const void __user *value");
log_32(env->regs[3], " size_t size");
log_32(env->regs[4], " int flags");
finish_syscall();
break;
// 227 long sys_lsetxattr ['const char __user *path', ' const char __user *name', 'const void __user *value', ' size_t size', ' int flags']
case 227 :
record_syscall("sys_lsetxattr");
log_string(env->regs[0], "const char __user *path");
log_string(env->regs[1], " const char __user *name");
log_pointer(env->regs[2], "const void __user *value");
log_32(env->regs[3], " size_t size");
log_32(env->regs[4], " int flags");
finish_syscall();
break;
// 228 long sys_fsetxattr ['int fd', ' const char __user *name', 'const void __user *value', ' size_t size', ' int flags']
case 228 :
record_syscall("sys_fsetxattr");
log_32(env->regs[0], "int fd");
log_string(env->regs[1], " const char __user *name");
log_pointer(env->regs[2], "const void __user *value");
log_32(env->regs[3], " size_t size");
log_32(env->regs[4], " int flags");
finish_syscall();
break;
// 229 long sys_getxattr ['const char __user *path', ' const char __user *name', 'void __user *value', ' size_t size']
case 229 :
record_syscall("sys_getxattr");
log_string(env->regs[0], "const char __user *path");
log_string(env->regs[1], " const char __user *name");
log_pointer(env->regs[2], "void __user *value");
log_32(env->regs[3], " size_t size");
finish_syscall();
break;
// 230 long sys_lgetxattr ['const char __user *path', ' const char __user *name', 'void __user *value', ' size_t size']
case 230 :
record_syscall("sys_lgetxattr");
log_string(env->regs[0], "const char __user *path");
log_string(env->regs[1], " const char __user *name");
log_pointer(env->regs[2], "void __user *value");
log_32(env->regs[3], " size_t size");
finish_syscall();
break;
// 231 long sys_fgetxattr ['int fd', ' const char __user *name', 'void __user *value', ' size_t size']
case 231 :
record_syscall("sys_fgetxattr");
log_32(env->regs[0], "int fd");
log_string(env->regs[1], " const char __user *name");
log_pointer(env->regs[2], "void __user *value");
log_32(env->regs[3], " size_t size");
finish_syscall();
break;
// 232 long sys_listxattr ['const char __user *path', ' char __user *list', 'size_t size']
case 232 :
record_syscall("sys_listxattr");
log_string(env->regs[0], "const char __user *path");
log_string(env->regs[1], " char __user *list");
log_32(env->regs[2], "size_t size");
finish_syscall();
break;
// 233 long sys_llistxattr ['const char __user *path', ' char __user *list', 'size_t size']
case 233 :
record_syscall("sys_llistxattr");
log_string(env->regs[0], "const char __user *path");
log_string(env->regs[1], " char __user *list");
log_32(env->regs[2], "size_t size");
finish_syscall();
break;
// 234 long sys_flistxattr ['int fd', ' char __user *list', ' size_t size']
case 234 :
record_syscall("sys_flistxattr");
log_32(env->regs[0], "int fd");
log_string(env->regs[1], " char __user *list");
log_32(env->regs[2], " size_t size");
finish_syscall();
break;
// 235 long sys_removexattr ['const char __user *path', 'const char __user *name']
case 235 :
record_syscall("sys_removexattr");
log_string(env->regs[0], "const char __user *path");
log_string(env->regs[1], "const char __user *name");
finish_syscall();
break;
// 236 long sys_lremovexattr ['const char __user *path', 'const char __user *name']
case 236 :
record_syscall("sys_lremovexattr");
log_string(env->regs[0], "const char __user *path");
log_string(env->regs[1], "const char __user *name");
finish_syscall();
break;
// 237 long sys_fremovexattr ['int fd', ' const char __user *name']
case 237 :
record_syscall("sys_fremovexattr");
log_32(env->regs[0], "int fd");
log_string(env->regs[1], " const char __user *name");
finish_syscall();
break;
// 238 long sys_tkill ['int pid', ' int sig']
case 238 :
record_syscall("sys_tkill");
log_32(env->regs[0], "int pid");
log_32(env->regs[1], " int sig");
finish_syscall();
break;
// 239 long sys_sendfile64 ['int out_fd', ' int in_fd', 'loff_t __user *offset', ' size_t count']
case 239 :
record_syscall("sys_sendfile64");
log_32(env->regs[0], "int out_fd");
log_32(env->regs[1], " int in_fd");
log_pointer(env->regs[2], "loff_t __user *offset");
log_32(env->regs[3], " size_t count");
finish_syscall();
break;
// 240 long sys_futex ['u32 __user *uaddr', ' int op', ' u32 val', 'struct timespec __user *utime', ' u32 __user *uaddr2', 'u32 val3']
case 240 :
record_syscall("sys_futex");
log_pointer(env->regs[0], "u32 __user *uaddr");
log_32(env->regs[1], " int op");
log_32(env->regs[2], " u32 val");
log_pointer(env->regs[3], "struct timespec __user *utime");
log_pointer(env->regs[4], " u32 __user *uaddr2");
log_32(env->regs[5], "u32 val3");
finish_syscall();
break;
// 241 long sys_sched_setaffinity ['pid_t pid', ' unsigned int len', 'unsigned long __user *user_mask_ptr']
case 241 :
record_syscall("sys_sched_setaffinity");
log_32(env->regs[0], "pid_t pid");
log_32(env->regs[1], " unsigned int len");
log_pointer(env->regs[2], "unsigned long __user *user_mask_ptr");
finish_syscall();
break;
// 242 long sys_sched_getaffinity ['pid_t pid', ' unsigned int len', 'unsigned long __user *user_mask_ptr']
case 242 :
record_syscall("sys_sched_getaffinity");
log_32(env->regs[0], "pid_t pid");
log_32(env->regs[1], " unsigned int len");
log_pointer(env->regs[2], "unsigned long __user *user_mask_ptr");
finish_syscall();
break;
// 243 long sys_io_setup ['unsigned nr_reqs', ' aio_context_t __user *ctx']
case 243 :
record_syscall("sys_io_setup");
log_32(env->regs[0], "unsigned nr_reqs");
log_pointer(env->regs[1], " aio_context_t __user *ctx");
finish_syscall();
break;
// 244 long sys_io_destroy ['aio_context_t ctx']
case 244 :
record_syscall("sys_io_destroy");
log_32(env->regs[0], "aio_context_t ctx");
finish_syscall();
break;
// 245 long sys_io_getevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct timespec __user *timeout']
case 245 :
record_syscall("sys_io_getevents");
log_32(env->regs[0], "aio_context_t ctx_id");
log_32(env->regs[1], "long min_nr");
log_32(env->regs[2], "long nr");
log_pointer(env->regs[3], "struct io_event __user *events");
log_pointer(env->regs[4], "struct timespec __user *timeout");
finish_syscall();
break;
// 246 long sys_io_submit ['aio_context_t', ' long', 'struct iocb __user * __user *']
case 246 :
record_syscall("sys_io_submit");
log_32(env->regs[0], "aio_context_t");
log_32(env->regs[1], " long");
log_pointer(env->regs[2], "struct iocb __user * __user *");
finish_syscall();
break;
// 247 long sys_io_cancel ['aio_context_t ctx_id', ' struct iocb __user *iocb', 'struct io_event __user *result']
case 247 :
record_syscall("sys_io_cancel");
log_32(env->regs[0], "aio_context_t ctx_id");
log_pointer(env->regs[1], " struct iocb __user *iocb");
log_pointer(env->regs[2], "struct io_event __user *result");
finish_syscall();
break;
// 248 long sys_exit_group ['int error_code']
case 248 :
record_syscall("sys_exit_group");
log_32(env->regs[0], "int error_code");
finish_syscall();
break;
// 249 long sys_lookup_dcookie ['u64 cookie64', ' char __user *buf', ' size_t len']
case 249 :
record_syscall("sys_lookup_dcookie");
log_64(env->regs[0], env->regs[1], "u64 cookie64");
log_pointer(env->regs[2], " char __user *buf");
log_32(env->regs[3], " size_t len");
finish_syscall();
break;
// 250 long sys_epoll_create ['int size']
case 250 :
record_syscall("sys_epoll_create");
log_32(env->regs[0], "int size");
finish_syscall();
break;
// 251 long sys_epoll_ctl ['int epfd', ' int op', ' int fd', 'struct epoll_event __user *event']
case 251 :
record_syscall("sys_epoll_ctl");
log_32(env->regs[0], "int epfd");
log_32(env->regs[1], " int op");
log_32(env->regs[2], " int fd");
log_pointer(env->regs[3], "struct epoll_event __user *event");
finish_syscall();
break;
// 252 long sys_epoll_wait ['int epfd', ' struct epoll_event __user *events', 'int maxevents', ' int timeout']
case 252 :
record_syscall("sys_epoll_wait");
log_32(env->regs[0], "int epfd");
log_pointer(env->regs[1], " struct epoll_event __user *events");
log_32(env->regs[2], "int maxevents");
log_32(env->regs[3], " int timeout");
finish_syscall();
break;
// 253 long sys_remap_file_pages ['unsigned long start', ' unsigned long size', 'unsigned long prot', ' unsigned long pgoff', 'unsigned long flags']
case 253 :
record_syscall("sys_remap_file_pages");
log_32(env->regs[0], "unsigned long start");
log_32(env->regs[1], " unsigned long size");
log_32(env->regs[2], "unsigned long prot");
log_32(env->regs[3], " unsigned long pgoff");
log_32(env->regs[4], "unsigned long flags");
finish_syscall();
break;
// 256 long sys_set_tid_address ['int __user *tidptr']
case 256 :
record_syscall("sys_set_tid_address");
log_pointer(env->regs[0], "int __user *tidptr");
finish_syscall();
break;
// 257 long sys_timer_create ['clockid_t which_clock', 'struct sigevent __user *timer_event_spec', 'timer_t __user * created_timer_id']
case 257 :
record_syscall("sys_timer_create");
log_32(env->regs[0], "clockid_t which_clock");
log_pointer(env->regs[1], "struct sigevent __user *timer_event_spec");
log_pointer(env->regs[2], "timer_t __user * created_timer_id");
finish_syscall();
break;
// 258 long sys_timer_settime ['timer_t timer_id', ' int flags', 'const struct itimerspec __user *new_setting', 'struct itimerspec __user *old_setting']
case 258 :
record_syscall("sys_timer_settime");
log_32(env->regs[0], "timer_t timer_id");
log_32(env->regs[1], " int flags");
log_pointer(env->regs[2], "const struct itimerspec __user *new_setting");
log_pointer(env->regs[3], "struct itimerspec __user *old_setting");
finish_syscall();
break;
// 259 long sys_timer_gettime ['timer_t timer_id', 'struct itimerspec __user *setting']
case 259 :
record_syscall("sys_timer_gettime");
log_32(env->regs[0], "timer_t timer_id");
log_pointer(env->regs[1], "struct itimerspec __user *setting");
finish_syscall();
break;
// 260 long sys_timer_getoverrun ['timer_t timer_id']
case 260 :
record_syscall("sys_timer_getoverrun");
log_32(env->regs[0], "timer_t timer_id");
finish_syscall();
break;
// 261 long sys_timer_delete ['timer_t timer_id']
case 261 :
record_syscall("sys_timer_delete");
log_32(env->regs[0], "timer_t timer_id");
finish_syscall();
break;
// 262 long sys_clock_settime ['clockid_t which_clock', 'const struct timespec __user *tp']
case 262 :
record_syscall("sys_clock_settime");
log_32(env->regs[0], "clockid_t which_clock");
log_pointer(env->regs[1], "const struct timespec __user *tp");
finish_syscall();
break;
// 263 long sys_clock_gettime ['clockid_t which_clock', 'struct timespec __user *tp']
case 263 :
record_syscall("sys_clock_gettime");
log_32(env->regs[0], "clockid_t which_clock");
log_pointer(env->regs[1], "struct timespec __user *tp");
finish_syscall();
break;
// 264 long sys_clock_getres ['clockid_t which_clock', 'struct timespec __user *tp']
case 264 :
record_syscall("sys_clock_getres");
log_32(env->regs[0], "clockid_t which_clock");
log_pointer(env->regs[1], "struct timespec __user *tp");
finish_syscall();
break;
// 265 long sys_clock_nanosleep ['clockid_t which_clock', ' int flags', 'const struct timespec __user *rqtp', 'struct timespec __user *rmtp']
case 265 :
record_syscall("sys_clock_nanosleep");
log_32(env->regs[0], "clockid_t which_clock");
log_32(env->regs[1], " int flags");
log_pointer(env->regs[2], "const struct timespec __user *rqtp");
log_pointer(env->regs[3], "struct timespec __user *rmtp");
finish_syscall();
break;
// 266 long sys_statfs64 ['const char __user *path', ' size_t sz', 'struct statfs64 __user *buf']
case 266 :
record_syscall("sys_statfs64");
log_string(env->regs[0], "const char __user *path");
log_32(env->regs[1], " size_t sz");
log_pointer(env->regs[2], "struct statfs64 __user *buf");
finish_syscall();
break;
// 267 long sys_fstatfs64 ['unsigned int fd', ' size_t sz', 'struct statfs64 __user *buf']
case 267 :
record_syscall("sys_fstatfs64");
log_32(env->regs[0], "unsigned int fd");
log_32(env->regs[1], " size_t sz");
log_pointer(env->regs[2], "struct statfs64 __user *buf");
finish_syscall();
break;
// 268 long sys_tgkill ['int tgid', ' int pid', ' int sig']
case 268 :
record_syscall("sys_tgkill");
log_32(env->regs[0], "int tgid");
log_32(env->regs[1], " int pid");
log_32(env->regs[2], " int sig");
finish_syscall();
break;
// 269 long sys_utimes ['char __user *filename', 'struct timeval __user *utimes']
case 269 :
record_syscall("sys_utimes");
log_string(env->regs[0], "char __user *filename");
log_pointer(env->regs[1], "struct timeval __user *utimes");
finish_syscall();
break;
// 270 long sys_arm_fadvise64_64 ['int fd', ' int advice', ' loff_t offset', ' loff_t len']
case 270 :
record_syscall("sys_arm_fadvise64_64");
log_32(env->regs[0], "int fd");
log_32(env->regs[1], " int advice");
log_64(env->regs[2], env->regs[3], " loff_t offset");
log_64(env->regs[4], env->regs[5], " loff_t len");
finish_syscall();
break;
// 271 long sys_pciconfig_iobase ['long which', ' unsigned long bus', ' unsigned long devfn']
case 271 :
record_syscall("sys_pciconfig_iobase");
log_32(env->regs[0], "long which");
log_32(env->regs[1], " unsigned long bus");
log_32(env->regs[2], " unsigned long devfn");
finish_syscall();
break;
// 272 long sys_pciconfig_read ['unsigned long bus', ' unsigned long dfn', 'unsigned long off', ' unsigned long len', 'void __user *buf']
case 272 :
record_syscall("sys_pciconfig_read");
log_32(env->regs[0], "unsigned long bus");
log_32(env->regs[1], " unsigned long dfn");
log_32(env->regs[2], "unsigned long off");
log_32(env->regs[3], " unsigned long len");
log_pointer(env->regs[4], "void __user *buf");
finish_syscall();
break;
// 273 long sys_pciconfig_write ['unsigned long bus', ' unsigned long dfn', 'unsigned long off', ' unsigned long len', 'void __user *buf']
case 273 :
record_syscall("sys_pciconfig_write");
log_32(env->regs[0], "unsigned long bus");
log_32(env->regs[1], " unsigned long dfn");
log_32(env->regs[2], "unsigned long off");
log_32(env->regs[3], " unsigned long len");
log_pointer(env->regs[4], "void __user *buf");
finish_syscall();
break;
// 274 long sys_mq_open ['const char __user *name', ' int oflag', ' mode_t mode', ' struct mq_attr __user *attr']
case 274 :
record_syscall("sys_mq_open");
log_string(env->regs[0], "const char __user *name");
log_32(env->regs[1], " int oflag");
log_32(env->regs[2], " mode_t mode");
log_pointer(env->regs[3], " struct mq_attr __user *attr");
finish_syscall();
break;
// 275 long sys_mq_unlink ['const char __user *name']
case 275 :
record_syscall("sys_mq_unlink");
log_string(env->regs[0], "const char __user *name");
finish_syscall();
break;
// 276 long sys_mq_timedsend ['mqd_t mqdes', ' const char __user *msg_ptr', ' size_t msg_len', ' unsigned int msg_prio', ' const struct timespec __user *abs_timeout']
case 276 :
record_syscall("sys_mq_timedsend");
log_32(env->regs[0], "mqd_t mqdes");
log_string(env->regs[1], " const char __user *msg_ptr");
log_32(env->regs[2], " size_t msg_len");
log_32(env->regs[3], " unsigned int msg_prio");
log_pointer(env->regs[4], " const struct timespec __user *abs_timeout");
finish_syscall();
break;
// 277 long sys_mq_timedreceive ['mqd_t mqdes', ' char __user *msg_ptr', ' size_t msg_len', ' unsigned int __user *msg_prio', ' const struct timespec __user *abs_timeout']
case 277 :
record_syscall("sys_mq_timedreceive");
log_32(env->regs[0], "mqd_t mqdes");
log_string(env->regs[1], " char __user *msg_ptr");
log_32(env->regs[2], " size_t msg_len");
log_pointer(env->regs[3], " unsigned int __user *msg_prio");
log_pointer(env->regs[4], " const struct timespec __user *abs_timeout");
finish_syscall();
break;
// 278 long sys_mq_notify ['mqd_t mqdes', ' const struct sigevent __user *notification']
case 278 :
record_syscall("sys_mq_notify");
log_32(env->regs[0], "mqd_t mqdes");
log_pointer(env->regs[1], " const struct sigevent __user *notification");
finish_syscall();
break;
// 279 long sys_mq_getsetattr ['mqd_t mqdes', ' const struct mq_attr __user *mqstat', ' struct mq_attr __user *omqstat']
case 279 :
record_syscall("sys_mq_getsetattr");
log_32(env->regs[0], "mqd_t mqdes");
log_pointer(env->regs[1], " const struct mq_attr __user *mqstat");
log_pointer(env->regs[2], " struct mq_attr __user *omqstat");
finish_syscall();
break;
// 280 long sys_waitid ['int which', ' pid_t pid', 'struct siginfo __user *infop', 'int options', ' struct rusage __user *ru']
case 280 :
record_syscall("sys_waitid");
log_32(env->regs[0], "int which");
log_32(env->regs[1], " pid_t pid");
log_pointer(env->regs[2], "struct siginfo __user *infop");
log_32(env->regs[3], "int options");
log_pointer(env->regs[4], " struct rusage __user *ru");
finish_syscall();
break;
// 281 long sys_socket ['int', ' int', ' int']
case 281 :
record_syscall("sys_socket");
log_32(env->regs[0], "int");
log_32(env->regs[1], " int");
log_32(env->regs[2], " int");
finish_syscall();
break;
// 282 long sys_bind ['int', ' struct sockaddr __user *', ' int']
case 282 :
record_syscall("sys_bind");
log_32(env->regs[0], "int");
log_pointer(env->regs[1], " struct sockaddr __user *");
log_32(env->regs[2], " int");
finish_syscall();
break;
// 283 long sys_connect ['int', ' struct sockaddr __user *', ' int']
case 283 :
record_syscall("sys_connect");
log_32(env->regs[0], "int");
log_pointer(env->regs[1], " struct sockaddr __user *");
log_32(env->regs[2], " int");
finish_syscall();
break;
// 284 long sys_listen ['int', ' int']
case 284 :
record_syscall("sys_listen");
log_32(env->regs[0], "int");
log_32(env->regs[1], " int");
finish_syscall();
break;
// 285 long sys_accept ['int', ' struct sockaddr __user *', ' int __user *']
case 285 :
record_syscall("sys_accept");
log_32(env->regs[0], "int");
log_pointer(env->regs[1], " struct sockaddr __user *");
log_pointer(env->regs[2], " int __user *");
finish_syscall();
break;
// 286 long sys_getsockname ['int', ' struct sockaddr __user *', ' int __user *']
case 286 :
record_syscall("sys_getsockname");
log_32(env->regs[0], "int");
log_pointer(env->regs[1], " struct sockaddr __user *");
log_pointer(env->regs[2], " int __user *");
finish_syscall();
break;
// 287 long sys_getpeername ['int', ' struct sockaddr __user *', ' int __user *']
case 287 :
record_syscall("sys_getpeername");
log_32(env->regs[0], "int");
log_pointer(env->regs[1], " struct sockaddr __user *");
log_pointer(env->regs[2], " int __user *");
finish_syscall();
break;
// 288 long sys_socketpair ['int', ' int', ' int', ' int __user *']
case 288 :
record_syscall("sys_socketpair");
log_32(env->regs[0], "int");
log_32(env->regs[1], " int");
log_32(env->regs[2], " int");
log_pointer(env->regs[3], " int __user *");
finish_syscall();
break;
// 289 long sys_send ['int', ' void __user *', ' size_t', ' unsigned']
case 289 :
record_syscall("sys_send");
log_32(env->regs[0], "int");
log_pointer(env->regs[1], " void __user *");
log_32(env->regs[2], " size_t");
log_32(env->regs[3], " unsigned");
finish_syscall();
break;
// 290 long sys_sendto ['int', ' void __user *', ' size_t', ' unsigned', 'struct sockaddr __user *', ' int']
case 290 :
record_syscall("sys_sendto");
log_32(env->regs[0], "int");
log_pointer(env->regs[1], " void __user *");
log_32(env->regs[2], " size_t");
log_32(env->regs[3], " unsigned");
log_pointer(env->regs[4], "struct sockaddr __user *");
log_32(env->regs[5], " int");
finish_syscall();
break;
// 291 long sys_recv ['int', ' void __user *', ' size_t', ' unsigned']
case 291 :
record_syscall("sys_recv");
log_32(env->regs[0], "int");
log_pointer(env->regs[1], " void __user *");
log_32(env->regs[2], " size_t");
log_32(env->regs[3], " unsigned");
finish_syscall();
break;
// 292 long sys_recvfrom ['int', ' void __user *', ' size_t', ' unsigned', 'struct sockaddr __user *', ' int __user *']
case 292 :
record_syscall("sys_recvfrom");
log_32(env->regs[0], "int");
log_pointer(env->regs[1], " void __user *");
log_32(env->regs[2], " size_t");
log_32(env->regs[3], " unsigned");
log_pointer(env->regs[4], "struct sockaddr __user *");
log_pointer(env->regs[5], " int __user *");
finish_syscall();
break;
// 293 long sys_shutdown ['int', ' int']
case 293 :
record_syscall("sys_shutdown");
log_32(env->regs[0], "int");
log_32(env->regs[1], " int");
finish_syscall();
break;
// 294 long sys_setsockopt ['int fd', ' int level', ' int optname', 'char __user *optval', ' int optlen']
case 294 :
record_syscall("sys_setsockopt");
log_32(env->regs[0], "int fd");
log_32(env->regs[1], " int level");
log_32(env->regs[2], " int optname");
log_string(env->regs[3], "char __user *optval");
log_32(env->regs[4], " int optlen");
finish_syscall();
break;
// 295 long sys_getsockopt ['int fd', ' int level', ' int optname', 'char __user *optval', ' int __user *optlen']
case 295 :
record_syscall("sys_getsockopt");
log_32(env->regs[0], "int fd");
log_32(env->regs[1], " int level");
log_32(env->regs[2], " int optname");
log_string(env->regs[3], "char __user *optval");
log_pointer(env->regs[4], " int __user *optlen");
finish_syscall();
break;
// 296 long sys_sendmsg ['int fd', ' struct msghdr __user *msg', ' unsigned flags']
case 296 :
record_syscall("sys_sendmsg");
log_32(env->regs[0], "int fd");
log_pointer(env->regs[1], " struct msghdr __user *msg");
log_32(env->regs[2], " unsigned flags");
finish_syscall();
break;
// 297 long sys_recvmsg ['int fd', ' struct msghdr __user *msg', ' unsigned flags']
case 297 :
record_syscall("sys_recvmsg");
log_32(env->regs[0], "int fd");
log_pointer(env->regs[1], " struct msghdr __user *msg");
log_32(env->regs[2], " unsigned flags");
finish_syscall();
break;
// 298 long sys_semop ['int semid', ' struct sembuf __user *sops', 'unsigned nsops']
case 298 :
record_syscall("sys_semop");
log_32(env->regs[0], "int semid");
log_pointer(env->regs[1], " struct sembuf __user *sops");
log_32(env->regs[2], "unsigned nsops");
finish_syscall();
break;
// 299 long sys_semget ['key_t key', ' int nsems', ' int semflg']
case 299 :
record_syscall("sys_semget");
log_32(env->regs[0], "key_t key");
log_32(env->regs[1], " int nsems");
log_32(env->regs[2], " int semflg");
finish_syscall();
break;
// 300 long sys_semctl ['int semid', ' int semnum', ' int cmd', ' union semun arg']
case 300 :
record_syscall("sys_semctl");
log_32(env->regs[0], "int semid");
log_32(env->regs[1], " int semnum");
log_32(env->regs[2], " int cmd");
log_32(env->regs[3], " union semun arg");
finish_syscall();
break;
// 301 long sys_msgsnd ['int msqid', ' struct msgbuf __user *msgp', 'size_t msgsz', ' int msgflg']
case 301 :
record_syscall("sys_msgsnd");
log_32(env->regs[0], "int msqid");
log_pointer(env->regs[1], " struct msgbuf __user *msgp");
log_32(env->regs[2], "size_t msgsz");
log_32(env->regs[3], " int msgflg");
finish_syscall();
break;
// 302 long sys_msgrcv ['int msqid', ' struct msgbuf __user *msgp', 'size_t msgsz', ' long msgtyp', ' int msgflg']
case 302 :
record_syscall("sys_msgrcv");
log_32(env->regs[0], "int msqid");
log_pointer(env->regs[1], " struct msgbuf __user *msgp");
log_32(env->regs[2], "size_t msgsz");
log_32(env->regs[3], " long msgtyp");
log_32(env->regs[4], " int msgflg");
finish_syscall();
break;
// 303 long sys_msgget ['key_t key', ' int msgflg']
case 303 :
record_syscall("sys_msgget");
log_32(env->regs[0], "key_t key");
log_32(env->regs[1], " int msgflg");
finish_syscall();
break;
// 304 long sys_msgctl ['int msqid', ' int cmd', ' struct msqid_ds __user *buf']
case 304 :
record_syscall("sys_msgctl");
log_32(env->regs[0], "int msqid");
log_32(env->regs[1], " int cmd");
log_pointer(env->regs[2], " struct msqid_ds __user *buf");
finish_syscall();
break;
// 305 long sys_shmat ['int shmid', ' char __user *shmaddr', ' int shmflg']
case 305 :
record_syscall("sys_shmat");
log_32(env->regs[0], "int shmid");
log_string(env->regs[1], " char __user *shmaddr");
log_32(env->regs[2], " int shmflg");
finish_syscall();
break;
// 306 long sys_shmdt ['char __user *shmaddr']
case 306 :
record_syscall("sys_shmdt");
log_string(env->regs[0], "char __user *shmaddr");
finish_syscall();
break;
// 307 long sys_shmget ['key_t key', ' size_t size', ' int flag']
case 307 :
record_syscall("sys_shmget");
log_32(env->regs[0], "key_t key");
log_32(env->regs[1], " size_t size");
log_32(env->regs[2], " int flag");
finish_syscall();
break;
// 308 long sys_shmctl ['int shmid', ' int cmd', ' struct shmid_ds __user *buf']
case 308 :
record_syscall("sys_shmctl");
log_32(env->regs[0], "int shmid");
log_32(env->regs[1], " int cmd");
log_pointer(env->regs[2], " struct shmid_ds __user *buf");
finish_syscall();
break;
// 309 long sys_add_key ['const char __user *_type', 'const char __user *_description', 'const void __user *_payload', 'size_t plen', 'key_serial_t destringid']
case 309 :
record_syscall("sys_add_key");
log_string(env->regs[0], "const char __user *_type");
log_string(env->regs[1], "const char __user *_description");
log_pointer(env->regs[2], "const void __user *_payload");
log_32(env->regs[3], "size_t plen");
log_32(env->regs[4], "key_serial_t destringid");
finish_syscall();
break;
// 310 long sys_request_key ['const char __user *_type', 'const char __user *_description', 'const char __user *_callout_info', 'key_serial_t destringid']
case 310 :
record_syscall("sys_request_key");
log_string(env->regs[0], "const char __user *_type");
log_string(env->regs[1], "const char __user *_description");
log_string(env->regs[2], "const char __user *_callout_info");
log_32(env->regs[3], "key_serial_t destringid");
finish_syscall();
break;
// 311 long sys_keyctl ['int cmd', ' unsigned long arg2', ' unsigned long arg3', 'unsigned long arg4', ' unsigned long arg5']
case 311 :
record_syscall("sys_keyctl");
log_32(env->regs[0], "int cmd");
log_32(env->regs[1], " unsigned long arg2");
log_32(env->regs[2], " unsigned long arg3");
log_32(env->regs[3], "unsigned long arg4");
log_32(env->regs[4], " unsigned long arg5");
finish_syscall();
break;
// 312 long sys_semtimedop ['int semid', ' struct sembuf __user *sops', 'unsigned nsops', 'const struct timespec __user *timeout']
case 312 :
record_syscall("sys_semtimedop");
log_32(env->regs[0], "int semid");
log_pointer(env->regs[1], " struct sembuf __user *sops");
log_32(env->regs[2], "unsigned nsops");
log_pointer(env->regs[3], "const struct timespec __user *timeout");
finish_syscall();
break;
// 314 long sys_ioprio_set ['int which', ' int who', ' int ioprio']
case 314 :
record_syscall("sys_ioprio_set");
log_32(env->regs[0], "int which");
log_32(env->regs[1], " int who");
log_32(env->regs[2], " int ioprio");
finish_syscall();
break;
// 315 long sys_ioprio_get ['int which', ' int who']
case 315 :
record_syscall("sys_ioprio_get");
log_32(env->regs[0], "int which");
log_32(env->regs[1], " int who");
finish_syscall();
break;
// 316 long sys_inotify_init ['void']
case 316 :
record_syscall("sys_inotify_init");
finish_syscall();
break;
// 317 long sys_inotify_add_watch ['int fd', ' const char __user *path', 'u32 mask']
case 317 :
record_syscall("sys_inotify_add_watch");
log_32(env->regs[0], "int fd");
log_string(env->regs[1], " const char __user *path");
log_32(env->regs[2], "u32 mask");
finish_syscall();
break;
// 318 long sys_inotify_rm_watch ['int fd', ' __s32 wd']
case 318 :
record_syscall("sys_inotify_rm_watch");
log_32(env->regs[0], "int fd");
log_32(env->regs[1], " __s32 wd");
finish_syscall();
break;
// 319 long sys_mbind ['unsigned long start', ' unsigned long len', 'unsigned long mode', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned flags']
case 319 :
record_syscall("sys_mbind");
log_32(env->regs[0], "unsigned long start");
log_32(env->regs[1], " unsigned long len");
log_32(env->regs[2], "unsigned long mode");
log_pointer(env->regs[3], "unsigned long __user *nmask");
log_32(env->regs[4], "unsigned long maxnode");
log_32(env->regs[5], "unsigned flags");
finish_syscall();
break;
// 320 long sys_get_mempolicy ['int __user *policy', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned long addr', ' unsigned long flags']
case 320 :
record_syscall("sys_get_mempolicy");
log_pointer(env->regs[0], "int __user *policy");
log_pointer(env->regs[1], "unsigned long __user *nmask");
log_32(env->regs[2], "unsigned long maxnode");
log_32(env->regs[3], "unsigned long addr");
log_32(env->regs[4], " unsigned long flags");
finish_syscall();
break;
// 321 long sys_set_mempolicy ['int mode', ' unsigned long __user *nmask', 'unsigned long maxnode']
case 321 :
record_syscall("sys_set_mempolicy");
log_32(env->regs[0], "int mode");
log_pointer(env->regs[1], " unsigned long __user *nmask");
log_32(env->regs[2], "unsigned long maxnode");
finish_syscall();
break;
// 322 long sys_openat ['int dfd', ' const char __user *filename', ' int flags', 'int mode']
case 322 :
record_syscall("sys_openat");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " const char __user *filename");
log_32(env->regs[2], " int flags");
log_32(env->regs[3], "int mode");
finish_syscall();
break;
// 323 long sys_mkdirat ['int dfd', ' const char __user * pathname', ' int mode']
case 323 :
record_syscall("sys_mkdirat");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " const char __user * pathname");
log_32(env->regs[2], " int mode");
finish_syscall();
break;
// 324 long sys_mknodat ['int dfd', ' const char __user * filename', ' int mode', 'unsigned dev']
case 324 :
record_syscall("sys_mknodat");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " const char __user * filename");
log_32(env->regs[2], " int mode");
log_32(env->regs[3], "unsigned dev");
finish_syscall();
break;
// 325 long sys_fchownat ['int dfd', ' const char __user *filename', ' uid_t user', 'gid_t group', ' int flag']
case 325 :
record_syscall("sys_fchownat");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " const char __user *filename");
log_32(env->regs[2], " uid_t user");
log_32(env->regs[3], "gid_t group");
log_32(env->regs[4], " int flag");
finish_syscall();
break;
// 326 long sys_futimesat ['int dfd', ' char __user *filename', 'struct timeval __user *utimes']
case 326 :
record_syscall("sys_futimesat");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " char __user *filename");
log_pointer(env->regs[2], "struct timeval __user *utimes");
finish_syscall();
break;
// 327 long sys_fstatat64 ['int dfd', ' char __user *filename', 'struct stat64 __user *statbuf', ' int flag']
case 327 :
record_syscall("sys_fstatat64");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " char __user *filename");
log_pointer(env->regs[2], "struct stat64 __user *statbuf");
log_32(env->regs[3], " int flag");
finish_syscall();
break;
// 328 long sys_unlinkat ['int dfd', ' const char __user * pathname', ' int flag']
case 328 :
record_syscall("sys_unlinkat");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " const char __user * pathname");
log_32(env->regs[2], " int flag");
finish_syscall();
break;
// 329 long sys_renameat ['int olddfd', ' const char __user * oldname', 'int newdfd', ' const char __user * newname']
case 329 :
record_syscall("sys_renameat");
log_32(env->regs[0], "int olddfd");
log_string(env->regs[1], " const char __user * oldname");
log_32(env->regs[2], "int newdfd");
log_string(env->regs[3], " const char __user * newname");
finish_syscall();
break;
// 330 long sys_linkat ['int olddfd', ' const char __user *oldname', 'int newdfd', ' const char __user *newname', ' int flags']
case 330 :
record_syscall("sys_linkat");
log_32(env->regs[0], "int olddfd");
log_string(env->regs[1], " const char __user *oldname");
log_32(env->regs[2], "int newdfd");
log_string(env->regs[3], " const char __user *newname");
log_32(env->regs[4], " int flags");
finish_syscall();
break;
// 331 long sys_symlinkat ['const char __user * oldname', 'int newdfd', ' const char __user * newname']
case 331 :
record_syscall("sys_symlinkat");
log_string(env->regs[0], "const char __user * oldname");
log_32(env->regs[1], "int newdfd");
log_string(env->regs[2], " const char __user * newname");
finish_syscall();
break;
// 332 long sys_readlinkat ['int dfd', ' const char __user *path', ' char __user *buf', 'int bufsiz']
case 332 :
record_syscall("sys_readlinkat");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " const char __user *path");
log_pointer(env->regs[2], " char __user *buf");
log_32(env->regs[3], "int bufsiz");
finish_syscall();
break;
// 333 long sys_fchmodat ['int dfd', ' const char __user * filename', 'mode_t mode']
case 333 :
record_syscall("sys_fchmodat");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " const char __user * filename");
log_32(env->regs[2], "mode_t mode");
finish_syscall();
break;
// 334 long sys_faccessat ['int dfd', ' const char __user *filename', ' int mode']
case 334 :
record_syscall("sys_faccessat");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " const char __user *filename");
log_32(env->regs[2], " int mode");
finish_syscall();
break;
// 337 long sys_unshare ['unsigned long unshare_flags']
case 337 :
record_syscall("sys_unshare");
log_32(env->regs[0], "unsigned long unshare_flags");
finish_syscall();
break;
// 338 long sys_set_robust_list ['struct robust_list_head __user *head', 'size_t len']
case 338 :
record_syscall("sys_set_robust_list");
log_pointer(env->regs[0], "struct robust_list_head __user *head");
log_32(env->regs[1], "size_t len");
finish_syscall();
break;
// 339 long sys_get_robust_list ['int pid', 'struct robust_list_head __user * __user *head_ptr', 'size_t __user *len_ptr']
case 339 :
record_syscall("sys_get_robust_list");
log_32(env->regs[0], "int pid");
log_pointer(env->regs[1], "struct robust_list_head __user * __user *head_ptr");
log_pointer(env->regs[2], "size_t __user *len_ptr");
finish_syscall();
break;
// 340 long sys_splice ['int fd_in', ' loff_t __user *off_in', 'int fd_out', ' loff_t __user *off_out', 'size_t len', ' unsigned int flags']
case 340 :
record_syscall("sys_splice");
log_32(env->regs[0], "int fd_in");
log_pointer(env->regs[1], " loff_t __user *off_in");
log_32(env->regs[2], "int fd_out");
log_pointer(env->regs[3], " loff_t __user *off_out");
log_32(env->regs[4], "size_t len");
log_32(env->regs[5], " unsigned int flags");
finish_syscall();
break;
// 341 long sys_sync_file_range2 ['int fd', ' unsigned int flags', 'loff_t offset', ' loff_t nbytes']
case 341 :
record_syscall("sys_sync_file_range2");
log_32(env->regs[0], "int fd");
log_32(env->regs[1], " unsigned int flags");
log_64(env->regs[2], env->regs[3], "loff_t offset");
log_64(env->regs[4], env->regs[5], " loff_t nbytes");
finish_syscall();
break;
// 342 long sys_tee ['int fdin', ' int fdout', ' size_t len', ' unsigned int flags']
case 342 :
record_syscall("sys_tee");
log_32(env->regs[0], "int fdin");
log_32(env->regs[1], " int fdout");
log_32(env->regs[2], " size_t len");
log_32(env->regs[3], " unsigned int flags");
finish_syscall();
break;
// 343 long sys_vmsplice ['int fd', ' const struct iovec __user *iov', 'unsigned long nr_segs', ' unsigned int flags']
case 343 :
record_syscall("sys_vmsplice");
log_32(env->regs[0], "int fd");
log_pointer(env->regs[1], " const struct iovec __user *iov");
log_32(env->regs[2], "unsigned long nr_segs");
log_32(env->regs[3], " unsigned int flags");
finish_syscall();
break;
// 344 long sys_move_pages ['pid_t pid', ' unsigned long nr_pages', 'const void __user * __user *pages', 'const int __user *nodes', 'int __user *status', 'int flags']
case 344 :
record_syscall("sys_move_pages");
log_32(env->regs[0], "pid_t pid");
log_32(env->regs[1], " unsigned long nr_pages");
log_pointer(env->regs[2], "const void __user * __user *pages");
log_pointer(env->regs[3], "const int __user *nodes");
log_pointer(env->regs[4], "int __user *status");
log_32(env->regs[5], "int flags");
finish_syscall();
break;
// 345 long sys_getcpu ['unsigned __user *cpu', ' unsigned __user *node', ' struct getcpu_cache __user *cache']
case 345 :
record_syscall("sys_getcpu");
log_pointer(env->regs[0], "unsigned __user *cpu");
log_pointer(env->regs[1], " unsigned __user *node");
log_pointer(env->regs[2], " struct getcpu_cache __user *cache");
finish_syscall();
break;
// 347 long sys_kexec_load ['unsigned long entry', ' unsigned long nr_segments', 'struct kexec_segment __user *segments', 'unsigned long flags']
case 347 :
record_syscall("sys_kexec_load");
log_32(env->regs[0], "unsigned long entry");
log_32(env->regs[1], " unsigned long nr_segments");
log_pointer(env->regs[2], "struct kexec_segment __user *segments");
log_32(env->regs[3], "unsigned long flags");
finish_syscall();
break;
// 348 long sys_utimensat ['int dfd', ' char __user *filename', 'struct timespec __user *utimes', ' int flags']
case 348 :
record_syscall("sys_utimensat");
log_32(env->regs[0], "int dfd");
log_string(env->regs[1], " char __user *filename");
log_pointer(env->regs[2], "struct timespec __user *utimes");
log_32(env->regs[3], " int flags");
finish_syscall();
break;
// 349 long sys_signalfd ['int ufd', ' sigset_t __user *user_mask', ' size_t sizemask']
case 349 :
record_syscall("sys_signalfd");
log_32(env->regs[0], "int ufd");
log_pointer(env->regs[1], " sigset_t __user *user_mask");
log_32(env->regs[2], " size_t sizemask");
finish_syscall();
break;
// 350 long sys_timerfd_create ['int clockid', ' int flags']
case 350 :
record_syscall("sys_timerfd_create");
log_32(env->regs[0], "int clockid");
log_32(env->regs[1], " int flags");
finish_syscall();
break;
// 351 long sys_eventfd ['unsigned int count']
case 351 :
record_syscall("sys_eventfd");
log_32(env->regs[0], "unsigned int count");
finish_syscall();
break;
// 352 long sys_fallocate ['int fd', ' int mode', ' loff_t offset', ' loff_t len']
case 352 :
record_syscall("sys_fallocate");
log_32(env->regs[0], "int fd");
log_32(env->regs[1], " int mode");
log_64(env->regs[2], env->regs[3], " loff_t offset");
log_64(env->regs[4], env->regs[5], " loff_t len");
finish_syscall();
break;
// 353 long sys_timerfd_settime ['int ufd', ' int flags', 'const struct itimerspec __user *utmr', 'struct itimerspec __user *otmr']
case 353 :
record_syscall("sys_timerfd_settime");
log_32(env->regs[0], "int ufd");
log_32(env->regs[1], " int flags");
log_pointer(env->regs[2], "const struct itimerspec __user *utmr");
log_pointer(env->regs[3], "struct itimerspec __user *otmr");
finish_syscall();
break;
// 354 long sys_timerfd_gettime ['int ufd', ' struct itimerspec __user *otmr']
case 354 :
record_syscall("sys_timerfd_gettime");
log_32(env->regs[0], "int ufd");
log_pointer(env->regs[1], " struct itimerspec __user *otmr");
finish_syscall();
break;
// 355 long sys_signalfd4 ['int ufd', ' sigset_t __user *user_mask', ' size_t sizemask', ' int flags']
case 355 :
record_syscall("sys_signalfd4");
log_32(env->regs[0], "int ufd");
log_pointer(env->regs[1], " sigset_t __user *user_mask");
log_32(env->regs[2], " size_t sizemask");
log_32(env->regs[3], " int flags");
finish_syscall();
break;
// 356 long sys_eventfd2 ['unsigned int count', ' int flags']
case 356 :
record_syscall("sys_eventfd2");
log_32(env->regs[0], "unsigned int count");
log_32(env->regs[1], " int flags");
finish_syscall();
break;
// 357 long sys_epoll_create1 ['int flags']
case 357 :
record_syscall("sys_epoll_create1");
log_32(env->regs[0], "int flags");
finish_syscall();
break;
// 358 long sys_dup3 ['unsigned int oldfd', ' unsigned int newfd', ' int flags']
case 358 :
record_syscall("sys_dup3");
log_32(env->regs[0], "unsigned int oldfd");
log_32(env->regs[1], " unsigned int newfd");
log_32(env->regs[2], " int flags");
finish_syscall();
break;
// 359 long sys_pipe2 ['int __user *', ' int']
case 359 :
record_syscall("sys_pipe2");
log_pointer(env->regs[0], "int __user *");
log_32(env->regs[1], " int");
finish_syscall();
break;
// 360 long sys_inotify_init1 ['int flags']
case 360 :
record_syscall("sys_inotify_init1");
log_32(env->regs[0], "int flags");
finish_syscall();
break;
// 10420225 long ARM_breakpoint ['void']
case 10420225 :
record_syscall("ARM_breakpoint");
finish_syscall();
break;
// 10420226 long ARM_cacheflush ['unsigned long start', ' unsigned long end', ' unsigned long flags']
case 10420226 :
record_syscall("ARM_cacheflush");
log_32(env->regs[0], "unsigned long start");
log_32(env->regs[1], " unsigned long end");
log_32(env->regs[2], " unsigned long flags");
finish_syscall();
break;
// 10420227 long ARM_user26_mode ['void']
case 10420227 :
record_syscall("ARM_user26_mode");
finish_syscall();
break;
// 10420228 long ARM_usr32_mode ['void']
case 10420228 :
record_syscall("ARM_usr32_mode");
finish_syscall();
break;
// 10420229 long ARM_set_tls ['unsigned long arg']
case 10420229 :
record_syscall("ARM_set_tls");
log_32(env->regs[0], "unsigned long arg");
finish_syscall();
break;
// 10485744 int ARM_cmpxchg ['unsigned long val', ' unsigned long src', ' unsigned long* dest']
case 10485744 :
record_syscall("ARM_cmpxchg");
log_32(env->regs[0], "unsigned long val");
log_32(env->regs[1], " unsigned long src");
log_pointer(env->regs[2], " unsigned long* dest");
finish_syscall();
break;
// 10420224 long ARM_null_segfault ['void']
case 10420224 :
record_syscall("ARM_null_segfault");
finish_syscall();
break;
default:
record_syscall("UNKNOWN");
}
