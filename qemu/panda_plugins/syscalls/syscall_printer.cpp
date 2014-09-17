#ifdef TARGET_ARM
switch( env->regs[7] ){
// we use std::string so that we only do lookups into guest memory once and cache the result
// 0 long sys_restart_syscall ['void']
case 0: {
record_syscall("sys_restart_syscall");
syscalls::call_sys_restart_syscall_callback(env,pc);
PPP_RUN_CB(on_sys_restart_syscall, env,pc)
finish_syscall();
}; break;
// 1 long sys_exit ['int error_code']
case 1: {
record_syscall("sys_exit");
int32_t error_code = log_s32(env->regs[0], "int error_code");
syscalls::call_sys_exit_callback(env,pc,error_code);
PPP_RUN_CB(on_sys_exit, env,pc,error_code)
finish_syscall();
}; break;
// 2 unsigned long fork ['void']
case 2: {
record_syscall("fork");
syscalls::call_fork_callback(env,pc);
PPP_RUN_CB(on_fork, env,pc)
finish_syscall();
}; break;
// 3 long sys_read ['unsigned int fd', ' char __user *buf', ' size_t count']
case 3: {
record_syscall("sys_read");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
target_ulong buf = log_pointer(env->regs[1], " char __user *buf");
uint32_t count = log_32(env->regs[2], " size_t count");
syscalls::call_sys_read_callback(env,pc,fd,buf,count);
PPP_RUN_CB(on_sys_read, env,pc,fd,buf,count)
finish_syscall();
}; break;
// 4 long sys_write ['unsigned int fd', ' const char __user *buf', 'size_t count']
case 4: {
record_syscall("sys_write");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
target_ulong buf = log_pointer(env->regs[1], " const char __user *buf");
uint32_t count = log_32(env->regs[2], "size_t count");
syscalls::call_sys_write_callback(env,pc,fd,buf,count);
PPP_RUN_CB(on_sys_write, env,pc,fd,buf,count)
finish_syscall();
}; break;
// 5 long sys_open ['const char __user *filename', 'int flags', ' int mode']
case 5: {
record_syscall("sys_open");
syscalls::string filename = log_string(env->regs[0], "const char __user *filename");
int32_t flags = log_s32(env->regs[1], "int flags");
int32_t mode = log_s32(env->regs[2], " int mode");
syscalls::call_sys_open_callback(env,pc,filename,flags,mode);
PPP_RUN_CB(on_sys_open, env,pc,filename.get_vaddr(),flags,mode)
finish_syscall();
}; break;
// 6 long sys_close ['unsigned int fd']
case 6: {
record_syscall("sys_close");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
syscalls::call_sys_close_callback(env,pc,fd);
PPP_RUN_CB(on_sys_close, env,pc,fd)
finish_syscall();
}; break;
// 8 long sys_creat ['const char __user *pathname', ' int mode']
case 8: {
record_syscall("sys_creat");
syscalls::string pathname = log_string(env->regs[0], "const char __user *pathname");
int32_t mode = log_s32(env->regs[1], " int mode");
syscalls::call_sys_creat_callback(env,pc,pathname,mode);
PPP_RUN_CB(on_sys_creat, env,pc,pathname.get_vaddr(),mode)
finish_syscall();
}; break;
// 9 long sys_link ['const char __user *oldname', 'const char __user *newname']
case 9: {
record_syscall("sys_link");
syscalls::string oldname = log_string(env->regs[0], "const char __user *oldname");
syscalls::string newname = log_string(env->regs[1], "const char __user *newname");
syscalls::call_sys_link_callback(env,pc,oldname,newname);
PPP_RUN_CB(on_sys_link, env,pc,oldname.get_vaddr(),newname.get_vaddr())
finish_syscall();
}; break;
// 10 long sys_unlink ['const char __user *pathname']
case 10: {
record_syscall("sys_unlink");
syscalls::string pathname = log_string(env->regs[0], "const char __user *pathname");
syscalls::call_sys_unlink_callback(env,pc,pathname);
PPP_RUN_CB(on_sys_unlink, env,pc,pathname.get_vaddr())
finish_syscall();
}; break;
// 11 unsigned long execve ['const char *filename', ' char *const argv[]', ' char *const envp[]']
case 11: {
record_syscall("execve");
syscalls::string filename = log_string(env->regs[0], "const char *filename");
target_ulong argv = log_pointer(env->regs[1], " char *const argv[]");
target_ulong envp = log_pointer(env->regs[2], " char *const envp[]");
syscalls::call_execve_callback(env,pc,filename,argv,envp);
PPP_RUN_CB(on_execve, env,pc,filename.get_vaddr(),argv,envp)
finish_syscall();
}; break;
// 12 long sys_chdir ['const char __user *filename']
case 12: {
record_syscall("sys_chdir");
syscalls::string filename = log_string(env->regs[0], "const char __user *filename");
syscalls::call_sys_chdir_callback(env,pc,filename);
PPP_RUN_CB(on_sys_chdir, env,pc,filename.get_vaddr())
finish_syscall();
}; break;
// 14 long sys_mknod ['const char __user *filename', ' int mode', 'unsigned dev']
case 14: {
record_syscall("sys_mknod");
syscalls::string filename = log_string(env->regs[0], "const char __user *filename");
int32_t mode = log_s32(env->regs[1], " int mode");
uint32_t dev = log_32(env->regs[2], "unsigned dev");
syscalls::call_sys_mknod_callback(env,pc,filename,mode,dev);
PPP_RUN_CB(on_sys_mknod, env,pc,filename.get_vaddr(),mode,dev)
finish_syscall();
}; break;
// 15 long sys_chmod ['const char __user *filename', ' mode_t mode']
case 15: {
record_syscall("sys_chmod");
syscalls::string filename = log_string(env->regs[0], "const char __user *filename");
uint32_t mode = log_32(env->regs[1], " mode_t mode");
syscalls::call_sys_chmod_callback(env,pc,filename,mode);
PPP_RUN_CB(on_sys_chmod, env,pc,filename.get_vaddr(),mode)
finish_syscall();
}; break;
// 16 long sys_lchown16 ['const char __user *filename', 'old_uid_t user', ' old_gid_t group']
case 16: {
record_syscall("sys_lchown16");
syscalls::string filename = log_string(env->regs[0], "const char __user *filename");
uint32_t user = log_32(env->regs[1], "old_uid_t user");
uint32_t group = log_32(env->regs[2], " old_gid_t group");
syscalls::call_sys_lchown16_callback(env,pc,filename,user,group);
PPP_RUN_CB(on_sys_lchown16, env,pc,filename.get_vaddr(),user,group)
finish_syscall();
}; break;
// 19 long sys_lseek ['unsigned int fd', ' off_t offset', 'unsigned int origin']
case 19: {
record_syscall("sys_lseek");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t offset = log_32(env->regs[1], " off_t offset");
uint32_t origin = log_32(env->regs[2], "unsigned int origin");
syscalls::call_sys_lseek_callback(env,pc,fd,offset,origin);
PPP_RUN_CB(on_sys_lseek, env,pc,fd,offset,origin)
finish_syscall();
}; break;
// 20 long sys_getpid ['void']
case 20: {
record_syscall("sys_getpid");
syscalls::call_sys_getpid_callback(env,pc);
PPP_RUN_CB(on_sys_getpid, env,pc)
finish_syscall();
}; break;
// 21 long sys_mount ['char __user *dev_name', ' char __user *dir_name', 'char __user *type', ' unsigned long flags', 'void __user *data']
case 21: {
record_syscall("sys_mount");
syscalls::string dev_name = log_string(env->regs[0], "char __user *dev_name");
syscalls::string dir_name = log_string(env->regs[1], " char __user *dir_name");
syscalls::string type = log_string(env->regs[2], "char __user *type");
uint32_t flags = log_32(env->regs[3], " unsigned long flags");
target_ulong data_arg = log_pointer(env->regs[4], "void __user *data");
syscalls::call_sys_mount_callback(env,pc,dev_name,dir_name,type,flags,data_arg);
PPP_RUN_CB(on_sys_mount, env,pc,dev_name.get_vaddr(),dir_name.get_vaddr(),type.get_vaddr(),flags,data_arg)
finish_syscall();
}; break;
// 23 long sys_setuid16 ['old_uid_t uid']
case 23: {
record_syscall("sys_setuid16");
uint32_t uid = log_32(env->regs[0], "old_uid_t uid");
syscalls::call_sys_setuid16_callback(env,pc,uid);
PPP_RUN_CB(on_sys_setuid16, env,pc,uid)
finish_syscall();
}; break;
// 24 long sys_getuid16 ['void']
case 24: {
record_syscall("sys_getuid16");
syscalls::call_sys_getuid16_callback(env,pc);
PPP_RUN_CB(on_sys_getuid16, env,pc)
finish_syscall();
}; break;
// 26 long sys_ptrace ['long request', ' long pid', ' long addr', ' long data']
case 26: {
record_syscall("sys_ptrace");
int32_t request = log_s32(env->regs[0], "long request");
int32_t pid = log_s32(env->regs[1], " long pid");
int32_t addr = log_s32(env->regs[2], " long addr");
int32_t data_arg = log_s32(env->regs[3], " long data");
syscalls::call_sys_ptrace_callback(env,pc,request,pid,addr,data_arg);
PPP_RUN_CB(on_sys_ptrace, env,pc,request,pid,addr,data_arg)
finish_syscall();
}; break;
// 29 long sys_pause ['void']
case 29: {
record_syscall("sys_pause");
syscalls::call_sys_pause_callback(env,pc);
PPP_RUN_CB(on_sys_pause, env,pc)
finish_syscall();
}; break;
// 33 long sys_access ['const char __user *filename', ' int mode']
case 33: {
record_syscall("sys_access");
syscalls::string filename = log_string(env->regs[0], "const char __user *filename");
int32_t mode = log_s32(env->regs[1], " int mode");
syscalls::call_sys_access_callback(env,pc,filename,mode);
PPP_RUN_CB(on_sys_access, env,pc,filename.get_vaddr(),mode)
finish_syscall();
}; break;
// 34 long sys_nice ['int increment']
case 34: {
record_syscall("sys_nice");
int32_t increment = log_s32(env->regs[0], "int increment");
syscalls::call_sys_nice_callback(env,pc,increment);
PPP_RUN_CB(on_sys_nice, env,pc,increment)
finish_syscall();
}; break;
// 36 long sys_sync ['void']
case 36: {
record_syscall("sys_sync");
syscalls::call_sys_sync_callback(env,pc);
PPP_RUN_CB(on_sys_sync, env,pc)
finish_syscall();
}; break;
// 37 long sys_kill ['int pid', ' int sig']
case 37: {
record_syscall("sys_kill");
int32_t pid = log_s32(env->regs[0], "int pid");
int32_t sig = log_s32(env->regs[1], " int sig");
syscalls::call_sys_kill_callback(env,pc,pid,sig);
PPP_RUN_CB(on_sys_kill, env,pc,pid,sig)
finish_syscall();
}; break;
// 38 long sys_rename ['const char __user *oldname', 'const char __user *newname']
case 38: {
record_syscall("sys_rename");
syscalls::string oldname = log_string(env->regs[0], "const char __user *oldname");
syscalls::string newname = log_string(env->regs[1], "const char __user *newname");
syscalls::call_sys_rename_callback(env,pc,oldname,newname);
PPP_RUN_CB(on_sys_rename, env,pc,oldname.get_vaddr(),newname.get_vaddr())
finish_syscall();
}; break;
// 39 long sys_mkdir ['const char __user *pathname', ' int mode']
case 39: {
record_syscall("sys_mkdir");
syscalls::string pathname = log_string(env->regs[0], "const char __user *pathname");
int32_t mode = log_s32(env->regs[1], " int mode");
syscalls::call_sys_mkdir_callback(env,pc,pathname,mode);
PPP_RUN_CB(on_sys_mkdir, env,pc,pathname.get_vaddr(),mode)
finish_syscall();
}; break;
// 40 long sys_rmdir ['const char __user *pathname']
case 40: {
record_syscall("sys_rmdir");
syscalls::string pathname = log_string(env->regs[0], "const char __user *pathname");
syscalls::call_sys_rmdir_callback(env,pc,pathname);
PPP_RUN_CB(on_sys_rmdir, env,pc,pathname.get_vaddr())
finish_syscall();
}; break;
// 41 long sys_dup ['unsigned int fildes']
case 41: {
record_syscall("sys_dup");
uint32_t fildes = log_32(env->regs[0], "unsigned int fildes");
syscalls::call_sys_dup_callback(env,pc,fildes);
PPP_RUN_CB(on_sys_dup, env,pc,fildes)
finish_syscall();
}; break;
// 42 long sys_pipe ['int __user *']
case 42: {
record_syscall("sys_pipe");
target_ulong arg0 = log_pointer(env->regs[0], "int __user *");
syscalls::call_sys_pipe_callback(env,pc,arg0);
PPP_RUN_CB(on_sys_pipe, env,pc,arg0)
finish_syscall();
}; break;
// 43 long sys_times ['struct tms __user *tbuf']
case 43: {
record_syscall("sys_times");
target_ulong tbuf = log_pointer(env->regs[0], "struct tms __user *tbuf");
syscalls::call_sys_times_callback(env,pc,tbuf);
PPP_RUN_CB(on_sys_times, env,pc,tbuf)
finish_syscall();
}; break;
// 45 long sys_brk ['unsigned long brk']
case 45: {
record_syscall("sys_brk");
uint32_t brk = log_32(env->regs[0], "unsigned long brk");
syscalls::call_sys_brk_callback(env,pc,brk);
PPP_RUN_CB(on_sys_brk, env,pc,brk)
finish_syscall();
}; break;
// 46 long sys_setgid16 ['old_gid_t gid']
case 46: {
record_syscall("sys_setgid16");
uint32_t gid = log_32(env->regs[0], "old_gid_t gid");
syscalls::call_sys_setgid16_callback(env,pc,gid);
PPP_RUN_CB(on_sys_setgid16, env,pc,gid)
finish_syscall();
}; break;
// 47 long sys_getgid16 ['void']
case 47: {
record_syscall("sys_getgid16");
syscalls::call_sys_getgid16_callback(env,pc);
PPP_RUN_CB(on_sys_getgid16, env,pc)
finish_syscall();
}; break;
// 49 long sys_geteuid16 ['void']
case 49: {
record_syscall("sys_geteuid16");
syscalls::call_sys_geteuid16_callback(env,pc);
PPP_RUN_CB(on_sys_geteuid16, env,pc)
finish_syscall();
}; break;
// 50 long sys_getegid16 ['void']
case 50: {
record_syscall("sys_getegid16");
syscalls::call_sys_getegid16_callback(env,pc);
PPP_RUN_CB(on_sys_getegid16, env,pc)
finish_syscall();
}; break;
// 51 long sys_acct ['const char __user *name']
case 51: {
record_syscall("sys_acct");
syscalls::string name = log_string(env->regs[0], "const char __user *name");
syscalls::call_sys_acct_callback(env,pc,name);
PPP_RUN_CB(on_sys_acct, env,pc,name.get_vaddr())
finish_syscall();
}; break;
// 52 long sys_umount ['char __user *name', ' int flags']
case 52: {
record_syscall("sys_umount");
syscalls::string name = log_string(env->regs[0], "char __user *name");
int32_t flags = log_s32(env->regs[1], " int flags");
syscalls::call_sys_umount_callback(env,pc,name,flags);
PPP_RUN_CB(on_sys_umount, env,pc,name.get_vaddr(),flags)
finish_syscall();
}; break;
// 54 long sys_ioctl ['unsigned int fd', ' unsigned int cmd', 'unsigned long arg']
case 54: {
record_syscall("sys_ioctl");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t cmd = log_32(env->regs[1], " unsigned int cmd");
uint32_t arg = log_32(env->regs[2], "unsigned long arg");
syscalls::call_sys_ioctl_callback(env,pc,fd,cmd,arg);
PPP_RUN_CB(on_sys_ioctl, env,pc,fd,cmd,arg)
finish_syscall();
}; break;
// 55 long sys_fcntl ['unsigned int fd', ' unsigned int cmd', ' unsigned long arg']
case 55: {
record_syscall("sys_fcntl");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t cmd = log_32(env->regs[1], " unsigned int cmd");
uint32_t arg = log_32(env->regs[2], " unsigned long arg");
syscalls::call_sys_fcntl_callback(env,pc,fd,cmd,arg);
PPP_RUN_CB(on_sys_fcntl, env,pc,fd,cmd,arg)
finish_syscall();
}; break;
// 57 long sys_setpgid ['pid_t pid', ' pid_t pgid']
case 57: {
record_syscall("sys_setpgid");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
uint32_t pgid = log_32(env->regs[1], " pid_t pgid");
syscalls::call_sys_setpgid_callback(env,pc,pid,pgid);
PPP_RUN_CB(on_sys_setpgid, env,pc,pid,pgid)
finish_syscall();
}; break;
// 60 long sys_umask ['int mask']
case 60: {
record_syscall("sys_umask");
int32_t mask = log_s32(env->regs[0], "int mask");
syscalls::call_sys_umask_callback(env,pc,mask);
PPP_RUN_CB(on_sys_umask, env,pc,mask)
finish_syscall();
}; break;
// 61 long sys_chroot ['const char __user *filename']
case 61: {
record_syscall("sys_chroot");
syscalls::string filename = log_string(env->regs[0], "const char __user *filename");
syscalls::call_sys_chroot_callback(env,pc,filename);
PPP_RUN_CB(on_sys_chroot, env,pc,filename.get_vaddr())
finish_syscall();
}; break;
// 62 long sys_ustat ['unsigned dev', ' struct ustat __user *ubuf']
case 62: {
record_syscall("sys_ustat");
uint32_t dev = log_32(env->regs[0], "unsigned dev");
target_ulong ubuf = log_pointer(env->regs[1], " struct ustat __user *ubuf");
syscalls::call_sys_ustat_callback(env,pc,dev,ubuf);
PPP_RUN_CB(on_sys_ustat, env,pc,dev,ubuf)
finish_syscall();
}; break;
// 63 long sys_dup2 ['unsigned int oldfd', ' unsigned int newfd']
case 63: {
record_syscall("sys_dup2");
uint32_t oldfd = log_32(env->regs[0], "unsigned int oldfd");
uint32_t newfd = log_32(env->regs[1], " unsigned int newfd");
syscalls::call_sys_dup2_callback(env,pc,oldfd,newfd);
PPP_RUN_CB(on_sys_dup2, env,pc,oldfd,newfd)
finish_syscall();
}; break;
// 64 long sys_getppid ['void']
case 64: {
record_syscall("sys_getppid");
syscalls::call_sys_getppid_callback(env,pc);
PPP_RUN_CB(on_sys_getppid, env,pc)
finish_syscall();
}; break;
// 65 long sys_getpgrp ['void']
case 65: {
record_syscall("sys_getpgrp");
syscalls::call_sys_getpgrp_callback(env,pc);
PPP_RUN_CB(on_sys_getpgrp, env,pc)
finish_syscall();
}; break;
// 66 long sys_setsid ['void']
case 66: {
record_syscall("sys_setsid");
syscalls::call_sys_setsid_callback(env,pc);
PPP_RUN_CB(on_sys_setsid, env,pc)
finish_syscall();
}; break;
// 67 int sigaction ['int sig', ' const struct old_sigaction __user *act', ' struct old_sigaction __user *oact']
case 67: {
record_syscall("sigaction");
int32_t sig = log_s32(env->regs[0], "int sig");
target_ulong act = log_pointer(env->regs[1], " const struct old_sigaction __user *act");
target_ulong oact = log_pointer(env->regs[2], " struct old_sigaction __user *oact");
syscalls::call_sigaction_callback(env,pc,sig,act,oact);
PPP_RUN_CB(on_sigaction, env,pc,sig,act,oact)
finish_syscall();
}; break;
// 70 long sys_setreuid16 ['old_uid_t ruid', ' old_uid_t euid']
case 70: {
record_syscall("sys_setreuid16");
uint32_t ruid = log_32(env->regs[0], "old_uid_t ruid");
uint32_t euid = log_32(env->regs[1], " old_uid_t euid");
syscalls::call_sys_setreuid16_callback(env,pc,ruid,euid);
PPP_RUN_CB(on_sys_setreuid16, env,pc,ruid,euid)
finish_syscall();
}; break;
// 71 long sys_setregid16 ['old_gid_t rgid', ' old_gid_t egid']
case 71: {
record_syscall("sys_setregid16");
uint32_t rgid = log_32(env->regs[0], "old_gid_t rgid");
uint32_t egid = log_32(env->regs[1], " old_gid_t egid");
syscalls::call_sys_setregid16_callback(env,pc,rgid,egid);
PPP_RUN_CB(on_sys_setregid16, env,pc,rgid,egid)
finish_syscall();
}; break;
// 72 long sigsuspend ['int restart', ' unsigned long oldmask', ' old_sigset_t mask']
case 72: {
record_syscall("sigsuspend");
int32_t restart = log_s32(env->regs[0], "int restart");
uint32_t oldmask = log_32(env->regs[1], " unsigned long oldmask");
uint32_t mask = log_32(env->regs[2], " old_sigset_t mask");
syscalls::call_sigsuspend_callback(env,pc,restart,oldmask,mask);
PPP_RUN_CB(on_sigsuspend, env,pc,restart,oldmask,mask)
finish_syscall();
}; break;
// 73 long sys_sigpending ['old_sigset_t __user *set']
case 73: {
record_syscall("sys_sigpending");
target_ulong set = log_pointer(env->regs[0], "old_sigset_t __user *set");
syscalls::call_sys_sigpending_callback(env,pc,set);
PPP_RUN_CB(on_sys_sigpending, env,pc,set)
finish_syscall();
}; break;
// 74 long sys_sethostname ['char __user *name', ' int len']
case 74: {
record_syscall("sys_sethostname");
syscalls::string name = log_string(env->regs[0], "char __user *name");
int32_t len = log_s32(env->regs[1], " int len");
syscalls::call_sys_sethostname_callback(env,pc,name,len);
PPP_RUN_CB(on_sys_sethostname, env,pc,name.get_vaddr(),len)
finish_syscall();
}; break;
// 75 long sys_setrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
case 75: {
record_syscall("sys_setrlimit");
uint32_t resource = log_32(env->regs[0], "unsigned int resource");
target_ulong rlim = log_pointer(env->regs[1], "struct rlimit __user *rlim");
syscalls::call_sys_setrlimit_callback(env,pc,resource,rlim);
PPP_RUN_CB(on_sys_setrlimit, env,pc,resource,rlim)
finish_syscall();
}; break;
// 77 long sys_getrusage ['int who', ' struct rusage __user *ru']
case 77: {
record_syscall("sys_getrusage");
int32_t who = log_s32(env->regs[0], "int who");
target_ulong ru = log_pointer(env->regs[1], " struct rusage __user *ru");
syscalls::call_sys_getrusage_callback(env,pc,who,ru);
PPP_RUN_CB(on_sys_getrusage, env,pc,who,ru)
finish_syscall();
}; break;
// 78 long sys_gettimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
case 78: {
record_syscall("sys_gettimeofday");
target_ulong tv = log_pointer(env->regs[0], "struct timeval __user *tv");
target_ulong tz = log_pointer(env->regs[1], "struct timezone __user *tz");
syscalls::call_sys_gettimeofday_callback(env,pc,tv,tz);
PPP_RUN_CB(on_sys_gettimeofday, env,pc,tv,tz)
finish_syscall();
}; break;
// 79 long sys_settimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
case 79: {
record_syscall("sys_settimeofday");
target_ulong tv = log_pointer(env->regs[0], "struct timeval __user *tv");
target_ulong tz = log_pointer(env->regs[1], "struct timezone __user *tz");
syscalls::call_sys_settimeofday_callback(env,pc,tv,tz);
PPP_RUN_CB(on_sys_settimeofday, env,pc,tv,tz)
finish_syscall();
}; break;
// 80 long sys_getgroups16 ['int gidsetsize', ' old_gid_t __user *grouplist']
case 80: {
record_syscall("sys_getgroups16");
int32_t gidsetsize = log_s32(env->regs[0], "int gidsetsize");
target_ulong grouplist = log_pointer(env->regs[1], " old_gid_t __user *grouplist");
syscalls::call_sys_getgroups16_callback(env,pc,gidsetsize,grouplist);
PPP_RUN_CB(on_sys_getgroups16, env,pc,gidsetsize,grouplist)
finish_syscall();
}; break;
// 81 long sys_setgroups16 ['int gidsetsize', ' old_gid_t __user *grouplist']
case 81: {
record_syscall("sys_setgroups16");
int32_t gidsetsize = log_s32(env->regs[0], "int gidsetsize");
target_ulong grouplist = log_pointer(env->regs[1], " old_gid_t __user *grouplist");
syscalls::call_sys_setgroups16_callback(env,pc,gidsetsize,grouplist);
PPP_RUN_CB(on_sys_setgroups16, env,pc,gidsetsize,grouplist)
finish_syscall();
}; break;
// 83 long sys_symlink ['const char __user *old', ' const char __user *new']
case 83: {
record_syscall("sys_symlink");
syscalls::string old = log_string(env->regs[0], "const char __user *old");
syscalls::string anew = log_string(env->regs[1], " const char __user *new");
syscalls::call_sys_symlink_callback(env,pc,old,anew);
PPP_RUN_CB(on_sys_symlink, env,pc,old.get_vaddr(),anew.get_vaddr())
finish_syscall();
}; break;
// 85 long sys_readlink ['const char __user *path', 'char __user *buf', ' int bufsiz']
case 85: {
record_syscall("sys_readlink");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
target_ulong buf = log_pointer(env->regs[1], "char __user *buf");
int32_t bufsiz = log_s32(env->regs[2], " int bufsiz");
syscalls::call_sys_readlink_callback(env,pc,path,buf,bufsiz);
PPP_RUN_CB(on_sys_readlink, env,pc,path.get_vaddr(),buf,bufsiz)
finish_syscall();
}; break;
// 86 long sys_uselib ['const char __user *library']
case 86: {
record_syscall("sys_uselib");
syscalls::string library = log_string(env->regs[0], "const char __user *library");
syscalls::call_sys_uselib_callback(env,pc,library);
PPP_RUN_CB(on_sys_uselib, env,pc,library.get_vaddr())
finish_syscall();
}; break;
// 87 long sys_swapon ['const char __user *specialfile', ' int swap_flags']
case 87: {
record_syscall("sys_swapon");
syscalls::string specialfile = log_string(env->regs[0], "const char __user *specialfile");
int32_t swap_flags = log_s32(env->regs[1], " int swap_flags");
syscalls::call_sys_swapon_callback(env,pc,specialfile,swap_flags);
PPP_RUN_CB(on_sys_swapon, env,pc,specialfile.get_vaddr(),swap_flags)
finish_syscall();
}; break;
// 88 long sys_reboot ['int magic1', ' int magic2', ' unsigned int cmd', 'void __user *arg']
case 88: {
record_syscall("sys_reboot");
int32_t magic1 = log_s32(env->regs[0], "int magic1");
int32_t magic2 = log_s32(env->regs[1], " int magic2");
uint32_t cmd = log_32(env->regs[2], " unsigned int cmd");
target_ulong arg = log_pointer(env->regs[3], "void __user *arg");
syscalls::call_sys_reboot_callback(env,pc,magic1,magic2,cmd,arg);
PPP_RUN_CB(on_sys_reboot, env,pc,magic1,magic2,cmd,arg)
finish_syscall();
}; break;
// 91 long sys_munmap ['unsigned long addr', ' size_t len']
case 91: {
record_syscall("sys_munmap");
uint32_t addr = log_32(env->regs[0], "unsigned long addr");
uint32_t len = log_32(env->regs[1], " size_t len");
syscalls::call_sys_munmap_callback(env,pc,addr,len);
PPP_RUN_CB(on_sys_munmap, env,pc,addr,len)
finish_syscall();
}; break;
// 92 long sys_truncate ['const char __user *path', 'unsigned long length']
case 92: {
record_syscall("sys_truncate");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
uint32_t length = log_32(env->regs[1], "unsigned long length");
syscalls::call_sys_truncate_callback(env,pc,path,length);
PPP_RUN_CB(on_sys_truncate, env,pc,path.get_vaddr(),length)
finish_syscall();
}; break;
// 93 long sys_ftruncate ['unsigned int fd', ' unsigned long length']
case 93: {
record_syscall("sys_ftruncate");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t length = log_32(env->regs[1], " unsigned long length");
syscalls::call_sys_ftruncate_callback(env,pc,fd,length);
PPP_RUN_CB(on_sys_ftruncate, env,pc,fd,length)
finish_syscall();
}; break;
// 94 long sys_fchmod ['unsigned int fd', ' mode_t mode']
case 94: {
record_syscall("sys_fchmod");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t mode = log_32(env->regs[1], " mode_t mode");
syscalls::call_sys_fchmod_callback(env,pc,fd,mode);
PPP_RUN_CB(on_sys_fchmod, env,pc,fd,mode)
finish_syscall();
}; break;
// 95 long sys_fchown16 ['unsigned int fd', ' old_uid_t user', ' old_gid_t group']
case 95: {
record_syscall("sys_fchown16");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t user = log_32(env->regs[1], " old_uid_t user");
uint32_t group = log_32(env->regs[2], " old_gid_t group");
syscalls::call_sys_fchown16_callback(env,pc,fd,user,group);
PPP_RUN_CB(on_sys_fchown16, env,pc,fd,user,group)
finish_syscall();
}; break;
// 96 long sys_getpriority ['int which', ' int who']
case 96: {
record_syscall("sys_getpriority");
int32_t which = log_s32(env->regs[0], "int which");
int32_t who = log_s32(env->regs[1], " int who");
syscalls::call_sys_getpriority_callback(env,pc,which,who);
PPP_RUN_CB(on_sys_getpriority, env,pc,which,who)
finish_syscall();
}; break;
// 97 long sys_setpriority ['int which', ' int who', ' int niceval']
case 97: {
record_syscall("sys_setpriority");
int32_t which = log_s32(env->regs[0], "int which");
int32_t who = log_s32(env->regs[1], " int who");
int32_t niceval = log_s32(env->regs[2], " int niceval");
syscalls::call_sys_setpriority_callback(env,pc,which,who,niceval);
PPP_RUN_CB(on_sys_setpriority, env,pc,which,who,niceval)
finish_syscall();
}; break;
// 99 long sys_statfs ['const char __user * path', 'struct statfs __user *buf']
case 99: {
record_syscall("sys_statfs");
syscalls::string path = log_string(env->regs[0], "const char __user * path");
target_ulong buf = log_pointer(env->regs[1], "struct statfs __user *buf");
syscalls::call_sys_statfs_callback(env,pc,path,buf);
PPP_RUN_CB(on_sys_statfs, env,pc,path.get_vaddr(),buf)
finish_syscall();
}; break;
// 100 long sys_fstatfs ['unsigned int fd', ' struct statfs __user *buf']
case 100: {
record_syscall("sys_fstatfs");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
target_ulong buf = log_pointer(env->regs[1], " struct statfs __user *buf");
syscalls::call_sys_fstatfs_callback(env,pc,fd,buf);
PPP_RUN_CB(on_sys_fstatfs, env,pc,fd,buf)
finish_syscall();
}; break;
// 103 long sys_syslog ['int type', ' char __user *buf', ' int len']
case 103: {
record_syscall("sys_syslog");
int32_t type = log_s32(env->regs[0], "int type");
target_ulong buf = log_pointer(env->regs[1], " char __user *buf");
int32_t len = log_s32(env->regs[2], " int len");
syscalls::call_sys_syslog_callback(env,pc,type,buf,len);
PPP_RUN_CB(on_sys_syslog, env,pc,type,buf,len)
finish_syscall();
}; break;
// 104 long sys_setitimer ['int which', 'struct itimerval __user *value', 'struct itimerval __user *ovalue']
case 104: {
record_syscall("sys_setitimer");
int32_t which = log_s32(env->regs[0], "int which");
target_ulong value = log_pointer(env->regs[1], "struct itimerval __user *value");
target_ulong ovalue = log_pointer(env->regs[2], "struct itimerval __user *ovalue");
syscalls::call_sys_setitimer_callback(env,pc,which,value,ovalue);
PPP_RUN_CB(on_sys_setitimer, env,pc,which,value,ovalue)
finish_syscall();
}; break;
// 105 long sys_getitimer ['int which', ' struct itimerval __user *value']
case 105: {
record_syscall("sys_getitimer");
int32_t which = log_s32(env->regs[0], "int which");
target_ulong value = log_pointer(env->regs[1], " struct itimerval __user *value");
syscalls::call_sys_getitimer_callback(env,pc,which,value);
PPP_RUN_CB(on_sys_getitimer, env,pc,which,value)
finish_syscall();
}; break;
// 106 long sys_newstat ['char __user *filename', 'struct stat __user *statbuf']
case 106: {
record_syscall("sys_newstat");
syscalls::string filename = log_string(env->regs[0], "char __user *filename");
target_ulong statbuf = log_pointer(env->regs[1], "struct stat __user *statbuf");
syscalls::call_sys_newstat_callback(env,pc,filename,statbuf);
PPP_RUN_CB(on_sys_newstat, env,pc,filename.get_vaddr(),statbuf)
finish_syscall();
}; break;
// 107 long sys_newlstat ['char __user *filename', 'struct stat __user *statbuf']
case 107: {
record_syscall("sys_newlstat");
syscalls::string filename = log_string(env->regs[0], "char __user *filename");
target_ulong statbuf = log_pointer(env->regs[1], "struct stat __user *statbuf");
syscalls::call_sys_newlstat_callback(env,pc,filename,statbuf);
PPP_RUN_CB(on_sys_newlstat, env,pc,filename.get_vaddr(),statbuf)
finish_syscall();
}; break;
// 108 long sys_newfstat ['unsigned int fd', ' struct stat __user *statbuf']
case 108: {
record_syscall("sys_newfstat");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
target_ulong statbuf = log_pointer(env->regs[1], " struct stat __user *statbuf");
syscalls::call_sys_newfstat_callback(env,pc,fd,statbuf);
PPP_RUN_CB(on_sys_newfstat, env,pc,fd,statbuf)
finish_syscall();
}; break;
// 111 long sys_vhangup ['void']
case 111: {
record_syscall("sys_vhangup");
syscalls::call_sys_vhangup_callback(env,pc);
PPP_RUN_CB(on_sys_vhangup, env,pc)
finish_syscall();
}; break;
// 114 long sys_wait4 ['pid_t pid', ' int __user *stat_addr', 'int options', ' struct rusage __user *ru']
case 114: {
record_syscall("sys_wait4");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
target_ulong stat_addr = log_pointer(env->regs[1], " int __user *stat_addr");
int32_t options = log_s32(env->regs[2], "int options");
target_ulong ru = log_pointer(env->regs[3], " struct rusage __user *ru");
syscalls::call_sys_wait4_callback(env,pc,pid,stat_addr,options,ru);
PPP_RUN_CB(on_sys_wait4, env,pc,pid,stat_addr,options,ru)
finish_syscall();
}; break;
// 115 long sys_swapoff ['const char __user *specialfile']
case 115: {
record_syscall("sys_swapoff");
syscalls::string specialfile = log_string(env->regs[0], "const char __user *specialfile");
syscalls::call_sys_swapoff_callback(env,pc,specialfile);
PPP_RUN_CB(on_sys_swapoff, env,pc,specialfile.get_vaddr())
finish_syscall();
}; break;
// 116 long sys_sysinfo ['struct sysinfo __user *info']
case 116: {
record_syscall("sys_sysinfo");
target_ulong info = log_pointer(env->regs[0], "struct sysinfo __user *info");
syscalls::call_sys_sysinfo_callback(env,pc,info);
PPP_RUN_CB(on_sys_sysinfo, env,pc,info)
finish_syscall();
}; break;
// 118 long sys_fsync ['unsigned int fd']
case 118: {
record_syscall("sys_fsync");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
syscalls::call_sys_fsync_callback(env,pc,fd);
PPP_RUN_CB(on_sys_fsync, env,pc,fd)
finish_syscall();
}; break;
// 119 int sigreturn ['void']
case 119: {
record_syscall("sigreturn");
syscalls::call_sigreturn_callback(env,pc);
PPP_RUN_CB(on_sigreturn, env,pc)
finish_syscall();
}; break;
// 120 unsigned long clone ['unsigned long clone_flags', ' unsigned long newsp', ' int __user *parent_tidptr', ' int tls_val', ' int __user *child_tidptr', ' struct pt_regs *regs']
case 120: {
record_syscall("clone");
uint32_t clone_flags = log_32(env->regs[0], "unsigned long clone_flags");
uint32_t newsp = log_32(env->regs[1], " unsigned long newsp");
target_ulong parent_tidptr = log_pointer(env->regs[2], " int __user *parent_tidptr");
int32_t tls_val = log_s32(env->regs[3], " int tls_val");
target_ulong child_tidptr = log_pointer(env->regs[4], " int __user *child_tidptr");
target_ulong regs = log_pointer(env->regs[5], " struct pt_regs *regs");
syscalls::call_clone_callback(env,pc,clone_flags,newsp,parent_tidptr,tls_val,child_tidptr,regs);
PPP_RUN_CB(on_clone, env,pc,clone_flags,newsp,parent_tidptr,tls_val,child_tidptr,regs)
finish_syscall();
}; break;
// 121 long sys_setdomainname ['char __user *name', ' int len']
case 121: {
record_syscall("sys_setdomainname");
syscalls::string name = log_string(env->regs[0], "char __user *name");
int32_t len = log_s32(env->regs[1], " int len");
syscalls::call_sys_setdomainname_callback(env,pc,name,len);
PPP_RUN_CB(on_sys_setdomainname, env,pc,name.get_vaddr(),len)
finish_syscall();
}; break;
// 122 long sys_newuname ['struct new_utsname __user *name']
case 122: {
record_syscall("sys_newuname");
target_ulong name = log_pointer(env->regs[0], "struct new_utsname __user *name");
syscalls::call_sys_newuname_callback(env,pc,name);
PPP_RUN_CB(on_sys_newuname, env,pc,name)
finish_syscall();
}; break;
// 124 long sys_adjtimex ['struct timex __user *txc_p']
case 124: {
record_syscall("sys_adjtimex");
target_ulong txc_p = log_pointer(env->regs[0], "struct timex __user *txc_p");
syscalls::call_sys_adjtimex_callback(env,pc,txc_p);
PPP_RUN_CB(on_sys_adjtimex, env,pc,txc_p)
finish_syscall();
}; break;
// 125 long sys_mprotect ['unsigned long start', ' size_t len', 'unsigned long prot']
case 125: {
record_syscall("sys_mprotect");
uint32_t start = log_32(env->regs[0], "unsigned long start");
uint32_t len = log_32(env->regs[1], " size_t len");
uint32_t prot = log_32(env->regs[2], "unsigned long prot");
syscalls::call_sys_mprotect_callback(env,pc,start,len,prot);
PPP_RUN_CB(on_sys_mprotect, env,pc,start,len,prot)
finish_syscall();
}; break;
// 126 long sys_sigprocmask ['int how', ' old_sigset_t __user *set', 'old_sigset_t __user *oset']
case 126: {
record_syscall("sys_sigprocmask");
int32_t how = log_s32(env->regs[0], "int how");
target_ulong set = log_pointer(env->regs[1], " old_sigset_t __user *set");
target_ulong oset = log_pointer(env->regs[2], "old_sigset_t __user *oset");
syscalls::call_sys_sigprocmask_callback(env,pc,how,set,oset);
PPP_RUN_CB(on_sys_sigprocmask, env,pc,how,set,oset)
finish_syscall();
}; break;
// 128 long sys_init_module ['void __user *umod', ' unsigned long len', 'const char __user *uargs']
case 128: {
record_syscall("sys_init_module");
target_ulong umod = log_pointer(env->regs[0], "void __user *umod");
uint32_t len = log_32(env->regs[1], " unsigned long len");
syscalls::string uargs = log_string(env->regs[2], "const char __user *uargs");
syscalls::call_sys_init_module_callback(env,pc,umod,len,uargs);
PPP_RUN_CB(on_sys_init_module, env,pc,umod,len,uargs.get_vaddr())
finish_syscall();
}; break;
// 129 long sys_delete_module ['const char __user *name_user', 'unsigned int flags']
case 129: {
record_syscall("sys_delete_module");
syscalls::string name_user = log_string(env->regs[0], "const char __user *name_user");
uint32_t flags = log_32(env->regs[1], "unsigned int flags");
syscalls::call_sys_delete_module_callback(env,pc,name_user,flags);
PPP_RUN_CB(on_sys_delete_module, env,pc,name_user.get_vaddr(),flags)
finish_syscall();
}; break;
// 131 long sys_quotactl ['unsigned int cmd', ' const char __user *special', 'qid_t id', ' void __user *addr']
case 131: {
record_syscall("sys_quotactl");
uint32_t cmd = log_32(env->regs[0], "unsigned int cmd");
syscalls::string special = log_string(env->regs[1], " const char __user *special");
uint32_t id = log_32(env->regs[2], "qid_t id");
target_ulong addr = log_pointer(env->regs[3], " void __user *addr");
syscalls::call_sys_quotactl_callback(env,pc,cmd,special,id,addr);
PPP_RUN_CB(on_sys_quotactl, env,pc,cmd,special.get_vaddr(),id,addr)
finish_syscall();
}; break;
// 132 long sys_getpgid ['pid_t pid']
case 132: {
record_syscall("sys_getpgid");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
syscalls::call_sys_getpgid_callback(env,pc,pid);
PPP_RUN_CB(on_sys_getpgid, env,pc,pid)
finish_syscall();
}; break;
// 133 long sys_fchdir ['unsigned int fd']
case 133: {
record_syscall("sys_fchdir");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
syscalls::call_sys_fchdir_callback(env,pc,fd);
PPP_RUN_CB(on_sys_fchdir, env,pc,fd)
finish_syscall();
}; break;
// 134 long sys_bdflush ['int func', ' long data']
case 134: {
record_syscall("sys_bdflush");
int32_t func = log_s32(env->regs[0], "int func");
int32_t data_arg = log_s32(env->regs[1], " long data");
syscalls::call_sys_bdflush_callback(env,pc,func,data_arg);
PPP_RUN_CB(on_sys_bdflush, env,pc,func,data_arg)
finish_syscall();
}; break;
// 135 long sys_sysfs ['int option', 'unsigned long arg1', ' unsigned long arg2']
case 135: {
record_syscall("sys_sysfs");
int32_t option = log_s32(env->regs[0], "int option");
uint32_t arg1 = log_32(env->regs[1], "unsigned long arg1");
uint32_t arg2 = log_32(env->regs[2], " unsigned long arg2");
syscalls::call_sys_sysfs_callback(env,pc,option,arg1,arg2);
PPP_RUN_CB(on_sys_sysfs, env,pc,option,arg1,arg2)
finish_syscall();
}; break;
// 136 long sys_personality ['u_long personality']
case 136: {
record_syscall("sys_personality");
int32_t personality = log_s32(env->regs[0], "u_long personality");
syscalls::call_sys_personality_callback(env,pc,personality);
PPP_RUN_CB(on_sys_personality, env,pc,personality)
finish_syscall();
}; break;
// 138 long sys_setfsuid16 ['old_uid_t uid']
case 138: {
record_syscall("sys_setfsuid16");
uint32_t uid = log_32(env->regs[0], "old_uid_t uid");
syscalls::call_sys_setfsuid16_callback(env,pc,uid);
PPP_RUN_CB(on_sys_setfsuid16, env,pc,uid)
finish_syscall();
}; break;
// 139 long sys_setfsgid16 ['old_gid_t gid']
case 139: {
record_syscall("sys_setfsgid16");
uint32_t gid = log_32(env->regs[0], "old_gid_t gid");
syscalls::call_sys_setfsgid16_callback(env,pc,gid);
PPP_RUN_CB(on_sys_setfsgid16, env,pc,gid)
finish_syscall();
}; break;
// 140 long sys_llseek ['unsigned int fd', ' unsigned long offset_high', 'unsigned long offset_low', ' loff_t __user *result', 'unsigned int origin']
case 140: {
record_syscall("sys_llseek");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t offset_high = log_32(env->regs[1], " unsigned long offset_high");
uint32_t offset_low = log_32(env->regs[2], "unsigned long offset_low");
target_ulong result = log_pointer(env->regs[3], " loff_t __user *result");
uint32_t origin = log_32(env->regs[4], "unsigned int origin");
syscalls::call_sys_llseek_callback(env,pc,fd,offset_high,offset_low,result,origin);
PPP_RUN_CB(on_sys_llseek, env,pc,fd,offset_high,offset_low,result,origin)
finish_syscall();
}; break;
// 141 long sys_getdents ['unsigned int fd', 'struct linux_dirent __user *dirent', 'unsigned int count']
case 141: {
record_syscall("sys_getdents");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
target_ulong dirent = log_pointer(env->regs[1], "struct linux_dirent __user *dirent");
uint32_t count = log_32(env->regs[2], "unsigned int count");
syscalls::call_sys_getdents_callback(env,pc,fd,dirent,count);
PPP_RUN_CB(on_sys_getdents, env,pc,fd,dirent,count)
finish_syscall();
}; break;
// 142 long sys_select ['int n', ' fd_set __user *inp', ' fd_set __user *outp', 'fd_set __user *exp', ' struct timeval __user *tvp']
case 142: {
record_syscall("sys_select");
int32_t n = log_s32(env->regs[0], "int n");
target_ulong inp = log_pointer(env->regs[1], " fd_set __user *inp");
target_ulong outp = log_pointer(env->regs[2], " fd_set __user *outp");
target_ulong exp = log_pointer(env->regs[3], "fd_set __user *exp");
target_ulong tvp = log_pointer(env->regs[4], " struct timeval __user *tvp");
syscalls::call_sys_select_callback(env,pc,n,inp,outp,exp,tvp);
PPP_RUN_CB(on_sys_select, env,pc,n,inp,outp,exp,tvp)
finish_syscall();
}; break;
// 143 long sys_flock ['unsigned int fd', ' unsigned int cmd']
case 143: {
record_syscall("sys_flock");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t cmd = log_32(env->regs[1], " unsigned int cmd");
syscalls::call_sys_flock_callback(env,pc,fd,cmd);
PPP_RUN_CB(on_sys_flock, env,pc,fd,cmd)
finish_syscall();
}; break;
// 144 long sys_msync ['unsigned long start', ' size_t len', ' int flags']
case 144: {
record_syscall("sys_msync");
uint32_t start = log_32(env->regs[0], "unsigned long start");
uint32_t len = log_32(env->regs[1], " size_t len");
int32_t flags = log_s32(env->regs[2], " int flags");
syscalls::call_sys_msync_callback(env,pc,start,len,flags);
PPP_RUN_CB(on_sys_msync, env,pc,start,len,flags)
finish_syscall();
}; break;
// 145 long sys_readv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
case 145: {
record_syscall("sys_readv");
uint32_t fd = log_32(env->regs[0], "unsigned long fd");
target_ulong vec = log_pointer(env->regs[1], "const struct iovec __user *vec");
uint32_t vlen = log_32(env->regs[2], "unsigned long vlen");
syscalls::call_sys_readv_callback(env,pc,fd,vec,vlen);
PPP_RUN_CB(on_sys_readv, env,pc,fd,vec,vlen)
finish_syscall();
}; break;
// 146 long sys_writev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
case 146: {
record_syscall("sys_writev");
uint32_t fd = log_32(env->regs[0], "unsigned long fd");
target_ulong vec = log_pointer(env->regs[1], "const struct iovec __user *vec");
uint32_t vlen = log_32(env->regs[2], "unsigned long vlen");
syscalls::call_sys_writev_callback(env,pc,fd,vec,vlen);
PPP_RUN_CB(on_sys_writev, env,pc,fd,vec,vlen)
finish_syscall();
}; break;
// 147 long sys_getsid ['pid_t pid']
case 147: {
record_syscall("sys_getsid");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
syscalls::call_sys_getsid_callback(env,pc,pid);
PPP_RUN_CB(on_sys_getsid, env,pc,pid)
finish_syscall();
}; break;
// 148 long sys_fdatasync ['unsigned int fd']
case 148: {
record_syscall("sys_fdatasync");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
syscalls::call_sys_fdatasync_callback(env,pc,fd);
PPP_RUN_CB(on_sys_fdatasync, env,pc,fd)
finish_syscall();
}; break;
// 149 long sys_sysctl ['struct __sysctl_args __user *args']
case 149: {
record_syscall("sys_sysctl");
target_ulong args = log_pointer(env->regs[0], "struct __sysctl_args __user *args");
syscalls::call_sys_sysctl_callback(env,pc,args);
PPP_RUN_CB(on_sys_sysctl, env,pc,args)
finish_syscall();
}; break;
// 150 long sys_mlock ['unsigned long start', ' size_t len']
case 150: {
record_syscall("sys_mlock");
uint32_t start = log_32(env->regs[0], "unsigned long start");
uint32_t len = log_32(env->regs[1], " size_t len");
syscalls::call_sys_mlock_callback(env,pc,start,len);
PPP_RUN_CB(on_sys_mlock, env,pc,start,len)
finish_syscall();
}; break;
// 151 long sys_munlock ['unsigned long start', ' size_t len']
case 151: {
record_syscall("sys_munlock");
uint32_t start = log_32(env->regs[0], "unsigned long start");
uint32_t len = log_32(env->regs[1], " size_t len");
syscalls::call_sys_munlock_callback(env,pc,start,len);
PPP_RUN_CB(on_sys_munlock, env,pc,start,len)
finish_syscall();
}; break;
// 152 long sys_mlockall ['int flags']
case 152: {
record_syscall("sys_mlockall");
int32_t flags = log_s32(env->regs[0], "int flags");
syscalls::call_sys_mlockall_callback(env,pc,flags);
PPP_RUN_CB(on_sys_mlockall, env,pc,flags)
finish_syscall();
}; break;
// 153 long sys_munlockall ['void']
case 153: {
record_syscall("sys_munlockall");
syscalls::call_sys_munlockall_callback(env,pc);
PPP_RUN_CB(on_sys_munlockall, env,pc)
finish_syscall();
}; break;
// 154 long sys_sched_setparam ['pid_t pid', 'struct sched_param __user *param']
case 154: {
record_syscall("sys_sched_setparam");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
target_ulong param = log_pointer(env->regs[1], "struct sched_param __user *param");
syscalls::call_sys_sched_setparam_callback(env,pc,pid,param);
PPP_RUN_CB(on_sys_sched_setparam, env,pc,pid,param)
finish_syscall();
}; break;
// 155 long sys_sched_getparam ['pid_t pid', 'struct sched_param __user *param']
case 155: {
record_syscall("sys_sched_getparam");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
target_ulong param = log_pointer(env->regs[1], "struct sched_param __user *param");
syscalls::call_sys_sched_getparam_callback(env,pc,pid,param);
PPP_RUN_CB(on_sys_sched_getparam, env,pc,pid,param)
finish_syscall();
}; break;
// 156 long sys_sched_setscheduler ['pid_t pid', ' int policy', 'struct sched_param __user *param']
case 156: {
record_syscall("sys_sched_setscheduler");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
int32_t policy = log_s32(env->regs[1], " int policy");
target_ulong param = log_pointer(env->regs[2], "struct sched_param __user *param");
syscalls::call_sys_sched_setscheduler_callback(env,pc,pid,policy,param);
PPP_RUN_CB(on_sys_sched_setscheduler, env,pc,pid,policy,param)
finish_syscall();
}; break;
// 157 long sys_sched_getscheduler ['pid_t pid']
case 157: {
record_syscall("sys_sched_getscheduler");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
syscalls::call_sys_sched_getscheduler_callback(env,pc,pid);
PPP_RUN_CB(on_sys_sched_getscheduler, env,pc,pid)
finish_syscall();
}; break;
// 158 long sys_sched_yield ['void']
case 158: {
record_syscall("sys_sched_yield");
syscalls::call_sys_sched_yield_callback(env,pc);
PPP_RUN_CB(on_sys_sched_yield, env,pc)
finish_syscall();
}; break;
// 159 long sys_sched_get_priority_max ['int policy']
case 159: {
record_syscall("sys_sched_get_priority_max");
int32_t policy = log_s32(env->regs[0], "int policy");
syscalls::call_sys_sched_get_priority_max_callback(env,pc,policy);
PPP_RUN_CB(on_sys_sched_get_priority_max, env,pc,policy)
finish_syscall();
}; break;
// 160 long sys_sched_get_priority_min ['int policy']
case 160: {
record_syscall("sys_sched_get_priority_min");
int32_t policy = log_s32(env->regs[0], "int policy");
syscalls::call_sys_sched_get_priority_min_callback(env,pc,policy);
PPP_RUN_CB(on_sys_sched_get_priority_min, env,pc,policy)
finish_syscall();
}; break;
// 161 long sys_sched_rr_get_interval ['pid_t pid', 'struct timespec __user *interval']
case 161: {
record_syscall("sys_sched_rr_get_interval");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
target_ulong interval = log_pointer(env->regs[1], "struct timespec __user *interval");
syscalls::call_sys_sched_rr_get_interval_callback(env,pc,pid,interval);
PPP_RUN_CB(on_sys_sched_rr_get_interval, env,pc,pid,interval)
finish_syscall();
}; break;
// 162 long sys_nanosleep ['struct timespec __user *rqtp', ' struct timespec __user *rmtp']
case 162: {
record_syscall("sys_nanosleep");
target_ulong rqtp = log_pointer(env->regs[0], "struct timespec __user *rqtp");
target_ulong rmtp = log_pointer(env->regs[1], " struct timespec __user *rmtp");
syscalls::call_sys_nanosleep_callback(env,pc,rqtp,rmtp);
PPP_RUN_CB(on_sys_nanosleep, env,pc,rqtp,rmtp)
finish_syscall();
}; break;
// 163 unsigned long arm_mremap ['unsigned long addr', ' unsigned long old_len', ' unsigned long new_len', ' unsigned long flags', ' unsigned long new_addr']
case 163: {
record_syscall("arm_mremap");
uint32_t addr = log_32(env->regs[0], "unsigned long addr");
uint32_t old_len = log_32(env->regs[1], " unsigned long old_len");
uint32_t new_len = log_32(env->regs[2], " unsigned long new_len");
uint32_t flags = log_32(env->regs[3], " unsigned long flags");
uint32_t new_addr = log_32(env->regs[4], " unsigned long new_addr");
syscalls::call_arm_mremap_callback(env,pc,addr,old_len,new_len,flags,new_addr);
PPP_RUN_CB(on_arm_mremap, env,pc,addr,old_len,new_len,flags,new_addr)
finish_syscall();
}; break;
// 164 long sys_setresuid16 ['old_uid_t ruid', ' old_uid_t euid', ' old_uid_t suid']
case 164: {
record_syscall("sys_setresuid16");
uint32_t ruid = log_32(env->regs[0], "old_uid_t ruid");
uint32_t euid = log_32(env->regs[1], " old_uid_t euid");
uint32_t suid = log_32(env->regs[2], " old_uid_t suid");
syscalls::call_sys_setresuid16_callback(env,pc,ruid,euid,suid);
PPP_RUN_CB(on_sys_setresuid16, env,pc,ruid,euid,suid)
finish_syscall();
}; break;
// 165 long sys_getresuid16 ['old_uid_t __user *ruid', 'old_uid_t __user *euid', ' old_uid_t __user *suid']
case 165: {
record_syscall("sys_getresuid16");
target_ulong ruid = log_pointer(env->regs[0], "old_uid_t __user *ruid");
target_ulong euid = log_pointer(env->regs[1], "old_uid_t __user *euid");
target_ulong suid = log_pointer(env->regs[2], " old_uid_t __user *suid");
syscalls::call_sys_getresuid16_callback(env,pc,ruid,euid,suid);
PPP_RUN_CB(on_sys_getresuid16, env,pc,ruid,euid,suid)
finish_syscall();
}; break;
// 168 long sys_poll ['struct pollfd __user *ufds', ' unsigned int nfds', 'long timeout']
case 168: {
record_syscall("sys_poll");
target_ulong ufds = log_pointer(env->regs[0], "struct pollfd __user *ufds");
uint32_t nfds = log_32(env->regs[1], " unsigned int nfds");
int32_t timeout = log_s32(env->regs[2], "long timeout");
syscalls::call_sys_poll_callback(env,pc,ufds,nfds,timeout);
PPP_RUN_CB(on_sys_poll, env,pc,ufds,nfds,timeout)
finish_syscall();
}; break;
// 169 long sys_nfsservctl ['int cmd', 'struct nfsctl_arg __user *arg', 'void __user *res']
case 169: {
record_syscall("sys_nfsservctl");
int32_t cmd = log_s32(env->regs[0], "int cmd");
target_ulong arg = log_pointer(env->regs[1], "struct nfsctl_arg __user *arg");
target_ulong res = log_pointer(env->regs[2], "void __user *res");
syscalls::call_sys_nfsservctl_callback(env,pc,cmd,arg,res);
PPP_RUN_CB(on_sys_nfsservctl, env,pc,cmd,arg,res)
finish_syscall();
}; break;
// 170 long sys_setresgid16 ['old_gid_t rgid', ' old_gid_t egid', ' old_gid_t sgid']
case 170: {
record_syscall("sys_setresgid16");
uint32_t rgid = log_32(env->regs[0], "old_gid_t rgid");
uint32_t egid = log_32(env->regs[1], " old_gid_t egid");
uint32_t sgid = log_32(env->regs[2], " old_gid_t sgid");
syscalls::call_sys_setresgid16_callback(env,pc,rgid,egid,sgid);
PPP_RUN_CB(on_sys_setresgid16, env,pc,rgid,egid,sgid)
finish_syscall();
}; break;
// 171 long sys_getresgid16 ['old_gid_t __user *rgid', 'old_gid_t __user *egid', ' old_gid_t __user *sgid']
case 171: {
record_syscall("sys_getresgid16");
target_ulong rgid = log_pointer(env->regs[0], "old_gid_t __user *rgid");
target_ulong egid = log_pointer(env->regs[1], "old_gid_t __user *egid");
target_ulong sgid = log_pointer(env->regs[2], " old_gid_t __user *sgid");
syscalls::call_sys_getresgid16_callback(env,pc,rgid,egid,sgid);
PPP_RUN_CB(on_sys_getresgid16, env,pc,rgid,egid,sgid)
finish_syscall();
}; break;
// 172 long sys_prctl ['int option', ' unsigned long arg2', ' unsigned long arg3', 'unsigned long arg4', ' unsigned long arg5']
case 172: {
record_syscall("sys_prctl");
int32_t option = log_s32(env->regs[0], "int option");
uint32_t arg2 = log_32(env->regs[1], " unsigned long arg2");
uint32_t arg3 = log_32(env->regs[2], " unsigned long arg3");
uint32_t arg4 = log_32(env->regs[3], "unsigned long arg4");
uint32_t arg5 = log_32(env->regs[4], " unsigned long arg5");
syscalls::call_sys_prctl_callback(env,pc,option,arg2,arg3,arg4,arg5);
PPP_RUN_CB(on_sys_prctl, env,pc,option,arg2,arg3,arg4,arg5)
finish_syscall();
}; break;
// 173 int sigreturn ['void']
case 173: {
record_syscall("sigreturn");
PPP_RUN_CB(on_sigreturn, env,pc)
finish_syscall();
}; break;
// 174 long rt_sigaction ['int sig', ' const struct sigaction __user * act', ' struct sigaction __user * oact', '  size_t sigsetsize']
case 174: {
record_syscall("rt_sigaction");
int32_t sig = log_s32(env->regs[0], "int sig");
target_ulong act = log_pointer(env->regs[1], " const struct sigaction __user * act");
target_ulong oact = log_pointer(env->regs[2], " struct sigaction __user * oact");
uint32_t sigsetsize = log_32(env->regs[3], "  size_t sigsetsize");
syscalls::call_rt_sigaction_callback(env,pc,sig,act,oact,sigsetsize);
PPP_RUN_CB(on_rt_sigaction, env,pc,sig,act,oact,sigsetsize)
finish_syscall();
}; break;
// 175 long sys_rt_sigprocmask ['int how', ' sigset_t __user *set', 'sigset_t __user *oset', ' size_t sigsetsize']
case 175: {
record_syscall("sys_rt_sigprocmask");
int32_t how = log_s32(env->regs[0], "int how");
target_ulong set = log_pointer(env->regs[1], " sigset_t __user *set");
target_ulong oset = log_pointer(env->regs[2], "sigset_t __user *oset");
uint32_t sigsetsize = log_32(env->regs[3], " size_t sigsetsize");
syscalls::call_sys_rt_sigprocmask_callback(env,pc,how,set,oset,sigsetsize);
PPP_RUN_CB(on_sys_rt_sigprocmask, env,pc,how,set,oset,sigsetsize)
finish_syscall();
}; break;
// 176 long sys_rt_sigpending ['sigset_t __user *set', ' size_t sigsetsize']
case 176: {
record_syscall("sys_rt_sigpending");
target_ulong set = log_pointer(env->regs[0], "sigset_t __user *set");
uint32_t sigsetsize = log_32(env->regs[1], " size_t sigsetsize");
syscalls::call_sys_rt_sigpending_callback(env,pc,set,sigsetsize);
PPP_RUN_CB(on_sys_rt_sigpending, env,pc,set,sigsetsize)
finish_syscall();
}; break;
// 177 long sys_rt_sigtimedwait ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct timespec __user *uts', 'size_t sigsetsize']
case 177: {
record_syscall("sys_rt_sigtimedwait");
target_ulong uthese = log_pointer(env->regs[0], "const sigset_t __user *uthese");
target_ulong uinfo = log_pointer(env->regs[1], "siginfo_t __user *uinfo");
target_ulong uts = log_pointer(env->regs[2], "const struct timespec __user *uts");
uint32_t sigsetsize = log_32(env->regs[3], "size_t sigsetsize");
syscalls::call_sys_rt_sigtimedwait_callback(env,pc,uthese,uinfo,uts,sigsetsize);
PPP_RUN_CB(on_sys_rt_sigtimedwait, env,pc,uthese,uinfo,uts,sigsetsize)
finish_syscall();
}; break;
// 178 long sys_rt_sigqueueinfo ['int pid', ' int sig', ' siginfo_t __user *uinfo']
case 178: {
record_syscall("sys_rt_sigqueueinfo");
int32_t pid = log_s32(env->regs[0], "int pid");
int32_t sig = log_s32(env->regs[1], " int sig");
target_ulong uinfo = log_pointer(env->regs[2], " siginfo_t __user *uinfo");
syscalls::call_sys_rt_sigqueueinfo_callback(env,pc,pid,sig,uinfo);
PPP_RUN_CB(on_sys_rt_sigqueueinfo, env,pc,pid,sig,uinfo)
finish_syscall();
}; break;
// 179 int sys_rt_sigsuspend ['sigset_t __user *unewset', ' size_t sigsetsize']
case 179: {
record_syscall("sys_rt_sigsuspend");
target_ulong unewset = log_pointer(env->regs[0], "sigset_t __user *unewset");
uint32_t sigsetsize = log_32(env->regs[1], " size_t sigsetsize");
syscalls::call_sys_rt_sigsuspend_callback(env,pc,unewset,sigsetsize);
PPP_RUN_CB(on_sys_rt_sigsuspend, env,pc,unewset,sigsetsize)
finish_syscall();
}; break;
// 180 long sys_pread64 ['unsigned int fd', ' char __user *buf', 'size_t count', ' loff_t pos']
case 180: {
record_syscall("sys_pread64");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
target_ulong buf = log_pointer(env->regs[1], " char __user *buf");
uint32_t count = log_32(env->regs[2], "size_t count");
// skipping arg for alignment
uint64_t pos = log_64(env->regs[4], env->regs[5], " loff_t pos");
syscalls::call_sys_pread64_callback(env,pc,fd,buf,count,pos);
PPP_RUN_CB(on_sys_pread64, env,pc,fd,buf,count,pos)
finish_syscall();
}; break;
// 181 long sys_pwrite64 ['unsigned int fd', ' const char __user *buf', 'size_t count', ' loff_t pos']
case 181: {
record_syscall("sys_pwrite64");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
target_ulong buf = log_pointer(env->regs[1], " const char __user *buf");
uint32_t count = log_32(env->regs[2], "size_t count");
// skipping arg for alignment
uint64_t pos = log_64(env->regs[4], env->regs[5], " loff_t pos");
syscalls::call_sys_pwrite64_callback(env,pc,fd,buf,count,pos);
PPP_RUN_CB(on_sys_pwrite64, env,pc,fd,buf,count,pos)
finish_syscall();
}; break;
// 182 long sys_chown16 ['const char __user *filename', 'old_uid_t user', ' old_gid_t group']
case 182: {
record_syscall("sys_chown16");
syscalls::string filename = log_string(env->regs[0], "const char __user *filename");
uint32_t user = log_32(env->regs[1], "old_uid_t user");
uint32_t group = log_32(env->regs[2], " old_gid_t group");
syscalls::call_sys_chown16_callback(env,pc,filename,user,group);
PPP_RUN_CB(on_sys_chown16, env,pc,filename.get_vaddr(),user,group)
finish_syscall();
}; break;
// 183 long sys_getcwd ['char __user *buf', ' unsigned long size']
case 183: {
record_syscall("sys_getcwd");
target_ulong buf = log_pointer(env->regs[0], "char __user *buf");
uint32_t size = log_32(env->regs[1], " unsigned long size");
syscalls::call_sys_getcwd_callback(env,pc,buf,size);
PPP_RUN_CB(on_sys_getcwd, env,pc,buf,size)
finish_syscall();
}; break;
// 184 long sys_capget ['cap_user_header_t header', 'cap_user_data_t dataptr']
case 184: {
record_syscall("sys_capget");
target_ulong header = log_pointer(env->regs[0], "cap_user_header_t header");
target_ulong dataptr = log_pointer(env->regs[1], "cap_user_data_t dataptr");
syscalls::call_sys_capget_callback(env,pc,header,dataptr);
PPP_RUN_CB(on_sys_capget, env,pc,header,dataptr)
finish_syscall();
}; break;
// 185 long sys_capset ['cap_user_header_t header', 'const cap_user_data_t data']
case 185: {
record_syscall("sys_capset");
target_ulong header = log_pointer(env->regs[0], "cap_user_header_t header");
target_ulong data_arg = log_pointer(env->regs[1], "const cap_user_data_t data");
syscalls::call_sys_capset_callback(env,pc,header,data_arg);
PPP_RUN_CB(on_sys_capset, env,pc,header,data_arg)
finish_syscall();
}; break;
// 186 int do_sigaltstack ['const stack_t __user *uss', ' stack_t __user *uoss']
case 186: {
record_syscall("do_sigaltstack");
target_ulong uss = log_pointer(env->regs[0], "const stack_t __user *uss");
target_ulong uoss = log_pointer(env->regs[1], " stack_t __user *uoss");
syscalls::call_do_sigaltstack_callback(env,pc,uss,uoss);
PPP_RUN_CB(on_do_sigaltstack, env,pc,uss,uoss)
finish_syscall();
}; break;
// 187 long sys_sendfile ['int out_fd', ' int in_fd', 'off_t __user *offset', ' size_t count']
case 187: {
record_syscall("sys_sendfile");
int32_t out_fd = log_s32(env->regs[0], "int out_fd");
int32_t in_fd = log_s32(env->regs[1], " int in_fd");
target_ulong offset = log_pointer(env->regs[2], "off_t __user *offset");
uint32_t count = log_32(env->regs[3], " size_t count");
syscalls::call_sys_sendfile_callback(env,pc,out_fd,in_fd,offset,count);
PPP_RUN_CB(on_sys_sendfile, env,pc,out_fd,in_fd,offset,count)
finish_syscall();
}; break;
// 190 unsigned long vfork ['void']
case 190: {
record_syscall("vfork");
syscalls::call_vfork_callback(env,pc);
PPP_RUN_CB(on_vfork, env,pc)
finish_syscall();
}; break;
// 191 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
case 191: {
record_syscall("sys_getrlimit");
uint32_t resource = log_32(env->regs[0], "unsigned int resource");
target_ulong rlim = log_pointer(env->regs[1], "struct rlimit __user *rlim");
syscalls::call_sys_getrlimit_callback(env,pc,resource,rlim);
PPP_RUN_CB(on_sys_getrlimit, env,pc,resource,rlim)
finish_syscall();
}; break;
// 192 long do_mmap2 ['unsigned long addr', ' unsigned long len', ' unsigned long prot', ' unsigned long flags', ' unsigned long fd', ' unsigned long pgoff']
case 192: {
record_syscall("do_mmap2");
uint32_t addr = log_32(env->regs[0], "unsigned long addr");
uint32_t len = log_32(env->regs[1], " unsigned long len");
uint32_t prot = log_32(env->regs[2], " unsigned long prot");
uint32_t flags = log_32(env->regs[3], " unsigned long flags");
uint32_t fd = log_32(env->regs[4], " unsigned long fd");
uint32_t pgoff = log_32(env->regs[5], " unsigned long pgoff");
syscalls::call_do_mmap2_callback(env,pc,addr,len,prot,flags,fd,pgoff);
PPP_RUN_CB(on_do_mmap2, env,pc,addr,len,prot,flags,fd,pgoff)
finish_syscall();
}; break;
// 193 long sys_truncate64 ['const char __user *path', ' loff_t length']
case 193: {
record_syscall("sys_truncate64");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
// skipping arg for alignment
uint64_t length = log_64(env->regs[2], env->regs[3], " loff_t length");
syscalls::call_sys_truncate64_callback(env,pc,path,length);
PPP_RUN_CB(on_sys_truncate64, env,pc,path.get_vaddr(),length)
finish_syscall();
}; break;
// 194 long sys_ftruncate64 ['unsigned int fd', ' loff_t length']
case 194: {
record_syscall("sys_ftruncate64");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
// skipping arg for alignment
uint64_t length = log_64(env->regs[2], env->regs[3], " loff_t length");
syscalls::call_sys_ftruncate64_callback(env,pc,fd,length);
PPP_RUN_CB(on_sys_ftruncate64, env,pc,fd,length)
finish_syscall();
}; break;
// 195 long sys_stat64 ['char __user *filename', 'struct stat64 __user *statbuf']
case 195: {
record_syscall("sys_stat64");
syscalls::string filename = log_string(env->regs[0], "char __user *filename");
target_ulong statbuf = log_pointer(env->regs[1], "struct stat64 __user *statbuf");
syscalls::call_sys_stat64_callback(env,pc,filename,statbuf);
PPP_RUN_CB(on_sys_stat64, env,pc,filename.get_vaddr(),statbuf)
finish_syscall();
}; break;
// 196 long sys_lstat64 ['char __user *filename', 'struct stat64 __user *statbuf']
case 196: {
record_syscall("sys_lstat64");
syscalls::string filename = log_string(env->regs[0], "char __user *filename");
target_ulong statbuf = log_pointer(env->regs[1], "struct stat64 __user *statbuf");
syscalls::call_sys_lstat64_callback(env,pc,filename,statbuf);
PPP_RUN_CB(on_sys_lstat64, env,pc,filename.get_vaddr(),statbuf)
finish_syscall();
}; break;
// 197 long sys_fstat64 ['unsigned long fd', ' struct stat64 __user *statbuf']
case 197: {
record_syscall("sys_fstat64");
uint32_t fd = log_32(env->regs[0], "unsigned long fd");
target_ulong statbuf = log_pointer(env->regs[1], " struct stat64 __user *statbuf");
syscalls::call_sys_fstat64_callback(env,pc,fd,statbuf);
PPP_RUN_CB(on_sys_fstat64, env,pc,fd,statbuf)
finish_syscall();
}; break;
// 198 long sys_lchown ['const char __user *filename', 'uid_t user', ' gid_t group']
case 198: {
record_syscall("sys_lchown");
syscalls::string filename = log_string(env->regs[0], "const char __user *filename");
uint32_t user = log_32(env->regs[1], "uid_t user");
uint32_t group = log_32(env->regs[2], " gid_t group");
syscalls::call_sys_lchown_callback(env,pc,filename,user,group);
PPP_RUN_CB(on_sys_lchown, env,pc,filename.get_vaddr(),user,group)
finish_syscall();
}; break;
// 199 long sys_getuid ['void']
case 199: {
record_syscall("sys_getuid");
syscalls::call_sys_getuid_callback(env,pc);
PPP_RUN_CB(on_sys_getuid, env,pc)
finish_syscall();
}; break;
// 200 long sys_getgid ['void']
case 200: {
record_syscall("sys_getgid");
syscalls::call_sys_getgid_callback(env,pc);
PPP_RUN_CB(on_sys_getgid, env,pc)
finish_syscall();
}; break;
// 201 long sys_geteuid ['void']
case 201: {
record_syscall("sys_geteuid");
syscalls::call_sys_geteuid_callback(env,pc);
PPP_RUN_CB(on_sys_geteuid, env,pc)
finish_syscall();
}; break;
// 202 long sys_getegid ['void']
case 202: {
record_syscall("sys_getegid");
syscalls::call_sys_getegid_callback(env,pc);
PPP_RUN_CB(on_sys_getegid, env,pc)
finish_syscall();
}; break;
// 203 long sys_setreuid ['uid_t ruid', ' uid_t euid']
case 203: {
record_syscall("sys_setreuid");
uint32_t ruid = log_32(env->regs[0], "uid_t ruid");
uint32_t euid = log_32(env->regs[1], " uid_t euid");
syscalls::call_sys_setreuid_callback(env,pc,ruid,euid);
PPP_RUN_CB(on_sys_setreuid, env,pc,ruid,euid)
finish_syscall();
}; break;
// 204 long sys_setregid ['gid_t rgid', ' gid_t egid']
case 204: {
record_syscall("sys_setregid");
uint32_t rgid = log_32(env->regs[0], "gid_t rgid");
uint32_t egid = log_32(env->regs[1], " gid_t egid");
syscalls::call_sys_setregid_callback(env,pc,rgid,egid);
PPP_RUN_CB(on_sys_setregid, env,pc,rgid,egid)
finish_syscall();
}; break;
// 205 long sys_getgroups ['int gidsetsize', ' gid_t __user *grouplist']
case 205: {
record_syscall("sys_getgroups");
int32_t gidsetsize = log_s32(env->regs[0], "int gidsetsize");
target_ulong grouplist = log_pointer(env->regs[1], " gid_t __user *grouplist");
syscalls::call_sys_getgroups_callback(env,pc,gidsetsize,grouplist);
PPP_RUN_CB(on_sys_getgroups, env,pc,gidsetsize,grouplist)
finish_syscall();
}; break;
// 206 long sys_setgroups ['int gidsetsize', ' gid_t __user *grouplist']
case 206: {
record_syscall("sys_setgroups");
int32_t gidsetsize = log_s32(env->regs[0], "int gidsetsize");
target_ulong grouplist = log_pointer(env->regs[1], " gid_t __user *grouplist");
syscalls::call_sys_setgroups_callback(env,pc,gidsetsize,grouplist);
PPP_RUN_CB(on_sys_setgroups, env,pc,gidsetsize,grouplist)
finish_syscall();
}; break;
// 207 long sys_fchown ['unsigned int fd', ' uid_t user', ' gid_t group']
case 207: {
record_syscall("sys_fchown");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t user = log_32(env->regs[1], " uid_t user");
uint32_t group = log_32(env->regs[2], " gid_t group");
syscalls::call_sys_fchown_callback(env,pc,fd,user,group);
PPP_RUN_CB(on_sys_fchown, env,pc,fd,user,group)
finish_syscall();
}; break;
// 208 long sys_setresuid ['uid_t ruid', ' uid_t euid', ' uid_t suid']
case 208: {
record_syscall("sys_setresuid");
uint32_t ruid = log_32(env->regs[0], "uid_t ruid");
uint32_t euid = log_32(env->regs[1], " uid_t euid");
uint32_t suid = log_32(env->regs[2], " uid_t suid");
syscalls::call_sys_setresuid_callback(env,pc,ruid,euid,suid);
PPP_RUN_CB(on_sys_setresuid, env,pc,ruid,euid,suid)
finish_syscall();
}; break;
// 209 long sys_getresuid ['uid_t __user *ruid', ' uid_t __user *euid', ' uid_t __user *suid']
case 209: {
record_syscall("sys_getresuid");
target_ulong ruid = log_pointer(env->regs[0], "uid_t __user *ruid");
target_ulong euid = log_pointer(env->regs[1], " uid_t __user *euid");
target_ulong suid = log_pointer(env->regs[2], " uid_t __user *suid");
syscalls::call_sys_getresuid_callback(env,pc,ruid,euid,suid);
PPP_RUN_CB(on_sys_getresuid, env,pc,ruid,euid,suid)
finish_syscall();
}; break;
// 210 long sys_setresgid ['gid_t rgid', ' gid_t egid', ' gid_t sgid']
case 210: {
record_syscall("sys_setresgid");
uint32_t rgid = log_32(env->regs[0], "gid_t rgid");
uint32_t egid = log_32(env->regs[1], " gid_t egid");
uint32_t sgid = log_32(env->regs[2], " gid_t sgid");
syscalls::call_sys_setresgid_callback(env,pc,rgid,egid,sgid);
PPP_RUN_CB(on_sys_setresgid, env,pc,rgid,egid,sgid)
finish_syscall();
}; break;
// 211 long sys_getresgid ['gid_t __user *rgid', ' gid_t __user *egid', ' gid_t __user *sgid']
case 211: {
record_syscall("sys_getresgid");
target_ulong rgid = log_pointer(env->regs[0], "gid_t __user *rgid");
target_ulong egid = log_pointer(env->regs[1], " gid_t __user *egid");
target_ulong sgid = log_pointer(env->regs[2], " gid_t __user *sgid");
syscalls::call_sys_getresgid_callback(env,pc,rgid,egid,sgid);
PPP_RUN_CB(on_sys_getresgid, env,pc,rgid,egid,sgid)
finish_syscall();
}; break;
// 212 long sys_chown ['const char __user *filename', 'uid_t user', ' gid_t group']
case 212: {
record_syscall("sys_chown");
syscalls::string filename = log_string(env->regs[0], "const char __user *filename");
uint32_t user = log_32(env->regs[1], "uid_t user");
uint32_t group = log_32(env->regs[2], " gid_t group");
syscalls::call_sys_chown_callback(env,pc,filename,user,group);
PPP_RUN_CB(on_sys_chown, env,pc,filename.get_vaddr(),user,group)
finish_syscall();
}; break;
// 213 long sys_setuid ['uid_t uid']
case 213: {
record_syscall("sys_setuid");
uint32_t uid = log_32(env->regs[0], "uid_t uid");
syscalls::call_sys_setuid_callback(env,pc,uid);
PPP_RUN_CB(on_sys_setuid, env,pc,uid)
finish_syscall();
}; break;
// 214 long sys_setgid ['gid_t gid']
case 214: {
record_syscall("sys_setgid");
uint32_t gid = log_32(env->regs[0], "gid_t gid");
syscalls::call_sys_setgid_callback(env,pc,gid);
PPP_RUN_CB(on_sys_setgid, env,pc,gid)
finish_syscall();
}; break;
// 215 long sys_setfsuid ['uid_t uid']
case 215: {
record_syscall("sys_setfsuid");
uint32_t uid = log_32(env->regs[0], "uid_t uid");
syscalls::call_sys_setfsuid_callback(env,pc,uid);
PPP_RUN_CB(on_sys_setfsuid, env,pc,uid)
finish_syscall();
}; break;
// 216 long sys_setfsgid ['gid_t gid']
case 216: {
record_syscall("sys_setfsgid");
uint32_t gid = log_32(env->regs[0], "gid_t gid");
syscalls::call_sys_setfsgid_callback(env,pc,gid);
PPP_RUN_CB(on_sys_setfsgid, env,pc,gid)
finish_syscall();
}; break;
// 217 long sys_getdents64 ['unsigned int fd', 'struct linux_dirent64 __user *dirent', 'unsigned int count']
case 217: {
record_syscall("sys_getdents64");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
target_ulong dirent = log_pointer(env->regs[1], "struct linux_dirent64 __user *dirent");
uint32_t count = log_32(env->regs[2], "unsigned int count");
syscalls::call_sys_getdents64_callback(env,pc,fd,dirent,count);
PPP_RUN_CB(on_sys_getdents64, env,pc,fd,dirent,count)
finish_syscall();
}; break;
// 218 long sys_pivot_root ['const char __user *new_root', 'const char __user *put_old']
case 218: {
record_syscall("sys_pivot_root");
syscalls::string new_root = log_string(env->regs[0], "const char __user *new_root");
syscalls::string put_old = log_string(env->regs[1], "const char __user *put_old");
syscalls::call_sys_pivot_root_callback(env,pc,new_root,put_old);
PPP_RUN_CB(on_sys_pivot_root, env,pc,new_root.get_vaddr(),put_old.get_vaddr())
finish_syscall();
}; break;
// 219 long sys_mincore ['unsigned long start', ' size_t len', 'unsigned char __user * vec']
case 219: {
record_syscall("sys_mincore");
uint32_t start = log_32(env->regs[0], "unsigned long start");
uint32_t len = log_32(env->regs[1], " size_t len");
syscalls::string vec = log_string(env->regs[2], "unsigned char __user * vec");
syscalls::call_sys_mincore_callback(env,pc,start,len,vec);
PPP_RUN_CB(on_sys_mincore, env,pc,start,len,vec.get_vaddr())
finish_syscall();
}; break;
// 220 long sys_madvise ['unsigned long start', ' size_t len', ' int behavior']
case 220: {
record_syscall("sys_madvise");
uint32_t start = log_32(env->regs[0], "unsigned long start");
uint32_t len = log_32(env->regs[1], " size_t len");
int32_t behavior = log_s32(env->regs[2], " int behavior");
syscalls::call_sys_madvise_callback(env,pc,start,len,behavior);
PPP_RUN_CB(on_sys_madvise, env,pc,start,len,behavior)
finish_syscall();
}; break;
// 221 long sys_fcntl64 ['unsigned int fd', 'unsigned int cmd', ' unsigned long arg']
case 221: {
record_syscall("sys_fcntl64");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t cmd = log_32(env->regs[1], "unsigned int cmd");
uint32_t arg = log_32(env->regs[2], " unsigned long arg");
syscalls::call_sys_fcntl64_callback(env,pc,fd,cmd,arg);
PPP_RUN_CB(on_sys_fcntl64, env,pc,fd,cmd,arg)
finish_syscall();
}; break;
// 224 long sys_gettid ['void']
case 224: {
record_syscall("sys_gettid");
syscalls::call_sys_gettid_callback(env,pc);
PPP_RUN_CB(on_sys_gettid, env,pc)
finish_syscall();
}; break;
// 225 long sys_readahead ['int fd', ' loff_t offset', ' size_t count']
case 225: {
record_syscall("sys_readahead");
int32_t fd = log_s32(env->regs[0], "int fd");
// skipping arg for alignment
uint64_t offset = log_64(env->regs[2], env->regs[3], " loff_t offset");
uint32_t count = log_32(env->regs[4], " size_t count");
syscalls::call_sys_readahead_callback(env,pc,fd,offset,count);
PPP_RUN_CB(on_sys_readahead, env,pc,fd,offset,count)
finish_syscall();
}; break;
// 226 long sys_setxattr ['const char __user *path', ' const char __user *name', 'const void __user *value', ' size_t size', ' int flags']
case 226: {
record_syscall("sys_setxattr");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
syscalls::string name = log_string(env->regs[1], " const char __user *name");
target_ulong value = log_pointer(env->regs[2], "const void __user *value");
uint32_t size = log_32(env->regs[3], " size_t size");
int32_t flags = log_s32(env->regs[4], " int flags");
syscalls::call_sys_setxattr_callback(env,pc,path,name,value,size,flags);
PPP_RUN_CB(on_sys_setxattr, env,pc,path.get_vaddr(),name.get_vaddr(),value,size,flags)
finish_syscall();
}; break;
// 227 long sys_lsetxattr ['const char __user *path', ' const char __user *name', 'const void __user *value', ' size_t size', ' int flags']
case 227: {
record_syscall("sys_lsetxattr");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
syscalls::string name = log_string(env->regs[1], " const char __user *name");
target_ulong value = log_pointer(env->regs[2], "const void __user *value");
uint32_t size = log_32(env->regs[3], " size_t size");
int32_t flags = log_s32(env->regs[4], " int flags");
syscalls::call_sys_lsetxattr_callback(env,pc,path,name,value,size,flags);
PPP_RUN_CB(on_sys_lsetxattr, env,pc,path.get_vaddr(),name.get_vaddr(),value,size,flags)
finish_syscall();
}; break;
// 228 long sys_fsetxattr ['int fd', ' const char __user *name', 'const void __user *value', ' size_t size', ' int flags']
case 228: {
record_syscall("sys_fsetxattr");
int32_t fd = log_s32(env->regs[0], "int fd");
syscalls::string name = log_string(env->regs[1], " const char __user *name");
target_ulong value = log_pointer(env->regs[2], "const void __user *value");
uint32_t size = log_32(env->regs[3], " size_t size");
int32_t flags = log_s32(env->regs[4], " int flags");
syscalls::call_sys_fsetxattr_callback(env,pc,fd,name,value,size,flags);
PPP_RUN_CB(on_sys_fsetxattr, env,pc,fd,name.get_vaddr(),value,size,flags)
finish_syscall();
}; break;
// 229 long sys_getxattr ['const char __user *path', ' const char __user *name', 'void __user *value', ' size_t size']
case 229: {
record_syscall("sys_getxattr");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
syscalls::string name = log_string(env->regs[1], " const char __user *name");
target_ulong value = log_pointer(env->regs[2], "void __user *value");
uint32_t size = log_32(env->regs[3], " size_t size");
syscalls::call_sys_getxattr_callback(env,pc,path,name,value,size);
PPP_RUN_CB(on_sys_getxattr, env,pc,path.get_vaddr(),name.get_vaddr(),value,size)
finish_syscall();
}; break;
// 230 long sys_lgetxattr ['const char __user *path', ' const char __user *name', 'void __user *value', ' size_t size']
case 230: {
record_syscall("sys_lgetxattr");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
syscalls::string name = log_string(env->regs[1], " const char __user *name");
target_ulong value = log_pointer(env->regs[2], "void __user *value");
uint32_t size = log_32(env->regs[3], " size_t size");
syscalls::call_sys_lgetxattr_callback(env,pc,path,name,value,size);
PPP_RUN_CB(on_sys_lgetxattr, env,pc,path.get_vaddr(),name.get_vaddr(),value,size)
finish_syscall();
}; break;
// 231 long sys_fgetxattr ['int fd', ' const char __user *name', 'void __user *value', ' size_t size']
case 231: {
record_syscall("sys_fgetxattr");
int32_t fd = log_s32(env->regs[0], "int fd");
syscalls::string name = log_string(env->regs[1], " const char __user *name");
target_ulong value = log_pointer(env->regs[2], "void __user *value");
uint32_t size = log_32(env->regs[3], " size_t size");
syscalls::call_sys_fgetxattr_callback(env,pc,fd,name,value,size);
PPP_RUN_CB(on_sys_fgetxattr, env,pc,fd,name.get_vaddr(),value,size)
finish_syscall();
}; break;
// 232 long sys_listxattr ['const char __user *path', ' char __user *list', 'size_t size']
case 232: {
record_syscall("sys_listxattr");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
syscalls::string list = log_string(env->regs[1], " char __user *list");
uint32_t size = log_32(env->regs[2], "size_t size");
syscalls::call_sys_listxattr_callback(env,pc,path,list,size);
PPP_RUN_CB(on_sys_listxattr, env,pc,path.get_vaddr(),list.get_vaddr(),size)
finish_syscall();
}; break;
// 233 long sys_llistxattr ['const char __user *path', ' char __user *list', 'size_t size']
case 233: {
record_syscall("sys_llistxattr");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
syscalls::string list = log_string(env->regs[1], " char __user *list");
uint32_t size = log_32(env->regs[2], "size_t size");
syscalls::call_sys_llistxattr_callback(env,pc,path,list,size);
PPP_RUN_CB(on_sys_llistxattr, env,pc,path.get_vaddr(),list.get_vaddr(),size)
finish_syscall();
}; break;
// 234 long sys_flistxattr ['int fd', ' char __user *list', ' size_t size']
case 234: {
record_syscall("sys_flistxattr");
int32_t fd = log_s32(env->regs[0], "int fd");
syscalls::string list = log_string(env->regs[1], " char __user *list");
uint32_t size = log_32(env->regs[2], " size_t size");
syscalls::call_sys_flistxattr_callback(env,pc,fd,list,size);
PPP_RUN_CB(on_sys_flistxattr, env,pc,fd,list.get_vaddr(),size)
finish_syscall();
}; break;
// 235 long sys_removexattr ['const char __user *path', 'const char __user *name']
case 235: {
record_syscall("sys_removexattr");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
syscalls::string name = log_string(env->regs[1], "const char __user *name");
syscalls::call_sys_removexattr_callback(env,pc,path,name);
PPP_RUN_CB(on_sys_removexattr, env,pc,path.get_vaddr(),name.get_vaddr())
finish_syscall();
}; break;
// 236 long sys_lremovexattr ['const char __user *path', 'const char __user *name']
case 236: {
record_syscall("sys_lremovexattr");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
syscalls::string name = log_string(env->regs[1], "const char __user *name");
syscalls::call_sys_lremovexattr_callback(env,pc,path,name);
PPP_RUN_CB(on_sys_lremovexattr, env,pc,path.get_vaddr(),name.get_vaddr())
finish_syscall();
}; break;
// 237 long sys_fremovexattr ['int fd', ' const char __user *name']
case 237: {
record_syscall("sys_fremovexattr");
int32_t fd = log_s32(env->regs[0], "int fd");
syscalls::string name = log_string(env->regs[1], " const char __user *name");
syscalls::call_sys_fremovexattr_callback(env,pc,fd,name);
PPP_RUN_CB(on_sys_fremovexattr, env,pc,fd,name.get_vaddr())
finish_syscall();
}; break;
// 238 long sys_tkill ['int pid', ' int sig']
case 238: {
record_syscall("sys_tkill");
int32_t pid = log_s32(env->regs[0], "int pid");
int32_t sig = log_s32(env->regs[1], " int sig");
syscalls::call_sys_tkill_callback(env,pc,pid,sig);
PPP_RUN_CB(on_sys_tkill, env,pc,pid,sig)
finish_syscall();
}; break;
// 239 long sys_sendfile64 ['int out_fd', ' int in_fd', 'loff_t __user *offset', ' size_t count']
case 239: {
record_syscall("sys_sendfile64");
int32_t out_fd = log_s32(env->regs[0], "int out_fd");
int32_t in_fd = log_s32(env->regs[1], " int in_fd");
target_ulong offset = log_pointer(env->regs[2], "loff_t __user *offset");
uint32_t count = log_32(env->regs[3], " size_t count");
syscalls::call_sys_sendfile64_callback(env,pc,out_fd,in_fd,offset,count);
PPP_RUN_CB(on_sys_sendfile64, env,pc,out_fd,in_fd,offset,count)
finish_syscall();
}; break;
// 240 long sys_futex ['u32 __user *uaddr', ' int op', ' u32 val', 'struct timespec __user *utime', ' u32 __user *uaddr2', 'u32 val3']
case 240: {
record_syscall("sys_futex");
target_ulong uaddr = log_pointer(env->regs[0], "u32 __user *uaddr");
int32_t op = log_s32(env->regs[1], " int op");
uint32_t val = log_32(env->regs[2], " u32 val");
target_ulong utime = log_pointer(env->regs[3], "struct timespec __user *utime");
target_ulong uaddr2 = log_pointer(env->regs[4], " u32 __user *uaddr2");
uint32_t val3 = log_32(env->regs[5], "u32 val3");
syscalls::call_sys_futex_callback(env,pc,uaddr,op,val,utime,uaddr2,val3);
PPP_RUN_CB(on_sys_futex, env,pc,uaddr,op,val,utime,uaddr2,val3)
finish_syscall();
}; break;
// 241 long sys_sched_setaffinity ['pid_t pid', ' unsigned int len', 'unsigned long __user *user_mask_ptr']
case 241: {
record_syscall("sys_sched_setaffinity");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
uint32_t len = log_32(env->regs[1], " unsigned int len");
target_ulong user_mask_ptr = log_pointer(env->regs[2], "unsigned long __user *user_mask_ptr");
syscalls::call_sys_sched_setaffinity_callback(env,pc,pid,len,user_mask_ptr);
PPP_RUN_CB(on_sys_sched_setaffinity, env,pc,pid,len,user_mask_ptr)
finish_syscall();
}; break;
// 242 long sys_sched_getaffinity ['pid_t pid', ' unsigned int len', 'unsigned long __user *user_mask_ptr']
case 242: {
record_syscall("sys_sched_getaffinity");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
uint32_t len = log_32(env->regs[1], " unsigned int len");
target_ulong user_mask_ptr = log_pointer(env->regs[2], "unsigned long __user *user_mask_ptr");
syscalls::call_sys_sched_getaffinity_callback(env,pc,pid,len,user_mask_ptr);
PPP_RUN_CB(on_sys_sched_getaffinity, env,pc,pid,len,user_mask_ptr)
finish_syscall();
}; break;
// 243 long sys_io_setup ['unsigned nr_reqs', ' aio_context_t __user *ctx']
case 243: {
record_syscall("sys_io_setup");
uint32_t nr_reqs = log_32(env->regs[0], "unsigned nr_reqs");
target_ulong ctx = log_pointer(env->regs[1], " aio_context_t __user *ctx");
syscalls::call_sys_io_setup_callback(env,pc,nr_reqs,ctx);
PPP_RUN_CB(on_sys_io_setup, env,pc,nr_reqs,ctx)
finish_syscall();
}; break;
// 244 long sys_io_destroy ['aio_context_t ctx']
case 244: {
record_syscall("sys_io_destroy");
uint32_t ctx = log_32(env->regs[0], "aio_context_t ctx");
syscalls::call_sys_io_destroy_callback(env,pc,ctx);
PPP_RUN_CB(on_sys_io_destroy, env,pc,ctx)
finish_syscall();
}; break;
// 245 long sys_io_getevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct timespec __user *timeout']
case 245: {
record_syscall("sys_io_getevents");
uint32_t ctx_id = log_32(env->regs[0], "aio_context_t ctx_id");
int32_t min_nr = log_s32(env->regs[1], "long min_nr");
int32_t nr = log_s32(env->regs[2], "long nr");
target_ulong events = log_pointer(env->regs[3], "struct io_event __user *events");
target_ulong timeout = log_pointer(env->regs[4], "struct timespec __user *timeout");
syscalls::call_sys_io_getevents_callback(env,pc,ctx_id,min_nr,nr,events,timeout);
PPP_RUN_CB(on_sys_io_getevents, env,pc,ctx_id,min_nr,nr,events,timeout)
finish_syscall();
}; break;
// 246 long sys_io_submit ['aio_context_t', ' long', 'struct iocb __user * __user *']
case 246: {
record_syscall("sys_io_submit");
uint32_t arg0 = log_32(env->regs[0], "aio_context_t");
int32_t arg1 = log_s32(env->regs[1], " long");
target_ulong arg2 = log_pointer(env->regs[2], "struct iocb __user * __user *");
syscalls::call_sys_io_submit_callback(env,pc,arg0,arg1,arg2);
PPP_RUN_CB(on_sys_io_submit, env,pc,arg0,arg1,arg2)
finish_syscall();
}; break;
// 247 long sys_io_cancel ['aio_context_t ctx_id', ' struct iocb __user *iocb', 'struct io_event __user *result']
case 247: {
record_syscall("sys_io_cancel");
uint32_t ctx_id = log_32(env->regs[0], "aio_context_t ctx_id");
target_ulong iocb = log_pointer(env->regs[1], " struct iocb __user *iocb");
target_ulong result = log_pointer(env->regs[2], "struct io_event __user *result");
syscalls::call_sys_io_cancel_callback(env,pc,ctx_id,iocb,result);
PPP_RUN_CB(on_sys_io_cancel, env,pc,ctx_id,iocb,result)
finish_syscall();
}; break;
// 248 long sys_exit_group ['int error_code']
case 248: {
record_syscall("sys_exit_group");
int32_t error_code = log_s32(env->regs[0], "int error_code");
syscalls::call_sys_exit_group_callback(env,pc,error_code);
PPP_RUN_CB(on_sys_exit_group, env,pc,error_code)
finish_syscall();
}; break;
// 249 long sys_lookup_dcookie ['u64 cookie64', ' char __user *buf', ' size_t len']
case 249: {
record_syscall("sys_lookup_dcookie");
uint64_t cookie64 = log_64(env->regs[0], env->regs[1], "u64 cookie64");
target_ulong buf = log_pointer(env->regs[2], " char __user *buf");
uint32_t len = log_32(env->regs[3], " size_t len");
syscalls::call_sys_lookup_dcookie_callback(env,pc,cookie64,buf,len);
PPP_RUN_CB(on_sys_lookup_dcookie, env,pc,cookie64,buf,len)
finish_syscall();
}; break;
// 250 long sys_epoll_create ['int size']
case 250: {
record_syscall("sys_epoll_create");
int32_t size = log_s32(env->regs[0], "int size");
syscalls::call_sys_epoll_create_callback(env,pc,size);
PPP_RUN_CB(on_sys_epoll_create, env,pc,size)
finish_syscall();
}; break;
// 251 long sys_epoll_ctl ['int epfd', ' int op', ' int fd', 'struct epoll_event __user *event']
case 251: {
record_syscall("sys_epoll_ctl");
int32_t epfd = log_s32(env->regs[0], "int epfd");
int32_t op = log_s32(env->regs[1], " int op");
int32_t fd = log_s32(env->regs[2], " int fd");
target_ulong event = log_pointer(env->regs[3], "struct epoll_event __user *event");
syscalls::call_sys_epoll_ctl_callback(env,pc,epfd,op,fd,event);
PPP_RUN_CB(on_sys_epoll_ctl, env,pc,epfd,op,fd,event)
finish_syscall();
}; break;
// 252 long sys_epoll_wait ['int epfd', ' struct epoll_event __user *events', 'int maxevents', ' int timeout']
case 252: {
record_syscall("sys_epoll_wait");
int32_t epfd = log_s32(env->regs[0], "int epfd");
target_ulong events = log_pointer(env->regs[1], " struct epoll_event __user *events");
int32_t maxevents = log_s32(env->regs[2], "int maxevents");
int32_t timeout = log_s32(env->regs[3], " int timeout");
syscalls::call_sys_epoll_wait_callback(env,pc,epfd,events,maxevents,timeout);
PPP_RUN_CB(on_sys_epoll_wait, env,pc,epfd,events,maxevents,timeout)
finish_syscall();
}; break;
// 253 long sys_remap_file_pages ['unsigned long start', ' unsigned long size', 'unsigned long prot', ' unsigned long pgoff', 'unsigned long flags']
case 253: {
record_syscall("sys_remap_file_pages");
uint32_t start = log_32(env->regs[0], "unsigned long start");
uint32_t size = log_32(env->regs[1], " unsigned long size");
uint32_t prot = log_32(env->regs[2], "unsigned long prot");
uint32_t pgoff = log_32(env->regs[3], " unsigned long pgoff");
uint32_t flags = log_32(env->regs[4], "unsigned long flags");
syscalls::call_sys_remap_file_pages_callback(env,pc,start,size,prot,pgoff,flags);
PPP_RUN_CB(on_sys_remap_file_pages, env,pc,start,size,prot,pgoff,flags)
finish_syscall();
}; break;
// 256 long sys_set_tid_address ['int __user *tidptr']
case 256: {
record_syscall("sys_set_tid_address");
target_ulong tidptr = log_pointer(env->regs[0], "int __user *tidptr");
syscalls::call_sys_set_tid_address_callback(env,pc,tidptr);
PPP_RUN_CB(on_sys_set_tid_address, env,pc,tidptr)
finish_syscall();
}; break;
// 257 long sys_timer_create ['clockid_t which_clock', 'struct sigevent __user *timer_event_spec', 'timer_t __user * created_timer_id']
case 257: {
record_syscall("sys_timer_create");
uint32_t which_clock = log_32(env->regs[0], "clockid_t which_clock");
target_ulong timer_event_spec = log_pointer(env->regs[1], "struct sigevent __user *timer_event_spec");
target_ulong created_timer_id = log_pointer(env->regs[2], "timer_t __user * created_timer_id");
syscalls::call_sys_timer_create_callback(env,pc,which_clock,timer_event_spec,created_timer_id);
PPP_RUN_CB(on_sys_timer_create, env,pc,which_clock,timer_event_spec,created_timer_id)
finish_syscall();
}; break;
// 258 long sys_timer_settime ['timer_t timer_id', ' int flags', 'const struct itimerspec __user *new_setting', 'struct itimerspec __user *old_setting']
case 258: {
record_syscall("sys_timer_settime");
uint32_t timer_id = log_32(env->regs[0], "timer_t timer_id");
int32_t flags = log_s32(env->regs[1], " int flags");
target_ulong new_setting = log_pointer(env->regs[2], "const struct itimerspec __user *new_setting");
target_ulong old_setting = log_pointer(env->regs[3], "struct itimerspec __user *old_setting");
syscalls::call_sys_timer_settime_callback(env,pc,timer_id,flags,new_setting,old_setting);
PPP_RUN_CB(on_sys_timer_settime, env,pc,timer_id,flags,new_setting,old_setting)
finish_syscall();
}; break;
// 259 long sys_timer_gettime ['timer_t timer_id', 'struct itimerspec __user *setting']
case 259: {
record_syscall("sys_timer_gettime");
uint32_t timer_id = log_32(env->regs[0], "timer_t timer_id");
target_ulong setting = log_pointer(env->regs[1], "struct itimerspec __user *setting");
syscalls::call_sys_timer_gettime_callback(env,pc,timer_id,setting);
PPP_RUN_CB(on_sys_timer_gettime, env,pc,timer_id,setting)
finish_syscall();
}; break;
// 260 long sys_timer_getoverrun ['timer_t timer_id']
case 260: {
record_syscall("sys_timer_getoverrun");
uint32_t timer_id = log_32(env->regs[0], "timer_t timer_id");
syscalls::call_sys_timer_getoverrun_callback(env,pc,timer_id);
PPP_RUN_CB(on_sys_timer_getoverrun, env,pc,timer_id)
finish_syscall();
}; break;
// 261 long sys_timer_delete ['timer_t timer_id']
case 261: {
record_syscall("sys_timer_delete");
uint32_t timer_id = log_32(env->regs[0], "timer_t timer_id");
syscalls::call_sys_timer_delete_callback(env,pc,timer_id);
PPP_RUN_CB(on_sys_timer_delete, env,pc,timer_id)
finish_syscall();
}; break;
// 262 long sys_clock_settime ['clockid_t which_clock', 'const struct timespec __user *tp']
case 262: {
record_syscall("sys_clock_settime");
uint32_t which_clock = log_32(env->regs[0], "clockid_t which_clock");
target_ulong tp = log_pointer(env->regs[1], "const struct timespec __user *tp");
syscalls::call_sys_clock_settime_callback(env,pc,which_clock,tp);
PPP_RUN_CB(on_sys_clock_settime, env,pc,which_clock,tp)
finish_syscall();
}; break;
// 263 long sys_clock_gettime ['clockid_t which_clock', 'struct timespec __user *tp']
case 263: {
record_syscall("sys_clock_gettime");
uint32_t which_clock = log_32(env->regs[0], "clockid_t which_clock");
target_ulong tp = log_pointer(env->regs[1], "struct timespec __user *tp");
syscalls::call_sys_clock_gettime_callback(env,pc,which_clock,tp);
PPP_RUN_CB(on_sys_clock_gettime, env,pc,which_clock,tp)
finish_syscall();
}; break;
// 264 long sys_clock_getres ['clockid_t which_clock', 'struct timespec __user *tp']
case 264: {
record_syscall("sys_clock_getres");
uint32_t which_clock = log_32(env->regs[0], "clockid_t which_clock");
target_ulong tp = log_pointer(env->regs[1], "struct timespec __user *tp");
syscalls::call_sys_clock_getres_callback(env,pc,which_clock,tp);
PPP_RUN_CB(on_sys_clock_getres, env,pc,which_clock,tp)
finish_syscall();
}; break;
// 265 long sys_clock_nanosleep ['clockid_t which_clock', ' int flags', 'const struct timespec __user *rqtp', 'struct timespec __user *rmtp']
case 265: {
record_syscall("sys_clock_nanosleep");
uint32_t which_clock = log_32(env->regs[0], "clockid_t which_clock");
int32_t flags = log_s32(env->regs[1], " int flags");
target_ulong rqtp = log_pointer(env->regs[2], "const struct timespec __user *rqtp");
target_ulong rmtp = log_pointer(env->regs[3], "struct timespec __user *rmtp");
syscalls::call_sys_clock_nanosleep_callback(env,pc,which_clock,flags,rqtp,rmtp);
PPP_RUN_CB(on_sys_clock_nanosleep, env,pc,which_clock,flags,rqtp,rmtp)
finish_syscall();
}; break;
// 266 long sys_statfs64 ['const char __user *path', ' size_t sz', 'struct statfs64 __user *buf']
case 266: {
record_syscall("sys_statfs64");
syscalls::string path = log_string(env->regs[0], "const char __user *path");
uint32_t sz = log_32(env->regs[1], " size_t sz");
target_ulong buf = log_pointer(env->regs[2], "struct statfs64 __user *buf");
syscalls::call_sys_statfs64_callback(env,pc,path,sz,buf);
PPP_RUN_CB(on_sys_statfs64, env,pc,path.get_vaddr(),sz,buf)
finish_syscall();
}; break;
// 267 long sys_fstatfs64 ['unsigned int fd', ' size_t sz', 'struct statfs64 __user *buf']
case 267: {
record_syscall("sys_fstatfs64");
uint32_t fd = log_32(env->regs[0], "unsigned int fd");
uint32_t sz = log_32(env->regs[1], " size_t sz");
target_ulong buf = log_pointer(env->regs[2], "struct statfs64 __user *buf");
syscalls::call_sys_fstatfs64_callback(env,pc,fd,sz,buf);
PPP_RUN_CB(on_sys_fstatfs64, env,pc,fd,sz,buf)
finish_syscall();
}; break;
// 268 long sys_tgkill ['int tgid', ' int pid', ' int sig']
case 268: {
record_syscall("sys_tgkill");
int32_t tgid = log_s32(env->regs[0], "int tgid");
int32_t pid = log_s32(env->regs[1], " int pid");
int32_t sig = log_s32(env->regs[2], " int sig");
syscalls::call_sys_tgkill_callback(env,pc,tgid,pid,sig);
PPP_RUN_CB(on_sys_tgkill, env,pc,tgid,pid,sig)
finish_syscall();
}; break;
// 269 long sys_utimes ['char __user *filename', 'struct timeval __user *utimes']
case 269: {
record_syscall("sys_utimes");
syscalls::string filename = log_string(env->regs[0], "char __user *filename");
target_ulong utimes = log_pointer(env->regs[1], "struct timeval __user *utimes");
syscalls::call_sys_utimes_callback(env,pc,filename,utimes);
PPP_RUN_CB(on_sys_utimes, env,pc,filename.get_vaddr(),utimes)
finish_syscall();
}; break;
// 270 long sys_arm_fadvise64_64 ['int fd', ' int advice', ' loff_t offset', ' loff_t len']
case 270: {
record_syscall("sys_arm_fadvise64_64");
int32_t fd = log_s32(env->regs[0], "int fd");
int32_t advice = log_s32(env->regs[1], " int advice");
uint64_t offset = log_64(env->regs[2], env->regs[3], " loff_t offset");
uint64_t len = log_64(env->regs[4], env->regs[5], " loff_t len");
syscalls::call_sys_arm_fadvise64_64_callback(env,pc,fd,advice,offset,len);
PPP_RUN_CB(on_sys_arm_fadvise64_64, env,pc,fd,advice,offset,len)
finish_syscall();
}; break;
// 271 long sys_pciconfig_iobase ['long which', ' unsigned long bus', ' unsigned long devfn']
case 271: {
record_syscall("sys_pciconfig_iobase");
int32_t which = log_s32(env->regs[0], "long which");
uint32_t bus = log_32(env->regs[1], " unsigned long bus");
uint32_t devfn = log_32(env->regs[2], " unsigned long devfn");
syscalls::call_sys_pciconfig_iobase_callback(env,pc,which,bus,devfn);
PPP_RUN_CB(on_sys_pciconfig_iobase, env,pc,which,bus,devfn)
finish_syscall();
}; break;
// 272 long sys_pciconfig_read ['unsigned long bus', ' unsigned long dfn', 'unsigned long off', ' unsigned long len', 'void __user *buf']
case 272: {
record_syscall("sys_pciconfig_read");
uint32_t bus = log_32(env->regs[0], "unsigned long bus");
uint32_t dfn = log_32(env->regs[1], " unsigned long dfn");
uint32_t off = log_32(env->regs[2], "unsigned long off");
uint32_t len = log_32(env->regs[3], " unsigned long len");
target_ulong buf = log_pointer(env->regs[4], "void __user *buf");
syscalls::call_sys_pciconfig_read_callback(env,pc,bus,dfn,off,len,buf);
PPP_RUN_CB(on_sys_pciconfig_read, env,pc,bus,dfn,off,len,buf)
finish_syscall();
}; break;
// 273 long sys_pciconfig_write ['unsigned long bus', ' unsigned long dfn', 'unsigned long off', ' unsigned long len', 'void __user *buf']
case 273: {
record_syscall("sys_pciconfig_write");
uint32_t bus = log_32(env->regs[0], "unsigned long bus");
uint32_t dfn = log_32(env->regs[1], " unsigned long dfn");
uint32_t off = log_32(env->regs[2], "unsigned long off");
uint32_t len = log_32(env->regs[3], " unsigned long len");
target_ulong buf = log_pointer(env->regs[4], "void __user *buf");
syscalls::call_sys_pciconfig_write_callback(env,pc,bus,dfn,off,len,buf);
PPP_RUN_CB(on_sys_pciconfig_write, env,pc,bus,dfn,off,len,buf)
finish_syscall();
}; break;
// 274 long sys_mq_open ['const char __user *name', ' int oflag', ' mode_t mode', ' struct mq_attr __user *attr']
case 274: {
record_syscall("sys_mq_open");
syscalls::string name = log_string(env->regs[0], "const char __user *name");
int32_t oflag = log_s32(env->regs[1], " int oflag");
uint32_t mode = log_32(env->regs[2], " mode_t mode");
target_ulong attr = log_pointer(env->regs[3], " struct mq_attr __user *attr");
syscalls::call_sys_mq_open_callback(env,pc,name,oflag,mode,attr);
PPP_RUN_CB(on_sys_mq_open, env,pc,name.get_vaddr(),oflag,mode,attr)
finish_syscall();
}; break;
// 275 long sys_mq_unlink ['const char __user *name']
case 275: {
record_syscall("sys_mq_unlink");
syscalls::string name = log_string(env->regs[0], "const char __user *name");
syscalls::call_sys_mq_unlink_callback(env,pc,name);
PPP_RUN_CB(on_sys_mq_unlink, env,pc,name.get_vaddr())
finish_syscall();
}; break;
// 276 long sys_mq_timedsend ['mqd_t mqdes', ' const char __user *msg_ptr', ' size_t msg_len', ' unsigned int msg_prio', ' const struct timespec __user *abs_timeout']
case 276: {
record_syscall("sys_mq_timedsend");
uint32_t mqdes = log_32(env->regs[0], "mqd_t mqdes");
syscalls::string msg_ptr = log_string(env->regs[1], " const char __user *msg_ptr");
uint32_t msg_len = log_32(env->regs[2], " size_t msg_len");
uint32_t msg_prio = log_32(env->regs[3], " unsigned int msg_prio");
target_ulong abs_timeout = log_pointer(env->regs[4], " const struct timespec __user *abs_timeout");
syscalls::call_sys_mq_timedsend_callback(env,pc,mqdes,msg_ptr,msg_len,msg_prio,abs_timeout);
PPP_RUN_CB(on_sys_mq_timedsend, env,pc,mqdes,msg_ptr.get_vaddr(),msg_len,msg_prio,abs_timeout)
finish_syscall();
}; break;
// 277 long sys_mq_timedreceive ['mqd_t mqdes', ' char __user *msg_ptr', ' size_t msg_len', ' unsigned int __user *msg_prio', ' const struct timespec __user *abs_timeout']
case 277: {
record_syscall("sys_mq_timedreceive");
uint32_t mqdes = log_32(env->regs[0], "mqd_t mqdes");
syscalls::string msg_ptr = log_string(env->regs[1], " char __user *msg_ptr");
uint32_t msg_len = log_32(env->regs[2], " size_t msg_len");
target_ulong msg_prio = log_pointer(env->regs[3], " unsigned int __user *msg_prio");
target_ulong abs_timeout = log_pointer(env->regs[4], " const struct timespec __user *abs_timeout");
syscalls::call_sys_mq_timedreceive_callback(env,pc,mqdes,msg_ptr,msg_len,msg_prio,abs_timeout);
PPP_RUN_CB(on_sys_mq_timedreceive, env,pc,mqdes,msg_ptr.get_vaddr(),msg_len,msg_prio,abs_timeout)
finish_syscall();
}; break;
// 278 long sys_mq_notify ['mqd_t mqdes', ' const struct sigevent __user *notification']
case 278: {
record_syscall("sys_mq_notify");
uint32_t mqdes = log_32(env->regs[0], "mqd_t mqdes");
target_ulong notification = log_pointer(env->regs[1], " const struct sigevent __user *notification");
syscalls::call_sys_mq_notify_callback(env,pc,mqdes,notification);
PPP_RUN_CB(on_sys_mq_notify, env,pc,mqdes,notification)
finish_syscall();
}; break;
// 279 long sys_mq_getsetattr ['mqd_t mqdes', ' const struct mq_attr __user *mqstat', ' struct mq_attr __user *omqstat']
case 279: {
record_syscall("sys_mq_getsetattr");
uint32_t mqdes = log_32(env->regs[0], "mqd_t mqdes");
target_ulong mqstat = log_pointer(env->regs[1], " const struct mq_attr __user *mqstat");
target_ulong omqstat = log_pointer(env->regs[2], " struct mq_attr __user *omqstat");
syscalls::call_sys_mq_getsetattr_callback(env,pc,mqdes,mqstat,omqstat);
PPP_RUN_CB(on_sys_mq_getsetattr, env,pc,mqdes,mqstat,omqstat)
finish_syscall();
}; break;
// 280 long sys_waitid ['int which', ' pid_t pid', 'struct siginfo __user *infop', 'int options', ' struct rusage __user *ru']
case 280: {
record_syscall("sys_waitid");
int32_t which = log_s32(env->regs[0], "int which");
uint32_t pid = log_32(env->regs[1], " pid_t pid");
target_ulong infop = log_pointer(env->regs[2], "struct siginfo __user *infop");
int32_t options = log_s32(env->regs[3], "int options");
target_ulong ru = log_pointer(env->regs[4], " struct rusage __user *ru");
syscalls::call_sys_waitid_callback(env,pc,which,pid,infop,options,ru);
PPP_RUN_CB(on_sys_waitid, env,pc,which,pid,infop,options,ru)
finish_syscall();
}; break;
// 281 long sys_socket ['int', ' int', ' int']
case 281: {
record_syscall("sys_socket");
int32_t arg0 = log_s32(env->regs[0], "int");
int32_t arg1 = log_s32(env->regs[1], " int");
int32_t arg2 = log_s32(env->regs[2], " int");
syscalls::call_sys_socket_callback(env,pc,arg0,arg1,arg2);
PPP_RUN_CB(on_sys_socket, env,pc,arg0,arg1,arg2)
finish_syscall();
}; break;
// 282 long sys_bind ['int', ' struct sockaddr __user *', ' int']
case 282: {
record_syscall("sys_bind");
int32_t arg0 = log_s32(env->regs[0], "int");
target_ulong arg1 = log_pointer(env->regs[1], " struct sockaddr __user *");
int32_t arg2 = log_s32(env->regs[2], " int");
syscalls::call_sys_bind_callback(env,pc,arg0,arg1,arg2);
PPP_RUN_CB(on_sys_bind, env,pc,arg0,arg1,arg2)
finish_syscall();
}; break;
// 283 long sys_connect ['int', ' struct sockaddr __user *', ' int']
case 283: {
record_syscall("sys_connect");
int32_t arg0 = log_s32(env->regs[0], "int");
target_ulong arg1 = log_pointer(env->regs[1], " struct sockaddr __user *");
int32_t arg2 = log_s32(env->regs[2], " int");
syscalls::call_sys_connect_callback(env,pc,arg0,arg1,arg2);
PPP_RUN_CB(on_sys_connect, env,pc,arg0,arg1,arg2)
finish_syscall();
}; break;
// 284 long sys_listen ['int', ' int']
case 284: {
record_syscall("sys_listen");
int32_t arg0 = log_s32(env->regs[0], "int");
int32_t arg1 = log_s32(env->regs[1], " int");
syscalls::call_sys_listen_callback(env,pc,arg0,arg1);
PPP_RUN_CB(on_sys_listen, env,pc,arg0,arg1)
finish_syscall();
}; break;
// 285 long sys_accept ['int', ' struct sockaddr __user *', ' int __user *']
case 285: {
record_syscall("sys_accept");
int32_t arg0 = log_s32(env->regs[0], "int");
target_ulong arg1 = log_pointer(env->regs[1], " struct sockaddr __user *");
target_ulong arg2 = log_pointer(env->regs[2], " int __user *");
syscalls::call_sys_accept_callback(env,pc,arg0,arg1,arg2);
PPP_RUN_CB(on_sys_accept, env,pc,arg0,arg1,arg2)
finish_syscall();
}; break;
// 286 long sys_getsockname ['int', ' struct sockaddr __user *', ' int __user *']
case 286: {
record_syscall("sys_getsockname");
int32_t arg0 = log_s32(env->regs[0], "int");
target_ulong arg1 = log_pointer(env->regs[1], " struct sockaddr __user *");
target_ulong arg2 = log_pointer(env->regs[2], " int __user *");
syscalls::call_sys_getsockname_callback(env,pc,arg0,arg1,arg2);
PPP_RUN_CB(on_sys_getsockname, env,pc,arg0,arg1,arg2)
finish_syscall();
}; break;
// 287 long sys_getpeername ['int', ' struct sockaddr __user *', ' int __user *']
case 287: {
record_syscall("sys_getpeername");
int32_t arg0 = log_s32(env->regs[0], "int");
target_ulong arg1 = log_pointer(env->regs[1], " struct sockaddr __user *");
target_ulong arg2 = log_pointer(env->regs[2], " int __user *");
syscalls::call_sys_getpeername_callback(env,pc,arg0,arg1,arg2);
PPP_RUN_CB(on_sys_getpeername, env,pc,arg0,arg1,arg2)
finish_syscall();
}; break;
// 288 long sys_socketpair ['int', ' int', ' int', ' int __user *']
case 288: {
record_syscall("sys_socketpair");
int32_t arg0 = log_s32(env->regs[0], "int");
int32_t arg1 = log_s32(env->regs[1], " int");
int32_t arg2 = log_s32(env->regs[2], " int");
target_ulong arg3 = log_pointer(env->regs[3], " int __user *");
syscalls::call_sys_socketpair_callback(env,pc,arg0,arg1,arg2,arg3);
PPP_RUN_CB(on_sys_socketpair, env,pc,arg0,arg1,arg2,arg3)
finish_syscall();
}; break;
// 289 long sys_send ['int', ' void __user *', ' size_t', ' unsigned']
case 289: {
record_syscall("sys_send");
int32_t arg0 = log_s32(env->regs[0], "int");
target_ulong arg1 = log_pointer(env->regs[1], " void __user *");
uint32_t arg2 = log_32(env->regs[2], " size_t");
uint32_t arg3 = log_32(env->regs[3], " unsigned");
syscalls::call_sys_send_callback(env,pc,arg0,arg1,arg2,arg3);
PPP_RUN_CB(on_sys_send, env,pc,arg0,arg1,arg2,arg3)
finish_syscall();
}; break;
// 290 long sys_sendto ['int', ' void __user *', ' size_t', ' unsigned', 'struct sockaddr __user *', ' int']
case 290: {
record_syscall("sys_sendto");
int32_t arg0 = log_s32(env->regs[0], "int");
target_ulong arg1 = log_pointer(env->regs[1], " void __user *");
uint32_t arg2 = log_32(env->regs[2], " size_t");
uint32_t arg3 = log_32(env->regs[3], " unsigned");
target_ulong arg4 = log_pointer(env->regs[4], "struct sockaddr __user *");
int32_t arg5 = log_s32(env->regs[5], " int");
syscalls::call_sys_sendto_callback(env,pc,arg0,arg1,arg2,arg3,arg4,arg5);
PPP_RUN_CB(on_sys_sendto, env,pc,arg0,arg1,arg2,arg3,arg4,arg5)
finish_syscall();
}; break;
// 291 long sys_recv ['int', ' void __user *', ' size_t', ' unsigned']
case 291: {
record_syscall("sys_recv");
int32_t arg0 = log_s32(env->regs[0], "int");
target_ulong arg1 = log_pointer(env->regs[1], " void __user *");
uint32_t arg2 = log_32(env->regs[2], " size_t");
uint32_t arg3 = log_32(env->regs[3], " unsigned");
syscalls::call_sys_recv_callback(env,pc,arg0,arg1,arg2,arg3);
PPP_RUN_CB(on_sys_recv, env,pc,arg0,arg1,arg2,arg3)
finish_syscall();
}; break;
// 292 long sys_recvfrom ['int', ' void __user *', ' size_t', ' unsigned', 'struct sockaddr __user *', ' int __user *']
case 292: {
record_syscall("sys_recvfrom");
int32_t arg0 = log_s32(env->regs[0], "int");
target_ulong arg1 = log_pointer(env->regs[1], " void __user *");
uint32_t arg2 = log_32(env->regs[2], " size_t");
uint32_t arg3 = log_32(env->regs[3], " unsigned");
target_ulong arg4 = log_pointer(env->regs[4], "struct sockaddr __user *");
target_ulong arg5 = log_pointer(env->regs[5], " int __user *");
syscalls::call_sys_recvfrom_callback(env,pc,arg0,arg1,arg2,arg3,arg4,arg5);
PPP_RUN_CB(on_sys_recvfrom, env,pc,arg0,arg1,arg2,arg3,arg4,arg5)
finish_syscall();
}; break;
// 293 long sys_shutdown ['int', ' int']
case 293: {
record_syscall("sys_shutdown");
int32_t arg0 = log_s32(env->regs[0], "int");
int32_t arg1 = log_s32(env->regs[1], " int");
syscalls::call_sys_shutdown_callback(env,pc,arg0,arg1);
PPP_RUN_CB(on_sys_shutdown, env,pc,arg0,arg1)
finish_syscall();
}; break;
// 294 long sys_setsockopt ['int fd', ' int level', ' int optname', 'char __user *optval', ' int optlen']
case 294: {
record_syscall("sys_setsockopt");
int32_t fd = log_s32(env->regs[0], "int fd");
int32_t level = log_s32(env->regs[1], " int level");
int32_t optname = log_s32(env->regs[2], " int optname");
syscalls::string optval = log_string(env->regs[3], "char __user *optval");
int32_t optlen = log_s32(env->regs[4], " int optlen");
syscalls::call_sys_setsockopt_callback(env,pc,fd,level,optname,optval,optlen);
PPP_RUN_CB(on_sys_setsockopt, env,pc,fd,level,optname,optval.get_vaddr(),optlen)
finish_syscall();
}; break;
// 295 long sys_getsockopt ['int fd', ' int level', ' int optname', 'char __user *optval', ' int __user *optlen']
case 295: {
record_syscall("sys_getsockopt");
int32_t fd = log_s32(env->regs[0], "int fd");
int32_t level = log_s32(env->regs[1], " int level");
int32_t optname = log_s32(env->regs[2], " int optname");
syscalls::string optval = log_string(env->regs[3], "char __user *optval");
target_ulong optlen = log_pointer(env->regs[4], " int __user *optlen");
syscalls::call_sys_getsockopt_callback(env,pc,fd,level,optname,optval,optlen);
PPP_RUN_CB(on_sys_getsockopt, env,pc,fd,level,optname,optval.get_vaddr(),optlen)
finish_syscall();
}; break;
// 296 long sys_sendmsg ['int fd', ' struct msghdr __user *msg', ' unsigned flags']
case 296: {
record_syscall("sys_sendmsg");
int32_t fd = log_s32(env->regs[0], "int fd");
target_ulong msg = log_pointer(env->regs[1], " struct msghdr __user *msg");
uint32_t flags = log_32(env->regs[2], " unsigned flags");
syscalls::call_sys_sendmsg_callback(env,pc,fd,msg,flags);
PPP_RUN_CB(on_sys_sendmsg, env,pc,fd,msg,flags)
finish_syscall();
}; break;
// 297 long sys_recvmsg ['int fd', ' struct msghdr __user *msg', ' unsigned flags']
case 297: {
record_syscall("sys_recvmsg");
int32_t fd = log_s32(env->regs[0], "int fd");
target_ulong msg = log_pointer(env->regs[1], " struct msghdr __user *msg");
uint32_t flags = log_32(env->regs[2], " unsigned flags");
syscalls::call_sys_recvmsg_callback(env,pc,fd,msg,flags);
PPP_RUN_CB(on_sys_recvmsg, env,pc,fd,msg,flags)
finish_syscall();
}; break;
// 298 long sys_semop ['int semid', ' struct sembuf __user *sops', 'unsigned nsops']
case 298: {
record_syscall("sys_semop");
int32_t semid = log_s32(env->regs[0], "int semid");
target_ulong sops = log_pointer(env->regs[1], " struct sembuf __user *sops");
uint32_t nsops = log_32(env->regs[2], "unsigned nsops");
syscalls::call_sys_semop_callback(env,pc,semid,sops,nsops);
PPP_RUN_CB(on_sys_semop, env,pc,semid,sops,nsops)
finish_syscall();
}; break;
// 299 long sys_semget ['key_t key', ' int nsems', ' int semflg']
case 299: {
record_syscall("sys_semget");
uint32_t key = log_32(env->regs[0], "key_t key");
int32_t nsems = log_s32(env->regs[1], " int nsems");
int32_t semflg = log_s32(env->regs[2], " int semflg");
syscalls::call_sys_semget_callback(env,pc,key,nsems,semflg);
PPP_RUN_CB(on_sys_semget, env,pc,key,nsems,semflg)
finish_syscall();
}; break;
// 300 long sys_semctl ['int semid', ' int semnum', ' int cmd', ' union semun arg']
case 300: {
record_syscall("sys_semctl");
int32_t semid = log_s32(env->regs[0], "int semid");
int32_t semnum = log_s32(env->regs[1], " int semnum");
int32_t cmd = log_s32(env->regs[2], " int cmd");
uint32_t arg = log_32(env->regs[3], " union semun arg");
syscalls::call_sys_semctl_callback(env,pc,semid,semnum,cmd,arg);
PPP_RUN_CB(on_sys_semctl, env,pc,semid,semnum,cmd,arg)
finish_syscall();
}; break;
// 301 long sys_msgsnd ['int msqid', ' struct msgbuf __user *msgp', 'size_t msgsz', ' int msgflg']
case 301: {
record_syscall("sys_msgsnd");
int32_t msqid = log_s32(env->regs[0], "int msqid");
target_ulong msgp = log_pointer(env->regs[1], " struct msgbuf __user *msgp");
uint32_t msgsz = log_32(env->regs[2], "size_t msgsz");
int32_t msgflg = log_s32(env->regs[3], " int msgflg");
syscalls::call_sys_msgsnd_callback(env,pc,msqid,msgp,msgsz,msgflg);
PPP_RUN_CB(on_sys_msgsnd, env,pc,msqid,msgp,msgsz,msgflg)
finish_syscall();
}; break;
// 302 long sys_msgrcv ['int msqid', ' struct msgbuf __user *msgp', 'size_t msgsz', ' long msgtyp', ' int msgflg']
case 302: {
record_syscall("sys_msgrcv");
int32_t msqid = log_s32(env->regs[0], "int msqid");
target_ulong msgp = log_pointer(env->regs[1], " struct msgbuf __user *msgp");
uint32_t msgsz = log_32(env->regs[2], "size_t msgsz");
int32_t msgtyp = log_s32(env->regs[3], " long msgtyp");
int32_t msgflg = log_s32(env->regs[4], " int msgflg");
syscalls::call_sys_msgrcv_callback(env,pc,msqid,msgp,msgsz,msgtyp,msgflg);
PPP_RUN_CB(on_sys_msgrcv, env,pc,msqid,msgp,msgsz,msgtyp,msgflg)
finish_syscall();
}; break;
// 303 long sys_msgget ['key_t key', ' int msgflg']
case 303: {
record_syscall("sys_msgget");
uint32_t key = log_32(env->regs[0], "key_t key");
int32_t msgflg = log_s32(env->regs[1], " int msgflg");
syscalls::call_sys_msgget_callback(env,pc,key,msgflg);
PPP_RUN_CB(on_sys_msgget, env,pc,key,msgflg)
finish_syscall();
}; break;
// 304 long sys_msgctl ['int msqid', ' int cmd', ' struct msqid_ds __user *buf']
case 304: {
record_syscall("sys_msgctl");
int32_t msqid = log_s32(env->regs[0], "int msqid");
int32_t cmd = log_s32(env->regs[1], " int cmd");
target_ulong buf = log_pointer(env->regs[2], " struct msqid_ds __user *buf");
syscalls::call_sys_msgctl_callback(env,pc,msqid,cmd,buf);
PPP_RUN_CB(on_sys_msgctl, env,pc,msqid,cmd,buf)
finish_syscall();
}; break;
// 305 long sys_shmat ['int shmid', ' char __user *shmaddr', ' int shmflg']
case 305: {
record_syscall("sys_shmat");
int32_t shmid = log_s32(env->regs[0], "int shmid");
syscalls::string shmaddr = log_string(env->regs[1], " char __user *shmaddr");
int32_t shmflg = log_s32(env->regs[2], " int shmflg");
syscalls::call_sys_shmat_callback(env,pc,shmid,shmaddr,shmflg);
PPP_RUN_CB(on_sys_shmat, env,pc,shmid,shmaddr.get_vaddr(),shmflg)
finish_syscall();
}; break;
// 306 long sys_shmdt ['char __user *shmaddr']
case 306: {
record_syscall("sys_shmdt");
syscalls::string shmaddr = log_string(env->regs[0], "char __user *shmaddr");
syscalls::call_sys_shmdt_callback(env,pc,shmaddr);
PPP_RUN_CB(on_sys_shmdt, env,pc,shmaddr.get_vaddr())
finish_syscall();
}; break;
// 307 long sys_shmget ['key_t key', ' size_t size', ' int flag']
case 307: {
record_syscall("sys_shmget");
uint32_t key = log_32(env->regs[0], "key_t key");
uint32_t size = log_32(env->regs[1], " size_t size");
int32_t flag = log_s32(env->regs[2], " int flag");
syscalls::call_sys_shmget_callback(env,pc,key,size,flag);
PPP_RUN_CB(on_sys_shmget, env,pc,key,size,flag)
finish_syscall();
}; break;
// 308 long sys_shmctl ['int shmid', ' int cmd', ' struct shmid_ds __user *buf']
case 308: {
record_syscall("sys_shmctl");
int32_t shmid = log_s32(env->regs[0], "int shmid");
int32_t cmd = log_s32(env->regs[1], " int cmd");
target_ulong buf = log_pointer(env->regs[2], " struct shmid_ds __user *buf");
syscalls::call_sys_shmctl_callback(env,pc,shmid,cmd,buf);
PPP_RUN_CB(on_sys_shmctl, env,pc,shmid,cmd,buf)
finish_syscall();
}; break;
// 309 long sys_add_key ['const char __user *_type', 'const char __user *_description', 'const void __user *_payload', 'size_t plen', 'key_serial_t destringid']
case 309: {
record_syscall("sys_add_key");
syscalls::string _type = log_string(env->regs[0], "const char __user *_type");
syscalls::string _description = log_string(env->regs[1], "const char __user *_description");
target_ulong _payload = log_pointer(env->regs[2], "const void __user *_payload");
uint32_t plen = log_32(env->regs[3], "size_t plen");
uint32_t destringid = log_32(env->regs[4], "key_serial_t destringid");
syscalls::call_sys_add_key_callback(env,pc,_type,_description,_payload,plen,destringid);
PPP_RUN_CB(on_sys_add_key, env,pc,_type.get_vaddr(),_description.get_vaddr(),_payload,plen,destringid)
finish_syscall();
}; break;
// 310 long sys_request_key ['const char __user *_type', 'const char __user *_description', 'const char __user *_callout_info', 'key_serial_t destringid']
case 310: {
record_syscall("sys_request_key");
syscalls::string _type = log_string(env->regs[0], "const char __user *_type");
syscalls::string _description = log_string(env->regs[1], "const char __user *_description");
syscalls::string _callout_info = log_string(env->regs[2], "const char __user *_callout_info");
uint32_t destringid = log_32(env->regs[3], "key_serial_t destringid");
syscalls::call_sys_request_key_callback(env,pc,_type,_description,_callout_info,destringid);
PPP_RUN_CB(on_sys_request_key, env,pc,_type.get_vaddr(),_description.get_vaddr(),_callout_info.get_vaddr(),destringid)
finish_syscall();
}; break;
// 311 long sys_keyctl ['int cmd', ' unsigned long arg2', ' unsigned long arg3', 'unsigned long arg4', ' unsigned long arg5']
case 311: {
record_syscall("sys_keyctl");
int32_t cmd = log_s32(env->regs[0], "int cmd");
uint32_t arg2 = log_32(env->regs[1], " unsigned long arg2");
uint32_t arg3 = log_32(env->regs[2], " unsigned long arg3");
uint32_t arg4 = log_32(env->regs[3], "unsigned long arg4");
uint32_t arg5 = log_32(env->regs[4], " unsigned long arg5");
syscalls::call_sys_keyctl_callback(env,pc,cmd,arg2,arg3,arg4,arg5);
PPP_RUN_CB(on_sys_keyctl, env,pc,cmd,arg2,arg3,arg4,arg5)
finish_syscall();
}; break;
// 312 long sys_semtimedop ['int semid', ' struct sembuf __user *sops', 'unsigned nsops', 'const struct timespec __user *timeout']
case 312: {
record_syscall("sys_semtimedop");
int32_t semid = log_s32(env->regs[0], "int semid");
target_ulong sops = log_pointer(env->regs[1], " struct sembuf __user *sops");
uint32_t nsops = log_32(env->regs[2], "unsigned nsops");
target_ulong timeout = log_pointer(env->regs[3], "const struct timespec __user *timeout");
syscalls::call_sys_semtimedop_callback(env,pc,semid,sops,nsops,timeout);
PPP_RUN_CB(on_sys_semtimedop, env,pc,semid,sops,nsops,timeout)
finish_syscall();
}; break;
// 314 long sys_ioprio_set ['int which', ' int who', ' int ioprio']
case 314: {
record_syscall("sys_ioprio_set");
int32_t which = log_s32(env->regs[0], "int which");
int32_t who = log_s32(env->regs[1], " int who");
int32_t ioprio = log_s32(env->regs[2], " int ioprio");
syscalls::call_sys_ioprio_set_callback(env,pc,which,who,ioprio);
PPP_RUN_CB(on_sys_ioprio_set, env,pc,which,who,ioprio)
finish_syscall();
}; break;
// 315 long sys_ioprio_get ['int which', ' int who']
case 315: {
record_syscall("sys_ioprio_get");
int32_t which = log_s32(env->regs[0], "int which");
int32_t who = log_s32(env->regs[1], " int who");
syscalls::call_sys_ioprio_get_callback(env,pc,which,who);
PPP_RUN_CB(on_sys_ioprio_get, env,pc,which,who)
finish_syscall();
}; break;
// 316 long sys_inotify_init ['void']
case 316: {
record_syscall("sys_inotify_init");
syscalls::call_sys_inotify_init_callback(env,pc);
PPP_RUN_CB(on_sys_inotify_init, env,pc)
finish_syscall();
}; break;
// 317 long sys_inotify_add_watch ['int fd', ' const char __user *path', 'u32 mask']
case 317: {
record_syscall("sys_inotify_add_watch");
int32_t fd = log_s32(env->regs[0], "int fd");
syscalls::string path = log_string(env->regs[1], " const char __user *path");
uint32_t mask = log_32(env->regs[2], "u32 mask");
syscalls::call_sys_inotify_add_watch_callback(env,pc,fd,path,mask);
PPP_RUN_CB(on_sys_inotify_add_watch, env,pc,fd,path.get_vaddr(),mask)
finish_syscall();
}; break;
// 318 long sys_inotify_rm_watch ['int fd', ' __s32 wd']
case 318: {
record_syscall("sys_inotify_rm_watch");
int32_t fd = log_s32(env->regs[0], "int fd");
int32_t wd = log_s32(env->regs[1], " __s32 wd");
syscalls::call_sys_inotify_rm_watch_callback(env,pc,fd,wd);
PPP_RUN_CB(on_sys_inotify_rm_watch, env,pc,fd,wd)
finish_syscall();
}; break;
// 319 long sys_mbind ['unsigned long start', ' unsigned long len', 'unsigned long mode', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned flags']
case 319: {
record_syscall("sys_mbind");
uint32_t start = log_32(env->regs[0], "unsigned long start");
uint32_t len = log_32(env->regs[1], " unsigned long len");
uint32_t mode = log_32(env->regs[2], "unsigned long mode");
target_ulong nmask = log_pointer(env->regs[3], "unsigned long __user *nmask");
uint32_t maxnode = log_32(env->regs[4], "unsigned long maxnode");
uint32_t flags = log_32(env->regs[5], "unsigned flags");
syscalls::call_sys_mbind_callback(env,pc,start,len,mode,nmask,maxnode,flags);
PPP_RUN_CB(on_sys_mbind, env,pc,start,len,mode,nmask,maxnode,flags)
finish_syscall();
}; break;
// 320 long sys_get_mempolicy ['int __user *policy', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned long addr', ' unsigned long flags']
case 320: {
record_syscall("sys_get_mempolicy");
target_ulong policy = log_pointer(env->regs[0], "int __user *policy");
target_ulong nmask = log_pointer(env->regs[1], "unsigned long __user *nmask");
uint32_t maxnode = log_32(env->regs[2], "unsigned long maxnode");
uint32_t addr = log_32(env->regs[3], "unsigned long addr");
uint32_t flags = log_32(env->regs[4], " unsigned long flags");
syscalls::call_sys_get_mempolicy_callback(env,pc,policy,nmask,maxnode,addr,flags);
PPP_RUN_CB(on_sys_get_mempolicy, env,pc,policy,nmask,maxnode,addr,flags)
finish_syscall();
}; break;
// 321 long sys_set_mempolicy ['int mode', ' unsigned long __user *nmask', 'unsigned long maxnode']
case 321: {
record_syscall("sys_set_mempolicy");
int32_t mode = log_s32(env->regs[0], "int mode");
target_ulong nmask = log_pointer(env->regs[1], " unsigned long __user *nmask");
uint32_t maxnode = log_32(env->regs[2], "unsigned long maxnode");
syscalls::call_sys_set_mempolicy_callback(env,pc,mode,nmask,maxnode);
PPP_RUN_CB(on_sys_set_mempolicy, env,pc,mode,nmask,maxnode)
finish_syscall();
}; break;
// 322 long sys_openat ['int dfd', ' const char __user *filename', ' int flags', 'int mode']
case 322: {
record_syscall("sys_openat");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string filename = log_string(env->regs[1], " const char __user *filename");
int32_t flags = log_s32(env->regs[2], " int flags");
int32_t mode = log_s32(env->regs[3], "int mode");
syscalls::call_sys_openat_callback(env,pc,dfd,filename,flags,mode);
PPP_RUN_CB(on_sys_openat, env,pc,dfd,filename.get_vaddr(),flags,mode)
finish_syscall();
}; break;
// 323 long sys_mkdirat ['int dfd', ' const char __user * pathname', ' int mode']
case 323: {
record_syscall("sys_mkdirat");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string pathname = log_string(env->regs[1], " const char __user * pathname");
int32_t mode = log_s32(env->regs[2], " int mode");
syscalls::call_sys_mkdirat_callback(env,pc,dfd,pathname,mode);
PPP_RUN_CB(on_sys_mkdirat, env,pc,dfd,pathname.get_vaddr(),mode)
finish_syscall();
}; break;
// 324 long sys_mknodat ['int dfd', ' const char __user * filename', ' int mode', 'unsigned dev']
case 324: {
record_syscall("sys_mknodat");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string filename = log_string(env->regs[1], " const char __user * filename");
int32_t mode = log_s32(env->regs[2], " int mode");
uint32_t dev = log_32(env->regs[3], "unsigned dev");
syscalls::call_sys_mknodat_callback(env,pc,dfd,filename,mode,dev);
PPP_RUN_CB(on_sys_mknodat, env,pc,dfd,filename.get_vaddr(),mode,dev)
finish_syscall();
}; break;
// 325 long sys_fchownat ['int dfd', ' const char __user *filename', ' uid_t user', 'gid_t group', ' int flag']
case 325: {
record_syscall("sys_fchownat");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string filename = log_string(env->regs[1], " const char __user *filename");
uint32_t user = log_32(env->regs[2], " uid_t user");
uint32_t group = log_32(env->regs[3], "gid_t group");
int32_t flag = log_s32(env->regs[4], " int flag");
syscalls::call_sys_fchownat_callback(env,pc,dfd,filename,user,group,flag);
PPP_RUN_CB(on_sys_fchownat, env,pc,dfd,filename.get_vaddr(),user,group,flag)
finish_syscall();
}; break;
// 326 long sys_futimesat ['int dfd', ' char __user *filename', 'struct timeval __user *utimes']
case 326: {
record_syscall("sys_futimesat");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string filename = log_string(env->regs[1], " char __user *filename");
target_ulong utimes = log_pointer(env->regs[2], "struct timeval __user *utimes");
syscalls::call_sys_futimesat_callback(env,pc,dfd,filename,utimes);
PPP_RUN_CB(on_sys_futimesat, env,pc,dfd,filename.get_vaddr(),utimes)
finish_syscall();
}; break;
// 327 long sys_fstatat64 ['int dfd', ' char __user *filename', 'struct stat64 __user *statbuf', ' int flag']
case 327: {
record_syscall("sys_fstatat64");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string filename = log_string(env->regs[1], " char __user *filename");
target_ulong statbuf = log_pointer(env->regs[2], "struct stat64 __user *statbuf");
int32_t flag = log_s32(env->regs[3], " int flag");
syscalls::call_sys_fstatat64_callback(env,pc,dfd,filename,statbuf,flag);
PPP_RUN_CB(on_sys_fstatat64, env,pc,dfd,filename.get_vaddr(),statbuf,flag)
finish_syscall();
}; break;
// 328 long sys_unlinkat ['int dfd', ' const char __user * pathname', ' int flag']
case 328: {
record_syscall("sys_unlinkat");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string pathname = log_string(env->regs[1], " const char __user * pathname");
int32_t flag = log_s32(env->regs[2], " int flag");
syscalls::call_sys_unlinkat_callback(env,pc,dfd,pathname,flag);
PPP_RUN_CB(on_sys_unlinkat, env,pc,dfd,pathname.get_vaddr(),flag)
finish_syscall();
}; break;
// 329 long sys_renameat ['int olddfd', ' const char __user * oldname', 'int newdfd', ' const char __user * newname']
case 329: {
record_syscall("sys_renameat");
int32_t olddfd = log_s32(env->regs[0], "int olddfd");
syscalls::string oldname = log_string(env->regs[1], " const char __user * oldname");
int32_t newdfd = log_s32(env->regs[2], "int newdfd");
syscalls::string newname = log_string(env->regs[3], " const char __user * newname");
syscalls::call_sys_renameat_callback(env,pc,olddfd,oldname,newdfd,newname);
PPP_RUN_CB(on_sys_renameat, env,pc,olddfd,oldname.get_vaddr(),newdfd,newname.get_vaddr())
finish_syscall();
}; break;
// 330 long sys_linkat ['int olddfd', ' const char __user *oldname', 'int newdfd', ' const char __user *newname', ' int flags']
case 330: {
record_syscall("sys_linkat");
int32_t olddfd = log_s32(env->regs[0], "int olddfd");
syscalls::string oldname = log_string(env->regs[1], " const char __user *oldname");
int32_t newdfd = log_s32(env->regs[2], "int newdfd");
syscalls::string newname = log_string(env->regs[3], " const char __user *newname");
int32_t flags = log_s32(env->regs[4], " int flags");
syscalls::call_sys_linkat_callback(env,pc,olddfd,oldname,newdfd,newname,flags);
PPP_RUN_CB(on_sys_linkat, env,pc,olddfd,oldname.get_vaddr(),newdfd,newname.get_vaddr(),flags)
finish_syscall();
}; break;
// 331 long sys_symlinkat ['const char __user * oldname', 'int newdfd', ' const char __user * newname']
case 331: {
record_syscall("sys_symlinkat");
syscalls::string oldname = log_string(env->regs[0], "const char __user * oldname");
int32_t newdfd = log_s32(env->regs[1], "int newdfd");
syscalls::string newname = log_string(env->regs[2], " const char __user * newname");
syscalls::call_sys_symlinkat_callback(env,pc,oldname,newdfd,newname);
PPP_RUN_CB(on_sys_symlinkat, env,pc,oldname.get_vaddr(),newdfd,newname.get_vaddr())
finish_syscall();
}; break;
// 332 long sys_readlinkat ['int dfd', ' const char __user *path', ' char __user *buf', 'int bufsiz']
case 332: {
record_syscall("sys_readlinkat");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string path = log_string(env->regs[1], " const char __user *path");
target_ulong buf = log_pointer(env->regs[2], " char __user *buf");
int32_t bufsiz = log_s32(env->regs[3], "int bufsiz");
syscalls::call_sys_readlinkat_callback(env,pc,dfd,path,buf,bufsiz);
PPP_RUN_CB(on_sys_readlinkat, env,pc,dfd,path.get_vaddr(),buf,bufsiz)
finish_syscall();
}; break;
// 333 long sys_fchmodat ['int dfd', ' const char __user * filename', 'mode_t mode']
case 333: {
record_syscall("sys_fchmodat");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string filename = log_string(env->regs[1], " const char __user * filename");
uint32_t mode = log_32(env->regs[2], "mode_t mode");
syscalls::call_sys_fchmodat_callback(env,pc,dfd,filename,mode);
PPP_RUN_CB(on_sys_fchmodat, env,pc,dfd,filename.get_vaddr(),mode)
finish_syscall();
}; break;
// 334 long sys_faccessat ['int dfd', ' const char __user *filename', ' int mode']
case 334: {
record_syscall("sys_faccessat");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string filename = log_string(env->regs[1], " const char __user *filename");
int32_t mode = log_s32(env->regs[2], " int mode");
syscalls::call_sys_faccessat_callback(env,pc,dfd,filename,mode);
PPP_RUN_CB(on_sys_faccessat, env,pc,dfd,filename.get_vaddr(),mode)
finish_syscall();
}; break;
// 337 long sys_unshare ['unsigned long unshare_flags']
case 337: {
record_syscall("sys_unshare");
uint32_t unshare_flags = log_32(env->regs[0], "unsigned long unshare_flags");
syscalls::call_sys_unshare_callback(env,pc,unshare_flags);
PPP_RUN_CB(on_sys_unshare, env,pc,unshare_flags)
finish_syscall();
}; break;
// 338 long sys_set_robust_list ['struct robust_list_head __user *head', 'size_t len']
case 338: {
record_syscall("sys_set_robust_list");
target_ulong head = log_pointer(env->regs[0], "struct robust_list_head __user *head");
uint32_t len = log_32(env->regs[1], "size_t len");
syscalls::call_sys_set_robust_list_callback(env,pc,head,len);
PPP_RUN_CB(on_sys_set_robust_list, env,pc,head,len)
finish_syscall();
}; break;
// 339 long sys_get_robust_list ['int pid', 'struct robust_list_head __user * __user *head_ptr', 'size_t __user *len_ptr']
case 339: {
record_syscall("sys_get_robust_list");
int32_t pid = log_s32(env->regs[0], "int pid");
target_ulong head_ptr = log_pointer(env->regs[1], "struct robust_list_head __user * __user *head_ptr");
target_ulong len_ptr = log_pointer(env->regs[2], "size_t __user *len_ptr");
syscalls::call_sys_get_robust_list_callback(env,pc,pid,head_ptr,len_ptr);
PPP_RUN_CB(on_sys_get_robust_list, env,pc,pid,head_ptr,len_ptr)
finish_syscall();
}; break;
// 340 long sys_splice ['int fd_in', ' loff_t __user *off_in', 'int fd_out', ' loff_t __user *off_out', 'size_t len', ' unsigned int flags']
case 340: {
record_syscall("sys_splice");
int32_t fd_in = log_s32(env->regs[0], "int fd_in");
target_ulong off_in = log_pointer(env->regs[1], " loff_t __user *off_in");
int32_t fd_out = log_s32(env->regs[2], "int fd_out");
target_ulong off_out = log_pointer(env->regs[3], " loff_t __user *off_out");
uint32_t len = log_32(env->regs[4], "size_t len");
uint32_t flags = log_32(env->regs[5], " unsigned int flags");
syscalls::call_sys_splice_callback(env,pc,fd_in,off_in,fd_out,off_out,len,flags);
PPP_RUN_CB(on_sys_splice, env,pc,fd_in,off_in,fd_out,off_out,len,flags)
finish_syscall();
}; break;
// 341 long sys_sync_file_range2 ['int fd', ' unsigned int flags', 'loff_t offset', ' loff_t nbytes']
case 341: {
record_syscall("sys_sync_file_range2");
int32_t fd = log_s32(env->regs[0], "int fd");
uint32_t flags = log_32(env->regs[1], " unsigned int flags");
uint64_t offset = log_64(env->regs[2], env->regs[3], "loff_t offset");
uint64_t nbytes = log_64(env->regs[4], env->regs[5], " loff_t nbytes");
syscalls::call_sys_sync_file_range2_callback(env,pc,fd,flags,offset,nbytes);
PPP_RUN_CB(on_sys_sync_file_range2, env,pc,fd,flags,offset,nbytes)
finish_syscall();
}; break;
// 342 long sys_tee ['int fdin', ' int fdout', ' size_t len', ' unsigned int flags']
case 342: {
record_syscall("sys_tee");
int32_t fdin = log_s32(env->regs[0], "int fdin");
int32_t fdout = log_s32(env->regs[1], " int fdout");
uint32_t len = log_32(env->regs[2], " size_t len");
uint32_t flags = log_32(env->regs[3], " unsigned int flags");
syscalls::call_sys_tee_callback(env,pc,fdin,fdout,len,flags);
PPP_RUN_CB(on_sys_tee, env,pc,fdin,fdout,len,flags)
finish_syscall();
}; break;
// 343 long sys_vmsplice ['int fd', ' const struct iovec __user *iov', 'unsigned long nr_segs', ' unsigned int flags']
case 343: {
record_syscall("sys_vmsplice");
int32_t fd = log_s32(env->regs[0], "int fd");
target_ulong iov = log_pointer(env->regs[1], " const struct iovec __user *iov");
uint32_t nr_segs = log_32(env->regs[2], "unsigned long nr_segs");
uint32_t flags = log_32(env->regs[3], " unsigned int flags");
syscalls::call_sys_vmsplice_callback(env,pc,fd,iov,nr_segs,flags);
PPP_RUN_CB(on_sys_vmsplice, env,pc,fd,iov,nr_segs,flags)
finish_syscall();
}; break;
// 344 long sys_move_pages ['pid_t pid', ' unsigned long nr_pages', 'const void __user * __user *pages', 'const int __user *nodes', 'int __user *status', 'int flags']
case 344: {
record_syscall("sys_move_pages");
uint32_t pid = log_32(env->regs[0], "pid_t pid");
uint32_t nr_pages = log_32(env->regs[1], " unsigned long nr_pages");
target_ulong pages = log_pointer(env->regs[2], "const void __user * __user *pages");
target_ulong nodes = log_pointer(env->regs[3], "const int __user *nodes");
target_ulong status = log_pointer(env->regs[4], "int __user *status");
int32_t flags = log_s32(env->regs[5], "int flags");
syscalls::call_sys_move_pages_callback(env,pc,pid,nr_pages,pages,nodes,status,flags);
PPP_RUN_CB(on_sys_move_pages, env,pc,pid,nr_pages,pages,nodes,status,flags)
finish_syscall();
}; break;
// 345 long sys_getcpu ['unsigned __user *cpu', ' unsigned __user *node', ' struct getcpu_cache __user *cache']
case 345: {
record_syscall("sys_getcpu");
target_ulong cpu = log_pointer(env->regs[0], "unsigned __user *cpu");
target_ulong node = log_pointer(env->regs[1], " unsigned __user *node");
target_ulong cache = log_pointer(env->regs[2], " struct getcpu_cache __user *cache");
syscalls::call_sys_getcpu_callback(env,pc,cpu,node,cache);
PPP_RUN_CB(on_sys_getcpu, env,pc,cpu,node,cache)
finish_syscall();
}; break;
// 347 long sys_kexec_load ['unsigned long entry', ' unsigned long nr_segments', 'struct kexec_segment __user *segments', 'unsigned long flags']
case 347: {
record_syscall("sys_kexec_load");
uint32_t entry = log_32(env->regs[0], "unsigned long entry");
uint32_t nr_segments = log_32(env->regs[1], " unsigned long nr_segments");
target_ulong segments = log_pointer(env->regs[2], "struct kexec_segment __user *segments");
uint32_t flags = log_32(env->regs[3], "unsigned long flags");
syscalls::call_sys_kexec_load_callback(env,pc,entry,nr_segments,segments,flags);
PPP_RUN_CB(on_sys_kexec_load, env,pc,entry,nr_segments,segments,flags)
finish_syscall();
}; break;
// 348 long sys_utimensat ['int dfd', ' char __user *filename', 'struct timespec __user *utimes', ' int flags']
case 348: {
record_syscall("sys_utimensat");
int32_t dfd = log_s32(env->regs[0], "int dfd");
syscalls::string filename = log_string(env->regs[1], " char __user *filename");
target_ulong utimes = log_pointer(env->regs[2], "struct timespec __user *utimes");
int32_t flags = log_s32(env->regs[3], " int flags");
syscalls::call_sys_utimensat_callback(env,pc,dfd,filename,utimes,flags);
PPP_RUN_CB(on_sys_utimensat, env,pc,dfd,filename.get_vaddr(),utimes,flags)
finish_syscall();
}; break;
// 349 long sys_signalfd ['int ufd', ' sigset_t __user *user_mask', ' size_t sizemask']
case 349: {
record_syscall("sys_signalfd");
int32_t ufd = log_s32(env->regs[0], "int ufd");
target_ulong user_mask = log_pointer(env->regs[1], " sigset_t __user *user_mask");
uint32_t sizemask = log_32(env->regs[2], " size_t sizemask");
syscalls::call_sys_signalfd_callback(env,pc,ufd,user_mask,sizemask);
PPP_RUN_CB(on_sys_signalfd, env,pc,ufd,user_mask,sizemask)
finish_syscall();
}; break;
// 350 long sys_timerfd_create ['int clockid', ' int flags']
case 350: {
record_syscall("sys_timerfd_create");
int32_t clockid = log_s32(env->regs[0], "int clockid");
int32_t flags = log_s32(env->regs[1], " int flags");
syscalls::call_sys_timerfd_create_callback(env,pc,clockid,flags);
PPP_RUN_CB(on_sys_timerfd_create, env,pc,clockid,flags)
finish_syscall();
}; break;
// 351 long sys_eventfd ['unsigned int count']
case 351: {
record_syscall("sys_eventfd");
uint32_t count = log_32(env->regs[0], "unsigned int count");
syscalls::call_sys_eventfd_callback(env,pc,count);
PPP_RUN_CB(on_sys_eventfd, env,pc,count)
finish_syscall();
}; break;
// 352 long sys_fallocate ['int fd', ' int mode', ' loff_t offset', ' loff_t len']
case 352: {
record_syscall("sys_fallocate");
int32_t fd = log_s32(env->regs[0], "int fd");
int32_t mode = log_s32(env->regs[1], " int mode");
uint64_t offset = log_64(env->regs[2], env->regs[3], " loff_t offset");
uint64_t len = log_64(env->regs[4], env->regs[5], " loff_t len");
syscalls::call_sys_fallocate_callback(env,pc,fd,mode,offset,len);
PPP_RUN_CB(on_sys_fallocate, env,pc,fd,mode,offset,len)
finish_syscall();
}; break;
// 353 long sys_timerfd_settime ['int ufd', ' int flags', 'const struct itimerspec __user *utmr', 'struct itimerspec __user *otmr']
case 353: {
record_syscall("sys_timerfd_settime");
int32_t ufd = log_s32(env->regs[0], "int ufd");
int32_t flags = log_s32(env->regs[1], " int flags");
target_ulong utmr = log_pointer(env->regs[2], "const struct itimerspec __user *utmr");
target_ulong otmr = log_pointer(env->regs[3], "struct itimerspec __user *otmr");
syscalls::call_sys_timerfd_settime_callback(env,pc,ufd,flags,utmr,otmr);
PPP_RUN_CB(on_sys_timerfd_settime, env,pc,ufd,flags,utmr,otmr)
finish_syscall();
}; break;
// 354 long sys_timerfd_gettime ['int ufd', ' struct itimerspec __user *otmr']
case 354: {
record_syscall("sys_timerfd_gettime");
int32_t ufd = log_s32(env->regs[0], "int ufd");
target_ulong otmr = log_pointer(env->regs[1], " struct itimerspec __user *otmr");
syscalls::call_sys_timerfd_gettime_callback(env,pc,ufd,otmr);
PPP_RUN_CB(on_sys_timerfd_gettime, env,pc,ufd,otmr)
finish_syscall();
}; break;
// 355 long sys_signalfd4 ['int ufd', ' sigset_t __user *user_mask', ' size_t sizemask', ' int flags']
case 355: {
record_syscall("sys_signalfd4");
int32_t ufd = log_s32(env->regs[0], "int ufd");
target_ulong user_mask = log_pointer(env->regs[1], " sigset_t __user *user_mask");
uint32_t sizemask = log_32(env->regs[2], " size_t sizemask");
int32_t flags = log_s32(env->regs[3], " int flags");
syscalls::call_sys_signalfd4_callback(env,pc,ufd,user_mask,sizemask,flags);
PPP_RUN_CB(on_sys_signalfd4, env,pc,ufd,user_mask,sizemask,flags)
finish_syscall();
}; break;
// 356 long sys_eventfd2 ['unsigned int count', ' int flags']
case 356: {
record_syscall("sys_eventfd2");
uint32_t count = log_32(env->regs[0], "unsigned int count");
int32_t flags = log_s32(env->regs[1], " int flags");
syscalls::call_sys_eventfd2_callback(env,pc,count,flags);
PPP_RUN_CB(on_sys_eventfd2, env,pc,count,flags)
finish_syscall();
}; break;
// 357 long sys_epoll_create1 ['int flags']
case 357: {
record_syscall("sys_epoll_create1");
int32_t flags = log_s32(env->regs[0], "int flags");
syscalls::call_sys_epoll_create1_callback(env,pc,flags);
PPP_RUN_CB(on_sys_epoll_create1, env,pc,flags)
finish_syscall();
}; break;
// 358 long sys_dup3 ['unsigned int oldfd', ' unsigned int newfd', ' int flags']
case 358: {
record_syscall("sys_dup3");
uint32_t oldfd = log_32(env->regs[0], "unsigned int oldfd");
uint32_t newfd = log_32(env->regs[1], " unsigned int newfd");
int32_t flags = log_s32(env->regs[2], " int flags");
syscalls::call_sys_dup3_callback(env,pc,oldfd,newfd,flags);
PPP_RUN_CB(on_sys_dup3, env,pc,oldfd,newfd,flags)
finish_syscall();
}; break;
// 359 long sys_pipe2 ['int __user *', ' int']
case 359: {
record_syscall("sys_pipe2");
target_ulong arg0 = log_pointer(env->regs[0], "int __user *");
int32_t arg1 = log_s32(env->regs[1], " int");
syscalls::call_sys_pipe2_callback(env,pc,arg0,arg1);
PPP_RUN_CB(on_sys_pipe2, env,pc,arg0,arg1)
finish_syscall();
}; break;
// 360 long sys_inotify_init1 ['int flags']
case 360: {
record_syscall("sys_inotify_init1");
int32_t flags = log_s32(env->regs[0], "int flags");
syscalls::call_sys_inotify_init1_callback(env,pc,flags);
PPP_RUN_CB(on_sys_inotify_init1, env,pc,flags)
finish_syscall();
}; break;
// 10420225 long ARM_breakpoint ['']
case 10420225: {
record_syscall("ARM_breakpoint");
syscalls::call_ARM_breakpoint_callback(env,pc);
PPP_RUN_CB(on_ARM_breakpoint, env,pc)
finish_syscall();
}; break;
// 10420226 long ARM_cacheflush ['unsigned long start', ' unsigned long end', ' unsigned long flags']
case 10420226: {
record_syscall("ARM_cacheflush");
uint32_t start = log_32(env->regs[0], "unsigned long start");
uint32_t end = log_32(env->regs[1], " unsigned long end");
uint32_t flags = log_32(env->regs[2], " unsigned long flags");
syscalls::call_ARM_cacheflush_callback(env,pc,start,end,flags);
PPP_RUN_CB(on_ARM_cacheflush, env,pc,start,end,flags)
finish_syscall();
}; break;
// 10420227 long ARM_user26_mode ['']
case 10420227: {
record_syscall("ARM_user26_mode");
syscalls::call_ARM_user26_mode_callback(env,pc);
PPP_RUN_CB(on_ARM_user26_mode, env,pc)
finish_syscall();
}; break;
// 10420228 long ARM_usr32_mode ['']
case 10420228: {
record_syscall("ARM_usr32_mode");
syscalls::call_ARM_usr32_mode_callback(env,pc);
PPP_RUN_CB(on_ARM_usr32_mode, env,pc)
finish_syscall();
}; break;
// 10420229 long ARM_set_tls ['unsigned long arg']
case 10420229: {
record_syscall("ARM_set_tls");
uint32_t arg = log_32(env->regs[0], "unsigned long arg");
syscalls::call_ARM_set_tls_callback(env,pc,arg);
PPP_RUN_CB(on_ARM_set_tls, env,pc,arg)
finish_syscall();
}; break;
// 10485744 int ARM_cmpxchg ['unsigned long val', ' unsigned long src', ' unsigned long* dest']
case 10485744: {
record_syscall("ARM_cmpxchg");
uint32_t val = log_32(env->regs[0], "unsigned long val");
uint32_t src = log_32(env->regs[1], " unsigned long src");
target_ulong dest = log_pointer(env->regs[2], " unsigned long* dest");
syscalls::call_ARM_cmpxchg_callback(env,pc,val,src,dest);
PPP_RUN_CB(on_ARM_cmpxchg, env,pc,val,src,dest)
finish_syscall();
}; break;
// 10420224 long ARM_null_segfault ['']
case 10420224: {
record_syscall("ARM_null_segfault");
syscalls::call_ARM_null_segfault_callback(env,pc);
PPP_RUN_CB(on_ARM_null_segfault, env,pc)
finish_syscall();
}; break;
default:
record_syscall("UNKNOWN");
}
#endif
