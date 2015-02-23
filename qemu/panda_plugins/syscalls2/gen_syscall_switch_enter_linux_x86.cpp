

extern "C" {
#include "panda_plugin.h" 
}

#include "syscalls2.h" 
#include "panda_common.h"
#include "panda_plugin_plugin.h"

extern "C" {
#include "gen_syscalls_ext_typedefs_linux_x86.h"   // osarch
#include "gen_syscall_ppp_register_enter_linux_x86.cpp"  // osarch
}

#include "gen_syscall_ppp_boilerplate_enter_linux_x86.cpp" // osarch

void syscall_enter_switch_linux_x86 ( CPUState *env, target_ulong pc ) {  // osarch
#ifdef TARGET_I386                                          // GUARD
    ReturnPoint rp;
    rp.ordinal = EAX;                        // CALLNO
    rp.proc_id = panda_current_asid(env);
    rp.retaddr = calc_retaddr(env, pc);
    appendReturnPoint(rp);
    switch( EAX ) {                          // CALLNO
// 0 long sys_restart_syscall ['void']
case 0: {
PPP_RUN_CB(on_sys_restart_syscall_enter, env,pc) ; 
}; break;
// 1 long sys_exit ['int error_code']
case 1: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_exit_enter, env,pc,arg0) ; 
}; break;
// 3 long sys_read ['unsigned int fd', ' char __user *buf', ' size_t count']
case 3: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_read_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 4 long sys_write ['unsigned int fd', ' const char __user *buf', 'size_t count']
case 4: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_write_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 5 long sys_open ['const char __user *filename', 'int flags', ' int mode']
case 5: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_open_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 6 long sys_close ['unsigned int fd']
case 6: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_close_enter, env,pc,arg0) ; 
}; break;
// 7 long sys_waitpid ['pid_t pid', ' int __user *stat_addr', ' int options']
case 7: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_waitpid_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 8 long sys_creat ['const char __user *pathname', ' int mode']
case 8: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_creat_enter, env,pc,arg0,arg1) ; 
}; break;
// 9 long sys_link ['const char __user *oldname', 'const char __user *newname']
case 9: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_link_enter, env,pc,arg0,arg1) ; 
}; break;
// 10 long sys_unlink ['const char __user *pathname']
case 10: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_unlink_enter, env,pc,arg0) ; 
}; break;
// 11 12 long sys_chdir ['const char __user *filename']
case 11: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_chdir_enter, env,pc,arg0) ; 
}; break;
// 13 long sys_time ['time_t __user *tloc']
case 13: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_time_enter, env,pc,arg0) ; 
}; break;
// 14 long sys_mknod ['const char __user *filename', ' int mode', 'unsigned dev']
case 14: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_mknod_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 15 long sys_chmod ['const char __user *filename', ' mode_t mode']
case 15: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_chmod_enter, env,pc,arg0,arg1) ; 
}; break;
// 16 long sys_lchown16 ['const char __user *filename', 'old_uid_t user', ' old_gid_t group']
case 16: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_lchown16_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 18 long sys_stat ['const char __user *filename', 'struct __old_kernel_stat __user *statbuf']
case 18: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_stat_enter, env,pc,arg0,arg1) ; 
}; break;
// 19 long sys_lseek ['unsigned int fd', ' off_t offset', 'unsigned int origin']
case 19: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_lseek_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 20 long sys_getpid ['void']
case 20: {
PPP_RUN_CB(on_sys_getpid_enter, env,pc) ; 
}; break;
// 21 long sys_mount ['char __user *dev_name', ' char __user *dir_name', 'char __user *type', ' unsigned long flags', 'void __user *data']
case 21: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
target_ulong arg4 = get_pointer(env, 4);
PPP_RUN_CB(on_sys_mount_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 22 long sys_oldumount ['char __user *name']
case 22: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_oldumount_enter, env,pc,arg0) ; 
}; break;
// 23 long sys_setuid16 ['old_uid_t uid']
case 23: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_setuid16_enter, env,pc,arg0) ; 
}; break;
// 24 long sys_getuid16 ['void']
case 24: {
PPP_RUN_CB(on_sys_getuid16_enter, env,pc) ; 
}; break;
// 25 long sys_stime ['time_t __user *tptr']
case 25: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_stime_enter, env,pc,arg0) ; 
}; break;
// 26 long sys_ptrace ['long request', ' long pid', ' unsigned long addr', 'unsigned long data']
case 26: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_ptrace_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 27 long sys_alarm ['unsigned int seconds']
case 27: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_alarm_enter, env,pc,arg0) ; 
}; break;
// 28 long sys_fstat ['unsigned int fd', 'struct __old_kernel_stat __user *statbuf']
case 28: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_fstat_enter, env,pc,arg0,arg1) ; 
}; break;
// 29 long sys_pause ['void']
case 29: {
PPP_RUN_CB(on_sys_pause_enter, env,pc) ; 
}; break;
// 30 long sys_utime ['char __user *filename', 'struct utimbuf __user *times']
case 30: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_utime_enter, env,pc,arg0,arg1) ; 
}; break;
// 33 long sys_access ['const char __user *filename', ' int mode']
case 33: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_access_enter, env,pc,arg0,arg1) ; 
}; break;
// 34 long sys_nice ['int increment']
case 34: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_nice_enter, env,pc,arg0) ; 
}; break;
// 36 long sys_sync ['void']
case 36: {
PPP_RUN_CB(on_sys_sync_enter, env,pc) ; 
}; break;
// 37 long sys_kill ['int pid', ' int sig']
case 37: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_kill_enter, env,pc,arg0,arg1) ; 
}; break;
// 38 long sys_rename ['const char __user *oldname', 'const char __user *newname']
case 38: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_rename_enter, env,pc,arg0,arg1) ; 
}; break;
// 39 long sys_mkdir ['const char __user *pathname', ' int mode']
case 39: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_mkdir_enter, env,pc,arg0,arg1) ; 
}; break;
// 40 long sys_rmdir ['const char __user *pathname']
case 40: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_rmdir_enter, env,pc,arg0) ; 
}; break;
// 41 long sys_dup ['unsigned int fildes']
case 41: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_dup_enter, env,pc,arg0) ; 
}; break;
// 42 long sys_pipe ['int __user *fildes']
case 42: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_pipe_enter, env,pc,arg0) ; 
}; break;
// 43 long sys_times ['struct tms __user *tbuf']
case 43: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_times_enter, env,pc,arg0) ; 
}; break;
// 45 long sys_brk ['unsigned long brk']
case 45: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_brk_enter, env,pc,arg0) ; 
}; break;
// 46 long sys_setgid16 ['old_gid_t gid']
case 46: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_setgid16_enter, env,pc,arg0) ; 
}; break;
// 47 long sys_getgid16 ['void']
case 47: {
PPP_RUN_CB(on_sys_getgid16_enter, env,pc) ; 
}; break;
// 48 long sys_signal ['int sig', ' __sighandler_t handler']
case 48: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_signal_enter, env,pc,arg0,arg1) ; 
}; break;
// 49 long sys_geteuid16 ['void']
case 49: {
PPP_RUN_CB(on_sys_geteuid16_enter, env,pc) ; 
}; break;
// 50 long sys_getegid16 ['void']
case 50: {
PPP_RUN_CB(on_sys_getegid16_enter, env,pc) ; 
}; break;
// 51 long sys_acct ['const char __user *name']
case 51: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_acct_enter, env,pc,arg0) ; 
}; break;
// 52 long sys_umount ['char __user *name', ' int flags']
case 52: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_umount_enter, env,pc,arg0,arg1) ; 
}; break;
// 54 long sys_ioctl ['unsigned int fd', ' unsigned int cmd', 'unsigned long arg']
case 54: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_ioctl_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 55 long sys_fcntl ['unsigned int fd', ' unsigned int cmd', ' unsigned long arg']
case 55: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_fcntl_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 57 long sys_setpgid ['pid_t pid', ' pid_t pgid']
case 57: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_setpgid_enter, env,pc,arg0,arg1) ; 
}; break;
// 59 long sys_olduname ['struct oldold_utsname __user *']
case 59: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_olduname_enter, env,pc,arg0) ; 
}; break;
// 60 long sys_umask ['int mask']
case 60: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_umask_enter, env,pc,arg0) ; 
}; break;
// 61 long sys_chroot ['const char __user *filename']
case 61: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_chroot_enter, env,pc,arg0) ; 
}; break;
// 62 long sys_ustat ['unsigned dev', ' struct ustat __user *ubuf']
case 62: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_ustat_enter, env,pc,arg0,arg1) ; 
}; break;
// 63 long sys_dup2 ['unsigned int oldfd', ' unsigned int newfd']
case 63: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_dup2_enter, env,pc,arg0,arg1) ; 
}; break;
// 64 long sys_getppid ['void']
case 64: {
PPP_RUN_CB(on_sys_getppid_enter, env,pc) ; 
}; break;
// 65 long sys_getpgrp ['void']
case 65: {
PPP_RUN_CB(on_sys_getpgrp_enter, env,pc) ; 
}; break;
// 66 long sys_setsid ['void']
case 66: {
PPP_RUN_CB(on_sys_setsid_enter, env,pc) ; 
}; break;
// 67 int sigaction ['int sig', ' const struct old_sigaction __user *act', ' struct old_sigaction __user *oact']
case 67: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sigaction_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 68 long sys_sgetmask ['void']
case 68: {
PPP_RUN_CB(on_sys_sgetmask_enter, env,pc) ; 
}; break;
// 69 long sys_ssetmask ['int newmask']
case 69: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_ssetmask_enter, env,pc,arg0) ; 
}; break;
// 70 long sys_setreuid16 ['old_uid_t ruid', ' old_uid_t euid']
case 70: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_setreuid16_enter, env,pc,arg0,arg1) ; 
}; break;
// 71 long sys_setregid16 ['old_gid_t rgid', ' old_gid_t egid']
case 71: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_setregid16_enter, env,pc,arg0,arg1) ; 
}; break;
// 72 long sigsuspend ['int restart', ' unsigned long oldmask', ' old_sigset_t mask']
case 72: {
int32_t arg0 = get_s32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sigsuspend_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 73 long sys_sigpending ['old_sigset_t __user *set']
case 73: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_sigpending_enter, env,pc,arg0) ; 
}; break;
// 74 long sys_sethostname ['char __user *name', ' int len']
case 74: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_sethostname_enter, env,pc,arg0,arg1) ; 
}; break;
// 75 long sys_setrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
case 75: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_setrlimit_enter, env,pc,arg0,arg1) ; 
}; break;
// 76 long sys_old_getrlimit ['unsigned int resource', ' struct rlimit __user *rlim']
case 76: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_old_getrlimit_enter, env,pc,arg0,arg1) ; 
}; break;
// 77 long sys_getrusage ['int who', ' struct rusage __user *ru']
case 77: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_getrusage_enter, env,pc,arg0,arg1) ; 
}; break;
// 78 long sys_gettimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
case 78: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_gettimeofday_enter, env,pc,arg0,arg1) ; 
}; break;
// 79 long sys_settimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
case 79: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_settimeofday_enter, env,pc,arg0,arg1) ; 
}; break;
// 80 long sys_getgroups16 ['int gidsetsize', ' old_gid_t __user *grouplist']
case 80: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_getgroups16_enter, env,pc,arg0,arg1) ; 
}; break;
// 81 long sys_setgroups16 ['int gidsetsize', ' old_gid_t __user *grouplist']
case 81: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_setgroups16_enter, env,pc,arg0,arg1) ; 
}; break;
// 82 long sys_old_select ['struct sel_arg_struct __user *arg']
case 82: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_old_select_enter, env,pc,arg0) ; 
}; break;
// 83 long sys_symlink ['const char __user *old', ' const char __user *new']
case 83: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_symlink_enter, env,pc,arg0,arg1) ; 
}; break;
// 84 long sys_lstat ['const char __user *filename', 'struct __old_kernel_stat __user *statbuf']
case 84: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_lstat_enter, env,pc,arg0,arg1) ; 
}; break;
// 85 long sys_readlink ['const char __user *path', 'char __user *buf', ' int bufsiz']
case 85: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_readlink_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 86 long sys_uselib ['const char __user *library']
case 86: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_uselib_enter, env,pc,arg0) ; 
}; break;
// 87 long sys_swapon ['const char __user *specialfile', ' int swap_flags']
case 87: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_swapon_enter, env,pc,arg0,arg1) ; 
}; break;
// 88 long sys_reboot ['int magic1', ' int magic2', ' unsigned int cmd', 'void __user *arg']
case 88: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
uint32_t arg2 = get_32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_reboot_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 89 long sys_old_readdir ['unsigned int', ' struct old_linux_dirent __user *', ' unsigned int']
case 89: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_old_readdir_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 90 long sys_old_mmap ['struct mmap_arg_struct __user *arg']
case 90: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_old_mmap_enter, env,pc,arg0) ; 
}; break;
// 91 long sys_munmap ['unsigned long addr', ' size_t len']
case 91: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_munmap_enter, env,pc,arg0,arg1) ; 
}; break;
// 92 long sys_truncate ['const char __user *path', ' long length']
case 92: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_truncate_enter, env,pc,arg0,arg1) ; 
}; break;
// 93 long sys_ftruncate ['unsigned int fd', ' unsigned long length']
case 93: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_ftruncate_enter, env,pc,arg0,arg1) ; 
}; break;
// 94 long sys_fchmod ['unsigned int fd', ' mode_t mode']
case 94: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_fchmod_enter, env,pc,arg0,arg1) ; 
}; break;
// 95 long sys_fchown16 ['unsigned int fd', ' old_uid_t user', ' old_gid_t group']
case 95: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_fchown16_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 96 long sys_getpriority ['int which', ' int who']
case 96: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_getpriority_enter, env,pc,arg0,arg1) ; 
}; break;
// 97 long sys_setpriority ['int which', ' int who', ' int niceval']
case 97: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_setpriority_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 99 long sys_statfs ['const char __user * path', 'struct statfs __user *buf']
case 99: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_statfs_enter, env,pc,arg0,arg1) ; 
}; break;
// 100 long sys_fstatfs ['unsigned int fd', ' struct statfs __user *buf']
case 100: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_fstatfs_enter, env,pc,arg0,arg1) ; 
}; break;
// 101 long sys_ioperm ['unsigned long from', ' unsigned long num', ' int on']
case 101: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_ioperm_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 102 long sys_socketcall ['int call', ' unsigned long __user *args']
case 102: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_socketcall_enter, env,pc,arg0,arg1) ; 
}; break;
// 103 long sys_syslog ['int type', ' char __user *buf', ' int len']
case 103: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_syslog_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 104 long sys_setitimer ['int which', 'struct itimerval __user *value', 'struct itimerval __user *ovalue']
case 104: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_setitimer_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 105 long sys_getitimer ['int which', ' struct itimerval __user *value']
case 105: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_getitimer_enter, env,pc,arg0,arg1) ; 
}; break;
// 106 long sys_newstat ['const char __user *filename', 'struct stat __user *statbuf']
case 106: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_newstat_enter, env,pc,arg0,arg1) ; 
}; break;
// 107 long sys_newlstat ['const char __user *filename', 'struct stat __user *statbuf']
case 107: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_newlstat_enter, env,pc,arg0,arg1) ; 
}; break;
// 108 long sys_newfstat ['unsigned int fd', ' struct stat __user *statbuf']
case 108: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_newfstat_enter, env,pc,arg0,arg1) ; 
}; break;
// 109 long sys_uname ['struct old_utsname __user *']
case 109: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_uname_enter, env,pc,arg0) ; 
}; break;
// 111 long sys_vhangup ['void']
case 111: {
PPP_RUN_CB(on_sys_vhangup_enter, env,pc) ; 
}; break;
// 114 long sys_wait4 ['pid_t pid', ' int __user *stat_addr', 'int options', ' struct rusage __user *ru']
case 114: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_wait4_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 115 long sys_swapoff ['const char __user *specialfile']
case 115: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_swapoff_enter, env,pc,arg0) ; 
}; break;
// 116 long sys_sysinfo ['struct sysinfo __user *info']
case 116: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_sysinfo_enter, env,pc,arg0) ; 
}; break;
// 117 long sys_ipc ['unsigned int call', ' int first', ' unsigned long second', 'unsigned long third', ' void __user *ptr', ' long fifth']
case 117: {
uint32_t arg0 = get_32(env, 0);
int32_t arg1 = get_s32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
target_ulong arg4 = get_pointer(env, 4);
int32_t arg5 = get_s32(env, 5);
PPP_RUN_CB(on_sys_ipc_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 118 long sys_fsync ['unsigned int fd']
case 118: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_fsync_enter, env,pc,arg0) ; 
}; break;
// 119 120 121 long sys_setdomainname ['char __user *name', ' int len']
case 119: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_setdomainname_enter, env,pc,arg0,arg1) ; 
}; break;
// 122 long sys_newuname ['struct new_utsname __user *name']
case 122: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_newuname_enter, env,pc,arg0) ; 
}; break;
// 123 124 long sys_adjtimex ['struct timex __user *txc_p']
case 123: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_adjtimex_enter, env,pc,arg0) ; 
}; break;
// 125 long sys_mprotect ['unsigned long start', ' size_t len', 'unsigned long prot']
case 125: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_mprotect_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 126 long sys_sigprocmask ['int how', ' old_sigset_t __user *set', 'old_sigset_t __user *oset']
case 126: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_sigprocmask_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 128 long sys_init_module ['void __user *umod', ' unsigned long len', 'const char __user *uargs']
case 128: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_init_module_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 129 long sys_delete_module ['const char __user *name_user', 'unsigned int flags']
case 129: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_delete_module_enter, env,pc,arg0,arg1) ; 
}; break;
// 131 long sys_quotactl ['unsigned int cmd', ' const char __user *special', 'qid_t id', ' void __user *addr']
case 131: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_quotactl_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 132 long sys_getpgid ['pid_t pid']
case 132: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_getpgid_enter, env,pc,arg0) ; 
}; break;
// 133 long sys_fchdir ['unsigned int fd']
case 133: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_fchdir_enter, env,pc,arg0) ; 
}; break;
// 134 long sys_bdflush ['int func', ' long data']
case 134: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_bdflush_enter, env,pc,arg0,arg1) ; 
}; break;
// 135 long sys_sysfs ['int option', 'unsigned long arg1', ' unsigned long arg2']
case 135: {
int32_t arg0 = get_s32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_sysfs_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 136 long sys_personality ['unsigned int personality']
case 136: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_personality_enter, env,pc,arg0) ; 
}; break;
// 138 long sys_setfsuid16 ['old_uid_t uid']
case 138: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_setfsuid16_enter, env,pc,arg0) ; 
}; break;
// 139 long sys_setfsgid16 ['old_gid_t gid']
case 139: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_setfsgid16_enter, env,pc,arg0) ; 
}; break;
// 140 long sys_llseek ['unsigned int fd', ' unsigned long offset_high', 'unsigned long offset_low', ' loff_t __user *result', 'unsigned int origin']
case 140: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_llseek_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 141 long sys_getdents ['unsigned int fd', 'struct linux_dirent __user *dirent', 'unsigned int count']
case 141: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_getdents_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 142 long sys_select ['int n', ' fd_set __user *inp', ' fd_set __user *outp', 'fd_set __user *exp', ' struct timeval __user *tvp']
case 142: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
target_ulong arg3 = get_pointer(env, 3);
target_ulong arg4 = get_pointer(env, 4);
PPP_RUN_CB(on_sys_select_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 143 long sys_flock ['unsigned int fd', ' unsigned int cmd']
case 143: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_flock_enter, env,pc,arg0,arg1) ; 
}; break;
// 144 long sys_msync ['unsigned long start', ' size_t len', ' int flags']
case 144: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_msync_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 145 long sys_readv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
case 145: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_readv_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 146 long sys_writev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
case 146: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_writev_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 147 long sys_getsid ['pid_t pid']
case 147: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_getsid_enter, env,pc,arg0) ; 
}; break;
// 148 long sys_fdatasync ['unsigned int fd']
case 148: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_fdatasync_enter, env,pc,arg0) ; 
}; break;
// 149 long sys_sysctl ['struct __sysctl_args __user *args']
case 149: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_sysctl_enter, env,pc,arg0) ; 
}; break;
// 150 long sys_mlock ['unsigned long start', ' size_t len']
case 150: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_mlock_enter, env,pc,arg0,arg1) ; 
}; break;
// 151 long sys_munlock ['unsigned long start', ' size_t len']
case 151: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_munlock_enter, env,pc,arg0,arg1) ; 
}; break;
// 152 long sys_mlockall ['int flags']
case 152: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_mlockall_enter, env,pc,arg0) ; 
}; break;
// 153 long sys_munlockall ['void']
case 153: {
PPP_RUN_CB(on_sys_munlockall_enter, env,pc) ; 
}; break;
// 154 long sys_sched_setparam ['pid_t pid', 'struct sched_param __user *param']
case 154: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_sched_setparam_enter, env,pc,arg0,arg1) ; 
}; break;
// 155 long sys_sched_getparam ['pid_t pid', 'struct sched_param __user *param']
case 155: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_sched_getparam_enter, env,pc,arg0,arg1) ; 
}; break;
// 156 long sys_sched_setscheduler ['pid_t pid', ' int policy', 'struct sched_param __user *param']
case 156: {
uint32_t arg0 = get_32(env, 0);
int32_t arg1 = get_s32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_sched_setscheduler_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 157 long sys_sched_getscheduler ['pid_t pid']
case 157: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_sched_getscheduler_enter, env,pc,arg0) ; 
}; break;
// 158 long sys_sched_yield ['void']
case 158: {
PPP_RUN_CB(on_sys_sched_yield_enter, env,pc) ; 
}; break;
// 159 long sys_sched_get_priority_max ['int policy']
case 159: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_sched_get_priority_max_enter, env,pc,arg0) ; 
}; break;
// 160 long sys_sched_get_priority_min ['int policy']
case 160: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_sched_get_priority_min_enter, env,pc,arg0) ; 
}; break;
// 161 long sys_sched_rr_get_interval ['pid_t pid', 'struct timespec __user *interval']
case 161: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_sched_rr_get_interval_enter, env,pc,arg0,arg1) ; 
}; break;
// 162 long sys_nanosleep ['struct timespec __user *rqtp', ' struct timespec __user *rmtp']
case 162: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_nanosleep_enter, env,pc,arg0,arg1) ; 
}; break;
// 163 long sys_mremap ['unsigned long addr', 'unsigned long old_len', ' unsigned long new_len', 'unsigned long flags', ' unsigned long new_addr']
case 163: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_mremap_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 164 long sys_setresuid16 ['old_uid_t ruid', ' old_uid_t euid', ' old_uid_t suid']
case 164: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_setresuid16_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 165 long sys_getresuid16 ['old_uid_t __user *ruid', 'old_uid_t __user *euid', ' old_uid_t __user *suid']
case 165: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_getresuid16_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 166 168 long sys_poll ['struct pollfd __user *ufds', ' unsigned int nfds', 'long timeout']
case 166: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_poll_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 170 long sys_setresgid16 ['old_gid_t rgid', ' old_gid_t egid', ' old_gid_t sgid']
case 170: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_setresgid16_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 171 long sys_getresgid16 ['old_gid_t __user *rgid', 'old_gid_t __user *egid', ' old_gid_t __user *sgid']
case 171: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_getresgid16_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 172 long sys_prctl ['int option', ' unsigned long arg2', ' unsigned long arg3', 'unsigned long arg4', ' unsigned long arg5']
case 172: {
int32_t arg0 = get_s32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_prctl_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 173 174 long rt_sigaction ['int sig', ' const struct sigaction __user * act', ' struct sigaction __user * oact', '  size_t sigsetsize']
case 173: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_rt_sigaction_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 175 long sys_rt_sigprocmask ['int how', ' sigset_t __user *set', 'sigset_t __user *oset', ' size_t sigsetsize']
case 175: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_rt_sigprocmask_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 176 long sys_rt_sigpending ['sigset_t __user *set', ' size_t sigsetsize']
case 176: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_rt_sigpending_enter, env,pc,arg0,arg1) ; 
}; break;
// 177 long sys_rt_sigtimedwait ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct timespec __user *uts', 'size_t sigsetsize']
case 177: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_rt_sigtimedwait_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 178 long sys_rt_sigqueueinfo ['int pid', ' int sig', ' siginfo_t __user *uinfo']
case 178: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_rt_sigqueueinfo_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 179 int sys_rt_sigsuspend ['sigset_t __user *unewset', ' size_t sigsetsize']
case 179: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_rt_sigsuspend_enter, env,pc,arg0,arg1) ; 
}; break;
// 180 long sys_pread64 ['unsigned int fd', ' char __user *buf', 'size_t count', ' loff_t pos']
case 180: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint64_t arg3 = get_64(env, 3);
PPP_RUN_CB(on_sys_pread64_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 181 long sys_pwrite64 ['unsigned int fd', ' const char __user *buf', 'size_t count', ' loff_t pos']
case 181: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint64_t arg3 = get_64(env, 3);
PPP_RUN_CB(on_sys_pwrite64_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 182 long sys_chown16 ['const char __user *filename', 'old_uid_t user', ' old_gid_t group']
case 182: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_chown16_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 183 long sys_getcwd ['char __user *buf', ' unsigned long size']
case 183: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_getcwd_enter, env,pc,arg0,arg1) ; 
}; break;
// 184 long sys_capget ['cap_user_header_t header', 'cap_user_data_t dataptr']
case 184: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_capget_enter, env,pc,arg0,arg1) ; 
}; break;
// 185 long sys_capset ['cap_user_header_t header', 'const cap_user_data_t data']
case 185: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_capset_enter, env,pc,arg0,arg1) ; 
}; break;
// 186 187 long sys_sendfile ['int out_fd', ' int in_fd', 'off_t __user *offset', ' size_t count']
case 186: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_sendfile_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 190 191 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
case 190: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_getrlimit_enter, env,pc,arg0,arg1) ; 
}; break;
// 192 long sys_mmap_pgoff ['unsigned long addr', ' unsigned long len', 'unsigned long prot', ' unsigned long flags', 'unsigned long fd', ' unsigned long pgoff']
case 192: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
PPP_RUN_CB(on_sys_mmap_pgoff_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 193 long sys_truncate64 ['const char __user *path', ' loff_t length']
case 193: {
target_ulong arg0 = get_pointer(env, 0);
uint64_t arg1 = get_64(env, 1);
PPP_RUN_CB(on_sys_truncate64_enter, env,pc,arg0,arg1) ; 
}; break;
// 194 long sys_ftruncate64 ['unsigned int fd', ' loff_t length']
case 194: {
uint32_t arg0 = get_32(env, 0);
uint64_t arg1 = get_64(env, 1);
PPP_RUN_CB(on_sys_ftruncate64_enter, env,pc,arg0,arg1) ; 
}; break;
// 195 long sys_stat64 ['const char __user *filename', 'struct stat64 __user *statbuf']
case 195: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_stat64_enter, env,pc,arg0,arg1) ; 
}; break;
// 196 long sys_lstat64 ['const char __user *filename', 'struct stat64 __user *statbuf']
case 196: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_lstat64_enter, env,pc,arg0,arg1) ; 
}; break;
// 197 long sys_fstat64 ['unsigned long fd', ' struct stat64 __user *statbuf']
case 197: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_fstat64_enter, env,pc,arg0,arg1) ; 
}; break;
// 198 long sys_lchown ['const char __user *filename', 'uid_t user', ' gid_t group']
case 198: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_lchown_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 199 long sys_getuid ['void']
case 199: {
PPP_RUN_CB(on_sys_getuid_enter, env,pc) ; 
}; break;
// 200 long sys_getgid ['void']
case 200: {
PPP_RUN_CB(on_sys_getgid_enter, env,pc) ; 
}; break;
// 201 long sys_geteuid ['void']
case 201: {
PPP_RUN_CB(on_sys_geteuid_enter, env,pc) ; 
}; break;
// 202 long sys_getegid ['void']
case 202: {
PPP_RUN_CB(on_sys_getegid_enter, env,pc) ; 
}; break;
// 203 long sys_setreuid ['uid_t ruid', ' uid_t euid']
case 203: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_setreuid_enter, env,pc,arg0,arg1) ; 
}; break;
// 204 long sys_setregid ['gid_t rgid', ' gid_t egid']
case 204: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_setregid_enter, env,pc,arg0,arg1) ; 
}; break;
// 205 long sys_getgroups ['int gidsetsize', ' gid_t __user *grouplist']
case 205: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_getgroups_enter, env,pc,arg0,arg1) ; 
}; break;
// 206 long sys_setgroups ['int gidsetsize', ' gid_t __user *grouplist']
case 206: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_setgroups_enter, env,pc,arg0,arg1) ; 
}; break;
// 207 long sys_fchown ['unsigned int fd', ' uid_t user', ' gid_t group']
case 207: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_fchown_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 208 long sys_setresuid ['uid_t ruid', ' uid_t euid', ' uid_t suid']
case 208: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_setresuid_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 209 long sys_getresuid ['uid_t __user *ruid', ' uid_t __user *euid', ' uid_t __user *suid']
case 209: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_getresuid_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 210 long sys_setresgid ['gid_t rgid', ' gid_t egid', ' gid_t sgid']
case 210: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_setresgid_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 211 long sys_getresgid ['gid_t __user *rgid', ' gid_t __user *egid', ' gid_t __user *sgid']
case 211: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_getresgid_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 212 long sys_chown ['const char __user *filename', 'uid_t user', ' gid_t group']
case 212: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_chown_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 213 long sys_setuid ['uid_t uid']
case 213: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_setuid_enter, env,pc,arg0) ; 
}; break;
// 214 long sys_setgid ['gid_t gid']
case 214: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_setgid_enter, env,pc,arg0) ; 
}; break;
// 215 long sys_setfsuid ['uid_t uid']
case 215: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_setfsuid_enter, env,pc,arg0) ; 
}; break;
// 216 long sys_setfsgid ['gid_t gid']
case 216: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_setfsgid_enter, env,pc,arg0) ; 
}; break;
// 217 long sys_pivot_root ['const char __user *new_root', 'const char __user *put_old']
case 217: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_pivot_root_enter, env,pc,arg0,arg1) ; 
}; break;
// 218 long sys_mincore ['unsigned long start', ' size_t len', 'unsigned char __user * vec']
case 218: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_mincore_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 219 long sys_madvise ['unsigned long start', ' size_t len', ' int behavior']
case 219: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_madvise_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 220 long sys_getdents64 ['unsigned int fd', 'struct linux_dirent64 __user *dirent', 'unsigned int count']
case 220: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_getdents64_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 221 long sys_fcntl64 ['unsigned int fd', 'unsigned int cmd', ' unsigned long arg']
case 221: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_fcntl64_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 224 long sys_gettid ['void']
case 224: {
PPP_RUN_CB(on_sys_gettid_enter, env,pc) ; 
}; break;
// 225 long sys_readahead ['int fd', ' loff_t offset', ' size_t count']
case 225: {
int32_t arg0 = get_s32(env, 0);
uint64_t arg1 = get_64(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_readahead_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 226 long sys_setxattr ['const char __user *path', ' const char __user *name', 'const void __user *value', ' size_t size', ' int flags']
case 226: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
int32_t arg4 = get_s32(env, 4);
PPP_RUN_CB(on_sys_setxattr_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 227 long sys_lsetxattr ['const char __user *path', ' const char __user *name', 'const void __user *value', ' size_t size', ' int flags']
case 227: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
int32_t arg4 = get_s32(env, 4);
PPP_RUN_CB(on_sys_lsetxattr_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 228 long sys_fsetxattr ['int fd', ' const char __user *name', 'const void __user *value', ' size_t size', ' int flags']
case 228: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
int32_t arg4 = get_s32(env, 4);
PPP_RUN_CB(on_sys_fsetxattr_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 229 long sys_getxattr ['const char __user *path', ' const char __user *name', 'void __user *value', ' size_t size']
case 229: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_getxattr_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 230 long sys_lgetxattr ['const char __user *path', ' const char __user *name', 'void __user *value', ' size_t size']
case 230: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_lgetxattr_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 231 long sys_fgetxattr ['int fd', ' const char __user *name', 'void __user *value', ' size_t size']
case 231: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_fgetxattr_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 232 long sys_listxattr ['const char __user *path', ' char __user *list', 'size_t size']
case 232: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_listxattr_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 233 long sys_llistxattr ['const char __user *path', ' char __user *list', 'size_t size']
case 233: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_llistxattr_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 234 long sys_flistxattr ['int fd', ' char __user *list', ' size_t size']
case 234: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_flistxattr_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 235 long sys_removexattr ['const char __user *path', 'const char __user *name']
case 235: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_removexattr_enter, env,pc,arg0,arg1) ; 
}; break;
// 236 long sys_lremovexattr ['const char __user *path', 'const char __user *name']
case 236: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_lremovexattr_enter, env,pc,arg0,arg1) ; 
}; break;
// 237 long sys_fremovexattr ['int fd', ' const char __user *name']
case 237: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_fremovexattr_enter, env,pc,arg0,arg1) ; 
}; break;
// 238 long sys_tkill ['int pid', ' int sig']
case 238: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_tkill_enter, env,pc,arg0,arg1) ; 
}; break;
// 239 long sys_sendfile64 ['int out_fd', ' int in_fd', 'loff_t __user *offset', ' size_t count']
case 239: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_sendfile64_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 240 long sys_futex ['u32 __user *uaddr', ' int op', ' u32 val', 'struct timespec __user *utime', ' u32 __user *uaddr2', 'u32 val3']
case 240: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
uint32_t arg2 = get_32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
target_ulong arg4 = get_pointer(env, 4);
uint32_t arg5 = get_32(env, 5);
PPP_RUN_CB(on_sys_futex_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 241 long sys_sched_setaffinity ['pid_t pid', ' unsigned int len', 'unsigned long __user *user_mask_ptr']
case 241: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_sched_setaffinity_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 242 long sys_sched_getaffinity ['pid_t pid', ' unsigned int len', 'unsigned long __user *user_mask_ptr']
case 242: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_sched_getaffinity_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 243 244 245 long sys_io_setup ['unsigned nr_reqs', ' aio_context_t __user *ctx']
case 243: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_io_setup_enter, env,pc,arg0,arg1) ; 
}; break;
// 246 long sys_io_destroy ['aio_context_t ctx']
case 246: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_io_destroy_enter, env,pc,arg0) ; 
}; break;
// 247 long sys_io_getevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct timespec __user *timeout']
case 247: {
uint32_t arg0 = get_32(env, 0);
int32_t arg1 = get_s32(env, 1);
int32_t arg2 = get_s32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
target_ulong arg4 = get_pointer(env, 4);
PPP_RUN_CB(on_sys_io_getevents_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 248 long sys_io_submit ['aio_context_t', ' long', 'struct iocb __user * __user *']
case 248: {
uint32_t arg0 = get_32(env, 0);
int32_t arg1 = get_s32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_io_submit_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 249 long sys_io_cancel ['aio_context_t ctx_id', ' struct iocb __user *iocb', 'struct io_event __user *result']
case 249: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_io_cancel_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 250 long sys_fadvise64 ['int fd', ' loff_t offset', ' size_t len', ' int advice']
case 250: {
int32_t arg0 = get_s32(env, 0);
uint64_t arg1 = get_64(env, 1);
uint32_t arg2 = get_32(env, 2);
int32_t arg3 = get_s32(env, 3);
PPP_RUN_CB(on_sys_fadvise64_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 252 long sys_exit_group ['int error_code']
case 252: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_exit_group_enter, env,pc,arg0) ; 
}; break;
// 253 long sys_lookup_dcookie ['u64 cookie64', ' char __user *buf', ' size_t len']
case 253: {
uint64_t arg0 = get_64(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_lookup_dcookie_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 254 long sys_epoll_create ['int size']
case 254: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_epoll_create_enter, env,pc,arg0) ; 
}; break;
// 255 long sys_epoll_ctl ['int epfd', ' int op', ' int fd', 'struct epoll_event __user *event']
case 255: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
int32_t arg2 = get_s32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_epoll_ctl_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 256 long sys_epoll_wait ['int epfd', ' struct epoll_event __user *events', 'int maxevents', ' int timeout']
case 256: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
int32_t arg3 = get_s32(env, 3);
PPP_RUN_CB(on_sys_epoll_wait_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 257 long sys_remap_file_pages ['unsigned long start', ' unsigned long size', 'unsigned long prot', ' unsigned long pgoff', 'unsigned long flags']
case 257: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_remap_file_pages_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 258 long sys_set_tid_address ['int __user *tidptr']
case 258: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_set_tid_address_enter, env,pc,arg0) ; 
}; break;
// 259 long sys_timer_create ['clockid_t which_clock', 'struct sigevent __user *timer_event_spec', 'timer_t __user * created_timer_id']
case 259: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_timer_create_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 260 long sys_timer_settime ['timer_t timer_id', ' int flags', 'const struct itimerspec __user *new_setting', 'struct itimerspec __user *old_setting']
case 260: {
uint32_t arg0 = get_32(env, 0);
int32_t arg1 = get_s32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_timer_settime_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 261 long sys_timer_gettime ['timer_t timer_id', 'struct itimerspec __user *setting']
case 261: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_timer_gettime_enter, env,pc,arg0,arg1) ; 
}; break;
// 262 long sys_timer_getoverrun ['timer_t timer_id']
case 262: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_timer_getoverrun_enter, env,pc,arg0) ; 
}; break;
// 263 long sys_timer_delete ['timer_t timer_id']
case 263: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_timer_delete_enter, env,pc,arg0) ; 
}; break;
// 264 long sys_clock_settime ['clockid_t which_clock', 'const struct timespec __user *tp']
case 264: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_clock_settime_enter, env,pc,arg0,arg1) ; 
}; break;
// 265 long sys_clock_gettime ['clockid_t which_clock', 'struct timespec __user *tp']
case 265: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_clock_gettime_enter, env,pc,arg0,arg1) ; 
}; break;
// 266 long sys_clock_getres ['clockid_t which_clock', 'struct timespec __user *tp']
case 266: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_clock_getres_enter, env,pc,arg0,arg1) ; 
}; break;
// 267 long sys_clock_nanosleep ['clockid_t which_clock', ' int flags', 'const struct timespec __user *rqtp', 'struct timespec __user *rmtp']
case 267: {
uint32_t arg0 = get_32(env, 0);
int32_t arg1 = get_s32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_clock_nanosleep_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 268 long sys_statfs64 ['const char __user *path', ' size_t sz', 'struct statfs64 __user *buf']
case 268: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_statfs64_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 269 long sys_fstatfs64 ['unsigned int fd', ' size_t sz', 'struct statfs64 __user *buf']
case 269: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_fstatfs64_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 270 long sys_tgkill ['int tgid', ' int pid', ' int sig']
case 270: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_tgkill_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 271 long sys_utimes ['char __user *filename', 'struct timeval __user *utimes']
case 271: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_utimes_enter, env,pc,arg0,arg1) ; 
}; break;
// 274 long sys_mbind ['unsigned long start', ' unsigned long len', 'unsigned long mode', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned flags']
case 274: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
PPP_RUN_CB(on_sys_mbind_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 275 long sys_get_mempolicy ['int __user *policy', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned long addr', ' unsigned long flags']
case 275: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_get_mempolicy_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 276 long sys_set_mempolicy ['int mode', ' unsigned long __user *nmask', 'unsigned long maxnode']
case 276: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_set_mempolicy_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 277 long sys_mq_open ['const char __user *name', ' int oflag', ' mode_t mode', ' struct mq_attr __user *attr']
case 277: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
uint32_t arg2 = get_32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_mq_open_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 278 long sys_mq_unlink ['const char __user *name']
case 278: {
target_ulong arg0 = get_pointer(env, 0);
PPP_RUN_CB(on_sys_mq_unlink_enter, env,pc,arg0) ; 
}; break;
// 279 long sys_mq_timedsend ['mqd_t mqdes', ' const char __user *msg_ptr', ' size_t msg_len', ' unsigned int msg_prio', ' const struct timespec __user *abs_timeout']
case 279: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
target_ulong arg4 = get_pointer(env, 4);
PPP_RUN_CB(on_sys_mq_timedsend_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 280 long sys_mq_timedreceive ['mqd_t mqdes', ' char __user *msg_ptr', ' size_t msg_len', ' unsigned int __user *msg_prio', ' const struct timespec __user *abs_timeout']
case 280: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
target_ulong arg4 = get_pointer(env, 4);
PPP_RUN_CB(on_sys_mq_timedreceive_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 281 long sys_mq_notify ['mqd_t mqdes', ' const struct sigevent __user *notification']
case 281: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_mq_notify_enter, env,pc,arg0,arg1) ; 
}; break;
// 282 long sys_mq_getsetattr ['mqd_t mqdes', ' const struct mq_attr __user *mqstat', ' struct mq_attr __user *omqstat']
case 282: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_mq_getsetattr_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 283 long sys_kexec_load ['unsigned long entry', ' unsigned long nr_segments', 'struct kexec_segment __user *segments', 'unsigned long flags']
case 283: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_kexec_load_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 284 long sys_waitid ['int which', ' pid_t pid', 'struct siginfo __user *infop', 'int options', ' struct rusage __user *ru']
case 284: {
int32_t arg0 = get_s32(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
int32_t arg3 = get_s32(env, 3);
target_ulong arg4 = get_pointer(env, 4);
PPP_RUN_CB(on_sys_waitid_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 286 long sys_add_key ['const char __user *_type', 'const char __user *_description', 'const void __user *_payload', 'size_t plen', 'key_serial_t destringid']
case 286: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_add_key_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 287 long sys_request_key ['const char __user *_type', 'const char __user *_description', 'const char __user *_callout_info', 'key_serial_t destringid']
case 287: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_request_key_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 288 long sys_keyctl ['int cmd', ' unsigned long arg2', ' unsigned long arg3', 'unsigned long arg4', ' unsigned long arg5']
case 288: {
int32_t arg0 = get_s32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_keyctl_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 289 long sys_ioprio_set ['int which', ' int who', ' int ioprio']
case 289: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_ioprio_set_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 290 long sys_ioprio_get ['int which', ' int who']
case 290: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_ioprio_get_enter, env,pc,arg0,arg1) ; 
}; break;
// 291 long sys_inotify_init ['void']
case 291: {
PPP_RUN_CB(on_sys_inotify_init_enter, env,pc) ; 
}; break;
// 292 long sys_inotify_add_watch ['int fd', ' const char __user *path', 'u32 mask']
case 292: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_inotify_add_watch_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 293 long sys_inotify_rm_watch ['int fd', ' __s32 wd']
case 293: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_inotify_rm_watch_enter, env,pc,arg0,arg1) ; 
}; break;
// 294 long sys_migrate_pages ['pid_t pid', ' unsigned long maxnode', 'const unsigned long __user *from', 'const unsigned long __user *to']
case 294: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_migrate_pages_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 295 long sys_openat ['int dfd', ' const char __user *filename', ' int flags', 'int mode']
case 295: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
int32_t arg3 = get_s32(env, 3);
PPP_RUN_CB(on_sys_openat_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 296 long sys_mkdirat ['int dfd', ' const char __user * pathname', ' int mode']
case 296: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_mkdirat_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 297 long sys_mknodat ['int dfd', ' const char __user * filename', ' int mode', 'unsigned dev']
case 297: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_mknodat_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 298 long sys_fchownat ['int dfd', ' const char __user *filename', ' uid_t user', 'gid_t group', ' int flag']
case 298: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
int32_t arg4 = get_s32(env, 4);
PPP_RUN_CB(on_sys_fchownat_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 299 long sys_futimesat ['int dfd', ' const char __user *filename', 'struct timeval __user *utimes']
case 299: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_futimesat_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 300 long sys_fstatat64 ['int dfd', ' const char __user *filename', 'struct stat64 __user *statbuf', ' int flag']
case 300: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
int32_t arg3 = get_s32(env, 3);
PPP_RUN_CB(on_sys_fstatat64_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 301 long sys_unlinkat ['int dfd', ' const char __user * pathname', ' int flag']
case 301: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_unlinkat_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 302 long sys_renameat ['int olddfd', ' const char __user * oldname', 'int newdfd', ' const char __user * newname']
case 302: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_renameat_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 303 long sys_linkat ['int olddfd', ' const char __user *oldname', 'int newdfd', ' const char __user *newname', ' int flags']
case 303: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
int32_t arg4 = get_s32(env, 4);
PPP_RUN_CB(on_sys_linkat_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 304 long sys_symlinkat ['const char __user * oldname', 'int newdfd', ' const char __user * newname']
case 304: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_symlinkat_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 305 long sys_readlinkat ['int dfd', ' const char __user *path', ' char __user *buf', 'int bufsiz']
case 305: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
int32_t arg3 = get_s32(env, 3);
PPP_RUN_CB(on_sys_readlinkat_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 306 long sys_fchmodat ['int dfd', ' const char __user * filename', 'mode_t mode']
case 306: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_fchmodat_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 307 long sys_faccessat ['int dfd', ' const char __user *filename', ' int mode']
case 307: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_faccessat_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 308 long sys_pselect6 ['int', ' fd_set __user *', ' fd_set __user *', 'fd_set __user *', ' struct timespec __user *', 'void __user *']
case 308: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
target_ulong arg3 = get_pointer(env, 3);
target_ulong arg4 = get_pointer(env, 4);
target_ulong arg5 = get_pointer(env, 5);
PPP_RUN_CB(on_sys_pselect6_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 309 long sys_ppoll ['struct pollfd __user *', ' unsigned int', 'struct timespec __user *', ' const sigset_t __user *', 'size_t']
case 309: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
target_ulong arg3 = get_pointer(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_ppoll_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 310 long sys_unshare ['unsigned long unshare_flags']
case 310: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_unshare_enter, env,pc,arg0) ; 
}; break;
// 311 long sys_set_robust_list ['struct robust_list_head __user *head', 'size_t len']
case 311: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_set_robust_list_enter, env,pc,arg0,arg1) ; 
}; break;
// 312 long sys_get_robust_list ['int pid', 'struct robust_list_head __user * __user *head_ptr', 'size_t __user *len_ptr']
case 312: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_get_robust_list_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 313 long sys_splice ['int fd_in', ' loff_t __user *off_in', 'int fd_out', ' loff_t __user *off_out', 'size_t len', ' unsigned int flags']
case 313: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
PPP_RUN_CB(on_sys_splice_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 315 long sys_tee ['int fdin', ' int fdout', ' size_t len', ' unsigned int flags']
case 315: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_tee_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 316 long sys_vmsplice ['int fd', ' const struct iovec __user *iov', 'unsigned long nr_segs', ' unsigned int flags']
case 316: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_vmsplice_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 317 long sys_move_pages ['pid_t pid', ' unsigned long nr_pages', 'const void __user * __user *pages', 'const int __user *nodes', 'int __user *status', 'int flags']
case 317: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
target_ulong arg3 = get_pointer(env, 3);
target_ulong arg4 = get_pointer(env, 4);
int32_t arg5 = get_s32(env, 5);
PPP_RUN_CB(on_sys_move_pages_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 318 long sys_getcpu ['unsigned __user *cpu', ' unsigned __user *node', ' struct getcpu_cache __user *cache']
case 318: {
target_ulong arg0 = get_pointer(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
PPP_RUN_CB(on_sys_getcpu_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 319 long sys_epoll_pwait ['int epfd', ' struct epoll_event __user *events', 'int maxevents', ' int timeout', 'const sigset_t __user *sigmask', 'size_t sigsetsize']
case 319: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
int32_t arg3 = get_s32(env, 3);
target_ulong arg4 = get_pointer(env, 4);
uint32_t arg5 = get_32(env, 5);
PPP_RUN_CB(on_sys_epoll_pwait_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 320 long sys_utimensat ['int dfd', ' const char __user *filename', 'struct timespec __user *utimes', ' int flags']
case 320: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
int32_t arg3 = get_s32(env, 3);
PPP_RUN_CB(on_sys_utimensat_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 321 long sys_signalfd ['int ufd', ' sigset_t __user *user_mask', ' size_t sizemask']
case 321: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
PPP_RUN_CB(on_sys_signalfd_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 322 long sys_timerfd_create ['int clockid', ' int flags']
case 322: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_timerfd_create_enter, env,pc,arg0,arg1) ; 
}; break;
// 323 long sys_eventfd ['unsigned int count']
case 323: {
uint32_t arg0 = get_32(env, 0);
PPP_RUN_CB(on_sys_eventfd_enter, env,pc,arg0) ; 
}; break;
// 324 long sys_fallocate ['int fd', ' int mode', ' loff_t offset', ' loff_t len']
case 324: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
uint64_t arg2 = get_64(env, 2);
uint64_t arg3 = get_64(env, 3);
PPP_RUN_CB(on_sys_fallocate_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 325 long sys_timerfd_settime ['int ufd', ' int flags', 'const struct itimerspec __user *utmr', 'struct itimerspec __user *otmr']
case 325: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_timerfd_settime_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 326 long sys_timerfd_gettime ['int ufd', ' struct itimerspec __user *otmr']
case 326: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_timerfd_gettime_enter, env,pc,arg0,arg1) ; 
}; break;
// 327 long sys_signalfd4 ['int ufd', ' sigset_t __user *user_mask', ' size_t sizemask', ' int flags']
case 327: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
int32_t arg3 = get_s32(env, 3);
PPP_RUN_CB(on_sys_signalfd4_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 328 long sys_eventfd2 ['unsigned int count', ' int flags']
case 328: {
uint32_t arg0 = get_32(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_eventfd2_enter, env,pc,arg0,arg1) ; 
}; break;
// 329 long sys_epoll_create1 ['int flags']
case 329: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_epoll_create1_enter, env,pc,arg0) ; 
}; break;
// 330 long sys_dup3 ['unsigned int oldfd', ' unsigned int newfd', ' int flags']
case 330: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_dup3_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 331 long sys_pipe2 ['int __user *fildes', ' int flags']
case 331: {
target_ulong arg0 = get_pointer(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_pipe2_enter, env,pc,arg0,arg1) ; 
}; break;
// 332 long sys_inotify_init1 ['int flags']
case 332: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_inotify_init1_enter, env,pc,arg0) ; 
}; break;
// 333 long sys_preadv ['unsigned long fd', ' const struct iovec __user *vec', 'unsigned long vlen', ' unsigned long pos_l', ' unsigned long pos_h']
case 333: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_preadv_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 334 long sys_pwritev ['unsigned long fd', ' const struct iovec __user *vec', 'unsigned long vlen', ' unsigned long pos_l', ' unsigned long pos_h']
case 334: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_pwritev_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 335 long sys_rt_tgsigqueueinfo ['pid_t tgid', ' pid_t  pid', ' int sig', 'siginfo_t __user *uinfo']
case 335: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
int32_t arg2 = get_s32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_rt_tgsigqueueinfo_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 336 long sys_perf_event_open ['struct perf_event_attr __user *attr_uptr', 'pid_t pid', ' int cpu', ' int group_fd', ' unsigned long flags']
case 336: {
target_ulong arg0 = get_pointer(env, 0);
uint32_t arg1 = get_32(env, 1);
int32_t arg2 = get_s32(env, 2);
int32_t arg3 = get_s32(env, 3);
uint32_t arg4 = get_32(env, 4);
PPP_RUN_CB(on_sys_perf_event_open_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 337 long sys_recvmmsg ['int fd', ' struct mmsghdr __user *msg', 'unsigned int vlen', ' unsigned flags', 'struct timespec __user *timeout']
case 337: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
target_ulong arg4 = get_pointer(env, 4);
PPP_RUN_CB(on_sys_recvmmsg_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 338 long sys_fanotify_init ['unsigned int flags', ' unsigned int event_f_flags']
case 338: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
PPP_RUN_CB(on_sys_fanotify_init_enter, env,pc,arg0,arg1) ; 
}; break;
// 339 long sys_fanotify_mark ['int fanotify_fd', ' unsigned int flags', 'u64 mask', ' int fd', 'const char  __user *pathname']
case 339: {
int32_t arg0 = get_s32(env, 0);
uint32_t arg1 = get_32(env, 1);
uint64_t arg2 = get_64(env, 2);
int32_t arg3 = get_s32(env, 3);
target_ulong arg4 = get_pointer(env, 4);
PPP_RUN_CB(on_sys_fanotify_mark_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 340 long sys_prlimit64 ['pid_t pid', ' unsigned int resource', 'const struct rlimit64 __user *new_rlim', 'struct rlimit64 __user *old_rlim']
case 340: {
uint32_t arg0 = get_32(env, 0);
uint32_t arg1 = get_32(env, 1);
target_ulong arg2 = get_pointer(env, 2);
target_ulong arg3 = get_pointer(env, 3);
PPP_RUN_CB(on_sys_prlimit64_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 341 long sys_name_to_handle_at ['int dfd', ' const char __user *name', 'struct file_handle __user *handle', 'int __user *mnt_id', ' int flag']
case 341: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
target_ulong arg2 = get_pointer(env, 2);
target_ulong arg3 = get_pointer(env, 3);
int32_t arg4 = get_s32(env, 4);
PPP_RUN_CB(on_sys_name_to_handle_at_enter, env,pc,arg0,arg1,arg2,arg3,arg4) ; 
}; break;
// 342 long sys_open_by_handle_at ['int mountdirfd', 'struct file_handle __user *handle', 'int flags']
case 342: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
int32_t arg2 = get_s32(env, 2);
PPP_RUN_CB(on_sys_open_by_handle_at_enter, env,pc,arg0,arg1,arg2) ; 
}; break;
// 343 long sys_clock_adjtime ['clockid_t which_clock', 'struct timex __user *tx']
case 343: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
PPP_RUN_CB(on_sys_clock_adjtime_enter, env,pc,arg0,arg1) ; 
}; break;
// 344 long sys_syncfs ['int fd']
case 344: {
int32_t arg0 = get_s32(env, 0);
PPP_RUN_CB(on_sys_syncfs_enter, env,pc,arg0) ; 
}; break;
// 345 long sys_sendmmsg ['int fd', ' struct mmsghdr __user *msg', 'unsigned int vlen', ' unsigned flags']
case 345: {
int32_t arg0 = get_s32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
uint32_t arg3 = get_32(env, 3);
PPP_RUN_CB(on_sys_sendmmsg_enter, env,pc,arg0,arg1,arg2,arg3) ; 
}; break;
// 346 long sys_setns ['int fd', ' int nstype']
case 346: {
int32_t arg0 = get_s32(env, 0);
int32_t arg1 = get_s32(env, 1);
PPP_RUN_CB(on_sys_setns_enter, env,pc,arg0,arg1) ; 
}; break;
// 347 long sys_process_vm_readv ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
case 347: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
PPP_RUN_CB(on_sys_process_vm_readv_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
// 348 long sys_process_vm_writev ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
case 348: {
uint32_t arg0 = get_32(env, 0);
target_ulong arg1 = get_pointer(env, 1);
uint32_t arg2 = get_32(env, 2);
target_ulong arg3 = get_pointer(env, 3);
uint32_t arg4 = get_32(env, 4);
uint32_t arg5 = get_32(env, 5);
PPP_RUN_CB(on_sys_process_vm_writev_enter, env,pc,arg0,arg1,arg2,arg3,arg4,arg5) ; 
}; break;
default:
PPP_RUN_CB(on_unknown_sys_linux_x86_enter, env, pc, EAX);
}
PPP_RUN_CB(on_all_sys_linux_x86_enter, env, pc, EAX);
#endif
 } 
