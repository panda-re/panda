#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls2_info.h"

extern const syscall_info_t *syscall_info;
extern const syscall_meta_t *syscall_meta;

extern "C" {
#include "syscalls_ext_typedefs.h"
#include "syscall_ppp_extern_return.h"
}

void syscall_return_switch_linux_mips(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx) {
#if defined(TARGET_MIPS)
	const syscall_info_t *call = (syscall_meta == NULL || ctx->no > syscall_meta->max_generic) ? NULL : &syscall_info[ctx->no];
	switch (ctx->no) {
		// 1 long sys_exit ['int error_code']
		case 1: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_exit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_exit_return, cpu, pc, arg0) ;
		}; break;
		// 3 long sys_read ['unsigned int fd', 'char __user *buf', 'size_t count']
		case 3: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_read_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_read_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4 long sys_write ['unsigned int fd', 'const char __user *buf', 'size_t count']
		case 4: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_write_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_write_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 5 long sys_open ['const char __user *filename', 'int flags', 'umode_t mode']
		case 5: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_open_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 6 long sys_close ['unsigned int fd']
		case 6: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_close_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_close_return, cpu, pc, arg0) ;
		}; break;
		// 7 long sys_waitpid ['pid_t pid', 'int __user *stat_addr', 'int options']
		case 7: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_waitpid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_waitpid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 8 long sys_creat ['const char __user *pathname', 'umode_t mode']
		case 8: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_creat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_creat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 9 long sys_link ['const char __user *oldname', 'const char __user *newname']
		case 9: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_link_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 10 long sys_unlink ['const char __user *pathname']
		case 10: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 11 long sys_execve ['const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp']
		case 11: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_execve_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_execve_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 12 long sys_chdir ['const char __user *filename']
		case 12: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_chdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chdir_return, cpu, pc, arg0) ;
		}; break;
		// 13 long sys_time32 ['old_time32_t __user *tloc']
		case 13: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_time32_return, cpu, pc, arg0) ;
		}; break;
		// 14 long sys_mknod ['const char __user *filename', 'umode_t mode', 'unsigned dev']
		case 14: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_mknod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mknod_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 15 long sys_chmod ['const char __user *filename', 'umode_t mode']
		case 15: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_chmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 16 long sys_lchown ['const char __user *filename', 'uid_t user', 'gid_t group']
		case 16: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_lchown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lchown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 19 long sys_lseek ['unsigned int fd', 'off_t offset', 'unsigned int whence']
		case 19: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_lseek_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lseek_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 20 long sys_getpid ['void']
		case 20: {
			if (PPP_CHECK_CB(on_sys_getpid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpid_return, cpu, pc) ;
		}; break;
		// 21 long sys_mount ['char __user *dev_name', 'char __user *dir_name', 'char __user *type', 'unsigned long flags', 'void __user *data']
		case 21: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_mount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mount_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 22 long sys_oldumount ['char __user *name']
		case 22: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_oldumount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_oldumount_return, cpu, pc, arg0) ;
		}; break;
		// 23 long sys_setuid ['uid_t uid']
		case 23: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_setuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setuid_return, cpu, pc, arg0) ;
		}; break;
		// 24 long sys_getuid ['void']
		case 24: {
			if (PPP_CHECK_CB(on_sys_getuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getuid_return, cpu, pc) ;
		}; break;
		// 25 long sys_stime32 ['old_time32_t __user *tptr']
		case 25: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_stime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_stime32_return, cpu, pc, arg0) ;
		}; break;
		// 26 long sys_ptrace ['long request', 'long pid', 'unsigned long addr', 'unsigned long data']
		case 26: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_ptrace_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ptrace_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 27 long sys_alarm ['unsigned int seconds']
		case 27: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_alarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_alarm_return, cpu, pc, arg0) ;
		}; break;
		// 29 long sys_pause ['void']
		case 29: {
			if (PPP_CHECK_CB(on_sys_pause_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_pause_return, cpu, pc) ;
		}; break;
		// 30 long sys_utime32 ['const char __user *filename', 'struct old_utimbuf32 __user *t']
		case 30: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_utime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_utime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 33 long sys_access ['const char __user *filename', 'int mode']
		case 33: {
			uint32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_access_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_access_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 34 long sys_nice ['int increment']
		case 34: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_nice_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_nice_return, cpu, pc, arg0) ;
		}; break;
		// 36 long sys_sync ['void']
		case 36: {
			if (PPP_CHECK_CB(on_sys_sync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sync_return, cpu, pc) ;
		}; break;
		// 37 long sys_kill ['pid_t pid', 'int sig']
		case 37: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_kill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_kill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 38 long sys_rename ['const char __user *oldname', 'const char __user *newname']
		case 38: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_rename_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rename_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 39 long sys_mkdir ['const char __user *pathname', 'umode_t mode']
		case 39: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_mkdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkdir_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 40 long sys_rmdir ['const char __user *pathname']
		case 40: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_rmdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rmdir_return, cpu, pc, arg0) ;
		}; break;
		// 41 long sys_dup ['unsigned int fildes']
		case 41: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_dup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_dup_return, cpu, pc, arg0) ;
		}; break;
		// 43 long sys_times ['struct tms __user *tbuf']
		case 43: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_times_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_times_return, cpu, pc, arg0) ;
		}; break;
		// 45 long sys_brk ['unsigned long brk']
		case 45: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_brk_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_brk_return, cpu, pc, arg0) ;
		}; break;
		// 46 long sys_setgid ['gid_t gid']
		case 46: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_setgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setgid_return, cpu, pc, arg0) ;
		}; break;
		// 47 long sys_getgid ['void']
		case 47: {
			if (PPP_CHECK_CB(on_sys_getgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getgid_return, cpu, pc) ;
		}; break;
		// 49 long sys_geteuid ['void']
		case 49: {
			if (PPP_CHECK_CB(on_sys_geteuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_geteuid_return, cpu, pc) ;
		}; break;
		// 50 long sys_getegid ['void']
		case 50: {
			if (PPP_CHECK_CB(on_sys_getegid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getegid_return, cpu, pc) ;
		}; break;
		// 51 long sys_acct ['const char __user *name']
		case 51: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_acct_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_acct_return, cpu, pc, arg0) ;
		}; break;
		// 52 long sys_umount ['char __user *name', 'int flags']
		case 52: {
			uint32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_umount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_umount_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 54 long sys_ioctl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
		case 54: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_ioctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ioctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 55 long sys_fcntl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
		case 55: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_fcntl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fcntl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 57 long sys_setpgid ['pid_t pid', 'pid_t pgid']
		case 57: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_setpgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setpgid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 59 long sys_olduname ['struct oldold_utsname __user *']
		case 59: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_olduname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_olduname_return, cpu, pc, arg0) ;
		}; break;
		// 60 long sys_umask ['int mask']
		case 60: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_umask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_umask_return, cpu, pc, arg0) ;
		}; break;
		// 61 long sys_chroot ['const char __user *filename']
		case 61: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_chroot_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chroot_return, cpu, pc, arg0) ;
		}; break;
		// 62 long sys_ustat ['unsigned dev', 'struct ustat __user *ubuf']
		case 62: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_ustat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ustat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 63 long sys_dup2 ['unsigned int oldfd', 'unsigned int newfd']
		case 63: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_dup2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_dup2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 64 long sys_getppid ['void']
		case 64: {
			if (PPP_CHECK_CB(on_sys_getppid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getppid_return, cpu, pc) ;
		}; break;
		// 65 long sys_getpgrp ['void']
		case 65: {
			if (PPP_CHECK_CB(on_sys_getpgrp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpgrp_return, cpu, pc) ;
		}; break;
		// 66 long sys_setsid ['void']
		case 66: {
			if (PPP_CHECK_CB(on_sys_setsid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_setsid_return, cpu, pc) ;
		}; break;
		// 67 long sys_sigaction ['int', 'const struct old_sigaction __user *', 'struct old_sigaction __user *']
		case 67: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sigaction_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigaction_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 68 long sys_sgetmask ['void']
		case 68: {
			if (PPP_CHECK_CB(on_sys_sgetmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sgetmask_return, cpu, pc) ;
		}; break;
		// 69 long sys_ssetmask ['int newmask']
		case 69: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_ssetmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ssetmask_return, cpu, pc, arg0) ;
		}; break;
		// 70 long sys_setreuid ['uid_t ruid', 'uid_t euid']
		case 70: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_setreuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setreuid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 71 long sys_setregid ['gid_t rgid', 'gid_t egid']
		case 71: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_setregid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setregid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 72 long sys_sigsuspend ['int unused1', 'int unused2', 'old_sigset_t mask']
		case 72: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sigsuspend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigsuspend_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 73 long sys_sigpending ['old_sigset_t __user *uset']
		case 73: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_sigpending_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigpending_return, cpu, pc, arg0) ;
		}; break;
		// 74 long sys_sethostname ['char __user *name', 'int len']
		case 74: {
			uint32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_sethostname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sethostname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 75 long sys_setrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
		case 75: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_setrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 76 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
		case 76: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_getrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 77 long sys_getrusage ['int who', 'struct rusage __user *ru']
		case 77: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_getrusage_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getrusage_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 78 long sys_gettimeofday ['struct __kernel_old_timeval __user *tv', 'struct timezone __user *tz']
		case 78: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_gettimeofday_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_gettimeofday_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 79 long sys_settimeofday ['struct __kernel_old_timeval __user *tv', 'struct timezone __user *tz']
		case 79: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_settimeofday_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_settimeofday_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 80 long sys_getgroups ['int gidsetsize', 'gid_t __user *grouplist']
		case 80: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_getgroups_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getgroups_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 81 long sys_setgroups ['int gidsetsize', 'gid_t __user *grouplist']
		case 81: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_setgroups_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setgroups_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 83 long sys_symlink ['const char __user *old', 'const char __user *new']
		case 83: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_symlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_symlink_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 85 long sys_readlink ['const char __user *path', 'char __user *buf', 'int bufsiz']
		case 85: {
			uint32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_readlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_readlink_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 86 long sys_uselib ['const char __user *library']
		case 86: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_uselib_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_uselib_return, cpu, pc, arg0) ;
		}; break;
		// 87 long sys_swapon ['const char __user *specialfile', 'int swap_flags']
		case 87: {
			uint32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_swapon_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_swapon_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 88 long sys_reboot ['int magic1', 'int magic2', 'unsigned int cmd', 'void __user *arg']
		case 88: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_reboot_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_reboot_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 89 long sys_old_readdir ['unsigned int', 'struct old_linux_dirent __user *', 'unsigned int']
		case 89: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_old_readdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_old_readdir_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 91 long sys_munmap ['unsigned long addr', 'size_t len']
		case 91: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_munmap_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_munmap_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 92 long sys_truncate ['const char __user *path', 'long length']
		case 92: {
			uint32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_truncate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_truncate_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 93 long sys_ftruncate ['unsigned int fd', 'unsigned long length']
		case 93: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_ftruncate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ftruncate_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 94 long sys_fchmod ['unsigned int fd', 'umode_t mode']
		case 94: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_fchmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 95 long sys_fchown ['unsigned int fd', 'uid_t user', 'gid_t group']
		case 95: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_fchown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 96 long sys_getpriority ['int which', 'int who']
		case 96: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_getpriority_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getpriority_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 97 long sys_setpriority ['int which', 'int who', 'int niceval']
		case 97: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_setpriority_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setpriority_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 99 long sys_statfs ['const char __user *path', 'struct statfs __user *buf']
		case 99: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_statfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_statfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 100 long sys_fstatfs ['unsigned int fd', 'struct statfs __user *buf']
		case 100: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_fstatfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fstatfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 102 long sys_socketcall ['int call', 'unsigned long __user *args']
		case 102: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_socketcall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_socketcall_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 103 long sys_syslog ['int type', 'char __user *buf', 'int len']
		case 103: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_syslog_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_syslog_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 104 long sys_setitimer ['int which', 'struct __kernel_old_itimerval __user *value', 'struct __kernel_old_itimerval __user *ovalue']
		case 104: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_setitimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setitimer_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 105 long sys_getitimer ['int which', 'struct __kernel_old_itimerval __user *value']
		case 105: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_getitimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getitimer_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 106 long sys_newstat ['const char __user *filename', 'struct stat __user *statbuf']
		case 106: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_newstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 107 long sys_newlstat ['const char __user *filename', 'struct stat __user *statbuf']
		case 107: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_newlstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newlstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 108 long sys_newfstat ['unsigned int fd', 'struct stat __user *statbuf']
		case 108: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_newfstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newfstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 109 long sys_uname ['struct old_utsname __user *']
		case 109: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_uname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_uname_return, cpu, pc, arg0) ;
		}; break;
		// 111 long sys_vhangup ['void']
		case 111: {
			if (PPP_CHECK_CB(on_sys_vhangup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_vhangup_return, cpu, pc) ;
		}; break;
		// 114 long sys_wait4 ['pid_t pid', 'int __user *stat_addr', 'int options', 'struct rusage __user *ru']
		case 114: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_wait4_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_wait4_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 115 long sys_swapoff ['const char __user *specialfile']
		case 115: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_swapoff_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_swapoff_return, cpu, pc, arg0) ;
		}; break;
		// 116 long sys_sysinfo ['struct sysinfo __user *info']
		case 116: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_sysinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sysinfo_return, cpu, pc, arg0) ;
		}; break;
		// 117 long sys_ipc ['unsigned int call', 'int first', 'unsigned long second', 'unsigned long third', 'void __user *ptr', 'long fifth']
		case 117: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			int32_t arg5;
			if (PPP_CHECK_CB(on_sys_ipc_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ipc_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 118 long sys_fsync ['unsigned int fd']
		case 118: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_fsync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fsync_return, cpu, pc, arg0) ;
		}; break;
		// 119 void sys_sigreturn ['void']
		case 119: {
			if (PPP_CHECK_CB(on_sys_sigreturn_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sigreturn_return, cpu, pc) ;
		}; break;
		// 121 long sys_setdomainname ['char __user *name', 'int len']
		case 121: {
			uint32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_setdomainname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setdomainname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 122 long sys_newuname ['struct new_utsname __user *name']
		case 122: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_newuname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newuname_return, cpu, pc, arg0) ;
		}; break;
		// 124 long sys_adjtimex_time32 ['struct old_timex32 __user *txc_p']
		case 124: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_adjtimex_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_adjtimex_time32_return, cpu, pc, arg0) ;
		}; break;
		// 125 long sys_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot']
		case 125: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_mprotect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mprotect_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 126 long sys_sigprocmask ['int how', 'old_sigset_t __user *set', 'old_sigset_t __user *oset']
		case 126: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sigprocmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigprocmask_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 128 long sys_init_module ['void __user *umod', 'unsigned long len', 'const char __user *uargs']
		case 128: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_init_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_init_module_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 129 long sys_delete_module ['const char __user *name_user', 'unsigned int flags']
		case 129: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_delete_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_delete_module_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 131 long sys_quotactl ['unsigned int cmd', 'const char __user *special', 'qid_t id', 'void __user *addr']
		case 131: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_quotactl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_quotactl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 132 long sys_getpgid ['pid_t pid']
		case 132: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_getpgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getpgid_return, cpu, pc, arg0) ;
		}; break;
		// 133 long sys_fchdir ['unsigned int fd']
		case 133: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_fchdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchdir_return, cpu, pc, arg0) ;
		}; break;
		// 134 long sys_bdflush ['int func', 'long data']
		case 134: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_bdflush_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_bdflush_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 135 long sys_sysfs ['int option', 'unsigned long arg1', 'unsigned long arg2']
		case 135: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sysfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sysfs_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 136 long sys_personality ['unsigned int personality']
		case 136: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_personality_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_personality_return, cpu, pc, arg0) ;
		}; break;
		// 138 long sys_setfsuid ['uid_t uid']
		case 138: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_setfsuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setfsuid_return, cpu, pc, arg0) ;
		}; break;
		// 139 long sys_setfsgid ['gid_t gid']
		case 139: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_setfsgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setfsgid_return, cpu, pc, arg0) ;
		}; break;
		// 140 long sys_llseek ['unsigned int fd', 'unsigned long offset_high', 'unsigned long offset_low', 'loff_t __user *result', 'unsigned int whence']
		case 140: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_llseek_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_llseek_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 141 long sys_getdents ['unsigned int fd', 'struct linux_dirent __user *dirent', 'unsigned int count']
		case 141: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_getdents_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getdents_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 142 long sys_select ['int n', 'fd_set __user *inp', 'fd_set __user *outp', 'fd_set __user *exp', 'struct __kernel_old_timeval __user *tvp']
		case 142: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_select_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_select_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 143 long sys_flock ['unsigned int fd', 'unsigned int cmd']
		case 143: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_flock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_flock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 144 long sys_msync ['unsigned long start', 'size_t len', 'int flags']
		case 144: {
			uint32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_msync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msync_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 145 long sys_readv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
		case 145: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_readv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_readv_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 146 long sys_writev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
		case 146: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_writev_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_writev_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 151 long sys_getsid ['pid_t pid']
		case 151: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_getsid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getsid_return, cpu, pc, arg0) ;
		}; break;
		// 152 long sys_fdatasync ['unsigned int fd']
		case 152: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_fdatasync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fdatasync_return, cpu, pc, arg0) ;
		}; break;
		// 153 long sys_sysctl ['struct __sysctl_args __user *args']
		case 153: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_sysctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sysctl_return, cpu, pc, arg0) ;
		}; break;
		// 154 long sys_mlock ['unsigned long start', 'size_t len']
		case 154: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_mlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mlock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 155 long sys_munlock ['unsigned long start', 'size_t len']
		case 155: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_munlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_munlock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 156 long sys_mlockall ['int flags']
		case 156: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_mlockall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_mlockall_return, cpu, pc, arg0) ;
		}; break;
		// 157 long sys_munlockall ['void']
		case 157: {
			if (PPP_CHECK_CB(on_sys_munlockall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_munlockall_return, cpu, pc) ;
		}; break;
		// 158 long sys_sched_setparam ['pid_t pid', 'struct sched_param __user *param']
		case 158: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_sched_setparam_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_setparam_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 159 long sys_sched_getparam ['pid_t pid', 'struct sched_param __user *param']
		case 159: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_sched_getparam_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_getparam_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 160 long sys_sched_setscheduler ['pid_t pid', 'int policy', 'struct sched_param __user *param']
		case 160: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sched_setscheduler_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_setscheduler_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 161 long sys_sched_getscheduler ['pid_t pid']
		case 161: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_sched_getscheduler_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_getscheduler_return, cpu, pc, arg0) ;
		}; break;
		// 162 long sys_sched_yield ['void']
		case 162: {
			if (PPP_CHECK_CB(on_sys_sched_yield_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sched_yield_return, cpu, pc) ;
		}; break;
		// 163 long sys_sched_get_priority_max ['int policy']
		case 163: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_sched_get_priority_max_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_get_priority_max_return, cpu, pc, arg0) ;
		}; break;
		// 164 long sys_sched_get_priority_min ['int policy']
		case 164: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_sched_get_priority_min_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_get_priority_min_return, cpu, pc, arg0) ;
		}; break;
		// 165 long sys_sched_rr_get_interval_time32 ['pid_t pid', 'struct old_timespec32 __user *interval']
		case 165: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_sched_rr_get_interval_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_rr_get_interval_time32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 166 long sys_nanosleep_time32 ['struct old_timespec32 __user *rqtp', 'struct old_timespec32 __user *rmtp']
		case 166: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_nanosleep_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_nanosleep_time32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 167 long sys_mremap ['unsigned long addr', 'unsigned long old_len', 'unsigned long new_len', 'unsigned long flags', 'unsigned long new_addr']
		case 167: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_mremap_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mremap_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 168 long sys_accept ['int', 'struct sockaddr __user *', 'int __user *']
		case 168: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_accept_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_accept_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 169 long sys_bind ['int', 'struct sockaddr __user *', 'int']
		case 169: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_bind_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_bind_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 170 long sys_connect ['int', 'struct sockaddr __user *', 'int']
		case 170: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_connect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_connect_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 171 long sys_getpeername ['int', 'struct sockaddr __user *', 'int __user *']
		case 171: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_getpeername_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getpeername_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 172 long sys_getsockname ['int', 'struct sockaddr __user *', 'int __user *']
		case 172: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_getsockname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getsockname_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 173 long sys_getsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int __user *optlen']
		case 173: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_getsockopt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getsockopt_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 174 long sys_listen ['int', 'int']
		case 174: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_listen_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_listen_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 175 long sys_recv ['int', 'void __user *', 'size_t', 'unsigned']
		case 175: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_recv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recv_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 176 long sys_recvfrom ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int __user *']
		case 176: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_recvfrom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recvfrom_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 177 long sys_recvmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
		case 177: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_recvmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recvmsg_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 178 long sys_send ['int', 'void __user *', 'size_t', 'unsigned']
		case 178: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_send_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_send_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 179 long sys_sendmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
		case 179: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sendmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendmsg_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 180 long sys_sendto ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int']
		case 180: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			int32_t arg5;
			if (PPP_CHECK_CB(on_sys_sendto_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sendto_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 181 long sys_setsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int optlen']
		case 181: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_setsockopt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setsockopt_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 182 long sys_shutdown ['int', 'int']
		case 182: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_shutdown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shutdown_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 183 long sys_socket ['int', 'int', 'int']
		case 183: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_socket_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_socket_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 184 long sys_socketpair ['int', 'int', 'int', 'int __user *']
		case 184: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_socketpair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_socketpair_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 185 long sys_setresuid ['uid_t ruid', 'uid_t euid', 'uid_t suid']
		case 185: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_setresuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setresuid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 186 long sys_getresuid ['uid_t __user *ruid', 'uid_t __user *euid', 'uid_t __user *suid']
		case 186: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_getresuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getresuid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 188 long sys_poll ['struct pollfd __user *ufds', 'unsigned int nfds', 'int timeout']
		case 188: {
			uint32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_poll_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_poll_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 190 long sys_setresgid ['gid_t rgid', 'gid_t egid', 'gid_t sgid']
		case 190: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_setresgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setresgid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 191 long sys_getresgid ['gid_t __user *rgid', 'gid_t __user *egid', 'gid_t __user *sgid']
		case 191: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_getresgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getresgid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 192 long sys_prctl ['int option', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
		case 192: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_prctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_prctl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 193 void sys_rt_sigreturn ['void']
		case 193: {
			if (PPP_CHECK_CB(on_sys_rt_sigreturn_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_rt_sigreturn_return, cpu, pc) ;
		}; break;
		// 194 long sys_rt_sigaction ['int', 'const struct sigaction __user *', 'struct sigaction __user *', 'size_t']
		case 194: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_rt_sigaction_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigaction_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 195 long sys_rt_sigprocmask ['int how', 'sigset_t __user *set', 'sigset_t __user *oset', 'size_t sigsetsize']
		case 195: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_rt_sigprocmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigprocmask_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 196 long sys_rt_sigpending ['sigset_t __user *set', 'size_t sigsetsize']
		case 196: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_rt_sigpending_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigpending_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 197 long sys_rt_sigtimedwait_time32 ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct old_timespec32 __user *uts', 'size_t sigsetsize']
		case 197: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_rt_sigtimedwait_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigtimedwait_time32_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 198 long sys_rt_sigqueueinfo ['pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
		case 198: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_rt_sigqueueinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigqueueinfo_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 199 long sys_rt_sigsuspend ['sigset_t __user *unewset', 'size_t sigsetsize']
		case 199: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_rt_sigsuspend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigsuspend_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 200 long sys_pread64 ['unsigned int fd', 'char __user *buf', 'size_t count', 'loff_t pos']
		case 200: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_pread64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pread64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 201 long sys_pwrite64 ['unsigned int fd', 'const char __user *buf', 'size_t count', 'loff_t pos']
		case 201: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_pwrite64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pwrite64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 202 long sys_chown ['const char __user *filename', 'uid_t user', 'gid_t group']
		case 202: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_chown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 203 long sys_getcwd ['char __user *buf', 'unsigned long size']
		case 203: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_getcwd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getcwd_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 204 long sys_capget ['cap_user_header_t header', 'cap_user_data_t dataptr']
		case 204: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_capget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_capget_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 205 long sys_capset ['cap_user_header_t header', 'const cap_user_data_t data']
		case 205: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_capset_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_capset_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 206 long sys_sigaltstack ['const struct sigaltstack __user *uss', 'struct sigaltstack __user *uoss']
		case 206: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_sigaltstack_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigaltstack_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 207 long sys_sendfile ['int out_fd', 'int in_fd', 'off_t __user *offset', 'size_t count']
		case 207: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_sendfile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendfile_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 211 long sys_truncate64 ['const char __user *path', 'loff_t length']
		case 211: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_truncate64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_truncate64_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 212 long sys_ftruncate64 ['unsigned int fd', 'loff_t length']
		case 212: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_ftruncate64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ftruncate64_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 213 long sys_stat64 ['const char __user *filename', 'struct stat64 __user *statbuf']
		case 213: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_stat64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_stat64_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 214 long sys_lstat64 ['const char __user *filename', 'struct stat64 __user *statbuf']
		case 214: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_lstat64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lstat64_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 215 long sys_fstat64 ['unsigned long fd', 'struct stat64 __user *statbuf']
		case 215: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_fstat64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fstat64_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 216 long sys_pivot_root ['const char __user *new_root', 'const char __user *put_old']
		case 216: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_pivot_root_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pivot_root_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 217 long sys_mincore ['unsigned long start', 'size_t len', 'unsigned char __user *vec']
		case 217: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_mincore_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mincore_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 218 long sys_madvise ['unsigned long start', 'size_t len', 'int behavior']
		case 218: {
			uint32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_madvise_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_madvise_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 219 long sys_getdents64 ['unsigned int fd', 'struct linux_dirent64 __user *dirent', 'unsigned int count']
		case 219: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_getdents64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getdents64_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 220 long sys_fcntl64 ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
		case 220: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_fcntl64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fcntl64_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 222 long sys_gettid ['void']
		case 222: {
			if (PPP_CHECK_CB(on_sys_gettid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_gettid_return, cpu, pc) ;
		}; break;
		// 223 long sys_readahead ['int fd', 'loff_t offset', 'size_t count']
		case 223: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_readahead_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_readahead_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 224 long sys_setxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 224: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_setxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setxattr_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 225 long sys_lsetxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 225: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_lsetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_lsetxattr_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 226 long sys_fsetxattr ['int fd', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 226: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_fsetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fsetxattr_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 227 long sys_getxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
		case 227: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_getxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getxattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 228 long sys_lgetxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
		case 228: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_lgetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lgetxattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 229 long sys_fgetxattr ['int fd', 'const char __user *name', 'void __user *value', 'size_t size']
		case 229: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_fgetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fgetxattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 230 long sys_listxattr ['const char __user *path', 'char __user *list', 'size_t size']
		case 230: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_listxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_listxattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 231 long sys_llistxattr ['const char __user *path', 'char __user *list', 'size_t size']
		case 231: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_llistxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_llistxattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 232 long sys_flistxattr ['int fd', 'char __user *list', 'size_t size']
		case 232: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_flistxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_flistxattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 233 long sys_removexattr ['const char __user *path', 'const char __user *name']
		case 233: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_removexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_removexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 234 long sys_lremovexattr ['const char __user *path', 'const char __user *name']
		case 234: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_lremovexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lremovexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 235 long sys_fremovexattr ['int fd', 'const char __user *name']
		case 235: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_fremovexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fremovexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 236 long sys_tkill ['pid_t pid', 'int sig']
		case 236: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_tkill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_tkill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 237 long sys_sendfile64 ['int out_fd', 'int in_fd', 'loff_t __user *offset', 'size_t count']
		case 237: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_sendfile64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendfile64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 238 long sys_futex_time32 ['u32 __user *uaddr', 'int op', 'u32 val', 'struct old_timespec32 __user *utime', 'u32 __user *uaddr2', 'u32 val3']
		case 238: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_futex_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_futex_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 239 long sys_sched_setaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
		case 239: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sched_setaffinity_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_setaffinity_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 240 long sys_sched_getaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
		case 240: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sched_getaffinity_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_getaffinity_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 241 long sys_io_setup ['unsigned nr_reqs', 'aio_context_t __user *ctx']
		case 241: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_io_setup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_setup_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 242 long sys_io_destroy ['aio_context_t ctx']
		case 242: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_io_destroy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_destroy_return, cpu, pc, arg0) ;
		}; break;
		// 243 long sys_io_getevents_time32 ['__u32 ctx_id', '__s32 min_nr', '__s32 nr', 'struct io_event __user *events', 'struct old_timespec32 __user *timeout']
		case 243: {
			uint32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_io_getevents_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_getevents_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 244 long sys_io_submit ['aio_context_t', 'long', 'struct iocb __user * __user *']
		case 244: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_io_submit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_submit_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 245 long sys_io_cancel ['aio_context_t ctx_id', 'struct iocb __user *iocb', 'struct io_event __user *result']
		case 245: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_io_cancel_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_cancel_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 246 long sys_exit_group ['int error_code']
		case 246: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_exit_group_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_exit_group_return, cpu, pc, arg0) ;
		}; break;
		// 247 long sys_lookup_dcookie ['u64 cookie64', 'char __user *buf', 'size_t len']
		case 247: {
			uint64_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_lookup_dcookie_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lookup_dcookie_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 248 long sys_epoll_create ['int size']
		case 248: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_epoll_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_epoll_create_return, cpu, pc, arg0) ;
		}; break;
		// 249 long sys_epoll_ctl ['int epfd', 'int op', 'int fd', 'struct epoll_event __user *event']
		case 249: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_epoll_ctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_epoll_ctl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 250 long sys_epoll_wait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout']
		case 250: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_epoll_wait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_epoll_wait_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 251 long sys_remap_file_pages ['unsigned long start', 'unsigned long size', 'unsigned long prot', 'unsigned long pgoff', 'unsigned long flags']
		case 251: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_remap_file_pages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_remap_file_pages_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 252 long sys_set_tid_address ['int __user *tidptr']
		case 252: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_set_tid_address_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_set_tid_address_return, cpu, pc, arg0) ;
		}; break;
		// 253 long sys_restart_syscall ['void']
		case 253: {
			if (PPP_CHECK_CB(on_sys_restart_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_restart_syscall_return, cpu, pc) ;
		}; break;
		// 254 long sys_fadvise64_64 ['int fd', 'loff_t offset', 'loff_t len', 'int advice']
		case 254: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_fadvise64_64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fadvise64_64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 255 long sys_statfs64 ['const char __user *path', 'size_t sz', 'struct statfs64 __user *buf']
		case 255: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_statfs64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_statfs64_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 256 long sys_fstatfs64 ['unsigned int fd', 'size_t sz', 'struct statfs64 __user *buf']
		case 256: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_fstatfs64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fstatfs64_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 257 long sys_timer_create ['clockid_t which_clock', 'struct sigevent __user *timer_event_spec', 'timer_t __user *created_timer_id']
		case 257: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_timer_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_create_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 258 long sys_timer_settime32 ['timer_t timer_id', 'int flags', 'struct old_itimerspec32 __user *new', 'struct old_itimerspec32 __user *old']
		case 258: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_timer_settime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_settime32_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 259 long sys_timer_gettime32 ['timer_t timer_id', 'struct old_itimerspec32 __user *setting']
		case 259: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_timer_gettime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_gettime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 260 long sys_timer_getoverrun ['timer_t timer_id']
		case 260: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_timer_getoverrun_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_getoverrun_return, cpu, pc, arg0) ;
		}; break;
		// 261 long sys_timer_delete ['timer_t timer_id']
		case 261: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_timer_delete_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_delete_return, cpu, pc, arg0) ;
		}; break;
		// 262 long sys_clock_settime32 ['clockid_t which_clock', 'struct old_timespec32 __user *tp']
		case 262: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_settime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_settime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 263 long sys_clock_gettime32 ['clockid_t which_clock', 'struct old_timespec32 __user *tp']
		case 263: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_gettime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_gettime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 264 long sys_clock_getres_time32 ['clockid_t which_clock', 'struct old_timespec32 __user *tp']
		case 264: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_getres_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_getres_time32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 265 long sys_clock_nanosleep_time32 ['clockid_t which_clock', 'int flags', 'struct old_timespec32 __user *rqtp', 'struct old_timespec32 __user *rmtp']
		case 265: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_clock_nanosleep_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_nanosleep_time32_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 266 long sys_tgkill ['pid_t tgid', 'pid_t pid', 'int sig']
		case 266: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_tgkill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_tgkill_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 267 long sys_utimes_time32 ['const char __user *filename', 'struct old_timeval32 __user *t']
		case 267: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_utimes_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_utimes_time32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 268 long sys_mbind ['unsigned long start', 'unsigned long len', 'unsigned long mode', 'const unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned flags']
		case 268: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_mbind_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mbind_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 269 long sys_get_mempolicy ['int __user *policy', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned long addr', 'unsigned long flags']
		case 269: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_get_mempolicy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_get_mempolicy_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 270 long sys_set_mempolicy ['int mode', 'const unsigned long __user *nmask', 'unsigned long maxnode']
		case 270: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_set_mempolicy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_set_mempolicy_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 271 long sys_mq_open ['const char __user *name', 'int oflag', 'umode_t mode', 'struct mq_attr __user *attr']
		case 271: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_mq_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_open_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 272 long sys_mq_unlink ['const char __user *name']
		case 272: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_mq_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 273 long sys_mq_timedsend_time32 ['mqd_t mqdes', 'const char __user *u_msg_ptr', 'unsigned int msg_len', 'unsigned int msg_prio', 'const struct old_timespec32 __user *u_abs_timeout']
		case 273: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_mq_timedsend_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_timedsend_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 274 long sys_mq_timedreceive_time32 ['mqd_t mqdes', 'char __user *u_msg_ptr', 'unsigned int msg_len', 'unsigned int __user *u_msg_prio', 'const struct old_timespec32 __user *u_abs_timeout']
		case 274: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_mq_timedreceive_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_timedreceive_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 275 long sys_mq_notify ['mqd_t mqdes', 'const struct sigevent __user *notification']
		case 275: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_mq_notify_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_notify_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 276 long sys_mq_getsetattr ['mqd_t mqdes', 'const struct mq_attr __user *mqstat', 'struct mq_attr __user *omqstat']
		case 276: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_mq_getsetattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_getsetattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 278 long sys_waitid ['int which', 'pid_t pid', 'struct siginfo __user *infop', 'int options', 'struct rusage __user *ru']
		case 278: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_waitid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_waitid_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 280 long sys_add_key ['const char __user *_type', 'const char __user *_description', 'const void __user *_payload', 'size_t plen', 'key_serial_t destringid']
		case 280: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_add_key_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_add_key_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 281 long sys_request_key ['const char __user *_type', 'const char __user *_description', 'const char __user *_callout_info', 'key_serial_t destringid']
		case 281: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_request_key_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_request_key_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 282 long sys_keyctl ['int cmd', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
		case 282: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_keyctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_keyctl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 284 long sys_inotify_init ['void']
		case 284: {
			if (PPP_CHECK_CB(on_sys_inotify_init_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_inotify_init_return, cpu, pc) ;
		}; break;
		// 285 long sys_inotify_add_watch ['int fd', 'const char __user *path', 'u32 mask']
		case 285: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_inotify_add_watch_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_inotify_add_watch_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 286 long sys_inotify_rm_watch ['int fd', '__s32 wd']
		case 286: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_inotify_rm_watch_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_inotify_rm_watch_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 287 long sys_migrate_pages ['pid_t pid', 'unsigned long maxnode', 'const unsigned long __user *from', 'const unsigned long __user *to']
		case 287: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_migrate_pages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_migrate_pages_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 288 long sys_openat ['int dfd', 'const char __user *filename', 'int flags', 'umode_t mode']
		case 288: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_openat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_openat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 289 long sys_mkdirat ['int dfd', 'const char __user *pathname', 'umode_t mode']
		case 289: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_mkdirat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkdirat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 290 long sys_mknodat ['int dfd', 'const char __user *filename', 'umode_t mode', 'unsigned dev']
		case 290: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_mknodat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mknodat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 291 long sys_fchownat ['int dfd', 'const char __user *filename', 'uid_t user', 'gid_t group', 'int flag']
		case 291: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_fchownat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fchownat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 292 long sys_futimesat_time32 ['unsigned int dfd', 'const char __user *filename', 'struct old_timeval32 __user *t']
		case 292: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_futimesat_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_futimesat_time32_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 293 long sys_fstatat64 ['int dfd', 'const char __user *filename', 'struct stat64 __user *statbuf', 'int flag']
		case 293: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_fstatat64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fstatat64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 294 long sys_unlinkat ['int dfd', 'const char __user *pathname', 'int flag']
		case 294: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_unlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_unlinkat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 295 long sys_renameat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname']
		case 295: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_renameat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_renameat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 296 long sys_linkat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'int flags']
		case 296: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_linkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_linkat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 297 long sys_symlinkat ['const char __user *oldname', 'int newdfd', 'const char __user *newname']
		case 297: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_symlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_symlinkat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 298 long sys_readlinkat ['int dfd', 'const char __user *path', 'char __user *buf', 'int bufsiz']
		case 298: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_readlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_readlinkat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 299 long sys_fchmodat ['int dfd', 'const char __user *filename', 'umode_t mode']
		case 299: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_fchmodat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchmodat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 300 long sys_faccessat ['int dfd', 'const char __user *filename', 'int mode']
		case 300: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_faccessat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_faccessat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 301 long sys_pselect6_time32 ['int', 'fd_set __user *', 'fd_set __user *', 'fd_set __user *', 'struct old_timespec32 __user *', 'void __user *']
		case 301: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_pselect6_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pselect6_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 302 long sys_ppoll_time32 ['struct pollfd __user *', 'unsigned int', 'struct old_timespec32 __user *', 'const sigset_t __user *', 'size_t']
		case 302: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_ppoll_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ppoll_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 303 long sys_unshare ['unsigned long unshare_flags']
		case 303: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_unshare_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_unshare_return, cpu, pc, arg0) ;
		}; break;
		// 304 long sys_splice ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
		case 304: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_splice_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_splice_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 305 long sys_sync_file_range ['int fd', 'loff_t offset', 'loff_t nbytes', 'unsigned int flags']
		case 305: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_sync_file_range_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sync_file_range_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 306 long sys_tee ['int fdin', 'int fdout', 'size_t len', 'unsigned int flags']
		case 306: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_tee_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_tee_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 307 long sys_vmsplice ['int fd', 'const struct iovec __user *iov', 'unsigned long nr_segs', 'unsigned int flags']
		case 307: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_vmsplice_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_vmsplice_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 308 long sys_move_pages ['pid_t pid', 'unsigned long nr_pages', 'const void __user * __user *pages', 'const int __user *nodes', 'int __user *status', 'int flags']
		case 308: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			int32_t arg5;
			if (PPP_CHECK_CB(on_sys_move_pages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_move_pages_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 309 long sys_set_robust_list ['struct robust_list_head __user *head', 'size_t len']
		case 309: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_set_robust_list_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_set_robust_list_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 310 long sys_get_robust_list ['int pid', 'struct robust_list_head __user * __user *head_ptr', 'size_t __user *len_ptr']
		case 310: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_get_robust_list_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_get_robust_list_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 311 long sys_kexec_load ['unsigned long entry', 'unsigned long nr_segments', 'struct kexec_segment __user *segments', 'unsigned long flags']
		case 311: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_kexec_load_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_kexec_load_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 312 long sys_getcpu ['unsigned __user *cpu', 'unsigned __user *node', 'struct getcpu_cache __user *cache']
		case 312: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_getcpu_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getcpu_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 313 long sys_epoll_pwait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout', 'const sigset_t __user *sigmask', 'size_t sigsetsize']
		case 313: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			int32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_epoll_pwait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_epoll_pwait_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 314 long sys_ioprio_set ['int which', 'int who', 'int ioprio']
		case 314: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_ioprio_set_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ioprio_set_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 315 long sys_ioprio_get ['int which', 'int who']
		case 315: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_ioprio_get_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ioprio_get_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 316 long sys_utimensat_time32 ['unsigned int dfd', 'const char __user *filename', 'struct old_timespec32 __user *t', 'int flags']
		case 316: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_utimensat_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_utimensat_time32_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 317 long sys_signalfd ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask']
		case 317: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_signalfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_signalfd_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 318 long sys_ni_syscall ['void']
		case 318: {
			if (PPP_CHECK_CB(on_sys_ni_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_ni_syscall_return, cpu, pc) ;
		}; break;
		// 319 long sys_eventfd ['unsigned int count']
		case 319: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_eventfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_eventfd_return, cpu, pc, arg0) ;
		}; break;
		// 320 long sys_fallocate ['int fd', 'int mode', 'loff_t offset', 'loff_t len']
		case 320: {
			int32_t arg0;
			int32_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_fallocate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fallocate_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 321 long sys_timerfd_create ['int clockid', 'int flags']
		case 321: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_timerfd_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_create_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 322 long sys_timerfd_gettime32 ['int ufd', 'struct old_itimerspec32 __user *otmr']
		case 322: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_timerfd_gettime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_gettime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 323 long sys_timerfd_settime32 ['int ufd', 'int flags', 'const struct old_itimerspec32 __user *utmr', 'struct old_itimerspec32 __user *otmr']
		case 323: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_timerfd_settime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_settime32_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 324 long sys_signalfd4 ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask', 'int flags']
		case 324: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_signalfd4_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_signalfd4_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 325 long sys_eventfd2 ['unsigned int count', 'int flags']
		case 325: {
			uint32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_eventfd2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_eventfd2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 326 long sys_epoll_create1 ['int flags']
		case 326: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_epoll_create1_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_epoll_create1_return, cpu, pc, arg0) ;
		}; break;
		// 327 long sys_dup3 ['unsigned int oldfd', 'unsigned int newfd', 'int flags']
		case 327: {
			uint32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_dup3_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_dup3_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 328 long sys_pipe2 ['int __user *fildes', 'int flags']
		case 328: {
			uint32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_pipe2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pipe2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 329 long sys_inotify_init1 ['int flags']
		case 329: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_inotify_init1_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_inotify_init1_return, cpu, pc, arg0) ;
		}; break;
		// 330 long sys_preadv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
		case 330: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_preadv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_preadv_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 331 long sys_pwritev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
		case 331: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_pwritev_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pwritev_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 332 long sys_rt_tgsigqueueinfo ['pid_t tgid', 'pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
		case 332: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_rt_tgsigqueueinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_tgsigqueueinfo_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 333 long sys_perf_event_open ['struct perf_event_attr __user *attr_uptr', 'pid_t pid', 'int cpu', 'int group_fd', 'unsigned long flags']
		case 333: {
			uint32_t arg0;
			int32_t arg1;
			int32_t arg2;
			int32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_perf_event_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_perf_event_open_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 334 long sys_accept4 ['int', 'struct sockaddr __user *', 'int __user *', 'int']
		case 334: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_accept4_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_accept4_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 335 long sys_recvmmsg_time32 ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags', 'struct old_timespec32 __user *timeout']
		case 335: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_recvmmsg_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recvmmsg_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 336 long sys_fanotify_init ['unsigned int flags', 'unsigned int event_f_flags']
		case 336: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_fanotify_init_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fanotify_init_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 337 long sys_fanotify_mark ['int fanotify_fd', 'unsigned int flags', 'u64 mask', 'int fd', 'const char __user *pathname']
		case 337: {
			int32_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			int32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_fanotify_mark_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fanotify_mark_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 338 long sys_prlimit64 ['pid_t pid', 'unsigned int resource', 'const struct rlimit64 __user *new_rlim', 'struct rlimit64 __user *old_rlim']
		case 338: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_prlimit64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_prlimit64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 339 long sys_name_to_handle_at ['int dfd', 'const char __user *name', 'struct file_handle __user *handle', 'int __user *mnt_id', 'int flag']
		case 339: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_name_to_handle_at_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_name_to_handle_at_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 340 long sys_open_by_handle_at ['int mountdirfd', 'struct file_handle __user *handle', 'int flags']
		case 340: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_open_by_handle_at_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_open_by_handle_at_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 341 long sys_clock_adjtime32 ['clockid_t which_clock', 'struct old_timex32 __user *tx']
		case 341: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_adjtime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_adjtime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 342 long sys_syncfs ['int fd']
		case 342: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_syncfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_syncfs_return, cpu, pc, arg0) ;
		}; break;
		// 343 long sys_sendmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags']
		case 343: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_sendmmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendmmsg_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 344 long sys_setns ['int fd', 'int nstype']
		case 344: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_setns_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setns_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 345 long sys_process_vm_readv ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
		case 345: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_process_vm_readv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_process_vm_readv_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 346 long sys_process_vm_writev ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
		case 346: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_process_vm_writev_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_process_vm_writev_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 347 long sys_kcmp ['pid_t pid1', 'pid_t pid2', 'int type', 'unsigned long idx1', 'unsigned long idx2']
		case 347: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_kcmp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_kcmp_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 348 long sys_finit_module ['int fd', 'const char __user *uargs', 'int flags']
		case 348: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_finit_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_finit_module_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 349 long sys_sched_setattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int flags']
		case 349: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sched_setattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_setattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 350 long sys_sched_getattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int size', 'unsigned int flags']
		case 350: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_sched_getattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_getattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 351 long sys_renameat2 ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'unsigned int flags']
		case 351: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_renameat2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_renameat2_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 352 long sys_seccomp ['unsigned int op', 'unsigned int flags', 'void __user *uargs']
		case 352: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_seccomp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_seccomp_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 353 long sys_getrandom ['char __user *buf', 'size_t count', 'unsigned int flags']
		case 353: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_getrandom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getrandom_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 354 long sys_memfd_create ['const char __user *uname_ptr', 'unsigned int flags']
		case 354: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_memfd_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_memfd_create_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 355 long sys_bpf ['int cmd', 'union bpf_attr *attr', 'unsigned int size']
		case 355: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_bpf_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_bpf_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 356 long sys_execveat ['int dfd', 'const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp', 'int flags']
		case 356: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_execveat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_execveat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 357 long sys_userfaultfd ['int flags']
		case 357: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_userfaultfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_userfaultfd_return, cpu, pc, arg0) ;
		}; break;
		// 358 long sys_membarrier ['int cmd', 'int flags']
		case 358: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_membarrier_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_membarrier_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 359 long sys_mlock2 ['unsigned long start', 'size_t len', 'int flags']
		case 359: {
			uint32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_mlock2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_mlock2_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 360 long sys_copy_file_range ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
		case 360: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_copy_file_range_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_copy_file_range_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 361 long sys_preadv2 ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h', 'rwf_t flags']
		case 361: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_preadv2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_preadv2_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 362 long sys_pwritev2 ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h', 'rwf_t flags']
		case 362: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_pwritev2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pwritev2_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 363 long sys_pkey_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot', 'int pkey']
		case 363: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_pkey_mprotect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pkey_mprotect_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 364 long sys_pkey_alloc ['unsigned long flags', 'unsigned long init_val']
		case 364: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_pkey_alloc_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pkey_alloc_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 365 long sys_pkey_free ['int pkey']
		case 365: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_pkey_free_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pkey_free_return, cpu, pc, arg0) ;
		}; break;
		// 366 long sys_statx ['int dfd', 'const char __user *path', 'unsigned flags', 'unsigned mask', 'struct statx __user *buffer']
		case 366: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_statx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_statx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 367 long sys_rseq ['struct rseq __user *rseq', 'uint32_t rseq_len', 'int flags', 'uint32_t sig']
		case 367: {
			uint32_t arg0;
			int32_t arg1;
			int32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_rseq_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_rseq_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 368 long sys_io_pgetevents_time32 ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct old_timespec32 __user *timeout', 'const struct __aio_sigset *sig']
		case 368: {
			uint32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_io_pgetevents_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_pgetevents_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 393 long sys_semget ['key_t key', 'int nsems', 'int semflg']
		case 393: {
			uint32_t arg0;
			int32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_semget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_semget_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 394 long sys_semctl ['int semid', 'int semnum', 'int cmd', 'unsigned long arg']
		case 394: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_semctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_semctl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 395 long sys_shmget ['key_t key', 'size_t size', 'int flag']
		case 395: {
			uint32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_shmget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shmget_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 396 long sys_shmctl ['int shmid', 'int cmd', 'struct shmid_ds __user *buf']
		case 396: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_shmctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_shmctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 397 long sys_shmat ['int shmid', 'char __user *shmaddr', 'int shmflg']
		case 397: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_shmat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shmat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 398 long sys_shmdt ['char __user *shmaddr']
		case 398: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_shmdt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_shmdt_return, cpu, pc, arg0) ;
		}; break;
		// 399 long sys_msgget ['key_t key', 'int msgflg']
		case 399: {
			uint32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_msgget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgget_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 400 long sys_msgsnd ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'int msgflg']
		case 400: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_msgsnd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgsnd_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 401 long sys_msgrcv ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'long msgtyp', 'int msgflg']
		case 401: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_msgrcv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgrcv_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 402 long sys_msgctl ['int msqid', 'int cmd', 'struct msqid_ds __user *buf']
		case 402: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_msgctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_msgctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 403 long sys_clock_gettime ['clockid_t which_clock', 'struct __kernel_timespec __user *tp']
		case 403: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 404 long sys_clock_settime ['clockid_t which_clock', 'const struct __kernel_timespec __user *tp']
		case 404: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_settime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 405 long sys_clock_adjtime ['clockid_t which_clock', 'struct __kernel_timex __user *tx']
		case 405: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_adjtime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_adjtime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 406 long sys_clock_getres ['clockid_t which_clock', 'struct __kernel_timespec __user *tp']
		case 406: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_getres_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_getres_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 407 long sys_clock_nanosleep ['clockid_t which_clock', 'int flags', 'const struct __kernel_timespec __user *rqtp', 'struct __kernel_timespec __user *rmtp']
		case 407: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_clock_nanosleep_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_nanosleep_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 408 long sys_timer_gettime ['timer_t timer_id', 'struct __kernel_itimerspec __user *setting']
		case 408: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_timer_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 409 long sys_timer_settime ['timer_t timer_id', 'int flags', 'const struct __kernel_itimerspec __user *new_setting', 'struct __kernel_itimerspec __user *old_setting']
		case 409: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_timer_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_settime_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 410 long sys_timerfd_gettime ['int ufd', 'struct __kernel_itimerspec __user *otmr']
		case 410: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_timerfd_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 411 long sys_timerfd_settime ['int ufd', 'int flags', 'const struct __kernel_itimerspec __user *utmr', 'struct __kernel_itimerspec __user *otmr']
		case 411: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_timerfd_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_settime_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 412 long sys_utimensat ['int dfd', 'const char __user *filename', 'struct __kernel_timespec __user *utimes', 'int flags']
		case 412: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_utimensat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_utimensat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 413 long sys_pselect6 ['int', 'fd_set __user *', 'fd_set __user *', 'fd_set __user *', 'struct __kernel_timespec __user *', 'void __user *']
		case 413: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_pselect6_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pselect6_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 414 long sys_ppoll ['struct pollfd __user *', 'unsigned int', 'struct __kernel_timespec __user *', 'const sigset_t __user *', 'size_t']
		case 414: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_ppoll_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ppoll_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 416 long sys_io_pgetevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct __kernel_timespec __user *timeout', 'const struct __aio_sigset *sig']
		case 416: {
			uint32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_io_pgetevents_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_pgetevents_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 417 long sys_recvmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags', 'struct __kernel_timespec __user *timeout']
		case 417: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_recvmmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recvmmsg_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 418 long sys_mq_timedsend ['mqd_t mqdes', 'const char __user *msg_ptr', 'size_t msg_len', 'unsigned int msg_prio', 'const struct __kernel_timespec __user *abs_timeout']
		case 418: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_mq_timedsend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_timedsend_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 419 long sys_mq_timedreceive ['mqd_t mqdes', 'char __user *msg_ptr', 'size_t msg_len', 'unsigned int __user *msg_prio', 'const struct __kernel_timespec __user *abs_timeout']
		case 419: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_mq_timedreceive_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_timedreceive_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 420 long sys_semtimedop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops', 'const struct __kernel_timespec __user *timeout']
		case 420: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_semtimedop_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_semtimedop_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 421 long sys_rt_sigtimedwait ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct __kernel_timespec __user *uts', 'size_t sigsetsize']
		case 421: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_rt_sigtimedwait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigtimedwait_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 422 long sys_futex ['u32 __user *uaddr', 'int op', 'u32 val', 'struct __kernel_timespec __user *utime', 'u32 __user *uaddr2', 'u32 val3']
		case 422: {
			uint32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_futex_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_futex_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 423 long sys_sched_rr_get_interval ['pid_t pid', 'struct __kernel_timespec __user *interval']
		case 423: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_sched_rr_get_interval_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_rr_get_interval_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 424 long sys_pidfd_send_signal ['int pidfd', 'int sig', 'siginfo_t __user *info', 'unsigned int flags']
		case 424: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_pidfd_send_signal_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pidfd_send_signal_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 425 long sys_io_uring_setup ['u32 entries', 'struct io_uring_params __user *p']
		case 425: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_io_uring_setup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_uring_setup_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 426 long sys_io_uring_enter ['unsigned int fd', 'u32 to_submit', 'u32 min_complete', 'u32 flags', 'const sigset_t __user *sig', 'size_t sigsz']
		case 426: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_io_uring_enter_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_uring_enter_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 427 long sys_io_uring_register ['unsigned int fd', 'unsigned int op', 'void __user *arg', 'unsigned int nr_args']
		case 427: {
			uint32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_io_uring_register_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_uring_register_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 428 long sys_open_tree ['int dfd', 'const char __user *path', 'unsigned flags']
		case 428: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_open_tree_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_open_tree_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 429 long sys_move_mount ['int from_dfd', 'const char __user *from_path', 'int to_dfd', 'const char __user *to_path', 'unsigned int ms_flags']
		case 429: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_move_mount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_move_mount_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 430 long sys_fsopen ['const char __user *fs_name', 'unsigned int flags']
		case 430: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_fsopen_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fsopen_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 431 long sys_fsconfig ['int fs_fd', 'unsigned int cmd', 'const char __user *key', 'const void __user *value', 'int aux']
		case 431: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_fsconfig_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fsconfig_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 432 long sys_fsmount ['int fs_fd', 'unsigned int flags', 'unsigned int ms_flags']
		case 432: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_fsmount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fsmount_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 433 long sys_fspick ['int dfd', 'const char __user *path', 'unsigned int flags']
		case 433: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_fspick_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fspick_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 434 long sys_pidfd_open ['pid_t pid', 'unsigned int flags']
		case 434: {
			int32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_pidfd_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pidfd_open_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 437 long sys_openat2 ['int dfd', 'const char __user *filename', 'struct open_how *how', 'size_t size']
		case 437: {
			int32_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_openat2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_openat2_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 438 long sys_pidfd_getfd ['int pidfd', 'int fd', 'unsigned int flags']
		case 438: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_pidfd_getfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pidfd_getfd_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 439 long sys_faccessat2 ['int dfd', 'const char __user *filename', 'int mode', 'int flags']
		case 439: {
			int32_t arg0;
			uint32_t arg1;
			int32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_faccessat2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_faccessat2_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		default:
			PPP_RUN_CB(on_unknown_sys_return, cpu, pc, ctx->no);
	}
	PPP_RUN_CB(on_all_sys_return, cpu, pc, ctx->no);
	PPP_RUN_CB(on_all_sys_return2, cpu, pc, call, ctx);
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */