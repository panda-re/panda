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
		// 4001 long sys_exit ['int error_code']
		case 4001: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_exit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_exit_return, cpu, pc, arg0) ;
		}; break;
		// 4002 pid_t sys_fork ['void']
		case 4002: {
			if (PPP_CHECK_CB(on_sys_fork_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_fork_return, cpu, pc) ;
		}; break;
		// 4003 long sys_read ['unsigned int fd', 'char __user *buf', 'size_t count']
		case 4003: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_read_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_read_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4004 long sys_write ['unsigned int fd', 'const char __user *buf', 'size_t count']
		case 4004: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_write_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_write_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4005 long sys_open ['const char __user *filename', 'int flags', 'umode_t mode']
		case 4005: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_open_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4006 long sys_close ['unsigned int fd']
		case 4006: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_close_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_close_return, cpu, pc, arg0) ;
		}; break;
		// 4007 long sys_waitpid ['pid_t pid', 'int __user *stat_addr', 'int options']
		case 4007: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_waitpid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_waitpid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4008 long sys_creat ['const char __user *pathname', 'umode_t mode']
		case 4008: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_creat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_creat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4009 long sys_link ['const char __user *oldname', 'const char __user *newname']
		case 4009: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_link_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4010 long sys_unlink ['const char __user *pathname']
		case 4010: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 4011 long sys_execve ['const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp']
		case 4011: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_execve_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_execve_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4012 long sys_chdir ['const char __user *filename']
		case 4012: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_chdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chdir_return, cpu, pc, arg0) ;
		}; break;
		// 4013 long sys_time32 ['old_time32_t __user *tloc']
		case 4013: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_time32_return, cpu, pc, arg0) ;
		}; break;
		// 4014 long sys_mknod ['const char __user *filename', 'umode_t mode', 'unsigned dev']
		case 4014: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mknod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mknod_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4015 long sys_chmod ['const char __user *filename', 'umode_t mode']
		case 4015: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_chmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4016 long sys_lchown ['const char __user *filename', 'uid_t user', 'gid_t group']
		case 4016: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_lchown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lchown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4018 long sys_stat ['const char __user *filename', 'struct __old_kernel_stat __user *statbuf']
		case 4018: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_stat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_stat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4019 long sys_lseek ['unsigned int fd', 'off_t offset', 'unsigned int whence']
		case 4019: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_lseek_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lseek_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4020 long sys_getpid ['void']
		case 4020: {
			if (PPP_CHECK_CB(on_sys_getpid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpid_return, cpu, pc) ;
		}; break;
		// 4021 long sys_mount ['char __user *dev_name', 'char __user *dir_name', 'char __user *type', 'unsigned long flags', 'void __user *data']
		case 4021: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_mount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mount_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4022 long sys_oldumount ['char __user *name']
		case 4022: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_oldumount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_oldumount_return, cpu, pc, arg0) ;
		}; break;
		// 4023 long sys_setuid ['uid_t uid']
		case 4023: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setuid_return, cpu, pc, arg0) ;
		}; break;
		// 4024 long sys_getuid ['void']
		case 4024: {
			if (PPP_CHECK_CB(on_sys_getuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getuid_return, cpu, pc) ;
		}; break;
		// 4025 long sys_stime32 ['old_time32_t __user *tptr']
		case 4025: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_stime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_stime32_return, cpu, pc, arg0) ;
		}; break;
		// 4026 long sys_ptrace ['long request', 'long pid', 'unsigned long addr', 'unsigned long data']
		case 4026: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_ptrace_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ptrace_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4027 long sys_alarm ['unsigned int seconds']
		case 4027: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_alarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_alarm_return, cpu, pc, arg0) ;
		}; break;
		// 4028 long sys_fstat ['unsigned int fd', 'struct __old_kernel_stat __user *statbuf']
		case 4028: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4029 long sys_pause ['void']
		case 4029: {
			if (PPP_CHECK_CB(on_sys_pause_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_pause_return, cpu, pc) ;
		}; break;
		// 4030 long sys_utime32 ['const char __user *filename', 'struct old_utimbuf32 __user *t']
		case 4030: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_utime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_utime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4033 long sys_access ['const char __user *filename', 'int mode']
		case 4033: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_access_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_access_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4034 long sys_nice ['int increment']
		case 4034: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_nice_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_nice_return, cpu, pc, arg0) ;
		}; break;
		// 4036 long sys_sync ['void']
		case 4036: {
			if (PPP_CHECK_CB(on_sys_sync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sync_return, cpu, pc) ;
		}; break;
		// 4037 long sys_kill ['pid_t pid', 'int sig']
		case 4037: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_kill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_kill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4038 long sys_rename ['const char __user *oldname', 'const char __user *newname']
		case 4038: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_rename_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rename_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4039 long sys_mkdir ['const char __user *pathname', 'umode_t mode']
		case 4039: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_mkdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkdir_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4040 long sys_rmdir ['const char __user *pathname']
		case 4040: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_rmdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rmdir_return, cpu, pc, arg0) ;
		}; break;
		// 4041 long sys_dup ['unsigned int fildes']
		case 4041: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_dup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_dup_return, cpu, pc, arg0) ;
		}; break;
		// 4042 long sys_pipe ['int __user *fildes']
		case 4042: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_pipe_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pipe_return, cpu, pc, arg0) ;
		}; break;
		// 4043 long sys_times ['struct tms __user *tbuf']
		case 4043: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_times_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_times_return, cpu, pc, arg0) ;
		}; break;
		// 4045 long sys_brk ['unsigned long brk']
		case 4045: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_brk_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_brk_return, cpu, pc, arg0) ;
		}; break;
		// 4046 long sys_setgid ['gid_t gid']
		case 4046: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setgid_return, cpu, pc, arg0) ;
		}; break;
		// 4047 long sys_getgid ['void']
		case 4047: {
			if (PPP_CHECK_CB(on_sys_getgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getgid_return, cpu, pc) ;
		}; break;
		// 4048 long sys_signal ['int sig', '__sighandler_t handler']
		case 4048: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_signal_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_signal_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4049 long sys_geteuid ['void']
		case 4049: {
			if (PPP_CHECK_CB(on_sys_geteuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_geteuid_return, cpu, pc) ;
		}; break;
		// 4050 long sys_getegid ['void']
		case 4050: {
			if (PPP_CHECK_CB(on_sys_getegid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getegid_return, cpu, pc) ;
		}; break;
		// 4051 long sys_acct ['const char __user *name']
		case 4051: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_acct_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_acct_return, cpu, pc, arg0) ;
		}; break;
		// 4052 long sys_umount ['char __user *name', 'int flags']
		case 4052: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_umount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_umount_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4054 long sys_ioctl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
		case 4054: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_ioctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ioctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4055 long sys_fcntl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
		case 4055: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fcntl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fcntl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4057 long sys_setpgid ['pid_t pid', 'pid_t pgid']
		case 4057: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setpgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setpgid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4059 long sys_olduname ['struct oldold_utsname __user *']
		case 4059: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_olduname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_olduname_return, cpu, pc, arg0) ;
		}; break;
		// 4060 long sys_umask ['int mask']
		case 4060: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_umask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_umask_return, cpu, pc, arg0) ;
		}; break;
		// 4061 long sys_chroot ['const char __user *filename']
		case 4061: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_chroot_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chroot_return, cpu, pc, arg0) ;
		}; break;
		// 4062 long sys_ustat ['unsigned dev', 'struct ustat __user *ubuf']
		case 4062: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ustat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ustat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4063 long sys_dup2 ['unsigned int oldfd', 'unsigned int newfd']
		case 4063: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_dup2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_dup2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4064 long sys_getppid ['void']
		case 4064: {
			if (PPP_CHECK_CB(on_sys_getppid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getppid_return, cpu, pc) ;
		}; break;
		// 4065 long sys_getpgrp ['void']
		case 4065: {
			if (PPP_CHECK_CB(on_sys_getpgrp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpgrp_return, cpu, pc) ;
		}; break;
		// 4066 long sys_setsid ['void']
		case 4066: {
			if (PPP_CHECK_CB(on_sys_setsid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_setsid_return, cpu, pc) ;
		}; break;
		// 4067 long sys_sigaction ['int', 'const struct old_sigaction __user *', 'struct old_sigaction __user *']
		case 4067: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sigaction_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigaction_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4068 long sys_sgetmask ['void']
		case 4068: {
			if (PPP_CHECK_CB(on_sys_sgetmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sgetmask_return, cpu, pc) ;
		}; break;
		// 4069 long sys_ssetmask ['int newmask']
		case 4069: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ssetmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ssetmask_return, cpu, pc, arg0) ;
		}; break;
		// 4070 long sys_setreuid ['uid_t ruid', 'uid_t euid']
		case 4070: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setreuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setreuid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4071 long sys_setregid ['gid_t rgid', 'gid_t egid']
		case 4071: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setregid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setregid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4072 long sys_sigsuspend ['int unused1', 'int unused2', 'old_sigset_t mask']
		case 4072: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sigsuspend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigsuspend_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4073 long sys_sigpending ['old_sigset_t __user *uset']
		case 4073: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sigpending_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigpending_return, cpu, pc, arg0) ;
		}; break;
		// 4074 long sys_sethostname ['char __user *name', 'int len']
		case 4074: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sethostname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sethostname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4075 long sys_setrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
		case 4075: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4076 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
		case 4076: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4077 long sys_getrusage ['int who', 'struct rusage __user *ru']
		case 4077: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getrusage_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getrusage_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4078 long sys_gettimeofday ['struct __kernel_old_timeval __user *tv', 'struct timezone __user *tz']
		case 4078: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_gettimeofday_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_gettimeofday_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4079 long sys_settimeofday ['struct __kernel_old_timeval __user *tv', 'struct timezone __user *tz']
		case 4079: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_settimeofday_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_settimeofday_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4080 long sys_getgroups ['int gidsetsize', 'gid_t __user *grouplist']
		case 4080: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getgroups_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getgroups_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4081 long sys_setgroups ['int gidsetsize', 'gid_t __user *grouplist']
		case 4081: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setgroups_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setgroups_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4083 long sys_symlink ['const char __user *old', 'const char __user *new']
		case 4083: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_symlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_symlink_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4084 long sys_lstat ['const char __user *filename', 'struct __old_kernel_stat __user *statbuf']
		case 4084: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4085 long sys_readlink ['const char __user *path', 'char __user *buf', 'int bufsiz']
		case 4085: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_readlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_readlink_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4086 long sys_uselib ['const char __user *library']
		case 4086: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_uselib_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_uselib_return, cpu, pc, arg0) ;
		}; break;
		// 4087 long sys_swapon ['const char __user *specialfile', 'int swap_flags']
		case 4087: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_swapon_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_swapon_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4088 long sys_reboot ['int magic1', 'int magic2', 'unsigned int cmd', 'void __user *arg']
		case 4088: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_reboot_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_reboot_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4089 long sys_old_readdir ['unsigned int', 'struct old_linux_dirent __user *', 'unsigned int']
		case 4089: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_old_readdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_old_readdir_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4090 long sys_mmap ['unsigned long addr', 'unsigned long len', 'unsigned long prot', 'unsigned long flags', 'unsigned long fd', 'unsigned long pgoff']
		case 4090: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys_mmap_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mmap_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 4091 long sys_munmap ['unsigned long addr', 'size_t len']
		case 4091: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_munmap_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_munmap_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4092 long sys_truncate ['const char __user *path', 'long length']
		case 4092: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_truncate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_truncate_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4093 long sys_ftruncate ['unsigned int fd', 'unsigned long length']
		case 4093: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ftruncate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ftruncate_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4094 long sys_fchmod ['unsigned int fd', 'umode_t mode']
		case 4094: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fchmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4095 long sys_fchown ['unsigned int fd', 'uid_t user', 'gid_t group']
		case 4095: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fchown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4096 long sys_getpriority ['int which', 'int who']
		case 4096: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getpriority_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getpriority_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4097 long sys_setpriority ['int which', 'int who', 'int niceval']
		case 4097: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_setpriority_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setpriority_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4099 long sys_statfs ['const char __user *path', 'struct statfs __user *buf']
		case 4099: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_statfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_statfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4100 long sys_fstatfs ['unsigned int fd', 'struct statfs __user *buf']
		case 4100: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fstatfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fstatfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4101 long sys_ioperm ['unsigned long from', 'unsigned long num', 'int on']
		case 4101: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_ioperm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ioperm_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4102 long sys_socketcall ['int call', 'unsigned long __user *args']
		case 4102: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_socketcall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_socketcall_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4103 long sys_syslog ['int type', 'char __user *buf', 'int len']
		case 4103: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_syslog_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_syslog_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4104 long sys_setitimer ['int which', 'struct __kernel_old_itimerval __user *value', 'struct __kernel_old_itimerval __user *ovalue']
		case 4104: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_setitimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setitimer_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4105 long sys_getitimer ['int which', 'struct __kernel_old_itimerval __user *value']
		case 4105: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getitimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getitimer_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4106 long sys_newstat ['const char __user *filename', 'struct stat __user *statbuf']
		case 4106: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_newstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4107 long sys_newlstat ['const char __user *filename', 'struct stat __user *statbuf']
		case 4107: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_newlstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newlstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4108 long sys_newfstat ['unsigned int fd', 'struct stat __user *statbuf']
		case 4108: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_newfstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newfstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4109 long sys_uname ['struct old_utsname __user *']
		case 4109: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_uname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_uname_return, cpu, pc, arg0) ;
		}; break;
		// 4110 long sys_iopl ['int level']
		case 4110: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_iopl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_iopl_return, cpu, pc, arg0) ;
		}; break;
		// 4111 long sys_vhangup ['void']
		case 4111: {
			if (PPP_CHECK_CB(on_sys_vhangup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_vhangup_return, cpu, pc) ;
		}; break;
		// 4112 long sys_idle ['void']
		case 4112: {
			if (PPP_CHECK_CB(on_sys_idle_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_idle_return, cpu, pc) ;
		}; break;
		// 4114 long sys_wait4 ['pid_t pid', 'int __user *stat_addr', 'int options', 'struct rusage __user *ru']
		case 4114: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_wait4_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_wait4_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4115 long sys_swapoff ['const char __user *specialfile']
		case 4115: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_swapoff_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_swapoff_return, cpu, pc, arg0) ;
		}; break;
		// 4116 long sys_sysinfo ['struct sysinfo __user *info']
		case 4116: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sysinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sysinfo_return, cpu, pc, arg0) ;
		}; break;
		// 4117 long sys_ipc ['unsigned int call', 'int first', 'unsigned long second', 'unsigned long third', 'void __user *ptr', 'long fifth']
		case 4117: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			int32_t arg5 = 0;
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
		// 4118 long sys_fsync ['unsigned int fd']
		case 4118: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_fsync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fsync_return, cpu, pc, arg0) ;
		}; break;
		// 4119 void sys_sigreturn ['void']
		case 4119: {
			if (PPP_CHECK_CB(on_sys_sigreturn_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sigreturn_return, cpu, pc) ;
		}; break;
		// 4120 long sys_clone ['unsigned long', 'unsigned long', 'int __user *', 'unsigned long', 'int __user *']
		case 4120: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_clone_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clone_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4121 long sys_setdomainname ['char __user *name', 'int len']
		case 4121: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setdomainname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setdomainname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4122 long sys_newuname ['struct new_utsname __user *name']
		case 4122: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_newuname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newuname_return, cpu, pc, arg0) ;
		}; break;
		// 4123 long modify_ldt ['int func', 'void *ptr', 'unsigned long bytecount']
		case 4123: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_modify_ldt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_modify_ldt_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4124 long sys_adjtimex_time32 ['struct old_timex32 __user *txc_p']
		case 4124: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_adjtimex_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_adjtimex_time32_return, cpu, pc, arg0) ;
		}; break;
		// 4125 long sys_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot']
		case 4125: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mprotect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mprotect_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4126 long sys_sigprocmask ['int how', 'old_sigset_t __user *set', 'old_sigset_t __user *oset']
		case 4126: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sigprocmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigprocmask_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4127 caddr_t create_module ['const char *name', 'size_t size']
		case 4127: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_create_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_create_module_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4128 long sys_init_module ['void __user *umod', 'unsigned long len', 'const char __user *uargs']
		case 4128: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_init_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_init_module_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4129 long sys_delete_module ['const char __user *name_user', 'unsigned int flags']
		case 4129: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_delete_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_delete_module_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4130 long get_kernel_syms ['struct kernel_sym *table']
		case 4130: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_get_kernel_syms_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_get_kernel_syms_return, cpu, pc, arg0) ;
		}; break;
		// 4131 long sys_quotactl ['unsigned int cmd', 'const char __user *special', 'qid_t id', 'void __user *addr']
		case 4131: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_quotactl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_quotactl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4132 long sys_getpgid ['pid_t pid']
		case 4132: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_getpgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getpgid_return, cpu, pc, arg0) ;
		}; break;
		// 4133 long sys_fchdir ['unsigned int fd']
		case 4133: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_fchdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchdir_return, cpu, pc, arg0) ;
		}; break;
		// 4134 long sys_bdflush ['int func', 'long data']
		case 4134: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_bdflush_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_bdflush_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4135 long sys_sysfs ['int option', 'unsigned long arg1', 'unsigned long arg2']
		case 4135: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sysfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sysfs_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4136 long sys_personality ['unsigned int personality']
		case 4136: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_personality_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_personality_return, cpu, pc, arg0) ;
		}; break;
		// 4138 long sys_setfsuid ['uid_t uid']
		case 4138: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setfsuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setfsuid_return, cpu, pc, arg0) ;
		}; break;
		// 4139 long sys_setfsgid ['gid_t gid']
		case 4139: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setfsgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setfsgid_return, cpu, pc, arg0) ;
		}; break;
		// 4140 long sys_llseek ['unsigned int fd', 'unsigned long offset_high', 'unsigned long offset_low', 'loff_t __user *result', 'unsigned int whence']
		case 4140: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_llseek_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_llseek_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4141 long sys_getdents ['unsigned int fd', 'struct linux_dirent __user *dirent', 'unsigned int count']
		case 4141: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getdents_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getdents_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4142 long sys_select ['int n', 'fd_set __user *inp', 'fd_set __user *outp', 'fd_set __user *exp', 'struct __kernel_old_timeval __user *tvp']
		case 4142: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_select_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_select_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4143 long sys_flock ['unsigned int fd', 'unsigned int cmd']
		case 4143: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_flock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_flock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4144 long sys_msync ['unsigned long start', 'size_t len', 'int flags']
		case 4144: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_msync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msync_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4145 long sys_readv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
		case 4145: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_readv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_readv_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4146 long sys_writev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
		case 4146: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_writev_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_writev_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4147 long sys_cacheflush ['char *addr', 'int nbytes', 'int cache']
		case 4147: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_cacheflush_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_cacheflush_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4150 long sys_setup ['void']
		case 4150: {
			if (PPP_CHECK_CB(on_sys_setup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_setup_return, cpu, pc) ;
		}; break;
		// 4151 long sys_getsid ['pid_t pid']
		case 4151: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_getsid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getsid_return, cpu, pc, arg0) ;
		}; break;
		// 4152 long sys_fdatasync ['unsigned int fd']
		case 4152: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_fdatasync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fdatasync_return, cpu, pc, arg0) ;
		}; break;
		// 4153 long sys_sysctl ['struct __sysctl_args __user *args']
		case 4153: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sysctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sysctl_return, cpu, pc, arg0) ;
		}; break;
		// 4154 long sys_mlock ['unsigned long start', 'size_t len']
		case 4154: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_mlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mlock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4155 long sys_munlock ['unsigned long start', 'size_t len']
		case 4155: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_munlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_munlock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4156 long sys_mlockall ['int flags']
		case 4156: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_mlockall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_mlockall_return, cpu, pc, arg0) ;
		}; break;
		// 4157 long sys_munlockall ['void']
		case 4157: {
			if (PPP_CHECK_CB(on_sys_munlockall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_munlockall_return, cpu, pc) ;
		}; break;
		// 4158 long sys_sched_setparam ['pid_t pid', 'struct sched_param __user *param']
		case 4158: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sched_setparam_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_setparam_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4159 long sys_sched_getparam ['pid_t pid', 'struct sched_param __user *param']
		case 4159: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sched_getparam_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_getparam_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4160 long sys_sched_setscheduler ['pid_t pid', 'int policy', 'struct sched_param __user *param']
		case 4160: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sched_setscheduler_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_setscheduler_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4161 long sys_sched_getscheduler ['pid_t pid']
		case 4161: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sched_getscheduler_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_getscheduler_return, cpu, pc, arg0) ;
		}; break;
		// 4162 long sys_sched_yield ['void']
		case 4162: {
			if (PPP_CHECK_CB(on_sys_sched_yield_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sched_yield_return, cpu, pc) ;
		}; break;
		// 4163 long sys_sched_get_priority_max ['int policy']
		case 4163: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sched_get_priority_max_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_get_priority_max_return, cpu, pc, arg0) ;
		}; break;
		// 4164 long sys_sched_get_priority_min ['int policy']
		case 4164: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sched_get_priority_min_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_get_priority_min_return, cpu, pc, arg0) ;
		}; break;
		// 4165 long sys_sched_rr_get_interval_time32 ['pid_t pid', 'struct old_timespec32 __user *interval']
		case 4165: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sched_rr_get_interval_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_rr_get_interval_time32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4166 long sys_nanosleep_time32 ['struct old_timespec32 __user *rqtp', 'struct old_timespec32 __user *rmtp']
		case 4166: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_nanosleep_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_nanosleep_time32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4167 long sys_mremap ['unsigned long addr', 'unsigned long old_len', 'unsigned long new_len', 'unsigned long flags', 'unsigned long new_addr']
		case 4167: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_mremap_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mremap_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4168 long sys_accept ['int', 'struct sockaddr __user *', 'int __user *']
		case 4168: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_accept_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_accept_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4169 long sys_bind ['int', 'struct sockaddr __user *', 'int']
		case 4169: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_bind_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_bind_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4170 long sys_connect ['int', 'struct sockaddr __user *', 'int']
		case 4170: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_connect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_connect_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4171 long sys_getpeername ['int', 'struct sockaddr __user *', 'int __user *']
		case 4171: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getpeername_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getpeername_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4172 long sys_getsockname ['int', 'struct sockaddr __user *', 'int __user *']
		case 4172: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getsockname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getsockname_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4173 long sys_getsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int __user *optlen']
		case 4173: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_getsockopt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getsockopt_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4174 long sys_listen ['int', 'int']
		case 4174: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_listen_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_listen_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4175 long sys_recv ['int', 'void __user *', 'size_t', 'unsigned']
		case 4175: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_recv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recv_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4176 long sys_recvfrom ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int __user *']
		case 4176: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4177 long sys_recvmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
		case 4177: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_recvmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recvmsg_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4178 long sys_send ['int', 'void __user *', 'size_t', 'unsigned']
		case 4178: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_send_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_send_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4179 long sys_sendmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
		case 4179: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sendmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendmsg_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4180 long sys_sendto ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int']
		case 4180: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			int32_t arg5 = 0;
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
		// 4181 long sys_setsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int optlen']
		case 4181: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_setsockopt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setsockopt_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4182 long sys_shutdown ['int', 'int']
		case 4182: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_shutdown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shutdown_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4183 long sys_socket ['int', 'int', 'int']
		case 4183: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_socket_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_socket_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4184 long sys_socketpair ['int', 'int', 'int', 'int __user *']
		case 4184: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_socketpair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_socketpair_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4185 long sys_setresuid ['uid_t ruid', 'uid_t euid', 'uid_t suid']
		case 4185: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_setresuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setresuid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4186 long sys_getresuid ['uid_t __user *ruid', 'uid_t __user *euid', 'uid_t __user *suid']
		case 4186: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getresuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getresuid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4187 long sys_query_module ['const char *name', 'int which', 'void *buf', 'size_t bufsize', 'size_t *ret']
		case 4187: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_query_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_query_module_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4188 long sys_poll ['struct pollfd __user *ufds', 'unsigned int nfds', 'int timeout']
		case 4188: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_poll_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_poll_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4189 long sys_nfsservctl ['int cmd', 'struct nfsctl_arg *argp', 'union nfsctl_res *resp']
		case 4189: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_nfsservctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_nfsservctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4190 long sys_setresgid ['gid_t rgid', 'gid_t egid', 'gid_t sgid']
		case 4190: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_setresgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setresgid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4191 long sys_getresgid ['gid_t __user *rgid', 'gid_t __user *egid', 'gid_t __user *sgid']
		case 4191: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getresgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getresgid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4192 long sys_prctl ['int option', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
		case 4192: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_prctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_prctl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4193 void sys_rt_sigreturn ['void']
		case 4193: {
			if (PPP_CHECK_CB(on_sys_rt_sigreturn_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_rt_sigreturn_return, cpu, pc) ;
		}; break;
		// 4194 long sys_rt_sigaction ['int', 'const struct sigaction __user *', 'struct sigaction __user *', 'size_t']
		case 4194: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rt_sigaction_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigaction_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4195 long sys_rt_sigprocmask ['int how', 'sigset_t __user *set', 'sigset_t __user *oset', 'size_t sigsetsize']
		case 4195: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rt_sigprocmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigprocmask_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4196 long sys_rt_sigpending ['sigset_t __user *set', 'size_t sigsetsize']
		case 4196: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_rt_sigpending_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigpending_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4197 long sys_rt_sigtimedwait_time32 ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct old_timespec32 __user *uts', 'size_t sigsetsize']
		case 4197: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rt_sigtimedwait_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigtimedwait_time32_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4198 long sys_rt_sigqueueinfo ['pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
		case 4198: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_rt_sigqueueinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigqueueinfo_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4199 long sys_rt_sigsuspend ['sigset_t __user *unewset', 'size_t sigsetsize']
		case 4199: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_rt_sigsuspend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigsuspend_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4200 long sys_pread64 ['unsigned int fd', 'char __user *buf', 'size_t count', 'loff_t pos']
		case 4200: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_pread64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pread64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4201 long sys_pwrite64 ['unsigned int fd', 'const char __user *buf', 'size_t count', 'loff_t pos']
		case 4201: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_pwrite64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pwrite64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4202 long sys_chown ['const char __user *filename', 'uid_t user', 'gid_t group']
		case 4202: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_chown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4203 long sys_getcwd ['char __user *buf', 'unsigned long size']
		case 4203: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getcwd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getcwd_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4204 long sys_capget ['cap_user_header_t header', 'cap_user_data_t dataptr']
		case 4204: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_capget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_capget_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4205 long sys_capset ['cap_user_header_t header', 'const cap_user_data_t data']
		case 4205: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_capset_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_capset_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4206 long sys_sigaltstack ['const struct sigaltstack __user *uss', 'struct sigaltstack __user *uoss']
		case 4206: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sigaltstack_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigaltstack_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4207 long sys_sendfile ['int out_fd', 'int in_fd', 'off_t __user *offset', 'size_t count']
		case 4207: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_sendfile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendfile_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4210 void* mmap2 ['void *addr', 'size_t length', 'int prot', 'int flags', 'int fd', 'off_t pgoffset']
		case 4210: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			int32_t arg4 = 0;
			uint32_t arg5 = 0;
			if (PPP_CHECK_CB(on_mmap2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_mmap2_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 4211 long sys_truncate64 ['const char __user *path', 'loff_t length']
		case 4211: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_truncate64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_truncate64_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4212 long sys_ftruncate64 ['unsigned int fd', 'loff_t length']
		case 4212: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ftruncate64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ftruncate64_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4213 long sys_stat64 ['const char __user *filename', 'struct stat64 __user *statbuf']
		case 4213: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_stat64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_stat64_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4214 long sys_lstat64 ['const char __user *filename', 'struct stat64 __user *statbuf']
		case 4214: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lstat64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lstat64_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4215 long sys_fstat64 ['unsigned long fd', 'struct stat64 __user *statbuf']
		case 4215: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fstat64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fstat64_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4216 long sys_pivot_root ['const char __user *new_root', 'const char __user *put_old']
		case 4216: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pivot_root_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pivot_root_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4217 long sys_mincore ['unsigned long start', 'size_t len', 'unsigned char __user *vec']
		case 4217: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mincore_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mincore_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4218 long sys_madvise ['unsigned long start', 'size_t len', 'int behavior']
		case 4218: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_madvise_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_madvise_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4219 long sys_getdents64 ['unsigned int fd', 'struct linux_dirent64 __user *dirent', 'unsigned int count']
		case 4219: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getdents64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getdents64_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4220 long sys_fcntl64 ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
		case 4220: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fcntl64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fcntl64_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4222 long sys_gettid ['void']
		case 4222: {
			if (PPP_CHECK_CB(on_sys_gettid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_gettid_return, cpu, pc) ;
		}; break;
		// 4223 long sys_readahead ['int fd', 'loff_t offset', 'size_t count']
		case 4223: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_readahead_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_readahead_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4224 long sys_setxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 4224: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_setxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setxattr_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4225 long sys_lsetxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 4225: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_lsetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_lsetxattr_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4226 long sys_fsetxattr ['int fd', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 4226: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_fsetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fsetxattr_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4227 long sys_getxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
		case 4227: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_getxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getxattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4228 long sys_lgetxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
		case 4228: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_lgetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lgetxattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4229 long sys_fgetxattr ['int fd', 'const char __user *name', 'void __user *value', 'size_t size']
		case 4229: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_fgetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fgetxattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4230 long sys_listxattr ['const char __user *path', 'char __user *list', 'size_t size']
		case 4230: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_listxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_listxattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4231 long sys_llistxattr ['const char __user *path', 'char __user *list', 'size_t size']
		case 4231: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_llistxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_llistxattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4232 long sys_flistxattr ['int fd', 'char __user *list', 'size_t size']
		case 4232: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_flistxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_flistxattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4233 long sys_removexattr ['const char __user *path', 'const char __user *name']
		case 4233: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_removexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_removexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4234 long sys_lremovexattr ['const char __user *path', 'const char __user *name']
		case 4234: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lremovexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lremovexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4235 long sys_fremovexattr ['int fd', 'const char __user *name']
		case 4235: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fremovexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fremovexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4236 long sys_tkill ['pid_t pid', 'int sig']
		case 4236: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_tkill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_tkill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4237 long sys_sendfile64 ['int out_fd', 'int in_fd', 'loff_t __user *offset', 'size_t count']
		case 4237: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_sendfile64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendfile64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4238 long sys_futex_time32 ['u32 __user *uaddr', 'int op', 'u32 val', 'struct old_timespec32 __user *utime', 'u32 __user *uaddr2', 'u32 val3']
		case 4238: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4239 long sys_sched_setaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
		case 4239: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sched_setaffinity_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_setaffinity_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4240 long sys_sched_getaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
		case 4240: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sched_getaffinity_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_getaffinity_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4241 long sys_io_setup ['unsigned nr_reqs', 'aio_context_t __user *ctx']
		case 4241: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_io_setup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_setup_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4242 long sys_io_destroy ['aio_context_t ctx']
		case 4242: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_io_destroy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_destroy_return, cpu, pc, arg0) ;
		}; break;
		// 4243 long sys_io_getevents_time32 ['__u32 ctx_id', '__s32 min_nr', '__s32 nr', 'struct io_event __user *events', 'struct old_timespec32 __user *timeout']
		case 4243: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_io_getevents_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_getevents_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4244 long sys_io_submit ['aio_context_t', 'long', 'struct iocb __user * __user *']
		case 4244: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_io_submit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_submit_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4245 long sys_io_cancel ['aio_context_t ctx_id', 'struct iocb __user *iocb', 'struct io_event __user *result']
		case 4245: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_io_cancel_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_cancel_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4246 long sys_exit_group ['int error_code']
		case 4246: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_exit_group_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_exit_group_return, cpu, pc, arg0) ;
		}; break;
		// 4247 long sys_lookup_dcookie ['u64 cookie64', 'char __user *buf', 'size_t len']
		case 4247: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_lookup_dcookie_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lookup_dcookie_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4248 long sys_epoll_create ['int size']
		case 4248: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_epoll_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_epoll_create_return, cpu, pc, arg0) ;
		}; break;
		// 4249 long sys_epoll_ctl ['int epfd', 'int op', 'int fd', 'struct epoll_event __user *event']
		case 4249: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_epoll_ctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_epoll_ctl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4250 long sys_epoll_wait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout']
		case 4250: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_epoll_wait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_epoll_wait_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4251 long sys_remap_file_pages ['unsigned long start', 'unsigned long size', 'unsigned long prot', 'unsigned long pgoff', 'unsigned long flags']
		case 4251: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_remap_file_pages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_remap_file_pages_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4252 long sys_set_tid_address ['int __user *tidptr']
		case 4252: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_set_tid_address_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_set_tid_address_return, cpu, pc, arg0) ;
		}; break;
		// 4253 long sys_restart_syscall ['void']
		case 4253: {
			if (PPP_CHECK_CB(on_sys_restart_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_restart_syscall_return, cpu, pc) ;
		}; break;
		// 4254 long sys_fadvise64_64 ['int fd', 'loff_t offset', 'loff_t len', 'int advice']
		case 4254: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_fadvise64_64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fadvise64_64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4255 long sys_statfs64 ['const char __user *path', 'size_t sz', 'struct statfs64 __user *buf']
		case 4255: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_statfs64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_statfs64_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4256 long sys_fstatfs64 ['unsigned int fd', 'size_t sz', 'struct statfs64 __user *buf']
		case 4256: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fstatfs64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fstatfs64_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4257 long sys_timer_create ['clockid_t which_clock', 'struct sigevent __user *timer_event_spec', 'timer_t __user *created_timer_id']
		case 4257: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_timer_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_create_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4258 long sys_timer_settime32 ['timer_t timer_id', 'int flags', 'struct old_itimerspec32 __user *new', 'struct old_itimerspec32 __user *old']
		case 4258: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_timer_settime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_settime32_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4259 long sys_timer_gettime32 ['timer_t timer_id', 'struct old_itimerspec32 __user *setting']
		case 4259: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_timer_gettime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_gettime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4260 long sys_timer_getoverrun ['timer_t timer_id']
		case 4260: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_timer_getoverrun_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_getoverrun_return, cpu, pc, arg0) ;
		}; break;
		// 4261 long sys_timer_delete ['timer_t timer_id']
		case 4261: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_timer_delete_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_delete_return, cpu, pc, arg0) ;
		}; break;
		// 4262 long sys_clock_settime32 ['clockid_t which_clock', 'struct old_timespec32 __user *tp']
		case 4262: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_settime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_settime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4263 long sys_clock_gettime32 ['clockid_t which_clock', 'struct old_timespec32 __user *tp']
		case 4263: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_gettime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_gettime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4264 long sys_clock_getres_time32 ['clockid_t which_clock', 'struct old_timespec32 __user *tp']
		case 4264: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_getres_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_getres_time32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4265 long sys_clock_nanosleep_time32 ['clockid_t which_clock', 'int flags', 'struct old_timespec32 __user *rqtp', 'struct old_timespec32 __user *rmtp']
		case 4265: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_clock_nanosleep_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_nanosleep_time32_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4266 long sys_tgkill ['pid_t tgid', 'pid_t pid', 'int sig']
		case 4266: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_tgkill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_tgkill_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4267 long sys_utimes_time32 ['const char __user *filename', 'struct old_timeval32 __user *t']
		case 4267: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_utimes_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_utimes_time32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4268 long sys_mbind ['unsigned long start', 'unsigned long len', 'unsigned long mode', 'const unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned flags']
		case 4268: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4269 long sys_get_mempolicy ['int __user *policy', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned long addr', 'unsigned long flags']
		case 4269: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_get_mempolicy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_get_mempolicy_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4270 long sys_set_mempolicy ['int mode', 'const unsigned long __user *nmask', 'unsigned long maxnode']
		case 4270: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_set_mempolicy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_set_mempolicy_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4271 long sys_mq_open ['const char __user *name', 'int oflag', 'umode_t mode', 'struct mq_attr __user *attr']
		case 4271: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_mq_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_open_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4272 long sys_mq_unlink ['const char __user *name']
		case 4272: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_mq_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 4273 long sys_mq_timedsend_time32 ['mqd_t mqdes', 'const char __user *u_msg_ptr', 'unsigned int msg_len', 'unsigned int msg_prio', 'const struct old_timespec32 __user *u_abs_timeout']
		case 4273: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_mq_timedsend_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_timedsend_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4274 long sys_mq_timedreceive_time32 ['mqd_t mqdes', 'char __user *u_msg_ptr', 'unsigned int msg_len', 'unsigned int __user *u_msg_prio', 'const struct old_timespec32 __user *u_abs_timeout']
		case 4274: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_mq_timedreceive_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_timedreceive_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4275 long sys_mq_notify ['mqd_t mqdes', 'const struct sigevent __user *notification']
		case 4275: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_mq_notify_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_notify_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4276 long sys_mq_getsetattr ['mqd_t mqdes', 'const struct mq_attr __user *mqstat', 'struct mq_attr __user *omqstat']
		case 4276: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mq_getsetattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_getsetattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4278 long sys_waitid ['int which', 'pid_t pid', 'struct siginfo __user *infop', 'int options', 'struct rusage __user *ru']
		case 4278: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_waitid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_waitid_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4280 long sys_add_key ['const char __user *_type', 'const char __user *_description', 'const void __user *_payload', 'size_t plen', 'key_serial_t destringid']
		case 4280: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_add_key_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_add_key_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4281 long sys_request_key ['const char __user *_type', 'const char __user *_description', 'const char __user *_callout_info', 'key_serial_t destringid']
		case 4281: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_request_key_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_request_key_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4282 long sys_keyctl ['int cmd', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
		case 4282: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_keyctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_keyctl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4283 long set_thread_area ['unsigned long tp']
		case 4283: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_set_thread_area_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_set_thread_area_return, cpu, pc, arg0) ;
		}; break;
		// 4284 long sys_inotify_init ['void']
		case 4284: {
			if (PPP_CHECK_CB(on_sys_inotify_init_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_inotify_init_return, cpu, pc) ;
		}; break;
		// 4285 long sys_inotify_add_watch ['int fd', 'const char __user *path', 'u32 mask']
		case 4285: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_inotify_add_watch_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_inotify_add_watch_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4286 long sys_inotify_rm_watch ['int fd', '__s32 wd']
		case 4286: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_inotify_rm_watch_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_inotify_rm_watch_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4287 long sys_migrate_pages ['pid_t pid', 'unsigned long maxnode', 'const unsigned long __user *from', 'const unsigned long __user *to']
		case 4287: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_migrate_pages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_migrate_pages_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4288 long sys_openat ['int dfd', 'const char __user *filename', 'int flags', 'umode_t mode']
		case 4288: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_openat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_openat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4289 long sys_mkdirat ['int dfd', 'const char __user *pathname', 'umode_t mode']
		case 4289: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mkdirat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkdirat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4290 long sys_mknodat ['int dfd', 'const char __user *filename', 'umode_t mode', 'unsigned dev']
		case 4290: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_mknodat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mknodat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4291 long sys_fchownat ['int dfd', 'const char __user *filename', 'uid_t user', 'gid_t group', 'int flag']
		case 4291: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_fchownat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fchownat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4292 long sys_futimesat_time32 ['unsigned int dfd', 'const char __user *filename', 'struct old_timeval32 __user *t']
		case 4292: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_futimesat_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_futimesat_time32_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4293 long sys_fstatat64 ['int dfd', 'const char __user *filename', 'struct stat64 __user *statbuf', 'int flag']
		case 4293: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_fstatat64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fstatat64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4294 long sys_unlinkat ['int dfd', 'const char __user *pathname', 'int flag']
		case 4294: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_unlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_unlinkat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4295 long sys_renameat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname']
		case 4295: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_renameat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_renameat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4296 long sys_linkat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'int flags']
		case 4296: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_linkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_linkat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4297 long sys_symlinkat ['const char __user *oldname', 'int newdfd', 'const char __user *newname']
		case 4297: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_symlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_symlinkat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4298 long sys_readlinkat ['int dfd', 'const char __user *path', 'char __user *buf', 'int bufsiz']
		case 4298: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_readlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_readlinkat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4299 long sys_fchmodat ['int dfd', 'const char __user *filename', 'umode_t mode']
		case 4299: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fchmodat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchmodat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4300 long sys_faccessat ['int dfd', 'const char __user *filename', 'int mode']
		case 4300: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_faccessat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_faccessat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4301 long sys_pselect6_time32 ['int', 'fd_set __user *', 'fd_set __user *', 'fd_set __user *', 'struct old_timespec32 __user *', 'void __user *']
		case 4301: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4302 long sys_ppoll_time32 ['struct pollfd __user *', 'unsigned int', 'struct old_timespec32 __user *', 'const sigset_t __user *', 'size_t']
		case 4302: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_ppoll_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ppoll_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4303 long sys_unshare ['unsigned long unshare_flags']
		case 4303: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_unshare_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_unshare_return, cpu, pc, arg0) ;
		}; break;
		// 4304 long sys_splice ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
		case 4304: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4305 long sys_sync_file_range ['int fd', 'loff_t offset', 'loff_t nbytes', 'unsigned int flags']
		case 4305: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_sync_file_range_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sync_file_range_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4306 long sys_tee ['int fdin', 'int fdout', 'size_t len', 'unsigned int flags']
		case 4306: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_tee_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_tee_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4307 long sys_vmsplice ['int fd', 'const struct iovec __user *iov', 'unsigned long nr_segs', 'unsigned int flags']
		case 4307: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_vmsplice_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_vmsplice_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4308 long sys_move_pages ['pid_t pid', 'unsigned long nr_pages', 'const void __user * __user *pages', 'const int __user *nodes', 'int __user *status', 'int flags']
		case 4308: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			int32_t arg5 = 0;
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
		// 4309 long sys_set_robust_list ['struct robust_list_head __user *head', 'size_t len']
		case 4309: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_set_robust_list_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_set_robust_list_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4310 long sys_get_robust_list ['int pid', 'struct robust_list_head __user * __user *head_ptr', 'size_t __user *len_ptr']
		case 4310: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_get_robust_list_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_get_robust_list_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4311 long sys_kexec_load ['unsigned long entry', 'unsigned long nr_segments', 'struct kexec_segment __user *segments', 'unsigned long flags']
		case 4311: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_kexec_load_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_kexec_load_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4312 long sys_getcpu ['unsigned __user *cpu', 'unsigned __user *node', 'struct getcpu_cache __user *cache']
		case 4312: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getcpu_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getcpu_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4313 long sys_epoll_pwait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout', 'const sigset_t __user *sigmask', 'size_t sigsetsize']
		case 4313: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4314 long sys_ioprio_set ['int which', 'int who', 'int ioprio']
		case 4314: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_ioprio_set_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ioprio_set_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4315 long sys_ioprio_get ['int which', 'int who']
		case 4315: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ioprio_get_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ioprio_get_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4316 long sys_utimensat_time32 ['unsigned int dfd', 'const char __user *filename', 'struct old_timespec32 __user *t', 'int flags']
		case 4316: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_utimensat_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_utimensat_time32_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4317 long sys_signalfd ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask']
		case 4317: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_signalfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_signalfd_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4318 long sys_ni_syscall ['void']
		case 4318: {
			if (PPP_CHECK_CB(on_sys_ni_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_ni_syscall_return, cpu, pc) ;
		}; break;
		// 4319 long sys_eventfd ['unsigned int count']
		case 4319: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_eventfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_eventfd_return, cpu, pc, arg0) ;
		}; break;
		// 4320 long sys_fallocate ['int fd', 'int mode', 'loff_t offset', 'loff_t len']
		case 4320: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_fallocate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fallocate_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4321 long sys_timerfd_create ['int clockid', 'int flags']
		case 4321: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_timerfd_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_create_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4322 long sys_timerfd_gettime32 ['int ufd', 'struct old_itimerspec32 __user *otmr']
		case 4322: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_timerfd_gettime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_gettime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4323 long sys_timerfd_settime32 ['int ufd', 'int flags', 'const struct old_itimerspec32 __user *utmr', 'struct old_itimerspec32 __user *otmr']
		case 4323: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_timerfd_settime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_settime32_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4324 long sys_signalfd4 ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask', 'int flags']
		case 4324: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_signalfd4_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_signalfd4_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4325 long sys_eventfd2 ['unsigned int count', 'int flags']
		case 4325: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_eventfd2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_eventfd2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4326 long sys_epoll_create1 ['int flags']
		case 4326: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_epoll_create1_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_epoll_create1_return, cpu, pc, arg0) ;
		}; break;
		// 4327 long sys_dup3 ['unsigned int oldfd', 'unsigned int newfd', 'int flags']
		case 4327: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_dup3_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_dup3_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4328 long sys_pipe2 ['int __user *fildes', 'int flags']
		case 4328: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pipe2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pipe2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4329 long sys_inotify_init1 ['int flags']
		case 4329: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_inotify_init1_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_inotify_init1_return, cpu, pc, arg0) ;
		}; break;
		// 4330 long sys_preadv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
		case 4330: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_preadv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_preadv_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4331 long sys_pwritev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
		case 4331: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_pwritev_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pwritev_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4332 long sys_rt_tgsigqueueinfo ['pid_t tgid', 'pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
		case 4332: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rt_tgsigqueueinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_tgsigqueueinfo_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4333 long sys_perf_event_open ['struct perf_event_attr __user *attr_uptr', 'pid_t pid', 'int cpu', 'int group_fd', 'unsigned long flags']
		case 4333: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_perf_event_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_perf_event_open_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4334 long sys_accept4 ['int', 'struct sockaddr __user *', 'int __user *', 'int']
		case 4334: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_accept4_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_accept4_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4335 long sys_recvmmsg_time32 ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags', 'struct old_timespec32 __user *timeout']
		case 4335: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_recvmmsg_time32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recvmmsg_time32_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4336 long sys_fanotify_init ['unsigned int flags', 'unsigned int event_f_flags']
		case 4336: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fanotify_init_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fanotify_init_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4337 long sys_fanotify_mark ['int fanotify_fd', 'unsigned int flags', 'u64 mask', 'int fd', 'const char __user *pathname']
		case 4337: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_fanotify_mark_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fanotify_mark_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4338 long sys_prlimit64 ['pid_t pid', 'unsigned int resource', 'const struct rlimit64 __user *new_rlim', 'struct rlimit64 __user *old_rlim']
		case 4338: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_prlimit64_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_prlimit64_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4339 long sys_name_to_handle_at ['int dfd', 'const char __user *name', 'struct file_handle __user *handle', 'int __user *mnt_id', 'int flag']
		case 4339: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_name_to_handle_at_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_name_to_handle_at_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4340 long sys_open_by_handle_at ['int mountdirfd', 'struct file_handle __user *handle', 'int flags']
		case 4340: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_open_by_handle_at_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_open_by_handle_at_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4341 long sys_clock_adjtime32 ['clockid_t which_clock', 'struct old_timex32 __user *tx']
		case 4341: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_adjtime32_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_adjtime32_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4342 long sys_syncfs ['int fd']
		case 4342: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_syncfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_syncfs_return, cpu, pc, arg0) ;
		}; break;
		// 4343 long sys_sendmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags']
		case 4343: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_sendmmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendmmsg_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4344 long sys_setns ['int fd', 'int nstype']
		case 4344: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setns_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setns_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4345 long sys_process_vm_readv ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
		case 4345: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4346 long sys_process_vm_writev ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
		case 4346: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4347 long sys_kcmp ['pid_t pid1', 'pid_t pid2', 'int type', 'unsigned long idx1', 'unsigned long idx2']
		case 4347: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_kcmp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_kcmp_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4348 long sys_finit_module ['int fd', 'const char __user *uargs', 'int flags']
		case 4348: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_finit_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_finit_module_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4349 long sys_sched_setattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int flags']
		case 4349: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sched_setattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_setattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4350 long sys_sched_getattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int size', 'unsigned int flags']
		case 4350: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_sched_getattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_getattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4351 long sys_renameat2 ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'unsigned int flags']
		case 4351: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_renameat2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_renameat2_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4352 long sys_seccomp ['unsigned int op', 'unsigned int flags', 'void __user *uargs']
		case 4352: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_seccomp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_seccomp_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4353 long sys_getrandom ['char __user *buf', 'size_t count', 'unsigned int flags']
		case 4353: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getrandom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getrandom_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4354 long sys_memfd_create ['const char __user *uname_ptr', 'unsigned int flags']
		case 4354: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_memfd_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_memfd_create_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4355 long sys_bpf ['int cmd', 'union bpf_attr *attr', 'unsigned int size']
		case 4355: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_bpf_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_bpf_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4356 long sys_execveat ['int dfd', 'const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp', 'int flags']
		case 4356: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_execveat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_execveat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4357 long sys_userfaultfd ['int flags']
		case 4357: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_userfaultfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_userfaultfd_return, cpu, pc, arg0) ;
		}; break;
		// 4358 long sys_membarrier ['int cmd', 'int flags']
		case 4358: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_membarrier_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_membarrier_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4359 long sys_mlock2 ['unsigned long start', 'size_t len', 'int flags']
		case 4359: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mlock2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_mlock2_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4360 long sys_copy_file_range ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
		case 4360: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4361 long sys_preadv2 ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h', 'rwf_t flags']
		case 4361: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4362 long sys_pwritev2 ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h', 'rwf_t flags']
		case 4362: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4363 long sys_pkey_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot', 'int pkey']
		case 4363: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_pkey_mprotect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pkey_mprotect_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4364 long sys_pkey_alloc ['unsigned long flags', 'unsigned long init_val']
		case 4364: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pkey_alloc_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pkey_alloc_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4365 long sys_pkey_free ['int pkey']
		case 4365: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_pkey_free_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pkey_free_return, cpu, pc, arg0) ;
		}; break;
		// 4366 long sys_statx ['int dfd', 'const char __user *path', 'unsigned flags', 'unsigned mask', 'struct statx __user *buffer']
		case 4366: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_statx_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_statx_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4367 long sys_rseq ['struct rseq __user *rseq', 'uint32_t rseq_len', 'int flags', 'uint32_t sig']
		case 4367: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rseq_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_rseq_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4368 long sys_io_pgetevents_time32 ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct old_timespec32 __user *timeout', 'const struct __aio_sigset *sig']
		case 4368: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4393 long sys_semget ['key_t key', 'int nsems', 'int semflg']
		case 4393: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_semget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_semget_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4394 long sys_semctl ['int semid', 'int semnum', 'int cmd', 'unsigned long arg']
		case 4394: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_semctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_semctl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4395 long sys_shmget ['key_t key', 'size_t size', 'int flag']
		case 4395: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_shmget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shmget_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4396 long sys_shmctl ['int shmid', 'int cmd', 'struct shmid_ds __user *buf']
		case 4396: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_shmctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_shmctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4397 long sys_shmat ['int shmid', 'char __user *shmaddr', 'int shmflg']
		case 4397: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_shmat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shmat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4398 long sys_shmdt ['char __user *shmaddr']
		case 4398: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_shmdt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_shmdt_return, cpu, pc, arg0) ;
		}; break;
		// 4399 long sys_msgget ['key_t key', 'int msgflg']
		case 4399: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_msgget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgget_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4400 long sys_msgsnd ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'int msgflg']
		case 4400: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_msgsnd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgsnd_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4401 long sys_msgrcv ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'long msgtyp', 'int msgflg']
		case 4401: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_msgrcv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgrcv_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4402 long sys_msgctl ['int msqid', 'int cmd', 'struct msqid_ds __user *buf']
		case 4402: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_msgctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_msgctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4403 long sys_clock_gettime ['clockid_t which_clock', 'struct __kernel_timespec __user *tp']
		case 4403: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4404 long sys_clock_settime ['clockid_t which_clock', 'const struct __kernel_timespec __user *tp']
		case 4404: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_settime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4405 long sys_clock_adjtime ['clockid_t which_clock', 'struct __kernel_timex __user *tx']
		case 4405: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_adjtime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_adjtime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4406 long sys_clock_getres ['clockid_t which_clock', 'struct __kernel_timespec __user *tp']
		case 4406: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_getres_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_getres_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4407 long sys_clock_nanosleep ['clockid_t which_clock', 'int flags', 'const struct __kernel_timespec __user *rqtp', 'struct __kernel_timespec __user *rmtp']
		case 4407: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_clock_nanosleep_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_nanosleep_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4408 long sys_timer_gettime ['timer_t timer_id', 'struct __kernel_itimerspec __user *setting']
		case 4408: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_timer_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4409 long sys_timer_settime ['timer_t timer_id', 'int flags', 'const struct __kernel_itimerspec __user *new_setting', 'struct __kernel_itimerspec __user *old_setting']
		case 4409: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_timer_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_settime_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4410 long sys_timerfd_gettime ['int ufd', 'struct __kernel_itimerspec __user *otmr']
		case 4410: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_timerfd_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4411 long sys_timerfd_settime ['int ufd', 'int flags', 'const struct __kernel_itimerspec __user *utmr', 'struct __kernel_itimerspec __user *otmr']
		case 4411: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_timerfd_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_settime_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4412 long sys_utimensat ['int dfd', 'const char __user *filename', 'struct __kernel_timespec __user *utimes', 'int flags']
		case 4412: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_utimensat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_utimensat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4413 long sys_pselect6 ['int', 'fd_set __user *', 'fd_set __user *', 'fd_set __user *', 'struct __kernel_timespec __user *', 'void __user *']
		case 4413: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4414 long sys_ppoll ['struct pollfd __user *', 'unsigned int', 'struct __kernel_timespec __user *', 'const sigset_t __user *', 'size_t']
		case 4414: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_ppoll_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ppoll_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4416 long sys_io_pgetevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct __kernel_timespec __user *timeout', 'const struct __aio_sigset *sig']
		case 4416: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4417 long sys_recvmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags', 'struct __kernel_timespec __user *timeout']
		case 4417: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_recvmmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recvmmsg_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4418 long sys_mq_timedsend ['mqd_t mqdes', 'const char __user *msg_ptr', 'size_t msg_len', 'unsigned int msg_prio', 'const struct __kernel_timespec __user *abs_timeout']
		case 4418: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_mq_timedsend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_timedsend_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4419 long sys_mq_timedreceive ['mqd_t mqdes', 'char __user *msg_ptr', 'size_t msg_len', 'unsigned int __user *msg_prio', 'const struct __kernel_timespec __user *abs_timeout']
		case 4419: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_mq_timedreceive_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_timedreceive_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4420 long sys_semtimedop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops', 'const struct __kernel_timespec __user *timeout']
		case 4420: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_semtimedop_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_semtimedop_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4421 long sys_rt_sigtimedwait ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct __kernel_timespec __user *uts', 'size_t sigsetsize']
		case 4421: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rt_sigtimedwait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigtimedwait_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4422 long sys_futex ['u32 __user *uaddr', 'int op', 'u32 val', 'struct __kernel_timespec __user *utime', 'u32 __user *uaddr2', 'u32 val3']
		case 4422: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4423 long sys_sched_rr_get_interval ['pid_t pid', 'struct __kernel_timespec __user *interval']
		case 4423: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sched_rr_get_interval_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_rr_get_interval_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4424 long sys_pidfd_send_signal ['int pidfd', 'int sig', 'siginfo_t __user *info', 'unsigned int flags']
		case 4424: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_pidfd_send_signal_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pidfd_send_signal_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4425 long sys_io_uring_setup ['u32 entries', 'struct io_uring_params __user *p']
		case 4425: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_io_uring_setup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_uring_setup_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4426 long sys_io_uring_enter ['unsigned int fd', 'u32 to_submit', 'u32 min_complete', 'u32 flags', 'const sigset_t __user *sig', 'size_t sigsz']
		case 4426: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 4427 long sys_io_uring_register ['unsigned int fd', 'unsigned int op', 'void __user *arg', 'unsigned int nr_args']
		case 4427: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_io_uring_register_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_uring_register_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4428 long sys_open_tree ['int dfd', 'const char __user *path', 'unsigned flags']
		case 4428: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_open_tree_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_open_tree_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4429 long sys_move_mount ['int from_dfd', 'const char __user *from_path', 'int to_dfd', 'const char __user *to_path', 'unsigned int ms_flags']
		case 4429: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_move_mount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_move_mount_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4430 long sys_fsopen ['const char __user *fs_name', 'unsigned int flags']
		case 4430: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fsopen_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fsopen_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4431 long sys_fsconfig ['int fs_fd', 'unsigned int cmd', 'const char __user *key', 'const void __user *value', 'int aux']
		case 4431: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_fsconfig_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fsconfig_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 4432 long sys_fsmount ['int fs_fd', 'unsigned int flags', 'unsigned int ms_flags']
		case 4432: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fsmount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fsmount_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4433 long sys_fspick ['int dfd', 'const char __user *path', 'unsigned int flags']
		case 4433: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fspick_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fspick_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4434 long sys_pidfd_open ['pid_t pid', 'unsigned int flags']
		case 4434: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pidfd_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pidfd_open_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 4437 long sys_openat2 ['int dfd', 'const char __user *filename', 'struct open_how *how', 'size_t size']
		case 4437: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_openat2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_openat2_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 4438 long sys_pidfd_getfd ['int pidfd', 'int fd', 'unsigned int flags']
		case 4438: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_pidfd_getfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pidfd_getfd_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4439 long sys_faccessat2 ['int dfd', 'const char __user *filename', 'int mode', 'int flags']
		case 4439: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
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