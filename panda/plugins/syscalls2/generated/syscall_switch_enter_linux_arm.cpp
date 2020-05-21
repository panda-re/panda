#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls2_info.h"

extern const syscall_info_t *syscall_info;
extern const syscall_meta_t *syscall_meta;

extern "C" {
#include "syscalls_ext_typedefs.h"
#include "syscall_ppp_extern_enter.h"
#include "syscall_ppp_extern_return.h"
}

/**
 * @brief Called when a system call invocation is identified.
 * Invokes all registered callbacks that should run for the call.
 *
 * Additionally, stores the context of the system call (number, asid,
 * arguments, return address) to prepare for handling the respective
 * system call return callbacks.
 */
void syscall_enter_switch_linux_arm(CPUState *cpu, target_ptr_t pc) {
#if defined(TARGET_ARM)
	CPUArchState *env = (CPUArchState*)cpu->env_ptr;
	syscall_ctx_t ctx = {0};
	ctx.no = env->regs[7];
	ctx.asid = panda_current_asid(cpu);
	ctx.retaddr = calc_retaddr(cpu, pc);
	bool panda_noreturn;	// true if PANDA should not track the return of this system call
	const syscall_info_t *call = (syscall_meta == NULL || ctx.no > syscall_meta->max_generic) ? NULL : &syscall_info[ctx.no];

	switch (ctx.no) {
	// 0 long sys_restart_syscall ['void']
	case 0: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_restart_syscall_enter, cpu, pc);
	}; break;
	// 1 long sys_exit ['int error_code']
	case 1: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_exit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_exit_enter, cpu, pc, arg0);
	}; break;
	// 2 long sys_fork ['void']
	case 2: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_fork_enter, cpu, pc);
	}; break;
	// 3 long sys_read ['unsigned int fd', 'char __user *buf', 'size_t count']
	case 3: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_read_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_read_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 4 long sys_write ['unsigned int fd', 'const char __user *buf', 'size_t count']
	case 4: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_write_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_write_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5 long sys_open ['const char __user *filename', 'int flags', 'umode_t mode']
	case 5: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_open_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 6 long sys_close ['unsigned int fd']
	case 6: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_close_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_close_enter, cpu, pc, arg0);
	}; break;
	// 8 long sys_creat ['const char __user *pathname', 'umode_t mode']
	case 8: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_creat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_creat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 9 long sys_link ['const char __user *oldname', 'const char __user *newname']
	case 9: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_link_enter, cpu, pc, arg0, arg1);
	}; break;
	// 10 long sys_unlink ['const char __user *pathname']
	case 10: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_unlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_unlink_enter, cpu, pc, arg0);
	}; break;
	// 11 long sys_execve ['const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp']
	case 11: {
		panda_noreturn = true;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_execve_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_execve_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 12 long sys_chdir ['const char __user *filename']
	case 12: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chdir_enter, cpu, pc, arg0);
	}; break;
	// 13 long sys_time ['time_t __user *tloc']
	case 13: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_time_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_time_enter, cpu, pc, arg0);
	}; break;
	// 14 long sys_mknod ['const char __user *filename', 'umode_t mode', 'unsigned dev']
	case 14: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mknod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mknod_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 15 long sys_chmod ['const char __user *filename', 'umode_t mode']
	case 15: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chmod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chmod_enter, cpu, pc, arg0, arg1);
	}; break;
	// 16 long sys_lchown16 ['const char __user *filename', 'old_uid_t user', 'old_gid_t group']
	case 16: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lchown16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lchown16_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 19 long sys_lseek ['unsigned int fd', 'off_t offset', 'unsigned int whence']
	case 19: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lseek_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lseek_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 20 long sys_getpid ['void']
	case 20: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_getpid_enter, cpu, pc);
	}; break;
	// 21 long sys_mount ['char __user *dev_name', 'char __user *dir_name', 'char __user *type', 'unsigned long flags', 'void __user *data']
	case 21: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mount_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 23 long sys_setuid16 ['old_uid_t uid']
	case 23: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setuid16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setuid16_enter, cpu, pc, arg0);
	}; break;
	// 24 long sys_getuid16 ['void']
	case 24: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_getuid16_enter, cpu, pc);
	}; break;
	// 25 long sys_stime ['time_t __user *tptr']
	case 25: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_stime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_stime_enter, cpu, pc, arg0);
	}; break;
	// 26 long sys_ptrace ['long request', 'long pid', 'unsigned long addr', 'unsigned long data']
	case 26: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ptrace_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ptrace_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 27 long sys_alarm ['unsigned int seconds']
	case 27: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_alarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_alarm_enter, cpu, pc, arg0);
	}; break;
	// 29 long sys_pause ['void']
	case 29: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_pause_enter, cpu, pc);
	}; break;
	// 30 long sys_utime ['char __user *filename', 'struct utimbuf __user *times']
	case 30: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_utime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 33 long sys_access ['const char __user *filename', 'int mode']
	case 33: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_access_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_access_enter, cpu, pc, arg0, arg1);
	}; break;
	// 34 long sys_nice ['int increment']
	case 34: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nice_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_nice_enter, cpu, pc, arg0);
	}; break;
	// 36 long sys_sync ['void']
	case 36: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_sync_enter, cpu, pc);
	}; break;
	// 37 long sys_kill ['int pid', 'int sig']
	case 37: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kill_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_kill_enter, cpu, pc, arg0, arg1);
	}; break;
	// 38 long sys_rename ['const char __user *oldname', 'const char __user *newname']
	case 38: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rename_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rename_enter, cpu, pc, arg0, arg1);
	}; break;
	// 39 long sys_mkdir ['const char __user *pathname', 'umode_t mode']
	case 39: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mkdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mkdir_enter, cpu, pc, arg0, arg1);
	}; break;
	// 40 long sys_rmdir ['const char __user *pathname']
	case 40: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rmdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rmdir_enter, cpu, pc, arg0);
	}; break;
	// 41 long sys_dup ['unsigned int fildes']
	case 41: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_dup_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_dup_enter, cpu, pc, arg0);
	}; break;
	// 42 long sys_pipe ['int __user *fildes']
	case 42: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pipe_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pipe_enter, cpu, pc, arg0);
	}; break;
	// 43 long sys_times ['struct tms __user *tbuf']
	case 43: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_times_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_times_enter, cpu, pc, arg0);
	}; break;
	// 45 long sys_brk ['unsigned long brk']
	case 45: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_brk_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_brk_enter, cpu, pc, arg0);
	}; break;
	// 46 long sys_setgid16 ['old_gid_t gid']
	case 46: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setgid16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setgid16_enter, cpu, pc, arg0);
	}; break;
	// 47 long sys_getgid16 ['void']
	case 47: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_getgid16_enter, cpu, pc);
	}; break;
	// 49 long sys_geteuid16 ['void']
	case 49: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_geteuid16_enter, cpu, pc);
	}; break;
	// 50 long sys_getegid16 ['void']
	case 50: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_getegid16_enter, cpu, pc);
	}; break;
	// 51 long sys_acct ['const char __user *name']
	case 51: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_acct_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_acct_enter, cpu, pc, arg0);
	}; break;
	// 52 long sys_umount ['char __user *name', 'int flags']
	case 52: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_umount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_umount_enter, cpu, pc, arg0, arg1);
	}; break;
	// 54 long sys_ioctl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
	case 54: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ioctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ioctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 55 long sys_fcntl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
	case 55: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fcntl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fcntl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 57 long sys_setpgid ['pid_t pid', 'pid_t pgid']
	case 57: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setpgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setpgid_enter, cpu, pc, arg0, arg1);
	}; break;
	// 60 long sys_umask ['int mask']
	case 60: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_umask_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_umask_enter, cpu, pc, arg0);
	}; break;
	// 61 long sys_chroot ['const char __user *filename']
	case 61: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chroot_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chroot_enter, cpu, pc, arg0);
	}; break;
	// 62 long sys_ustat ['unsigned dev', 'struct ustat __user *ubuf']
	case 62: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ustat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ustat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 63 long sys_dup2 ['unsigned int oldfd', 'unsigned int newfd']
	case 63: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_dup2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_dup2_enter, cpu, pc, arg0, arg1);
	}; break;
	// 64 long sys_getppid ['void']
	case 64: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_getppid_enter, cpu, pc);
	}; break;
	// 65 long sys_getpgrp ['void']
	case 65: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_getpgrp_enter, cpu, pc);
	}; break;
	// 66 long sys_setsid ['void']
	case 66: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_setsid_enter, cpu, pc);
	}; break;
	// 67 long sys_sigaction ['int', 'const struct old_sigaction __user *', 'struct old_sigaction __user *']
	case 67: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sigaction_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 70 long sys_setreuid16 ['old_uid_t ruid', 'old_uid_t euid']
	case 70: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setreuid16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setreuid16_enter, cpu, pc, arg0, arg1);
	}; break;
	// 71 long sys_setregid16 ['old_gid_t rgid', 'old_gid_t egid']
	case 71: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setregid16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setregid16_enter, cpu, pc, arg0, arg1);
	}; break;
	// 72 long sys_sigsuspend ['int unused1', 'int unused2', 'old_sigset_t mask']
	case 72: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigsuspend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sigsuspend_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 73 long sys_sigpending ['old_sigset_t __user *set']
	case 73: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigpending_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sigpending_enter, cpu, pc, arg0);
	}; break;
	// 74 long sys_sethostname ['char __user *name', 'int len']
	case 74: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sethostname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sethostname_enter, cpu, pc, arg0, arg1);
	}; break;
	// 75 long sys_setrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
	case 75: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setrlimit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setrlimit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 77 long sys_getrusage ['int who', 'struct rusage __user *ru']
	case 77: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getrusage_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getrusage_enter, cpu, pc, arg0, arg1);
	}; break;
	// 78 long sys_gettimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
	case 78: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_gettimeofday_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_gettimeofday_enter, cpu, pc, arg0, arg1);
	}; break;
	// 79 long sys_settimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
	case 79: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_settimeofday_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_settimeofday_enter, cpu, pc, arg0, arg1);
	}; break;
	// 80 long sys_getgroups16 ['int gidsetsize', 'old_gid_t __user *grouplist']
	case 80: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getgroups16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getgroups16_enter, cpu, pc, arg0, arg1);
	}; break;
	// 81 long sys_setgroups16 ['int gidsetsize', 'old_gid_t __user *grouplist']
	case 81: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setgroups16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setgroups16_enter, cpu, pc, arg0, arg1);
	}; break;
	// 83 long sys_symlink ['const char __user *old', 'const char __user *new']
	case 83: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_symlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_symlink_enter, cpu, pc, arg0, arg1);
	}; break;
	// 85 long sys_readlink ['const char __user *path', 'char __user *buf', 'int bufsiz']
	case 85: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_readlink_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 86 long sys_uselib ['const char __user *library']
	case 86: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_uselib_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_uselib_enter, cpu, pc, arg0);
	}; break;
	// 87 long sys_swapon ['const char __user *specialfile', 'int swap_flags']
	case 87: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_swapon_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_swapon_enter, cpu, pc, arg0, arg1);
	}; break;
	// 88 long sys_reboot ['int magic1', 'int magic2', 'unsigned int cmd', 'void __user *arg']
	case 88: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_reboot_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_reboot_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 91 long sys_munmap ['unsigned long addr', 'size_t len']
	case 91: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_munmap_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_munmap_enter, cpu, pc, arg0, arg1);
	}; break;
	// 92 long sys_truncate ['const char __user *path', 'long length']
	case 92: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_truncate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_truncate_enter, cpu, pc, arg0, arg1);
	}; break;
	// 93 long sys_ftruncate ['unsigned int fd', 'unsigned long length']
	case 93: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ftruncate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ftruncate_enter, cpu, pc, arg0, arg1);
	}; break;
	// 94 long sys_fchmod ['unsigned int fd', 'umode_t mode']
	case 94: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchmod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchmod_enter, cpu, pc, arg0, arg1);
	}; break;
	// 95 long sys_fchown16 ['unsigned int fd', 'old_uid_t user', 'old_gid_t group']
	case 95: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchown16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchown16_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 96 long sys_getpriority ['int which', 'int who']
	case 96: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getpriority_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getpriority_enter, cpu, pc, arg0, arg1);
	}; break;
	// 97 long sys_setpriority ['int which', 'int who', 'int niceval']
	case 97: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setpriority_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setpriority_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 99 long sys_statfs ['const char __user *path', 'struct statfs __user *buf']
	case 99: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_statfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_statfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 100 long sys_fstatfs ['unsigned int fd', 'struct statfs __user *buf']
	case 100: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fstatfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 102 long sys_socketcall ['int call', 'unsigned long __user *args']
	case 102: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_socketcall_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_socketcall_enter, cpu, pc, arg0, arg1);
	}; break;
	// 103 long sys_syslog ['int type', 'char __user *buf', 'int len']
	case 103: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_syslog_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_syslog_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 104 long sys_setitimer ['int which', 'struct itimerval __user *value', 'struct itimerval __user *ovalue']
	case 104: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setitimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setitimer_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 105 long sys_getitimer ['int which', 'struct itimerval __user *value']
	case 105: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getitimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getitimer_enter, cpu, pc, arg0, arg1);
	}; break;
	// 106 long sys_newstat ['const char __user *filename', 'struct stat __user *statbuf']
	case 106: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_newstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 107 long sys_newlstat ['const char __user *filename', 'struct stat __user *statbuf']
	case 107: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newlstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_newlstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 108 long sys_newfstat ['unsigned int fd', 'struct stat __user *statbuf']
	case 108: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newfstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_newfstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 111 long sys_vhangup ['void']
	case 111: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_vhangup_enter, cpu, pc);
	}; break;
	// 114 long sys_wait4 ['pid_t pid', 'int __user *stat_addr', 'int options', 'struct rusage __user *ru']
	case 114: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_wait4_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_wait4_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 115 long sys_swapoff ['const char __user *specialfile']
	case 115: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_swapoff_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_swapoff_enter, cpu, pc, arg0);
	}; break;
	// 116 long sys_sysinfo ['struct sysinfo __user *info']
	case 116: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sysinfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sysinfo_enter, cpu, pc, arg0);
	}; break;
	// 117 long sys_ipc ['unsigned int call', 'int first', 'unsigned long second', 'unsigned long third', 'void __user *ptr', 'long fifth']
	case 117: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		int32_t arg5 = get_s32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ipc_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_ipc_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 118 long sys_fsync ['unsigned int fd']
	case 118: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fsync_enter, cpu, pc, arg0);
	}; break;
	// 119 int sys_sigreturn ['struct pt_regs *regs']
	case 119: {
		panda_noreturn = true;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigreturn_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sigreturn_enter, cpu, pc, arg0);
	}; break;
	// 120 long sys_clone ['unsigned long', 'unsigned long', 'int __user *', 'int __user *', 'unsigned long']
	case 120: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clone_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clone_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 121 long sys_setdomainname ['char __user *name', 'int len']
	case 121: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setdomainname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setdomainname_enter, cpu, pc, arg0, arg1);
	}; break;
	// 122 long sys_newuname ['struct new_utsname __user *name']
	case 122: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newuname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_newuname_enter, cpu, pc, arg0);
	}; break;
	// 124 long sys_adjtimex ['struct timex __user *txc_p']
	case 124: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_adjtimex_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_adjtimex_enter, cpu, pc, arg0);
	}; break;
	// 125 long sys_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot']
	case 125: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mprotect_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mprotect_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 126 long sys_sigprocmask ['int how', 'old_sigset_t __user *set', 'old_sigset_t __user *oset']
	case 126: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigprocmask_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sigprocmask_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 128 long sys_init_module ['void __user *umod', 'unsigned long len', 'const char __user *uargs']
	case 128: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_init_module_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_init_module_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 129 long sys_delete_module ['const char __user *name_user', 'unsigned int flags']
	case 129: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_delete_module_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_delete_module_enter, cpu, pc, arg0, arg1);
	}; break;
	// 131 long sys_quotactl ['unsigned int cmd', 'const char __user *special', 'qid_t id', 'void __user *addr']
	case 131: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_quotactl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_quotactl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 132 long sys_getpgid ['pid_t pid']
	case 132: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getpgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getpgid_enter, cpu, pc, arg0);
	}; break;
	// 133 long sys_fchdir ['unsigned int fd']
	case 133: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchdir_enter, cpu, pc, arg0);
	}; break;
	// 134 long sys_bdflush ['int func', 'long data']
	case 134: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_bdflush_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_bdflush_enter, cpu, pc, arg0, arg1);
	}; break;
	// 135 long sys_sysfs ['int option', 'unsigned long arg1', 'unsigned long arg2']
	case 135: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sysfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sysfs_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 136 long sys_personality ['unsigned int personality']
	case 136: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_personality_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_personality_enter, cpu, pc, arg0);
	}; break;
	// 138 long sys_setfsuid16 ['old_uid_t uid']
	case 138: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setfsuid16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setfsuid16_enter, cpu, pc, arg0);
	}; break;
	// 139 long sys_setfsgid16 ['old_gid_t gid']
	case 139: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setfsgid16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setfsgid16_enter, cpu, pc, arg0);
	}; break;
	// 140 long sys_llseek ['unsigned int fd', 'unsigned long offset_high', 'unsigned long offset_low', 'loff_t __user *result', 'unsigned int whence']
	case 140: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_llseek_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_llseek_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 141 long sys_getdents ['unsigned int fd', 'struct linux_dirent __user *dirent', 'unsigned int count']
	case 141: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdents_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getdents_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 142 long sys_select ['int n', 'fd_set __user *inp', 'fd_set __user *outp', 'fd_set __user *exp', 'struct timeval __user *tvp']
	case 142: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_select_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_select_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 143 long sys_flock ['unsigned int fd', 'unsigned int cmd']
	case 143: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_flock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_flock_enter, cpu, pc, arg0, arg1);
	}; break;
	// 144 long sys_msync ['unsigned long start', 'size_t len', 'int flags']
	case 144: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_msync_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 145 long sys_readv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
	case 145: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_readv_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 146 long sys_writev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
	case 146: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_writev_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_writev_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 147 long sys_getsid ['pid_t pid']
	case 147: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getsid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getsid_enter, cpu, pc, arg0);
	}; break;
	// 148 long sys_fdatasync ['unsigned int fd']
	case 148: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fdatasync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fdatasync_enter, cpu, pc, arg0);
	}; break;
	// 149 long sys_sysctl ['struct __sysctl_args __user *args']
	case 149: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sysctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sysctl_enter, cpu, pc, arg0);
	}; break;
	// 150 long sys_mlock ['unsigned long start', 'size_t len']
	case 150: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mlock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mlock_enter, cpu, pc, arg0, arg1);
	}; break;
	// 151 long sys_munlock ['unsigned long start', 'size_t len']
	case 151: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_munlock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_munlock_enter, cpu, pc, arg0, arg1);
	}; break;
	// 152 long sys_mlockall ['int flags']
	case 152: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mlockall_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_mlockall_enter, cpu, pc, arg0);
	}; break;
	// 153 long sys_munlockall ['void']
	case 153: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_munlockall_enter, cpu, pc);
	}; break;
	// 154 long sys_sched_setparam ['pid_t pid', 'struct sched_param __user *param']
	case 154: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setparam_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_setparam_enter, cpu, pc, arg0, arg1);
	}; break;
	// 155 long sys_sched_getparam ['pid_t pid', 'struct sched_param __user *param']
	case 155: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getparam_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_getparam_enter, cpu, pc, arg0, arg1);
	}; break;
	// 156 long sys_sched_setscheduler ['pid_t pid', 'int policy', 'struct sched_param __user *param']
	case 156: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setscheduler_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_setscheduler_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 157 long sys_sched_getscheduler ['pid_t pid']
	case 157: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getscheduler_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sched_getscheduler_enter, cpu, pc, arg0);
	}; break;
	// 158 long sys_sched_yield ['void']
	case 158: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_sched_yield_enter, cpu, pc);
	}; break;
	// 159 long sys_sched_get_priority_max ['int policy']
	case 159: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_get_priority_max_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sched_get_priority_max_enter, cpu, pc, arg0);
	}; break;
	// 160 long sys_sched_get_priority_min ['int policy']
	case 160: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_get_priority_min_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sched_get_priority_min_enter, cpu, pc, arg0);
	}; break;
	// 161 long sys_sched_rr_get_interval ['pid_t pid', 'struct timespec __user *interval']
	case 161: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_rr_get_interval_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_rr_get_interval_enter, cpu, pc, arg0, arg1);
	}; break;
	// 162 long sys_nanosleep ['struct timespec __user *rqtp', 'struct timespec __user *rmtp']
	case 162: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nanosleep_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_nanosleep_enter, cpu, pc, arg0, arg1);
	}; break;
	// 163 long sys_mremap ['unsigned long addr', 'unsigned long old_len', 'unsigned long new_len', 'unsigned long flags', 'unsigned long new_addr']
	case 163: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mremap_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mremap_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 164 long sys_setresuid16 ['old_uid_t ruid', 'old_uid_t euid', 'old_uid_t suid']
	case 164: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setresuid16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setresuid16_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 165 long sys_getresuid16 ['old_uid_t __user *ruid', 'old_uid_t __user *euid', 'old_uid_t __user *suid']
	case 165: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getresuid16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getresuid16_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 168 long sys_poll ['struct pollfd __user *ufds', 'unsigned int nfds', 'int timeout']
	case 168: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_poll_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_poll_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 170 long sys_setresgid16 ['old_gid_t rgid', 'old_gid_t egid', 'old_gid_t sgid']
	case 170: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setresgid16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setresgid16_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 171 long sys_getresgid16 ['old_gid_t __user *rgid', 'old_gid_t __user *egid', 'old_gid_t __user *sgid']
	case 171: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getresgid16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getresgid16_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 172 long sys_prctl ['int option', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
	case 172: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_prctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_prctl_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 173 int sys_rt_sigreturn ['struct pt_regs *regs']
	case 173: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigreturn_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigreturn_enter, cpu, pc, arg0);
	}; break;
	// 174 long sys_rt_sigaction ['int', 'const struct sigaction __user *', 'struct sigaction __user *', 'size_t']
	case 174: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigaction_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 175 long sys_rt_sigprocmask ['int how', 'sigset_t __user *set', 'sigset_t __user *oset', 'size_t sigsetsize']
	case 175: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigprocmask_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigprocmask_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 176 long sys_rt_sigpending ['sigset_t __user *set', 'size_t sigsetsize']
	case 176: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigpending_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigpending_enter, cpu, pc, arg0, arg1);
	}; break;
	// 177 long sys_rt_sigtimedwait ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct timespec __user *uts', 'size_t sigsetsize']
	case 177: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigtimedwait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigtimedwait_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 178 long sys_rt_sigqueueinfo ['int pid', 'int sig', 'siginfo_t __user *uinfo']
	case 178: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigqueueinfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigqueueinfo_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 179 long sys_rt_sigsuspend ['sigset_t __user *unewset', 'size_t sigsetsize']
	case 179: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigsuspend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigsuspend_enter, cpu, pc, arg0, arg1);
	}; break;
	// 180 long sys_pread64 ['unsigned int fd', 'char __user *buf', 'size_t count', 'loff_t pos']
	case 180: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pread64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pread64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 181 long sys_pwrite64 ['unsigned int fd', 'const char __user *buf', 'size_t count', 'loff_t pos']
	case 181: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pwrite64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pwrite64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 182 long sys_chown16 ['const char __user *filename', 'old_uid_t user', 'old_gid_t group']
	case 182: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chown16_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chown16_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 183 long sys_getcwd ['char __user *buf', 'unsigned long size']
	case 183: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getcwd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getcwd_enter, cpu, pc, arg0, arg1);
	}; break;
	// 184 long sys_capget ['cap_user_header_t header', 'cap_user_data_t dataptr']
	case 184: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_capget_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_capget_enter, cpu, pc, arg0, arg1);
	}; break;
	// 185 long sys_capset ['cap_user_header_t header', 'const cap_user_data_t data']
	case 185: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_capset_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_capset_enter, cpu, pc, arg0, arg1);
	}; break;
	// 186 long sys_sigaltstack ['const struct sigaltstack __user *uss', 'struct sigaltstack __user *uoss']
	case 186: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigaltstack_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sigaltstack_enter, cpu, pc, arg0, arg1);
	}; break;
	// 187 long sys_sendfile ['int out_fd', 'int in_fd', 'off_t __user *offset', 'size_t count']
	case 187: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendfile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sendfile_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 190 long sys_vfork ['void']
	case 190: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_vfork_enter, cpu, pc);
	}; break;
	// 191 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
	case 191: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getrlimit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getrlimit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 192 long do_mmap2 ['unsigned long addr', 'unsigned long len', 'unsigned long prot', 'unsigned long flags', 'unsigned long fd', 'unsigned long pgoff']
	case 192: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_do_mmap2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_do_mmap2_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 193 long sys_truncate64 ['const char __user *path', 'loff_t length']
	case 193: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_truncate64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_truncate64_enter, cpu, pc, arg0, arg1);
	}; break;
	// 194 long sys_ftruncate64 ['unsigned int fd', 'loff_t length']
	case 194: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ftruncate64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ftruncate64_enter, cpu, pc, arg0, arg1);
	}; break;
	// 195 long sys_stat64 ['const char __user *filename', 'struct stat64 __user *statbuf']
	case 195: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_stat64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_stat64_enter, cpu, pc, arg0, arg1);
	}; break;
	// 196 long sys_lstat64 ['const char __user *filename', 'struct stat64 __user *statbuf']
	case 196: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lstat64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lstat64_enter, cpu, pc, arg0, arg1);
	}; break;
	// 197 long sys_fstat64 ['unsigned long fd', 'struct stat64 __user *statbuf']
	case 197: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstat64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fstat64_enter, cpu, pc, arg0, arg1);
	}; break;
	// 198 long sys_lchown ['const char __user *filename', 'uid_t user', 'gid_t group']
	case 198: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lchown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lchown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 199 long sys_getuid ['void']
	case 199: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_getuid_enter, cpu, pc);
	}; break;
	// 200 long sys_getgid ['void']
	case 200: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_getgid_enter, cpu, pc);
	}; break;
	// 201 long sys_geteuid ['void']
	case 201: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_geteuid_enter, cpu, pc);
	}; break;
	// 202 long sys_getegid ['void']
	case 202: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_getegid_enter, cpu, pc);
	}; break;
	// 203 long sys_setreuid ['uid_t ruid', 'uid_t euid']
	case 203: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setreuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setreuid_enter, cpu, pc, arg0, arg1);
	}; break;
	// 204 long sys_setregid ['gid_t rgid', 'gid_t egid']
	case 204: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setregid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setregid_enter, cpu, pc, arg0, arg1);
	}; break;
	// 205 long sys_getgroups ['int gidsetsize', 'gid_t __user *grouplist']
	case 205: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getgroups_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getgroups_enter, cpu, pc, arg0, arg1);
	}; break;
	// 206 long sys_setgroups ['int gidsetsize', 'gid_t __user *grouplist']
	case 206: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setgroups_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setgroups_enter, cpu, pc, arg0, arg1);
	}; break;
	// 207 long sys_fchown ['unsigned int fd', 'uid_t user', 'gid_t group']
	case 207: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 208 long sys_setresuid ['uid_t ruid', 'uid_t euid', 'uid_t suid']
	case 208: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setresuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setresuid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 209 long sys_getresuid ['uid_t __user *ruid', 'uid_t __user *euid', 'uid_t __user *suid']
	case 209: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getresuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getresuid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 210 long sys_setresgid ['gid_t rgid', 'gid_t egid', 'gid_t sgid']
	case 210: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setresgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setresgid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 211 long sys_getresgid ['gid_t __user *rgid', 'gid_t __user *egid', 'gid_t __user *sgid']
	case 211: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getresgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getresgid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 212 long sys_chown ['const char __user *filename', 'uid_t user', 'gid_t group']
	case 212: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 213 long sys_setuid ['uid_t uid']
	case 213: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setuid_enter, cpu, pc, arg0);
	}; break;
	// 214 long sys_setgid ['gid_t gid']
	case 214: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setgid_enter, cpu, pc, arg0);
	}; break;
	// 215 long sys_setfsuid ['uid_t uid']
	case 215: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setfsuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setfsuid_enter, cpu, pc, arg0);
	}; break;
	// 216 long sys_setfsgid ['gid_t gid']
	case 216: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setfsgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setfsgid_enter, cpu, pc, arg0);
	}; break;
	// 217 long sys_getdents64 ['unsigned int fd', 'struct linux_dirent64 __user *dirent', 'unsigned int count']
	case 217: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdents64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getdents64_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 218 long sys_pivot_root ['const char __user *new_root', 'const char __user *put_old']
	case 218: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pivot_root_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pivot_root_enter, cpu, pc, arg0, arg1);
	}; break;
	// 219 long sys_mincore ['unsigned long start', 'size_t len', 'unsigned char __user *vec']
	case 219: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mincore_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mincore_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 220 long sys_madvise ['unsigned long start', 'size_t len', 'int behavior']
	case 220: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_madvise_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_madvise_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 221 long sys_fcntl64 ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
	case 221: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fcntl64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fcntl64_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 224 long sys_gettid ['void']
	case 224: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_gettid_enter, cpu, pc);
	}; break;
	// 225 long sys_readahead ['int fd', 'loff_t offset', 'size_t count']
	case 225: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readahead_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_readahead_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 226 long sys_setxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
	case 226: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setxattr_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 227 long sys_lsetxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
	case 227: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lsetxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_lsetxattr_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 228 long sys_fsetxattr ['int fd', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
	case 228: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsetxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fsetxattr_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 229 long sys_getxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
	case 229: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getxattr_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 230 long sys_lgetxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
	case 230: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lgetxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lgetxattr_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 231 long sys_fgetxattr ['int fd', 'const char __user *name', 'void __user *value', 'size_t size']
	case 231: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fgetxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fgetxattr_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 232 long sys_listxattr ['const char __user *path', 'char __user *list', 'size_t size']
	case 232: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_listxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_listxattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 233 long sys_llistxattr ['const char __user *path', 'char __user *list', 'size_t size']
	case 233: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_llistxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_llistxattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 234 long sys_flistxattr ['int fd', 'char __user *list', 'size_t size']
	case 234: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_flistxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_flistxattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 235 long sys_removexattr ['const char __user *path', 'const char __user *name']
	case 235: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_removexattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_removexattr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 236 long sys_lremovexattr ['const char __user *path', 'const char __user *name']
	case 236: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lremovexattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lremovexattr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 237 long sys_fremovexattr ['int fd', 'const char __user *name']
	case 237: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fremovexattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fremovexattr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 238 long sys_tkill ['int pid', 'int sig']
	case 238: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_tkill_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_tkill_enter, cpu, pc, arg0, arg1);
	}; break;
	// 239 long sys_sendfile64 ['int out_fd', 'int in_fd', 'loff_t __user *offset', 'size_t count']
	case 239: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendfile64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sendfile64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 240 long sys_futex ['u32 __user *uaddr', 'int op', 'u32 val', 'struct timespec __user *utime', 'u32 __user *uaddr2', 'u32 val3']
	case 240: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_futex_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_futex_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 241 long sys_sched_setaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
	case 241: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setaffinity_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_setaffinity_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 242 long sys_sched_getaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
	case 242: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getaffinity_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_getaffinity_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 243 long sys_io_setup ['unsigned nr_reqs', 'aio_context_t __user *ctx']
	case 243: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_setup_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_setup_enter, cpu, pc, arg0, arg1);
	}; break;
	// 244 long sys_io_destroy ['aio_context_t ctx']
	case 244: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_destroy_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_destroy_enter, cpu, pc, arg0);
	}; break;
	// 245 long sys_io_getevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct timespec __user *timeout']
	case 245: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_getevents_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_getevents_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 246 long sys_io_submit ['aio_context_t', 'long', 'struct iocb __user * __user *']
	case 246: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_submit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_submit_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 247 long sys_io_cancel ['aio_context_t ctx_id', 'struct iocb __user *iocb', 'struct io_event __user *result']
	case 247: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_cancel_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_cancel_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 248 long sys_exit_group ['int error_code']
	case 248: {
		panda_noreturn = true;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_exit_group_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_exit_group_enter, cpu, pc, arg0);
	}; break;
	// 249 long sys_lookup_dcookie ['u64 cookie64', 'char __user *buf', 'size_t len']
	case 249: {
		panda_noreturn = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lookup_dcookie_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lookup_dcookie_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 250 long sys_epoll_create ['int size']
	case 250: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_epoll_create_enter, cpu, pc, arg0);
	}; break;
	// 251 long sys_epoll_ctl ['int epfd', 'int op', 'int fd', 'struct epoll_event __user *event']
	case 251: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_ctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_epoll_ctl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 252 long sys_epoll_wait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout']
	case 252: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_wait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_epoll_wait_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 253 long sys_remap_file_pages ['unsigned long start', 'unsigned long size', 'unsigned long prot', 'unsigned long pgoff', 'unsigned long flags']
	case 253: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_remap_file_pages_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_remap_file_pages_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 256 long sys_set_tid_address ['int __user *tidptr']
	case 256: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_set_tid_address_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_set_tid_address_enter, cpu, pc, arg0);
	}; break;
	// 257 long sys_timer_create ['clockid_t which_clock', 'struct sigevent __user *timer_event_spec', 'timer_t __user *created_timer_id']
	case 257: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_create_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 258 long sys_timer_settime ['timer_t timer_id', 'int flags', 'const struct itimerspec __user *new_setting', 'struct itimerspec __user *old_setting']
	case 258: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_settime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_settime_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 259 long sys_timer_gettime ['timer_t timer_id', 'struct itimerspec __user *setting']
	case 259: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_gettime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 260 long sys_timer_getoverrun ['timer_t timer_id']
	case 260: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_getoverrun_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_getoverrun_enter, cpu, pc, arg0);
	}; break;
	// 261 long sys_timer_delete ['timer_t timer_id']
	case 261: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_delete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_delete_enter, cpu, pc, arg0);
	}; break;
	// 262 long sys_clock_settime ['clockid_t which_clock', 'const struct timespec __user *tp']
	case 262: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_settime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clock_settime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 263 long sys_clock_gettime ['clockid_t which_clock', 'struct timespec __user *tp']
	case 263: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clock_gettime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 264 long sys_clock_getres ['clockid_t which_clock', 'struct timespec __user *tp']
	case 264: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_getres_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clock_getres_enter, cpu, pc, arg0, arg1);
	}; break;
	// 265 long sys_clock_nanosleep ['clockid_t which_clock', 'int flags', 'const struct timespec __user *rqtp', 'struct timespec __user *rmtp']
	case 265: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_nanosleep_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clock_nanosleep_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 266 long sys_statfs64 ['const char __user *path', 'size_t sz', 'struct statfs64 __user *buf']
	case 266: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_statfs64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_statfs64_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 267 long sys_fstatfs64 ['unsigned int fd', 'size_t sz', 'struct statfs64 __user *buf']
	case 267: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatfs64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fstatfs64_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 268 long sys_tgkill ['int tgid', 'int pid', 'int sig']
	case 268: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_tgkill_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_tgkill_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 269 long sys_utimes ['char __user *filename', 'struct timeval __user *utimes']
	case 269: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utimes_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_utimes_enter, cpu, pc, arg0, arg1);
	}; break;
	// 270 long sys_arm_fadvise64_64 ['int fd', 'int advice', 'loff_t offset', 'loff_t len']
	case 270: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_arm_fadvise64_64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_arm_fadvise64_64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 271 long sys_pciconfig_iobase ['long which', 'unsigned long bus', 'unsigned long devfn']
	case 271: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pciconfig_iobase_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pciconfig_iobase_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 272 long sys_pciconfig_read ['unsigned long bus', 'unsigned long dfn', 'unsigned long off', 'unsigned long len', 'void __user *buf']
	case 272: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pciconfig_read_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pciconfig_read_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 273 long sys_pciconfig_write ['unsigned long bus', 'unsigned long dfn', 'unsigned long off', 'unsigned long len', 'void __user *buf']
	case 273: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pciconfig_write_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pciconfig_write_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 274 long sys_mq_open ['const char __user *name', 'int oflag', 'umode_t mode', 'struct mq_attr __user *attr']
	case 274: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mq_open_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 275 long sys_mq_unlink ['const char __user *name']
	case 275: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_unlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mq_unlink_enter, cpu, pc, arg0);
	}; break;
	// 276 long sys_mq_timedsend ['mqd_t mqdes', 'const char __user *msg_ptr', 'size_t msg_len', 'unsigned int msg_prio', 'const struct timespec __user *abs_timeout']
	case 276: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_timedsend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mq_timedsend_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 277 long sys_mq_timedreceive ['mqd_t mqdes', 'char __user *msg_ptr', 'size_t msg_len', 'unsigned int __user *msg_prio', 'const struct timespec __user *abs_timeout']
	case 277: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_timedreceive_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mq_timedreceive_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 278 long sys_mq_notify ['mqd_t mqdes', 'const struct sigevent __user *notification']
	case 278: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_notify_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mq_notify_enter, cpu, pc, arg0, arg1);
	}; break;
	// 279 long sys_mq_getsetattr ['mqd_t mqdes', 'const struct mq_attr __user *mqstat', 'struct mq_attr __user *omqstat']
	case 279: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_getsetattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mq_getsetattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 280 long sys_waitid ['int which', 'pid_t pid', 'struct siginfo __user *infop', 'int options', 'struct rusage __user *ru']
	case 280: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_waitid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_waitid_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 281 long sys_socket ['int', 'int', 'int']
	case 281: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_socket_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_socket_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 282 long sys_bind ['int', 'struct sockaddr __user *', 'int']
	case 282: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_bind_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_bind_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 283 long sys_connect ['int', 'struct sockaddr __user *', 'int']
	case 283: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_connect_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_connect_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 284 long sys_listen ['int', 'int']
	case 284: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_listen_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_listen_enter, cpu, pc, arg0, arg1);
	}; break;
	// 285 long sys_accept ['int', 'struct sockaddr __user *', 'int __user *']
	case 285: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_accept_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_accept_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 286 long sys_getsockname ['int', 'struct sockaddr __user *', 'int __user *']
	case 286: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getsockname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getsockname_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 287 long sys_getpeername ['int', 'struct sockaddr __user *', 'int __user *']
	case 287: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getpeername_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getpeername_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 288 long sys_socketpair ['int', 'int', 'int', 'int __user *']
	case 288: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_socketpair_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_socketpair_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 289 long sys_send ['int', 'void __user *', 'size_t', 'unsigned']
	case 289: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_send_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_send_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 290 long sys_sendto ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int']
	case 290: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		int32_t arg5 = get_s32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendto_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sendto_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 291 long sys_recv ['int', 'void __user *', 'size_t', 'unsigned']
	case 291: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_recv_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 292 long sys_recvfrom ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int __user *']
	case 292: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvfrom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_recvfrom_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 293 long sys_shutdown ['int', 'int']
	case 293: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shutdown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_shutdown_enter, cpu, pc, arg0, arg1);
	}; break;
	// 294 long sys_setsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int optlen']
	case 294: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setsockopt_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setsockopt_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 295 long sys_getsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int __user *optlen']
	case 295: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getsockopt_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getsockopt_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 296 long sys_sendmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
	case 296: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sendmsg_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 297 long sys_recvmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
	case 297: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_recvmsg_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 298 long sys_semop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops']
	case 298: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semop_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_semop_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 299 long sys_semget ['key_t key', 'int nsems', 'int semflg']
	case 299: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semget_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_semget_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 300 long sys_semctl ['int semid', 'int semnum', 'int cmd', 'unsigned long arg']
	case 300: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_semctl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 301 long sys_msgsnd ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'int msgflg']
	case 301: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msgsnd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_msgsnd_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 302 long sys_msgrcv ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'long msgtyp', 'int msgflg']
	case 302: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msgrcv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_msgrcv_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 303 long sys_msgget ['key_t key', 'int msgflg']
	case 303: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msgget_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_msgget_enter, cpu, pc, arg0, arg1);
	}; break;
	// 304 long sys_msgctl ['int msqid', 'int cmd', 'struct msqid_ds __user *buf']
	case 304: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msgctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_msgctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 305 long sys_shmat ['int shmid', 'char __user *shmaddr', 'int shmflg']
	case 305: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_shmat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 306 long sys_shmdt ['char __user *shmaddr']
	case 306: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmdt_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_shmdt_enter, cpu, pc, arg0);
	}; break;
	// 307 long sys_shmget ['key_t key', 'size_t size', 'int flag']
	case 307: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmget_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_shmget_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 308 long sys_shmctl ['int shmid', 'int cmd', 'struct shmid_ds __user *buf']
	case 308: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_shmctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 309 long sys_add_key ['const char __user *_type', 'const char __user *_description', 'const void __user *_payload', 'size_t plen', 'key_serial_t destringid']
	case 309: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_add_key_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_add_key_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 310 long sys_request_key ['const char __user *_type', 'const char __user *_description', 'const char __user *_callout_info', 'key_serial_t destringid']
	case 310: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_request_key_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_request_key_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 311 long sys_keyctl ['int cmd', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
	case 311: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_keyctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_keyctl_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 312 long sys_semtimedop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops', 'const struct timespec __user *timeout']
	case 312: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semtimedop_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_semtimedop_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 314 long sys_ioprio_set ['int which', 'int who', 'int ioprio']
	case 314: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ioprio_set_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_ioprio_set_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 315 long sys_ioprio_get ['int which', 'int who']
	case 315: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ioprio_get_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_ioprio_get_enter, cpu, pc, arg0, arg1);
	}; break;
	// 316 long sys_inotify_init ['void']
	case 316: {
		panda_noreturn = false;
		PPP_RUN_CB(on_sys_inotify_init_enter, cpu, pc);
	}; break;
	// 317 long sys_inotify_add_watch ['int fd', 'const char __user *path', 'u32 mask']
	case 317: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_inotify_add_watch_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_inotify_add_watch_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 318 long sys_inotify_rm_watch ['int fd', '__s32 wd']
	case 318: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_inotify_rm_watch_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_inotify_rm_watch_enter, cpu, pc, arg0, arg1);
	}; break;
	// 319 long sys_mbind ['unsigned long start', 'unsigned long len', 'unsigned long mode', 'const unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned flags']
	case 319: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mbind_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mbind_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 320 long sys_get_mempolicy ['int __user *policy', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned long addr', 'unsigned long flags']
	case 320: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_get_mempolicy_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_get_mempolicy_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 321 long sys_set_mempolicy ['int mode', 'const unsigned long __user *nmask', 'unsigned long maxnode']
	case 321: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_set_mempolicy_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_set_mempolicy_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 322 long sys_openat ['int dfd', 'const char __user *filename', 'int flags', 'umode_t mode']
	case 322: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_openat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_openat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 323 long sys_mkdirat ['int dfd', 'const char __user *pathname', 'umode_t mode']
	case 323: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mkdirat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mkdirat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 324 long sys_mknodat ['int dfd', 'const char __user *filename', 'umode_t mode', 'unsigned dev']
	case 324: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mknodat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mknodat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 325 long sys_fchownat ['int dfd', 'const char __user *filename', 'uid_t user', 'gid_t group', 'int flag']
	case 325: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchownat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fchownat_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 326 long sys_futimesat ['int dfd', 'const char __user *filename', 'struct timeval __user *utimes']
	case 326: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_futimesat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_futimesat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 327 long sys_fstatat64 ['int dfd', 'const char __user *filename', 'struct stat64 __user *statbuf', 'int flag']
	case 327: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatat64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fstatat64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 328 long sys_unlinkat ['int dfd', 'const char __user *pathname', 'int flag']
	case 328: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_unlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_unlinkat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 329 long sys_renameat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname']
	case 329: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_renameat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_renameat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 330 long sys_linkat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'int flags']
	case 330: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_linkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_linkat_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 331 long sys_symlinkat ['const char __user *oldname', 'int newdfd', 'const char __user *newname']
	case 331: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_symlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_symlinkat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 332 long sys_readlinkat ['int dfd', 'const char __user *path', 'char __user *buf', 'int bufsiz']
	case 332: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_readlinkat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 333 long sys_fchmodat ['int dfd', 'const char __user *filename', 'umode_t mode']
	case 333: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchmodat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchmodat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 334 long sys_faccessat ['int dfd', 'const char __user *filename', 'int mode']
	case 334: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_faccessat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_faccessat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 335 long sys_pselect6 ['int', 'fd_set __user *', 'fd_set __user *', 'fd_set __user *', 'struct timespec __user *', 'void __user *']
	case 335: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pselect6_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pselect6_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 336 long sys_ppoll ['struct pollfd __user *', 'unsigned int', 'struct timespec __user *', 'const sigset_t __user *', 'size_t']
	case 336: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ppoll_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ppoll_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 337 long sys_unshare ['unsigned long unshare_flags']
	case 337: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_unshare_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_unshare_enter, cpu, pc, arg0);
	}; break;
	// 338 long sys_set_robust_list ['struct robust_list_head __user *head', 'size_t len']
	case 338: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_set_robust_list_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_set_robust_list_enter, cpu, pc, arg0, arg1);
	}; break;
	// 339 long sys_get_robust_list ['int pid', 'struct robust_list_head __user * __user *head_ptr', 'size_t __user *len_ptr']
	case 339: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_get_robust_list_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_get_robust_list_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 340 long sys_splice ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
	case 340: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_splice_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_splice_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 341 long sys_sync_file_range2 ['int fd', 'unsigned int flags', 'loff_t offset', 'loff_t nbytes']
	case 341: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sync_file_range2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sync_file_range2_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 342 long sys_tee ['int fdin', 'int fdout', 'size_t len', 'unsigned int flags']
	case 342: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_tee_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_tee_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 343 long sys_vmsplice ['int fd', 'const struct iovec __user *iov', 'unsigned long nr_segs', 'unsigned int flags']
	case 343: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_vmsplice_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_vmsplice_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 344 long sys_move_pages ['pid_t pid', 'unsigned long nr_pages', 'const void __user * __user *pages', 'const int __user *nodes', 'int __user *status', 'int flags']
	case 344: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		int32_t arg5 = get_s32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_move_pages_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_move_pages_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 345 long sys_getcpu ['unsigned __user *cpu', 'unsigned __user *node', 'struct getcpu_cache __user *cache']
	case 345: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getcpu_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getcpu_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 346 long sys_epoll_pwait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout', 'const sigset_t __user *sigmask', 'size_t sigsetsize']
	case 346: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_pwait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_epoll_pwait_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 347 long sys_kexec_load ['unsigned long entry', 'unsigned long nr_segments', 'struct kexec_segment __user *segments', 'unsigned long flags']
	case 347: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kexec_load_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_kexec_load_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 348 long sys_utimensat ['int dfd', 'const char __user *filename', 'struct timespec __user *utimes', 'int flags']
	case 348: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utimensat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_utimensat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 349 long sys_signalfd ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask']
	case 349: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_signalfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_signalfd_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 350 long sys_timerfd_create ['int clockid', 'int flags']
	case 350: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timerfd_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_timerfd_create_enter, cpu, pc, arg0, arg1);
	}; break;
	// 351 long sys_eventfd ['unsigned int count']
	case 351: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_eventfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_eventfd_enter, cpu, pc, arg0);
	}; break;
	// 352 long sys_fallocate ['int fd', 'int mode', 'loff_t offset', 'loff_t len']
	case 352: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fallocate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fallocate_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 353 long sys_timerfd_settime ['int ufd', 'int flags', 'const struct itimerspec __user *utmr', 'struct itimerspec __user *otmr']
	case 353: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timerfd_settime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timerfd_settime_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 354 long sys_timerfd_gettime ['int ufd', 'struct itimerspec __user *otmr']
	case 354: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timerfd_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timerfd_gettime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 355 long sys_signalfd4 ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask', 'int flags']
	case 355: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_signalfd4_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_signalfd4_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 356 long sys_eventfd2 ['unsigned int count', 'int flags']
	case 356: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_eventfd2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_eventfd2_enter, cpu, pc, arg0, arg1);
	}; break;
	// 357 long sys_epoll_create1 ['int flags']
	case 357: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_create1_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_epoll_create1_enter, cpu, pc, arg0);
	}; break;
	// 358 long sys_dup3 ['unsigned int oldfd', 'unsigned int newfd', 'int flags']
	case 358: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_dup3_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_dup3_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 359 long sys_pipe2 ['int __user *fildes', 'int flags']
	case 359: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pipe2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_pipe2_enter, cpu, pc, arg0, arg1);
	}; break;
	// 360 long sys_inotify_init1 ['int flags']
	case 360: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_inotify_init1_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_inotify_init1_enter, cpu, pc, arg0);
	}; break;
	// 361 long sys_preadv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
	case 361: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_preadv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_preadv_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 362 long sys_pwritev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
	case 362: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pwritev_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pwritev_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 363 long sys_rt_tgsigqueueinfo ['pid_t tgid', 'pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
	case 363: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_tgsigqueueinfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_tgsigqueueinfo_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 364 long sys_perf_event_open ['struct perf_event_attr __user *attr_uptr', 'pid_t pid', 'int cpu', 'int group_fd', 'unsigned long flags']
	case 364: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_perf_event_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_perf_event_open_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 365 long sys_recvmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags', 'struct timespec __user *timeout']
	case 365: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvmmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_recvmmsg_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 366 long sys_accept4 ['int', 'struct sockaddr __user *', 'int __user *', 'int']
	case 366: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_accept4_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_accept4_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 367 long sys_fanotify_init ['unsigned int flags', 'unsigned int event_f_flags']
	case 367: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fanotify_init_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fanotify_init_enter, cpu, pc, arg0, arg1);
	}; break;
	// 368 long sys_fanotify_mark ['int fanotify_fd', 'unsigned int flags', 'u64 mask', 'int fd', 'const char __user *pathname']
	case 368: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fanotify_mark_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fanotify_mark_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 369 long sys_prlimit64 ['pid_t pid', 'unsigned int resource', 'const struct rlimit64 __user *new_rlim', 'struct rlimit64 __user *old_rlim']
	case 369: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_prlimit64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_prlimit64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 370 long sys_name_to_handle_at ['int dfd', 'const char __user *name', 'struct file_handle __user *handle', 'int __user *mnt_id', 'int flag']
	case 370: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_name_to_handle_at_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_name_to_handle_at_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 371 long sys_open_by_handle_at ['int mountdirfd', 'struct file_handle __user *handle', 'int flags']
	case 371: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_open_by_handle_at_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_open_by_handle_at_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 372 long sys_clock_adjtime ['clockid_t which_clock', 'struct timex __user *tx']
	case 372: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_adjtime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clock_adjtime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 373 long sys_syncfs ['int fd']
	case 373: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_syncfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_syncfs_enter, cpu, pc, arg0);
	}; break;
	// 374 long sys_sendmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags']
	case 374: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendmmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sendmmsg_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 375 long sys_setns ['int fd', 'int nstype']
	case 375: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setns_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setns_enter, cpu, pc, arg0, arg1);
	}; break;
	// 376 long sys_process_vm_readv ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
	case 376: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_process_vm_readv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_process_vm_readv_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 377 long sys_process_vm_writev ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
	case 377: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_process_vm_writev_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_process_vm_writev_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 378 long sys_kcmp ['pid_t pid1', 'pid_t pid2', 'int type', 'unsigned long idx1', 'unsigned long idx2']
	case 378: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kcmp_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_kcmp_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 379 long sys_finit_module ['int fd', 'const char __user *uargs', 'int flags']
	case 379: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_finit_module_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_finit_module_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 380 long sys_sched_setattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int flags']
	case 380: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_setattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 381 long sys_sched_getattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int size', 'unsigned int flags']
	case 381: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_getattr_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 382 long sys_renameat2 ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'unsigned int flags']
	case 382: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_renameat2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_renameat2_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 383 long sys_seccomp ['unsigned int op', 'unsigned int flags', 'const char __user *uargs']
	case 383: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_seccomp_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_seccomp_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 384 long sys_getrandom ['char __user *buf', 'size_t count', 'unsigned int flags']
	case 384: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getrandom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getrandom_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 385 long sys_memfd_create ['const char __user *uname_ptr', 'unsigned int flags']
	case 385: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_memfd_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_memfd_create_enter, cpu, pc, arg0, arg1);
	}; break;
	// 386 long sys_bpf ['int cmd', 'union bpf_attr *attr', 'unsigned int size']
	case 386: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_bpf_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_bpf_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 387 long sys_execveat ['int dfd', 'const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp', 'int flags']
	case 387: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_execveat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_execveat_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 388 long sys_userfaultfd ['int flags']
	case 388: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_userfaultfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_userfaultfd_enter, cpu, pc, arg0);
	}; break;
	// 389 long sys_membarrier ['int cmd', 'int flags']
	case 389: {
		panda_noreturn = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_membarrier_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_membarrier_enter, cpu, pc, arg0, arg1);
	}; break;
	// 390 long sys_mlock2 ['unsigned long start', 'size_t len', 'int flags']
	case 390: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mlock2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_mlock2_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 983041 long ARM_breakpoint ['void']
	case 983041: {
		panda_noreturn = false;
		PPP_RUN_CB(on_ARM_breakpoint_enter, cpu, pc);
	}; break;
	// 983042 long ARM_cacheflush ['unsigned long start', 'unsigned long end', 'unsigned long flags']
	case 983042: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_ARM_cacheflush_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_ARM_cacheflush_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 983043 long ARM_user26_mode ['void']
	case 983043: {
		panda_noreturn = false;
		PPP_RUN_CB(on_ARM_user26_mode_enter, cpu, pc);
	}; break;
	// 983044 long ARM_usr32_mode ['void']
	case 983044: {
		panda_noreturn = false;
		PPP_RUN_CB(on_ARM_usr32_mode_enter, cpu, pc);
	}; break;
	// 983045 long ARM_set_tls ['unsigned long arg']
	case 983045: {
		panda_noreturn = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_ARM_set_tls_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_ARM_set_tls_enter, cpu, pc, arg0);
	}; break;
	default:
		panda_noreturn = false;
		PPP_RUN_CB(on_unknown_sys_enter, cpu, pc, ctx.no);
	} // switch (ctx.no)

	PPP_RUN_CB(on_all_sys_enter, cpu, pc, ctx.no);
	PPP_RUN_CB(on_all_sys_enter2, cpu, pc, call, &ctx);
	if (!panda_noreturn) {
		running_syscalls[std::make_pair(ctx.retaddr, ctx.asid)] = ctx;
	}
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */