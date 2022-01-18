#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls2_info.h"
#include "hooks/hooks_int_fns.h"

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
void syscall_enter_switch_freebsd_x64(CPUState *cpu, target_ptr_t pc, int static_callno) {
#if defined(TARGET_X86_64)
	CPUArchState *env = (CPUArchState*)cpu->env_ptr;
	syscall_ctx_t ctx = {0};
	if (static_callno == -1) {
	  ctx.no = env->regs[R_EAX];
	} else {
	  ctx.no = static_callno;
	}
	ctx.asid = panda_current_asid(cpu);
	ctx.retaddr = calc_retaddr(cpu, pc);
	ctx.double_return = false;
	bool panda_noreturn;	// true if PANDA should not track the return of this system call
	const syscall_info_t *call = NULL;
	syscall_info_t zero = {0};
	if (syscall_meta != NULL && ctx.no <= syscall_meta->max_generic) {
	  // If the syscall_info object from dso_info_....c doesn't have an entry
	  // for this syscall, we want to leave it as a NULL pointer
	  if (memcmp(&syscall_info[ctx.no], &zero, sizeof(syscall_info_t)) != 0) {
		call = &syscall_info[ctx.no];
	  }
	}

	switch (ctx.no) {
	// 0 int sys_nosys ['void']
	case 0: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_nosys_enter, cpu, pc);
	}; break;
	// 1 void sys_exit ['int rval']
	case 1: {
		panda_noreturn = true;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_exit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_exit_enter, cpu, pc, arg0);
	}; break;
	// 2 int sys_fork ['void']
	case 2: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_fork_enter, cpu, pc);
	}; break;
	// 3 ssize_t sys_read ['int fd', 'void *buf', 'size_t nbyte']
	case 3: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_read_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_read_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 4 ssize_t sys_write ['int fd', 'const void *buf', 'size_t nbyte']
	case 4: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_write_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_write_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5 int sys_open ['const char *path', 'int flags', 'mode_t mode']
	case 5: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_open_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 6 int sys_close ['int fd']
	case 6: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_close_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_close_enter, cpu, pc, arg0);
	}; break;
	// 7 int sys_wait4 ['int pid', 'int *status', 'int options', 'struct rusage *rusage']
	case 7: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_wait4_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_wait4_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 8 int sys_creat ['const char *path', 'int mode']
	case 8: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_creat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_creat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 9 int sys_link ['const char *path', 'const char *link']
	case 9: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_link_enter, cpu, pc, arg0, arg1);
	}; break;
	// 10 int sys_unlink ['const char *path']
	case 10: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_unlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_unlink_enter, cpu, pc, arg0);
	}; break;
	// 12 int sys_chdir ['const char *path']
	case 12: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_chdir_enter, cpu, pc, arg0);
	}; break;
	// 13 int sys_fchdir ['int fd']
	case 13: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fchdir_enter, cpu, pc, arg0);
	}; break;
	// 14 int sys_mknod ['const char *path', 'int mode', 'uint32_t dev']
	case 14: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mknod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_mknod_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 15 int sys_chmod ['const char *path', 'mode_t mode']
	case 15: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chmod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chmod_enter, cpu, pc, arg0, arg1);
	}; break;
	// 16 int sys_chown ['const char *path', 'int uid', 'int gid']
	case 16: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_chown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 18 int sys_getfsstat ['struct ostatfs *buf', 'long bufsize', 'int mode']
	case 18: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getfsstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getfsstat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 20 pid_t sys_getpid ['void']
	case 20: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getpid_enter, cpu, pc);
	}; break;
	// 21 int sys_mount ['const char *type', 'const char *path', 'int flags', 'void *data']
	case 21: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mount_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 22 int sys_unmount ['const char *path', 'int flags']
	case 22: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_unmount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_unmount_enter, cpu, pc, arg0, arg1);
	}; break;
	// 23 int sys_setuid ['uid_t uid']
	case 23: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setuid_enter, cpu, pc, arg0);
	}; break;
	// 24 uid_t sys_getuid ['void']
	case 24: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getuid_enter, cpu, pc);
	}; break;
	// 25 uid_t sys_geteuid ['void']
	case 25: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_geteuid_enter, cpu, pc);
	}; break;
	// 26 int sys_ptrace ['int req', 'pid_t pid', 'caddr_t addr', 'int data']
	case 26: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ptrace_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_ptrace_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 27 int sys_recvmsg ['int s', 'struct msghdr *msg', 'int flags']
	case 27: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_recvmsg_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 28 int sys_sendmsg ['int s', 'struct msghdr *msg', 'int flags']
	case 28: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sendmsg_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 29 int sys_recvfrom ['int s', 'void *buf', 'size_t len', 'int flags', 'struct sockaddr *from', '__socklen_t *fromlenaddr']
	case 29: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvfrom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_recvfrom_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 30 int sys_accept ['int s', 'struct sockaddr *name', '__socklen_t *anamelen']
	case 30: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_accept_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_accept_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 31 int sys_getpeername ['int fdes', 'struct sockaddr *asa', '__socklen_t *alen']
	case 31: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getpeername_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getpeername_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 32 int sys_getsockname ['int fdes', 'struct sockaddr *asa', '__socklen_t *alen']
	case 32: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getsockname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getsockname_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 33 int sys_access ['const char *path', 'int amode']
	case 33: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_access_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_access_enter, cpu, pc, arg0, arg1);
	}; break;
	// 34 int sys_chflags ['const char *path', 'u_long flags']
	case 34: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chflags_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
		}
		PPP_RUN_CB(on_sys_chflags_enter, cpu, pc, arg0, arg1);
	}; break;
	// 35 int sys_fchflags ['int fd', 'u_long flags']
	case 35: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchflags_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
		}
		PPP_RUN_CB(on_sys_fchflags_enter, cpu, pc, arg0, arg1);
	}; break;
	// 36 int sys_sync ['void']
	case 36: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_sync_enter, cpu, pc);
	}; break;
	// 37 int sys_kill ['int pid', 'int signum']
	case 37: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 38 int sys_stat ['const char *path', 'struct ostat *ub']
	case 38: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_stat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_stat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 39 pid_t sys_getppid ['void']
	case 39: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getppid_enter, cpu, pc);
	}; break;
	// 40 int sys_lstat ['const char *path', 'struct ostat *ub']
	case 40: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_lstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 41 int sys_dup ['unsigned fd']
	case 41: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_dup_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_dup_enter, cpu, pc, arg0);
	}; break;
	// 42 int sys_pipe ['void']
	case 42: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_pipe_enter, cpu, pc);
	}; break;
	// 43 gid_t sys_getegid ['void']
	case 43: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getegid_enter, cpu, pc);
	}; break;
	// 44 int sys_profil ['char *samples', 'size_t size', 'size_t offset', 'unsigned scale']
	case 44: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_profil_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_profil_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 45 int sys_ktrace ['const char *fname', 'int ops', 'int facs', 'int pid']
	case 45: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ktrace_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_ktrace_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 46 int sys_sigaction ['int signum', 'struct osigaction *nsa', 'struct osigaction *osa']
	case 46: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigaction_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 47 gid_t sys_getgid ['void']
	case 47: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getgid_enter, cpu, pc);
	}; break;
	// 49 int sys_getlogin ['char *namebuf', 'unsigned namelen']
	case 49: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getlogin_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getlogin_enter, cpu, pc, arg0, arg1);
	}; break;
	// 50 int sys_setlogin ['const char *namebuf']
	case 50: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setlogin_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setlogin_enter, cpu, pc, arg0);
	}; break;
	// 51 int sys_acct ['const char *path']
	case 51: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_acct_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_acct_enter, cpu, pc, arg0);
	}; break;
	// 53 int sys_sigaltstack ['stack_t *ss', 'stack_t *oss']
	case 53: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigaltstack_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigaltstack_enter, cpu, pc, arg0, arg1);
	}; break;
	// 54 int sys_ioctl ['int fd', 'u_long com', 'char *data']
	case 54: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ioctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ioctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 55 int sys_reboot ['int opt']
	case 55: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_reboot_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_reboot_enter, cpu, pc, arg0);
	}; break;
	// 56 int sys_revoke ['const char *path']
	case 56: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_revoke_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_revoke_enter, cpu, pc, arg0);
	}; break;
	// 57 int sys_symlink ['const char *path', 'const char *link']
	case 57: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_symlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_symlink_enter, cpu, pc, arg0, arg1);
	}; break;
	// 58 ssize_t sys_readlink ['const char *path', 'char *buf', 'size_t count']
	case 58: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_readlink_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 59 int sys_execve ['const char *fname', 'char **argv', 'char **envv']
	case 59: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_execve_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_execve_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 60 int sys_umask ['mode_t newmask']
	case 60: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_umask_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_umask_enter, cpu, pc, arg0);
	}; break;
	// 61 int sys_chroot ['const char *path']
	case 61: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chroot_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_chroot_enter, cpu, pc, arg0);
	}; break;
	// 62 int sys_fstat ['int fd', 'struct ostat *sb']
	case 62: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 63 int sys_getkerninfo ['int op', 'char *where', 'size_t *size', 'int arg']
	case 63: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getkerninfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getkerninfo_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 64 int sys_getpagesize ['void']
	case 64: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getpagesize_enter, cpu, pc);
	}; break;
	// 65 int sys_msync ['void *addr', 'size_t len', 'int flags']
	case 65: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_msync_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 66 int sys_vfork ['void']
	case 66: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_vfork_enter, cpu, pc);
	}; break;
	// 69 int sys_sbrk ['int incr']
	case 69: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sbrk_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sbrk_enter, cpu, pc, arg0);
	}; break;
	// 70 int sys_sstk ['int incr']
	case 70: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sstk_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sstk_enter, cpu, pc, arg0);
	}; break;
	// 72 int sys_vadvise ['int anom']
	case 72: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_vadvise_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_vadvise_enter, cpu, pc, arg0);
	}; break;
	// 73 int sys_munmap ['void *addr', 'size_t len']
	case 73: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_munmap_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_munmap_enter, cpu, pc, arg0, arg1);
	}; break;
	// 74 int sys_mprotect ['void *addr', 'size_t len', 'int prot']
	case 74: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mprotect_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_mprotect_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 75 int sys_madvise ['void *addr', 'size_t len', 'int behav']
	case 75: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_madvise_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_madvise_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 78 int sys_mincore ['const void *addr', 'size_t len', 'char *vec']
	case 78: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mincore_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mincore_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 79 int sys_getgroups ['unsigned gidsetsize', 'gid_t *gidset']
	case 79: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getgroups_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getgroups_enter, cpu, pc, arg0, arg1);
	}; break;
	// 80 int sys_setgroups ['unsigned gidsetsize', 'gid_t *gidset']
	case 80: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setgroups_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setgroups_enter, cpu, pc, arg0, arg1);
	}; break;
	// 81 int sys_getpgrp ['void']
	case 81: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getpgrp_enter, cpu, pc);
	}; break;
	// 82 int sys_setpgid ['int pid', 'int pgid']
	case 82: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 83 int sys_setitimer ['unsigned which', 'struct itimerval *itv', 'struct itimerval *oitv']
	case 83: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setitimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setitimer_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 84 int sys_wait ['void']
	case 84: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_wait_enter, cpu, pc);
	}; break;
	// 85 int sys_swapon ['const char *name']
	case 85: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_swapon_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_swapon_enter, cpu, pc, arg0);
	}; break;
	// 86 int sys_getitimer ['unsigned which', 'struct itimerval *itv']
	case 86: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getitimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getitimer_enter, cpu, pc, arg0, arg1);
	}; break;
	// 87 int sys_gethostname ['char *hostname', 'unsigned len']
	case 87: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_gethostname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_gethostname_enter, cpu, pc, arg0, arg1);
	}; break;
	// 88 int sys_sethostname ['char *hostname', 'unsigned len']
	case 88: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sethostname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sethostname_enter, cpu, pc, arg0, arg1);
	}; break;
	// 89 int sys_getdtablesize ['void']
	case 89: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getdtablesize_enter, cpu, pc);
	}; break;
	// 90 int sys_dup2 ['unsigned from', 'unsigned to']
	case 90: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 92 int sys_fcntl ['int fd', 'int cmd', 'long arg']
	case 92: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int64_t arg2 = get_s64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fcntl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int64_t));
		}
		PPP_RUN_CB(on_sys_fcntl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 93 int sys_select ['int nd', 'fd_set *in', 'fd_set *ou', 'fd_set *ex', 'struct timeval *tv']
	case 93: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_select_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_select_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 95 int sys_fsync ['int fd']
	case 95: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fsync_enter, cpu, pc, arg0);
	}; break;
	// 96 int sys_setpriority ['int which', 'int who', 'int prio']
	case 96: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 97 int sys_socket ['int domain', 'int type', 'int protocol']
	case 97: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 98 int sys_connect ['int s', 'const struct sockaddr *name', 'int namelen']
	case 98: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_connect_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_connect_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 99 int sys_accept ['int s', 'struct sockaddr *name', 'int *anamelen']
	case 99: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_accept_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_accept_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 100 int sys_getpriority ['int which', 'int who']
	case 100: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 101 int sys_send ['int s', 'const void *buf', 'int len', 'int flags']
	case 101: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_send_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_send_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 102 int sys_recv ['int s', 'void *buf', 'int len', 'int flags']
	case 102: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_recv_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 103 int sys_sigreturn ['struct osigcontext *sigcntxp']
	case 103: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigreturn_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigreturn_enter, cpu, pc, arg0);
	}; break;
	// 104 int sys_bind ['int s', 'const struct sockaddr *name', 'int namelen']
	case 104: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_bind_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_bind_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 105 int sys_setsockopt ['int s', 'int level', 'int name', 'const void *val', 'int valsize']
	case 105: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setsockopt_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setsockopt_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 106 int sys_listen ['int s', 'int backlog']
	case 106: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 108 int sys_sigvec ['int signum', 'struct sigvec *nsv', 'struct sigvec *osv']
	case 108: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigvec_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigvec_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 109 int sys_sigblock ['int mask']
	case 109: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigblock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sigblock_enter, cpu, pc, arg0);
	}; break;
	// 110 int sys_sigsetmask ['int mask']
	case 110: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigsetmask_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sigsetmask_enter, cpu, pc, arg0);
	}; break;
	// 111 int sys_sigsuspend ['osigset_t mask']
	case 111: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigsuspend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sigsuspend_enter, cpu, pc, arg0);
	}; break;
	// 112 int sys_sigstack ['struct sigstack *nss', 'struct sigstack *oss']
	case 112: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigstack_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigstack_enter, cpu, pc, arg0, arg1);
	}; break;
	// 113 int sys_recvmsg ['int s', 'struct omsghdr *msg', 'int flags']
	case 113: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_recvmsg_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 114 int sys_sendmsg ['int s', 'const void *msg', 'int flags']
	case 114: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sendmsg_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 116 int sys_gettimeofday ['struct timeval *tp', 'struct timezone *tzp']
	case 116: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_gettimeofday_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_gettimeofday_enter, cpu, pc, arg0, arg1);
	}; break;
	// 117 int sys_getrusage ['int who', 'struct rusage *rusage']
	case 117: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getrusage_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getrusage_enter, cpu, pc, arg0, arg1);
	}; break;
	// 118 int sys_getsockopt ['int s', 'int level', 'int name', 'void *val', 'int *avalsize']
	case 118: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getsockopt_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getsockopt_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 120 int sys_readv ['int fd', 'struct iovec *iovp', 'unsigned iovcnt']
	case 120: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_readv_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 121 int sys_writev ['int fd', 'struct iovec *iovp', 'unsigned iovcnt']
	case 121: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_writev_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_writev_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 122 int sys_settimeofday ['struct timeval *tv', 'struct timezone *tzp']
	case 122: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_settimeofday_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_settimeofday_enter, cpu, pc, arg0, arg1);
	}; break;
	// 123 int sys_fchown ['int fd', 'int uid', 'int gid']
	case 123: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fchown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 124 int sys_fchmod ['int fd', 'mode_t mode']
	case 124: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchmod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchmod_enter, cpu, pc, arg0, arg1);
	}; break;
	// 125 int sys_recvfrom ['int s', 'void *buf', 'size_t len', 'int flags', 'struct sockaddr *from', 'int *fromlenaddr']
	case 125: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvfrom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_recvfrom_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 126 int sys_setreuid ['int ruid', 'int euid']
	case 126: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setreuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setreuid_enter, cpu, pc, arg0, arg1);
	}; break;
	// 127 int sys_setregid ['int rgid', 'int egid']
	case 127: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setregid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setregid_enter, cpu, pc, arg0, arg1);
	}; break;
	// 128 int sys_rename ['const char *from', 'const char *to']
	case 128: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rename_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_rename_enter, cpu, pc, arg0, arg1);
	}; break;
	// 131 int sys_flock ['int fd', 'int how']
	case 131: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_flock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_flock_enter, cpu, pc, arg0, arg1);
	}; break;
	// 132 int sys_mkfifo ['const char *path', 'mode_t mode']
	case 132: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mkfifo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mkfifo_enter, cpu, pc, arg0, arg1);
	}; break;
	// 133 int sys_sendto ['int s', 'const void *buf', 'size_t len', 'int flags', 'const struct sockaddr *to', 'int tolen']
	case 133: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		int32_t arg5 = get_s32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendto_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sendto_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 134 int sys_shutdown ['int s', 'int how']
	case 134: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 135 int sys_socketpair ['int domain', 'int type', 'int protocol', 'int *rsv']
	case 135: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_socketpair_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_socketpair_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 136 int sys_mkdir ['const char *path', 'mode_t mode']
	case 136: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mkdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mkdir_enter, cpu, pc, arg0, arg1);
	}; break;
	// 137 int sys_rmdir ['const char *path']
	case 137: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rmdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_rmdir_enter, cpu, pc, arg0);
	}; break;
	// 138 int sys_utimes ['const char *path', 'struct timeval *tptr']
	case 138: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utimes_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_utimes_enter, cpu, pc, arg0, arg1);
	}; break;
	// 140 int sys_adjtime ['struct timeval *delta', 'struct timeval *olddelta']
	case 140: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_adjtime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_adjtime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 141 int sys_getpeername ['int fdes', 'struct sockaddr *asa', 'int *alen']
	case 141: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getpeername_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getpeername_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 142 long sys_gethostid ['void']
	case 142: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_gethostid_enter, cpu, pc);
	}; break;
	// 143 int sys_sethostid ['long hostid']
	case 143: {
		panda_noreturn = false;
		ctx.double_return = false;
		int64_t arg0 = get_s64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sethostid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int64_t));
		}
		PPP_RUN_CB(on_sys_sethostid_enter, cpu, pc, arg0);
	}; break;
	// 144 int sys_getrlimit ['unsigned which', 'struct orlimit *rlp']
	case 144: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getrlimit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getrlimit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 145 int sys_setrlimit ['unsigned which', 'struct orlimit *rlp']
	case 145: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setrlimit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setrlimit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 146 int sys_killpg ['int pgid', 'int signum']
	case 146: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_killpg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_killpg_enter, cpu, pc, arg0, arg1);
	}; break;
	// 147 int sys_setsid ['void']
	case 147: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_setsid_enter, cpu, pc);
	}; break;
	// 148 int sys_quotactl ['const char *path', 'int cmd', 'int uid', 'void *arg']
	case 148: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_quotactl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_quotactl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 149 int sys_quota ['void']
	case 149: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_quota_enter, cpu, pc);
	}; break;
	// 150 int sys_getsockname ['int fdec', 'struct sockaddr *asa', 'int *alen']
	case 150: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getsockname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getsockname_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 154 int sys_nlm_syscall ['int debug_level', 'int grace_period', 'int addr_count', 'char **addrs']
	case 154: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nlm_syscall_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_nlm_syscall_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 155 int sys_nfssvc ['int flag', 'void *argp']
	case 155: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nfssvc_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_nfssvc_enter, cpu, pc, arg0, arg1);
	}; break;
	// 156 int sys_getdirentries ['int fd', 'char *buf', 'unsigned count', 'long *basep']
	case 156: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdirentries_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getdirentries_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 157 int sys_statfs ['const char *path', 'struct ostatfs *buf']
	case 157: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_statfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_statfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 158 int sys_fstatfs ['int fd', 'struct ostatfs *buf']
	case 158: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fstatfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 160 int sys_lgetfh ['const char *fname', 'struct fhandle *fhp']
	case 160: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lgetfh_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_lgetfh_enter, cpu, pc, arg0, arg1);
	}; break;
	// 161 int sys_getfh ['const char *fname', 'struct fhandle *fhp']
	case 161: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getfh_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getfh_enter, cpu, pc, arg0, arg1);
	}; break;
	// 162 int sys_getdomainname ['char *domainname', 'int len']
	case 162: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdomainname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getdomainname_enter, cpu, pc, arg0, arg1);
	}; break;
	// 163 int sys_setdomainname ['char *domainname', 'int len']
	case 163: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setdomainname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setdomainname_enter, cpu, pc, arg0, arg1);
	}; break;
	// 164 int sys_uname ['struct utsname *name']
	case 164: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_uname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_uname_enter, cpu, pc, arg0);
	}; break;
	// 165 int sys_sysarch ['int op', 'char *parms']
	case 165: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sysarch_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sysarch_enter, cpu, pc, arg0, arg1);
	}; break;
	// 166 int sys_rtprio ['int function', 'pid_t pid', 'struct rtprio *rtp']
	case 166: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rtprio_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_rtprio_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 169 int sys_semsys ['int which', 'int a2', 'int a3', 'int a4', 'int a5']
	case 169: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semsys_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_semsys_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 175 int sys_setfib ['int fibnum']
	case 175: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setfib_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setfib_enter, cpu, pc, arg0);
	}; break;
	// 176 int sys_ntp_adjtime ['struct timex *tp']
	case 176: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ntp_adjtime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ntp_adjtime_enter, cpu, pc, arg0);
	}; break;
	// 181 int sys_setgid ['gid_t gid']
	case 181: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setgid_enter, cpu, pc, arg0);
	}; break;
	// 182 int sys_setegid ['gid_t egid']
	case 182: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setegid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setegid_enter, cpu, pc, arg0);
	}; break;
	// 183 int sys_seteuid ['uid_t euid']
	case 183: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_seteuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_seteuid_enter, cpu, pc, arg0);
	}; break;
	// 188 int sys_stat ['const char *path', 'struct freebsd11_stat *ub']
	case 188: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_stat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_stat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 189 int sys_fstat ['int fd', 'struct freebsd11_stat *sb']
	case 189: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 190 int sys_lstat ['const char *path', 'struct freebsd11_stat *ub']
	case 190: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_lstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 191 int sys_pathconf ['const char *path', 'int name']
	case 191: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pathconf_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_pathconf_enter, cpu, pc, arg0, arg1);
	}; break;
	// 192 int sys_fpathconf ['int fd', 'int name']
	case 192: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fpathconf_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fpathconf_enter, cpu, pc, arg0, arg1);
	}; break;
	// 194 int sys_getrlimit ['unsigned which', 'struct rlimit *rlp']
	case 194: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getrlimit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getrlimit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 195 int sys_setrlimit ['unsigned which', 'struct rlimit *rlp']
	case 195: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setrlimit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setrlimit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 196 int sys_getdirentries ['int fd', 'char *buf', 'unsigned count', 'long *basep']
	case 196: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdirentries_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getdirentries_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 198 int sys_nosys ['void']
	case 198: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_nosys_enter, cpu, pc);
	}; break;
	// 202 int sys___sysctl ['int *name', 'unsigned namelen', 'void *old', 'size_t *oldlenp', 'const void *new', 'size_t newlen']
	case 202: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___sysctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys___sysctl_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 203 int sys_mlock ['const void *addr', 'size_t len']
	case 203: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mlock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mlock_enter, cpu, pc, arg0, arg1);
	}; break;
	// 204 int sys_munlock ['const void *addr', 'size_t len']
	case 204: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_munlock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_munlock_enter, cpu, pc, arg0, arg1);
	}; break;
	// 205 int sys_undelete ['const char *path']
	case 205: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_undelete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_undelete_enter, cpu, pc, arg0);
	}; break;
	// 206 int sys_futimes ['int fd', 'struct timeval *tptr']
	case 206: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_futimes_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_futimes_enter, cpu, pc, arg0, arg1);
	}; break;
	// 207 int sys_getpgid ['pid_t pid']
	case 207: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getpgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getpgid_enter, cpu, pc, arg0);
	}; break;
	// 209 int sys_poll ['struct pollfd *fds', 'unsigned nfds', 'int timeout']
	case 209: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_poll_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_poll_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 220 int sys___semctl ['int semid', 'int semnum', 'int cmd', 'union semun_old *arg']
	case 220: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___semctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___semctl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 221 int sys_semget ['key_t key', 'int nsems', 'int semflg']
	case 221: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 222 int sys_semop ['int semid', 'struct sembuf *sops', 'size_t nsops']
	case 222: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semop_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_semop_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 224 int sys_msgctl ['int msqid', 'int cmd', 'struct msqid_ds_old *buf']
	case 224: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msgctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_msgctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 225 int sys_msgget ['key_t key', 'int msgflg']
	case 225: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 226 int sys_msgsnd ['int msqid', 'const void *msgp', 'size_t msgsz', 'int msgflg']
	case 226: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msgsnd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_msgsnd_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 227 ssize_t sys_msgrcv ['int msqid', 'void *msgp', 'size_t msgsz', 'long msgtyp', 'int msgflg']
	case 227: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int64_t arg3 = get_s64(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msgrcv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int64_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_msgrcv_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 229 int sys_shmctl ['int shmid', 'int cmd', 'struct shmid_ds_old *buf']
	case 229: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_shmctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 230 int sys_shmdt ['const void *shmaddr']
	case 230: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmdt_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_shmdt_enter, cpu, pc, arg0);
	}; break;
	// 231 int sys_shmget ['key_t key', 'size_t size', 'int shmflg']
	case 231: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 232 int sys_clock_gettime ['clockid_t clock_id', 'struct timespec *tp']
	case 232: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_gettime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 233 int sys_clock_settime ['clockid_t clock_id', 'const struct timespec *tp']
	case 233: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_settime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_settime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 234 int sys_clock_getres ['clockid_t clock_id', 'struct timespec *tp']
	case 234: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_getres_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_getres_enter, cpu, pc, arg0, arg1);
	}; break;
	// 235 int sys_ktimer_create ['clockid_t clock_id', 'struct sigevent *evp', 'int *timerid']
	case 235: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ktimer_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ktimer_create_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 236 int sys_ktimer_delete ['int timerid']
	case 236: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ktimer_delete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_ktimer_delete_enter, cpu, pc, arg0);
	}; break;
	// 237 int sys_ktimer_settime ['int timerid', 'int flags', 'const struct itimerspec *value', 'struct itimerspec *ovalue']
	case 237: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ktimer_settime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ktimer_settime_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 238 int sys_ktimer_gettime ['int timerid', 'struct itimerspec *value']
	case 238: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ktimer_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ktimer_gettime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 239 int sys_ktimer_getoverrun ['int timerid']
	case 239: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ktimer_getoverrun_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_ktimer_getoverrun_enter, cpu, pc, arg0);
	}; break;
	// 240 int sys_nanosleep ['const struct timespec *rqtp', 'struct timespec *rmtp']
	case 240: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nanosleep_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_nanosleep_enter, cpu, pc, arg0, arg1);
	}; break;
	// 241 int sys_ffclock_getcounter ['ffcounter *ffcount']
	case 241: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ffclock_getcounter_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ffclock_getcounter_enter, cpu, pc, arg0);
	}; break;
	// 242 int sys_ffclock_setestimate ['struct ffclock_estimate *cest']
	case 242: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ffclock_setestimate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ffclock_setestimate_enter, cpu, pc, arg0);
	}; break;
	// 243 int sys_ffclock_getestimate ['struct ffclock_estimate *cest']
	case 243: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ffclock_getestimate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ffclock_getestimate_enter, cpu, pc, arg0);
	}; break;
	// 244 int sys_clock_nanosleep ['clockid_t clock_id', 'int flags', 'const struct timespec *rqtp', 'struct timespec *rmtp']
	case 244: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_nanosleep_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_nanosleep_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 247 int sys_clock_getcpuclockid2 ['id_t id', 'int which', 'clockid_t *clock_id']
	case 247: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_getcpuclockid2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_getcpuclockid2_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 248 int sys_ntp_gettime ['struct ntptimeval *ntvp']
	case 248: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ntp_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ntp_gettime_enter, cpu, pc, arg0);
	}; break;
	// 250 int sys_minherit ['void *addr', 'size_t len', 'int inherit']
	case 250: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_minherit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_minherit_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 251 int sys_rfork ['int flags']
	case 251: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rfork_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_rfork_enter, cpu, pc, arg0);
	}; break;
	// 253 int sys_issetugid ['void']
	case 253: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_issetugid_enter, cpu, pc);
	}; break;
	// 254 int sys_lchown ['const char *path', 'int uid', 'int gid']
	case 254: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lchown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_lchown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 255 int sys_aio_read ['struct aiocb *aiocbp']
	case 255: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_read_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_read_enter, cpu, pc, arg0);
	}; break;
	// 256 int sys_aio_write ['struct aiocb *aiocbp']
	case 256: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_write_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_write_enter, cpu, pc, arg0);
	}; break;
	// 257 int sys_lio_listio ['int mode', 'struct aiocb * const *acb_list', 'int nent', 'struct sigevent *sig']
	case 257: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lio_listio_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_lio_listio_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 272 int sys_getdents ['int fd', 'char *buf', 'size_t count']
	case 272: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdents_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getdents_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 274 int sys_lchmod ['const char *path', 'mode_t mode']
	case 274: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lchmod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lchmod_enter, cpu, pc, arg0, arg1);
	}; break;
	// 276 int sys_lutimes ['const char *path', 'struct timeval *tptr']
	case 276: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lutimes_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_lutimes_enter, cpu, pc, arg0, arg1);
	}; break;
	// 278 int sys_nstat ['const char *path', 'struct nstat *ub']
	case 278: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_nstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 279 int sys_nfstat ['int fd', 'struct nstat *sb']
	case 279: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nfstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_nfstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 280 int sys_nlstat ['const char *path', 'struct nstat *ub']
	case 280: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nlstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_nlstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 289 ssize_t sys_preadv ['int fd', 'struct iovec *iovp', 'unsigned iovcnt', 'off_t offset']
	case 289: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_preadv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_preadv_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 290 ssize_t sys_pwritev ['int fd', 'struct iovec *iovp', 'unsigned iovcnt', 'off_t offset']
	case 290: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pwritev_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pwritev_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 297 int sys_fhstatfs ['const struct fhandle *u_fhp', 'struct ostatfs *buf']
	case 297: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fhstatfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fhstatfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 298 int sys_fhopen ['const struct fhandle *u_fhp', 'int flags']
	case 298: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fhopen_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fhopen_enter, cpu, pc, arg0, arg1);
	}; break;
	// 299 int sys_fhstat ['const struct fhandle *u_fhp', 'struct freebsd11_stat *sb']
	case 299: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fhstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fhstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 300 int sys_modnext ['int modid']
	case 300: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_modnext_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_modnext_enter, cpu, pc, arg0);
	}; break;
	// 301 int sys_modstat ['int modid', 'struct module_stat *stat']
	case 301: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_modstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_modstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 302 int sys_modfnext ['int modid']
	case 302: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_modfnext_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_modfnext_enter, cpu, pc, arg0);
	}; break;
	// 303 int sys_modfind ['const char *name']
	case 303: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_modfind_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_modfind_enter, cpu, pc, arg0);
	}; break;
	// 304 int sys_kldload ['const char *file']
	case 304: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kldload_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kldload_enter, cpu, pc, arg0);
	}; break;
	// 305 int sys_kldunload ['int fileid']
	case 305: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kldunload_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_kldunload_enter, cpu, pc, arg0);
	}; break;
	// 306 int sys_kldfind ['const char *file']
	case 306: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kldfind_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kldfind_enter, cpu, pc, arg0);
	}; break;
	// 307 int sys_kldnext ['int fileid']
	case 307: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kldnext_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_kldnext_enter, cpu, pc, arg0);
	}; break;
	// 308 int sys_kldstat ['int fileid', 'struct kld_file_stat *stat']
	case 308: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kldstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kldstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 309 int sys_kldfirstmod ['int fileid']
	case 309: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kldfirstmod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_kldfirstmod_enter, cpu, pc, arg0);
	}; break;
	// 310 int sys_getsid ['pid_t pid']
	case 310: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getsid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getsid_enter, cpu, pc, arg0);
	}; break;
	// 311 int sys_setresuid ['uid_t ruid', 'uid_t euid', 'uid_t suid']
	case 311: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 312 int sys_setresgid ['gid_t rgid', 'gid_t egid', 'gid_t sgid']
	case 312: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 314 ssize_t sys_aio_return ['struct aiocb *aiocbp']
	case 314: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_return_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_return_enter, cpu, pc, arg0);
	}; break;
	// 315 int sys_aio_suspend ['struct aiocb * const * aiocbp', 'int nent', 'const struct timespec *timeout']
	case 315: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_suspend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_suspend_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 316 int sys_aio_cancel ['int fd', 'struct aiocb *aiocbp']
	case 316: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_cancel_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_cancel_enter, cpu, pc, arg0, arg1);
	}; break;
	// 317 int sys_aio_error ['struct aiocb *aiocbp']
	case 317: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_error_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_error_enter, cpu, pc, arg0);
	}; break;
	// 318 int sys_aio_read ['struct oaiocb *aiocbp']
	case 318: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_read_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_read_enter, cpu, pc, arg0);
	}; break;
	// 319 int sys_aio_write ['struct oaiocb *aiocbp']
	case 319: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_write_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_write_enter, cpu, pc, arg0);
	}; break;
	// 320 int sys_lio_listio ['int mode', 'struct oaiocb * const *acb_list', 'int nent', 'struct osigevent *sig']
	case 320: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lio_listio_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_lio_listio_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 321 int sys_yield ['void']
	case 321: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_yield_enter, cpu, pc);
	}; break;
	// 324 int sys_mlockall ['int how']
	case 324: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mlockall_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_mlockall_enter, cpu, pc, arg0);
	}; break;
	// 325 int sys_munlockall(void); 326 int __getcwd ['char *buf', 'size_t buflen']
	case 325: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on___getcwd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on___getcwd_enter, cpu, pc, arg0, arg1);
	}; break;
	// 327 int sys_sched_setparam ['pid_t pid', 'const struct sched_param *param']
	case 327: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setparam_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sched_setparam_enter, cpu, pc, arg0, arg1);
	}; break;
	// 328 int sys_sched_getparam ['pid_t pid', 'struct sched_param *param']
	case 328: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getparam_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sched_getparam_enter, cpu, pc, arg0, arg1);
	}; break;
	// 329 int sys_sched_setscheduler ['pid_t pid', 'int policy', 'const struct sched_param *param']
	case 329: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setscheduler_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sched_setscheduler_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 330 int sys_sched_getscheduler ['pid_t pid']
	case 330: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getscheduler_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sched_getscheduler_enter, cpu, pc, arg0);
	}; break;
	// 331 int sys_sched_yield ['void']
	case 331: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_sched_yield_enter, cpu, pc);
	}; break;
	// 332 int sys_sched_get_priority_max ['int policy']
	case 332: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_get_priority_max_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sched_get_priority_max_enter, cpu, pc, arg0);
	}; break;
	// 333 int sys_sched_get_priority_min ['int policy']
	case 333: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_get_priority_min_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sched_get_priority_min_enter, cpu, pc, arg0);
	}; break;
	// 334 int sys_sched_rr_get_interval ['pid_t pid', 'struct timespec *interval']
	case 334: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_rr_get_interval_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sched_rr_get_interval_enter, cpu, pc, arg0, arg1);
	}; break;
	// 335 int sys_utrace ['const void *addr', 'size_t len']
	case 335: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utrace_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_utrace_enter, cpu, pc, arg0, arg1);
	}; break;
	// 336 int sys_sendfile ['int fd', 'int s', 'off_t offset', 'size_t nbytes', 'struct sf_hdtr *hdtr', 'off_t *sbytes', 'int flags']
	case 336: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		int32_t arg6 = get_s32(cpu, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendfile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sendfile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 337 int sys_kldsym ['int fileid', 'int cmd', 'void *data']
	case 337: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kldsym_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kldsym_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 338 int sys_jail ['struct jail *jail']
	case 338: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_jail_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_jail_enter, cpu, pc, arg0);
	}; break;
	// 339 int sys_nnpfs_syscall ['int operation', 'char *a_pathP', 'int a_opcode', 'void *a_paramsP', 'int a_followSymlinks']
	case 339: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nnpfs_syscall_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_nnpfs_syscall_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 340 int sys_sigprocmask ['int how', 'const sigset_t *set', 'sigset_t *oset']
	case 340: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigprocmask_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigprocmask_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 341 int sys_sigsuspend ['const sigset_t *sigmask']
	case 341: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigsuspend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigsuspend_enter, cpu, pc, arg0);
	}; break;
	// 342 int sys_sigaction ['int sig', 'const struct sigaction *act', 'struct sigaction *oact']
	case 342: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigaction_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 343 int sys_sigpending ['sigset_t *set']
	case 343: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigpending_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigpending_enter, cpu, pc, arg0);
	}; break;
	// 344 int sys_sigreturn ['const struct ucontext4 *sigcntxp']
	case 344: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigreturn_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigreturn_enter, cpu, pc, arg0);
	}; break;
	// 345 int sys_sigtimedwait ['const sigset_t *set', 'siginfo_t *info', 'const struct timespec *timeout']
	case 345: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigtimedwait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigtimedwait_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 346 int sys_sigwaitinfo ['const sigset_t *set', 'siginfo_t *info']
	case 346: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigwaitinfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigwaitinfo_enter, cpu, pc, arg0, arg1);
	}; break;
	// 347 int sys___acl_get_file ['const char *path', 'acl_type_t type', 'struct acl *aclp']
	case 347: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_get_file_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___acl_get_file_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 348 int sys___acl_set_file ['const char *path', 'acl_type_t type', 'struct acl *aclp']
	case 348: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_set_file_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___acl_set_file_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 349 int sys___acl_get_fd ['int filedes', 'acl_type_t type', 'struct acl *aclp']
	case 349: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_get_fd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___acl_get_fd_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 350 int sys___acl_set_fd ['int filedes', 'acl_type_t type', 'struct acl *aclp']
	case 350: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_set_fd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___acl_set_fd_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 351 int sys___acl_delete_file ['const char *path', 'acl_type_t type']
	case 351: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_delete_file_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys___acl_delete_file_enter, cpu, pc, arg0, arg1);
	}; break;
	// 352 int sys___acl_delete_fd ['int filedes', 'acl_type_t type']
	case 352: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_delete_fd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys___acl_delete_fd_enter, cpu, pc, arg0, arg1);
	}; break;
	// 353 int sys___acl_aclcheck_file ['const char *path', 'acl_type_t type', 'struct acl *aclp']
	case 353: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_aclcheck_file_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___acl_aclcheck_file_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 354 int sys___acl_aclcheck_fd ['int filedes', 'acl_type_t type', 'struct acl *aclp']
	case 354: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_aclcheck_fd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___acl_aclcheck_fd_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 355 int sys_extattrctl ['const char *path', 'int cmd', 'const char *filename', 'int attrnamespace', 'const char *attrname']
	case 355: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattrctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_extattrctl_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 356 ssize_t sys_extattr_set_file ['const char *path', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
	case 356: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_set_file_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_extattr_set_file_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 357 ssize_t sys_extattr_get_file ['const char *path', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
	case 357: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_get_file_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_extattr_get_file_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 358 int sys_extattr_delete_file ['const char *path', 'int attrnamespace', 'const char *attrname']
	case 358: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_delete_file_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_extattr_delete_file_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 359 ssize_t sys_aio_waitcomplete ['struct aiocb **aiocbp', 'struct timespec *timeout']
	case 359: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_waitcomplete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_waitcomplete_enter, cpu, pc, arg0, arg1);
	}; break;
	// 360 int sys_getresuid ['uid_t *ruid', 'uid_t *euid', 'uid_t *suid']
	case 360: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getresuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getresuid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 361 int sys_getresgid ['gid_t *rgid', 'gid_t *egid', 'gid_t *sgid']
	case 361: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getresgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getresgid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 362 int sys_kqueue ['void']
	case 362: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_kqueue_enter, cpu, pc);
	}; break;
	// 363 int sys_kevent ['int fd', 'struct kevent_freebsd11 *changelist', 'int nchanges', 'struct kevent_freebsd11 *eventlist', 'int nevents', 'const struct timespec *timeout']
	case 363: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kevent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kevent_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 371 ssize_t sys_extattr_set_fd ['int fd', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
	case 371: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_set_fd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_extattr_set_fd_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 372 ssize_t sys_extattr_get_fd ['int fd', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
	case 372: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_get_fd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_extattr_get_fd_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 373 int sys_extattr_delete_fd ['int fd', 'int attrnamespace', 'const char *attrname']
	case 373: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_delete_fd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_extattr_delete_fd_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 374 int sys___setugid ['int flag']
	case 374: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___setugid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys___setugid_enter, cpu, pc, arg0);
	}; break;
	// 376 int sys_eaccess ['const char *path', 'int amode']
	case 376: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_eaccess_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_eaccess_enter, cpu, pc, arg0, arg1);
	}; break;
	// 377 int sys_afs3_syscall ['long syscall', 'long parm1', 'long parm2', 'long parm3', 'long parm4', 'long parm5', 'long parm6']
	case 377: {
		panda_noreturn = false;
		ctx.double_return = false;
		int64_t arg0 = get_s64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		int64_t arg2 = get_s64(cpu, 2);
		int64_t arg3 = get_s64(cpu, 3);
		int64_t arg4 = get_s64(cpu, 4);
		int64_t arg5 = get_s64(cpu, 5);
		int64_t arg6 = get_s64(cpu, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_afs3_syscall_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int64_t));
			memcpy(ctx.args[4], &arg4, sizeof(int64_t));
			memcpy(ctx.args[5], &arg5, sizeof(int64_t));
			memcpy(ctx.args[6], &arg6, sizeof(int64_t));
		}
		PPP_RUN_CB(on_sys_afs3_syscall_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 378 int sys_nmount ['struct iovec *iovp', 'unsigned int iovcnt', 'int flags']
	case 378: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nmount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_nmount_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 384 int sys___mac_get_proc ['struct mac *mac_p']
	case 384: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___mac_get_proc_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___mac_get_proc_enter, cpu, pc, arg0);
	}; break;
	// 385 int sys___mac_set_proc ['struct mac *mac_p']
	case 385: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___mac_set_proc_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___mac_set_proc_enter, cpu, pc, arg0);
	}; break;
	// 386 int sys___mac_get_fd ['int fd', 'struct mac *mac_p']
	case 386: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___mac_get_fd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___mac_get_fd_enter, cpu, pc, arg0, arg1);
	}; break;
	// 387 int sys___mac_get_file ['const char *path_p', 'struct mac *mac_p']
	case 387: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___mac_get_file_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___mac_get_file_enter, cpu, pc, arg0, arg1);
	}; break;
	// 388 int sys___mac_set_fd ['int fd', 'struct mac *mac_p']
	case 388: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___mac_set_fd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___mac_set_fd_enter, cpu, pc, arg0, arg1);
	}; break;
	// 389 int sys___mac_set_file ['const char *path_p', 'struct mac *mac_p']
	case 389: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___mac_set_file_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___mac_set_file_enter, cpu, pc, arg0, arg1);
	}; break;
	// 390 int sys_kenv ['int what', 'const char *name', 'char *value', 'int len']
	case 390: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kenv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_kenv_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 391 int sys_lchflags ['const char *path', 'u_long flags']
	case 391: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lchflags_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
		}
		PPP_RUN_CB(on_sys_lchflags_enter, cpu, pc, arg0, arg1);
	}; break;
	// 392 int sys_uuidgen ['struct uuid *store', 'int count']
	case 392: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_uuidgen_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_uuidgen_enter, cpu, pc, arg0, arg1);
	}; break;
	// 393 int sys_sendfile ['int fd', 'int s', 'off_t offset', 'size_t nbytes', 'struct sf_hdtr *hdtr', 'off_t *sbytes', 'int flags']
	case 393: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		int32_t arg6 = get_s32(cpu, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendfile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sendfile_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 394 int sys_mac_syscall ['const char *policy', 'int call', 'void *arg']
	case 394: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mac_syscall_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mac_syscall_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 395 int sys_getfsstat ['struct freebsd11_statfs *buf', 'long bufsize', 'int mode']
	case 395: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getfsstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getfsstat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 396 int sys_statfs ['const char *path', 'struct freebsd11_statfs *buf']
	case 396: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_statfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_statfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 397 int sys_fstatfs ['int fd', 'struct freebsd11_statfs *buf']
	case 397: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fstatfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 398 int sys_fhstatfs ['const struct fhandle *u_fhp', 'struct freebsd11_statfs *buf']
	case 398: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fhstatfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fhstatfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 400 int sys_ksem_close ['semid_t id']
	case 400: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ksem_close_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ksem_close_enter, cpu, pc, arg0);
	}; break;
	// 401 int sys_ksem_post ['semid_t id']
	case 401: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ksem_post_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ksem_post_enter, cpu, pc, arg0);
	}; break;
	// 402 int sys_ksem_wait ['semid_t id']
	case 402: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ksem_wait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ksem_wait_enter, cpu, pc, arg0);
	}; break;
	// 403 int sys_ksem_trywait ['semid_t id']
	case 403: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ksem_trywait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ksem_trywait_enter, cpu, pc, arg0);
	}; break;
	// 404 int sys_ksem_init ['semid_t *idp', 'unsigned int value']
	case 404: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ksem_init_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ksem_init_enter, cpu, pc, arg0, arg1);
	}; break;
	// 405 int sys_ksem_open ['semid_t *idp', 'const char *name', 'int oflag', 'mode_t mode', 'unsigned int value']
	case 405: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ksem_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ksem_open_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 406 int sys_ksem_unlink ['const char *name']
	case 406: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ksem_unlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ksem_unlink_enter, cpu, pc, arg0);
	}; break;
	// 407 int sys_ksem_getvalue ['semid_t id', 'int *val']
	case 407: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ksem_getvalue_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ksem_getvalue_enter, cpu, pc, arg0, arg1);
	}; break;
	// 408 int sys_ksem_destroy ['semid_t id']
	case 408: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ksem_destroy_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ksem_destroy_enter, cpu, pc, arg0);
	}; break;
	// 409 int sys___mac_get_pid ['pid_t pid', 'struct mac *mac_p']
	case 409: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___mac_get_pid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___mac_get_pid_enter, cpu, pc, arg0, arg1);
	}; break;
	// 410 int sys___mac_get_link ['const char *path_p', 'struct mac *mac_p']
	case 410: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___mac_get_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___mac_get_link_enter, cpu, pc, arg0, arg1);
	}; break;
	// 411 int sys___mac_set_link ['const char *path_p', 'struct mac *mac_p']
	case 411: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___mac_set_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___mac_set_link_enter, cpu, pc, arg0, arg1);
	}; break;
	// 412 ssize_t sys_extattr_set_link ['const char *path', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
	case 412: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_set_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_extattr_set_link_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 413 ssize_t sys_extattr_get_link ['const char *path', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
	case 413: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_get_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_extattr_get_link_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 414 int sys_extattr_delete_link ['const char *path', 'int attrnamespace', 'const char *attrname']
	case 414: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_delete_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_extattr_delete_link_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 415 int sys___mac_execve ['const char *fname', 'char **argv', 'char **envv', 'struct mac *mac_p']
	case 415: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___mac_execve_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___mac_execve_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 416 int sys_sigaction ['int sig', 'const struct sigaction *act', 'struct sigaction *oact']
	case 416: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigaction_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 417 int sys_sigreturn ['const struct __ucontext *sigcntxp']
	case 417: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigreturn_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigreturn_enter, cpu, pc, arg0);
	}; break;
	// 421 int sys_getcontext ['struct __ucontext *ucp']
	case 421: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getcontext_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getcontext_enter, cpu, pc, arg0);
	}; break;
	// 422 int sys_setcontext ['const struct __ucontext *ucp']
	case 422: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setcontext_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setcontext_enter, cpu, pc, arg0);
	}; break;
	// 423 int sys_swapcontext ['struct __ucontext *oucp', 'const struct __ucontext *ucp']
	case 423: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_swapcontext_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_swapcontext_enter, cpu, pc, arg0, arg1);
	}; break;
	// 424 int sys_swapoff ['const char *name']
	case 424: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_swapoff_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_swapoff_enter, cpu, pc, arg0);
	}; break;
	// 425 int sys___acl_get_link ['const char *path', 'acl_type_t type', 'struct acl *aclp']
	case 425: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_get_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___acl_get_link_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 426 int sys___acl_set_link ['const char *path', 'acl_type_t type', 'struct acl *aclp']
	case 426: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_set_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___acl_set_link_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 427 int sys___acl_delete_link ['const char *path', 'acl_type_t type']
	case 427: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_delete_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys___acl_delete_link_enter, cpu, pc, arg0, arg1);
	}; break;
	// 428 int sys___acl_aclcheck_link ['const char *path', 'acl_type_t type', 'struct acl *aclp']
	case 428: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___acl_aclcheck_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___acl_aclcheck_link_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 429 int sys_sigwait ['const sigset_t *set', 'int *sig']
	case 429: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigwait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigwait_enter, cpu, pc, arg0, arg1);
	}; break;
	// 430 int sys_thr_create ['ucontext_t *ctx', 'long *id', 'int flags']
	case 430: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_thr_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_thr_create_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 431 void sys_thr_exit ['long *state']
	case 431: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_thr_exit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_thr_exit_enter, cpu, pc, arg0);
	}; break;
	// 432 int sys_thr_self ['long *id']
	case 432: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_thr_self_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_thr_self_enter, cpu, pc, arg0);
	}; break;
	// 433 int sys_thr_kill ['long id', 'int sig']
	case 433: {
		panda_noreturn = false;
		ctx.double_return = false;
		int64_t arg0 = get_s64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_thr_kill_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_thr_kill_enter, cpu, pc, arg0, arg1);
	}; break;
	// 436 int sys_jail_attach ['int jid']
	case 436: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_jail_attach_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_jail_attach_enter, cpu, pc, arg0);
	}; break;
	// 437 ssize_t sys_extattr_list_fd ['int fd', 'int attrnamespace', 'void *data', 'size_t nbytes']
	case 437: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_list_fd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_extattr_list_fd_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 438 ssize_t sys_extattr_list_file ['const char *path', 'int attrnamespace', 'void *data', 'size_t nbytes']
	case 438: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_list_file_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_extattr_list_file_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 439 ssize_t sys_extattr_list_link ['const char *path', 'int attrnamespace', 'void *data', 'size_t nbytes']
	case 439: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_extattr_list_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_extattr_list_link_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 441 int sys_ksem_timedwait ['semid_t id', 'const struct timespec *abstime']
	case 441: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ksem_timedwait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ksem_timedwait_enter, cpu, pc, arg0, arg1);
	}; break;
	// 442 int sys_thr_suspend ['const struct timespec *timeout']
	case 442: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_thr_suspend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_thr_suspend_enter, cpu, pc, arg0);
	}; break;
	// 443 int sys_thr_wake ['long id']
	case 443: {
		panda_noreturn = false;
		ctx.double_return = false;
		int64_t arg0 = get_s64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_thr_wake_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int64_t));
		}
		PPP_RUN_CB(on_sys_thr_wake_enter, cpu, pc, arg0);
	}; break;
	// 444 int sys_kldunloadf ['int fileid', 'int flags']
	case 444: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kldunloadf_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_kldunloadf_enter, cpu, pc, arg0, arg1);
	}; break;
	// 445 int sys_audit ['const void *record', 'unsigned length']
	case 445: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_audit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_audit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 446 int sys_auditon ['int cmd', 'void *data', 'unsigned length']
	case 446: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_auditon_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_auditon_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 447 int sys_getauid ['uid_t *auid']
	case 447: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getauid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getauid_enter, cpu, pc, arg0);
	}; break;
	// 448 int sys_setauid ['uid_t *auid']
	case 448: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setauid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setauid_enter, cpu, pc, arg0);
	}; break;
	// 449 int sys_getaudit ['struct auditinfo *auditinfo']
	case 449: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getaudit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getaudit_enter, cpu, pc, arg0);
	}; break;
	// 450 int sys_setaudit ['struct auditinfo *auditinfo']
	case 450: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setaudit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setaudit_enter, cpu, pc, arg0);
	}; break;
	// 451 int sys_getaudit_addr ['struct auditinfo_addr *auditinfo_addr', 'unsigned length']
	case 451: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getaudit_addr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getaudit_addr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 452 int sys_setaudit_addr ['struct auditinfo_addr *auditinfo_addr', 'unsigned length']
	case 452: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setaudit_addr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setaudit_addr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 453 int sys_auditctl ['const char *path']
	case 453: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_auditctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_auditctl_enter, cpu, pc, arg0);
	}; break;
	// 454 int sys__umtx_op ['void *obj', 'int op', 'u_long val', 'void *uaddr1', 'void *uaddr2']
	case 454: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int64_t arg2 = get_s64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys__umtx_op_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys__umtx_op_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 455 int sys_thr_new ['struct thr_param *param', 'int param_size']
	case 455: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_thr_new_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_thr_new_enter, cpu, pc, arg0, arg1);
	}; break;
	// 456 int sys_sigqueue ['pid_t pid', 'int signum', 'void *value']
	case 456: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigqueue_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigqueue_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 457 int sys_kmq_open ['const char *path', 'int flags', 'mode_t mode', 'const struct mq_attr *attr']
	case 457: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kmq_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kmq_open_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 458 int sys_kmq_setattr ['int mqd', 'const struct mq_attr *attr', 'struct mq_attr *oattr']
	case 458: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kmq_setattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kmq_setattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 459 int sys_kmq_timedreceive ['int mqd', 'char *msg_ptr', 'size_t msg_len', 'unsigned *msg_prio', 'const struct timespec *abs_timeout']
	case 459: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kmq_timedreceive_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kmq_timedreceive_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 460 int sys_kmq_timedsend ['int mqd', 'const char *msg_ptr', 'size_t msg_len', 'unsigned msg_prio', 'const struct timespec *abs_timeout']
	case 460: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kmq_timedsend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kmq_timedsend_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 461 int sys_kmq_notify ['int mqd', 'const struct sigevent *sigev']
	case 461: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kmq_notify_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kmq_notify_enter, cpu, pc, arg0, arg1);
	}; break;
	// 462 int sys_kmq_unlink ['const char *path']
	case 462: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kmq_unlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kmq_unlink_enter, cpu, pc, arg0);
	}; break;
	// 463 int sys_abort2 ['const char *why', 'int nargs', 'void **args']
	case 463: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_abort2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_abort2_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 464 int sys_thr_set_name ['long id', 'const char *name']
	case 464: {
		panda_noreturn = false;
		ctx.double_return = false;
		int64_t arg0 = get_s64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_thr_set_name_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_thr_set_name_enter, cpu, pc, arg0, arg1);
	}; break;
	// 465 int sys_aio_fsync ['int op', 'struct aiocb *aiocbp']
	case 465: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_fsync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_fsync_enter, cpu, pc, arg0, arg1);
	}; break;
	// 466 int sys_rtprio_thread ['int function', 'lwpid_t lwpid', 'struct rtprio *rtp']
	case 466: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rtprio_thread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_rtprio_thread_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 471 int sys_sctp_peeloff ['int sd', 'uint32_t name']
	case 471: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sctp_peeloff_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sctp_peeloff_enter, cpu, pc, arg0, arg1);
	}; break;
	// 472 int sys_sctp_generic_sendmsg ['int sd', 'void *msg', 'int mlen', 'struct sockaddr *to', '__socklen_t tolen', 'struct sctp_sndrcvinfo *sinfo', 'int flags']
	case 472: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		int32_t arg6 = get_s32(cpu, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sctp_generic_sendmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sctp_generic_sendmsg_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 473 int sys_sctp_generic_sendmsg_iov ['int sd', 'struct iovec *iov', 'int iovlen', 'struct sockaddr *to', '__socklen_t tolen', 'struct sctp_sndrcvinfo *sinfo', 'int flags']
	case 473: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		int32_t arg6 = get_s32(cpu, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sctp_generic_sendmsg_iov_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sctp_generic_sendmsg_iov_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 474 int sys_sctp_generic_recvmsg ['int sd', 'struct iovec *iov', 'int iovlen', 'struct sockaddr *from', '__socklen_t *fromlenaddr', 'struct sctp_sndrcvinfo *sinfo', 'int *msg_flags']
	case 474: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		uint64_t arg6 = get_64(cpu, 6);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sctp_generic_recvmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
			memcpy(ctx.args[6], &arg6, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sctp_generic_recvmsg_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6);
	}; break;
	// 475 ssize_t sys_pread ['int fd', 'void *buf', 'size_t nbyte', 'off_t offset']
	case 475: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pread_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pread_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 476 ssize_t sys_pwrite ['int fd', 'const void *buf', 'size_t nbyte', 'off_t offset']
	case 476: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pwrite_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pwrite_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 478 off_t sys_lseek ['int fd', 'off_t offset', 'int whence']
	case 478: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lseek_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_lseek_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 479 int sys_truncate ['const char *path', 'off_t length']
	case 479: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_truncate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_truncate_enter, cpu, pc, arg0, arg1);
	}; break;
	// 480 int sys_ftruncate ['int fd', 'off_t length']
	case 480: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ftruncate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ftruncate_enter, cpu, pc, arg0, arg1);
	}; break;
	// 481 int sys_thr_kill2 ['pid_t pid', 'long id', 'int sig']
	case 481: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_thr_kill2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_thr_kill2_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 482 int sys_shm_open ['const char *path', 'int flags', 'mode_t mode']
	case 482: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shm_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_shm_open_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 483 int sys_shm_unlink ['const char *path']
	case 483: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shm_unlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_shm_unlink_enter, cpu, pc, arg0);
	}; break;
	// 484 int sys_cpuset ['cpusetid_t *setid']
	case 484: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cpuset_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_cpuset_enter, cpu, pc, arg0);
	}; break;
	// 485 int sys_cpuset_setid ['cpuwhich_t which', 'id_t id', 'cpusetid_t setid']
	case 485: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cpuset_setid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_cpuset_setid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 486 int sys_cpuset_getid ['cpulevel_t level', 'cpuwhich_t which', 'id_t id', 'cpusetid_t *setid']
	case 486: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cpuset_getid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_cpuset_getid_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 487 int sys_cpuset_getaffinity ['cpulevel_t level', 'cpuwhich_t which', 'id_t id', 'size_t cpusetsize', 'cpuset_t *mask']
	case 487: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cpuset_getaffinity_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_cpuset_getaffinity_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 488 int sys_cpuset_setaffinity ['cpulevel_t level', 'cpuwhich_t which', 'id_t id', 'size_t cpusetsize', 'const cpuset_t *mask']
	case 488: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cpuset_setaffinity_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_cpuset_setaffinity_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 489 int sys_faccessat ['int fd', 'const char *path', 'int amode', 'int flag']
	case 489: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_faccessat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_faccessat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 490 int sys_fchmodat ['int fd', 'const char *path', 'mode_t mode', 'int flag']
	case 490: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchmodat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fchmodat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 491 int sys_fchownat ['int fd', 'const char *path', 'uid_t uid', 'gid_t gid', 'int flag']
	case 491: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchownat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fchownat_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 492 int sys_fexecve ['int fd', 'char **argv', 'char **envv']
	case 492: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fexecve_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fexecve_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 493 int sys_fstatat ['int fd', 'const char *path', 'struct freebsd11_stat *buf', 'int flag']
	case 493: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fstatat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 494 int sys_futimesat ['int fd', 'const char *path', 'struct timeval *times']
	case 494: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_futimesat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_futimesat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 495 int sys_linkat ['int fd1', 'const char *path1', 'int fd2', 'const char *path2', 'int flag']
	case 495: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_linkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_linkat_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 496 int sys_mkdirat ['int fd', 'const char *path', 'mode_t mode']
	case 496: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mkdirat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mkdirat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 497 int sys_mkfifoat ['int fd', 'const char *path', 'mode_t mode']
	case 497: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mkfifoat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mkfifoat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 498 int sys_mknodat ['int fd', 'const char *path', 'mode_t mode', 'uint32_t dev']
	case 498: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mknodat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_mknodat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 499 int sys_openat ['int fd', 'const char *path', 'int flag', 'mode_t mode']
	case 499: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_openat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_openat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 500 ssize_t sys_readlinkat ['int fd', 'const char *path', 'char *buf', 'size_t bufsize']
	case 500: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_readlinkat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 501 int sys_renameat ['int oldfd', 'const char *old', 'int newfd', 'const char *new']
	case 501: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_renameat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_renameat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 502 int sys_symlinkat ['const char *path1', 'int fd', 'const char *path2']
	case 502: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_symlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_symlinkat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 503 int sys_unlinkat ['int fd', 'const char *path', 'int flag']
	case 503: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_unlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_unlinkat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 504 int sys_posix_openpt ['int flags']
	case 504: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_posix_openpt_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_posix_openpt_enter, cpu, pc, arg0);
	}; break;
	// 505 int sys_gssd_syscall ['const char *path']
	case 505: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_gssd_syscall_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_gssd_syscall_enter, cpu, pc, arg0);
	}; break;
	// 506 int sys_jail_get ['struct iovec *iovp', 'unsigned int iovcnt', 'int flags']
	case 506: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_jail_get_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_jail_get_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 507 int sys_jail_set ['struct iovec *iovp', 'unsigned int iovcnt', 'int flags']
	case 507: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_jail_set_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_jail_set_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 508 int sys_jail_remove ['int jid']
	case 508: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_jail_remove_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_jail_remove_enter, cpu, pc, arg0);
	}; break;
	// 509 int sys_closefrom ['int lowfd']
	case 509: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_closefrom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_closefrom_enter, cpu, pc, arg0);
	}; break;
	// 510 int sys___semctl ['int semid', 'int semnum', 'int cmd', 'union semun *arg']
	case 510: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___semctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys___semctl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 511 int sys_msgctl ['int msqid', 'int cmd', 'struct msqid_ds *buf']
	case 511: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msgctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_msgctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 512 int sys_shmctl ['int shmid', 'int cmd', 'struct shmid_ds *buf']
	case 512: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_shmctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 513 int sys_lpathconf ['const char *path', 'int name']
	case 513: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lpathconf_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_lpathconf_enter, cpu, pc, arg0, arg1);
	}; break;
	// 516 int sys_cap_enter ['void']
	case 516: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_cap_enter_enter, cpu, pc);
	}; break;
	// 517 int sys_cap_getmode ['unsigned *modep']
	case 517: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cap_getmode_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_cap_getmode_enter, cpu, pc, arg0);
	}; break;
	// 518 int sys_pdfork ['int *fdp', 'int flags']
	case 518: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pdfork_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_pdfork_enter, cpu, pc, arg0, arg1);
	}; break;
	// 519 int sys_pdkill ['int fd', 'int signum']
	case 519: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pdkill_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_pdkill_enter, cpu, pc, arg0, arg1);
	}; break;
	// 520 int sys_pdgetpid ['int fd', 'pid_t *pidp']
	case 520: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pdgetpid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pdgetpid_enter, cpu, pc, arg0, arg1);
	}; break;
	// 522 int sys_pselect ['int nd', 'fd_set *in', 'fd_set *ou', 'fd_set *ex', 'const struct timespec *ts', 'const sigset_t *sm']
	case 522: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pselect_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pselect_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 523 int sys_getloginclass ['char *namebuf', 'size_t namelen']
	case 523: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getloginclass_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getloginclass_enter, cpu, pc, arg0, arg1);
	}; break;
	// 524 int sys_setloginclass ['const char *namebuf']
	case 524: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setloginclass_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setloginclass_enter, cpu, pc, arg0);
	}; break;
	// 525 int sys_rctl_get_racct ['const void *inbufp', 'size_t inbuflen', 'void *outbufp', 'size_t outbuflen']
	case 525: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rctl_get_racct_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rctl_get_racct_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 526 int sys_rctl_get_rules ['const void *inbufp', 'size_t inbuflen', 'void *outbufp', 'size_t outbuflen']
	case 526: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rctl_get_rules_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rctl_get_rules_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 527 int sys_rctl_get_limits ['const void *inbufp', 'size_t inbuflen', 'void *outbufp', 'size_t outbuflen']
	case 527: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rctl_get_limits_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rctl_get_limits_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 528 int sys_rctl_add_rule ['const void *inbufp', 'size_t inbuflen', 'void *outbufp', 'size_t outbuflen']
	case 528: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rctl_add_rule_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rctl_add_rule_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 529 int sys_rctl_remove_rule ['const void *inbufp', 'size_t inbuflen', 'void *outbufp', 'size_t outbuflen']
	case 529: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rctl_remove_rule_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rctl_remove_rule_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 530 int sys_posix_fallocate ['int fd', 'off_t offset', 'off_t len']
	case 530: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_posix_fallocate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_posix_fallocate_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 531 int sys_posix_fadvise ['int fd', 'off_t offset', 'off_t len', 'int advice']
	case 531: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_posix_fadvise_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_posix_fadvise_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 532 int sys_wait6 ['idtype_t idtype', 'id_t id', 'int *status', 'int options', 'struct __wrusage *wrusage', 'siginfo_t *info']
	case 532: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_wait6_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_wait6_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 533 int sys_cap_rights_limit ['int fd', 'cap_rights_t *rightsp']
	case 533: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cap_rights_limit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_cap_rights_limit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 534 int sys_cap_ioctls_limit ['int fd', 'const u_long *cmds', 'size_t ncmds']
	case 534: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cap_ioctls_limit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_cap_ioctls_limit_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 535 ssize_t sys_cap_ioctls_get ['int fd', 'u_long *cmds', 'size_t maxcmds']
	case 535: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cap_ioctls_get_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_cap_ioctls_get_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 536 int sys_cap_fcntls_limit ['int fd', 'uint32_t fcntlrights']
	case 536: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cap_fcntls_limit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_cap_fcntls_limit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 537 int sys_cap_fcntls_get ['int fd', 'uint32_t *fcntlrightsp']
	case 537: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cap_fcntls_get_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_cap_fcntls_get_enter, cpu, pc, arg0, arg1);
	}; break;
	// 538 int sys_bindat ['int fd', 'int s', 'const struct sockaddr *name', 'int namelen']
	case 538: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_bindat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_bindat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 539 int sys_connectat ['int fd', 'int s', 'const struct sockaddr *name', 'int namelen']
	case 539: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_connectat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_connectat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 540 int sys_chflagsat ['int fd', 'const char *path', 'u_long flags', 'int atflag']
	case 540: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int64_t arg2 = get_s64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chflagsat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_chflagsat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 541 int sys_accept4 ['int s', 'struct sockaddr *name', '__socklen_t *anamelen', 'int flags']
	case 541: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_accept4_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_accept4_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 542 int sys_pipe2 ['int *fildes', 'int flags']
	case 542: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pipe2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_pipe2_enter, cpu, pc, arg0, arg1);
	}; break;
	// 543 int sys_aio_mlock ['struct aiocb *aiocbp']
	case 543: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_aio_mlock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_aio_mlock_enter, cpu, pc, arg0);
	}; break;
	// 544 int sys_procctl ['idtype_t idtype', 'id_t id', 'int com', 'void *data']
	case 544: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_procctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_procctl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 545 int sys_ppoll ['struct pollfd *fds', 'unsigned nfds', 'const struct timespec *ts', 'const sigset_t *set']
	case 545: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ppoll_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ppoll_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 546 int sys_futimens ['int fd', 'struct timespec *times']
	case 546: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_futimens_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_futimens_enter, cpu, pc, arg0, arg1);
	}; break;
	// 547 int sys_utimensat ['int fd', 'const char *path', 'struct timespec *times', 'int flag']
	case 547: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utimensat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_utimensat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 550 int sys_fdatasync ['int fd']
	case 550: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fdatasync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fdatasync_enter, cpu, pc, arg0);
	}; break;
	// 551 int sys_fstat ['int fd', 'struct stat *sb']
	case 551: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 552 int sys_fstatat ['int fd', 'const char *path', 'struct stat *buf', 'int flag']
	case 552: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fstatat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 553 int sys_fhstat ['const struct fhandle *u_fhp', 'struct stat *sb']
	case 553: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fhstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fhstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 554 ssize_t sys_getdirentries ['int fd', 'char *buf', 'size_t count', 'off_t *basep']
	case 554: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdirentries_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getdirentries_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 555 int sys_statfs ['const char *path', 'struct statfs *buf']
	case 555: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_statfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_statfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 556 int sys_fstatfs ['int fd', 'struct statfs *buf']
	case 556: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fstatfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 557 int sys_getfsstat ['struct statfs *buf', 'long bufsize', 'int mode']
	case 557: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getfsstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getfsstat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 558 int sys_fhstatfs ['const struct fhandle *u_fhp', 'struct statfs *buf']
	case 558: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fhstatfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fhstatfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 559 int sys_mknodat ['int fd', 'const char *path', 'mode_t mode', 'dev_t dev']
	case 559: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mknodat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mknodat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 560 int sys_kevent ['int fd', 'struct kevent *changelist', 'int nchanges', 'struct kevent *eventlist', 'int nevents', 'const struct timespec *timeout']
	case 560: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kevent_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kevent_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 561 int sys_cpuset_getdomain ['cpulevel_t level', 'cpuwhich_t which', 'id_t id', 'size_t domainsetsize', 'domainset_t *mask', 'int *policy']
	case 561: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cpuset_getdomain_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_cpuset_getdomain_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 562 int sys_cpuset_setdomain ['cpulevel_t level', 'cpuwhich_t which', 'id_t id', 'size_t domainsetsize', 'domainset_t *mask', 'int policy']
	case 562: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		int32_t arg5 = get_s32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_cpuset_setdomain_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_cpuset_setdomain_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 563 int sys_getrandom ['void *buf', 'size_t buflen', 'unsigned int flags']
	case 563: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getrandom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getrandom_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 564 int sys_getfhat ['int fd', 'char *path', 'struct fhandle *fhp', 'int flags']
	case 564: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getfhat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getfhat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 565 int sys_fhlink ['struct fhandle *fhp', 'const char *to']
	case 565: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fhlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fhlink_enter, cpu, pc, arg0, arg1);
	}; break;
	// 566 int sys_fhlinkat ['struct fhandle *fhp', 'int tofd', 'const char *to', '']
	case 566: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fhlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fhlinkat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 567 int sys_fhreadlink ['struct fhandle *fhp', 'char *buf', 'size_t bufsize']
	case 567: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fhreadlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fhreadlink_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 568 int sys_funlinkat ['int dfd', 'const char *path', 'int fd', 'int flag']
	case 568: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_funlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_funlinkat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 569 ssize_t sys_copy_file_range ['int infd', 'off_t *inoffp', 'int outfd', 'off_t *outoffp', 'size_t len', 'unsigned int flags']
	case 569: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_copy_file_range_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_copy_file_range_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 570 int sys___sysctlbyname ['const char *name', 'size_t namelen', 'void *old', 'size_t *oldlenp', 'void *new', 'size_t newlen']
	case 570: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___sysctlbyname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys___sysctlbyname_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 571 int sys_shm_open2 ['const char *path', 'int flags', 'mode_t mode', 'int shmflags', 'const char *name']
	case 571: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shm_open2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_shm_open2_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 572 int sys_shm_rename ['const char *path_from', 'const char *path_to', 'int flags']
	case 572: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shm_rename_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_shm_rename_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 573 int sys_sigfastblock ['int cmd', 'uint32_t *ptr']
	case 573: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigfastblock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sigfastblock_enter, cpu, pc, arg0, arg1);
	}; break;
	// 574 int sys___realpathat ['int fd', 'const char *path', 'char *buf', 'size_t size', 'int flags']
	case 574: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys___realpathat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys___realpathat_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 575 int sys_close_range ['unsigned lowfd', 'unsigned highfd', 'int flags']
	case 575: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_close_range_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_close_range_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 576 int sys_rpctls_syscall ['int op', 'const char *path']
	case 576: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rpctls_syscall_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_rpctls_syscall_enter, cpu, pc, arg0, arg1);
	}; break;
	default:
		panda_noreturn = false;
		PPP_RUN_CB(on_unknown_sys_enter, cpu, pc, ctx.no);
	} // switch (ctx.no)

	PPP_RUN_CB(on_all_sys_enter, cpu, pc, ctx.no);
	PPP_RUN_CB(on_all_sys_enter2, cpu, pc, call, &ctx);
	if (!panda_noreturn) {
		struct hook h;
		h.addr = ctx.retaddr;
		h.asid = ctx.asid;
		h.cb.start_block_exec = hook_syscall_return;
		h.type = PANDA_CB_START_BLOCK_EXEC;
		h.enabled = true;
		h.km = MODE_ANY; //you'd expect this to be user only
		hooks_add_hook(&h);

		running_syscalls[std::make_pair(ctx.retaddr, ctx.asid)] = ctx;
	}
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */