#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls2_info.h"
#include "hooks/hooks_int_fns.h"
#include "hw_proc_id/hw_proc_id_ext.h"

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
void syscall_enter_switch_linux_mips64n32(CPUState *cpu, target_ptr_t pc, int static_callno) {
#if defined(TARGET_MIPS) && defined(TARGET_MIPS64)
	CPUArchState *env = (CPUArchState*)cpu->env_ptr;
	syscall_ctx_t ctx = {0};
	if (static_callno == -1) {
	  ctx.no = env->active_tc.gpr[2];
	} else {
	  ctx.no = static_callno;
	}
	ctx.asid = get_id(cpu);
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
	// 5000 long sys_read ['unsigned int fd', 'char __user *buf', 'size_t count']
	case 5000: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_read_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_read_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5001 long sys_write ['unsigned int fd', 'const char __user *buf', 'size_t count']
	case 5001: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_write_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_write_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5002 long sys_open ['const char __user *filename', 'int flags', 'umode_t mode']
	case 5002: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_open_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5003 long sys_close ['unsigned int fd']
	case 5003: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_close_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_close_enter, cpu, pc, arg0);
	}; break;
	// 5004 long sys_newstat ['const char __user *filename', 'struct stat __user *statbuf']
	case 5004: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_newstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5005 long sys_newfstat ['unsigned int fd', 'struct stat __user *statbuf']
	case 5005: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newfstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_newfstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5006 long sys_newlstat ['const char __user *filename', 'struct stat __user *statbuf']
	case 5006: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newlstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_newlstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5007 long sys_poll ['struct pollfd __user *ufds', 'unsigned int nfds', 'int timeout']
	case 5007: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_poll_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_poll_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5008 long sys_lseek ['unsigned int fd', 'off_t offset', 'unsigned int whence']
	case 5008: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lseek_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lseek_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5009 long sys_old_mmap ['struct mmap_arg_struct __user *arg']
	case 5009: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_old_mmap_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_old_mmap_enter, cpu, pc, arg0);
	}; break;
	// 5010 long sys_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot']
	case 5010: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mprotect_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mprotect_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5011 long sys_munmap ['unsigned long addr', 'size_t len']
	case 5011: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_munmap_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_munmap_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5012 long sys_brk ['unsigned long brk']
	case 5012: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_brk_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_brk_enter, cpu, pc, arg0);
	}; break;
	// 5013 long sys_rt_sigaction ['int', 'const struct sigaction __user *', 'struct sigaction __user *', 'size_t']
	case 5013: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5014 long sys_rt_sigprocmask ['int how', 'sigset_t __user *set', 'sigset_t __user *oset', 'size_t sigsetsize']
	case 5014: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5015 long sys_ioctl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
	case 5015: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ioctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ioctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5016 long sys_pread64 ['unsigned int fd', 'char __user *buf', 'size_t count', 'loff_t pos']
	case 5016: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = (uint64_t)get_32(cpu, &ctx, 4) << 32 | (uint64_t)get_32(cpu, &ctx, 3);
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
	// 5017 long sys_pwrite64 ['unsigned int fd', 'const char __user *buf', 'size_t count', 'loff_t pos']
	case 5017: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint64_t arg3 = (uint64_t)get_32(cpu, &ctx, 4) << 32 | (uint64_t)get_32(cpu, &ctx, 3);
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
	// 5018 long sys_readv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
	case 5018: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_readv_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5019 long sys_writev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
	case 5019: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_writev_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_writev_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5020 long sys_access ['const char __user *filename', 'int mode']
	case 5020: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_access_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_access_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5021 long sys_pipe ['int __user *fildes']
	case 5021: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pipe_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pipe_enter, cpu, pc, arg0);
	}; break;
	// 5022 long sys_select ['int n', 'fd_set __user *inp', 'fd_set __user *outp', 'fd_set __user *exp', 'struct __kernel_old_timeval __user *tvp']
	case 5022: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5023 long sys_sched_yield ['void']
	case 5023: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_sched_yield_enter, cpu, pc);
	}; break;
	// 5024 long sys_mremap ['unsigned long addr', 'unsigned long old_len', 'unsigned long new_len', 'unsigned long flags', 'unsigned long new_addr']
	case 5024: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5025 long sys_msync ['unsigned long start', 'size_t len', 'int flags']
	case 5025: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_msync_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5026 long sys_mincore ['unsigned long start', 'size_t len', 'unsigned char __user *vec']
	case 5026: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mincore_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mincore_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5027 long sys_madvise ['unsigned long start', 'size_t len', 'int behavior']
	case 5027: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_madvise_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_madvise_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5028 long sys_shmget ['key_t key', 'size_t size', 'int flag']
	case 5028: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmget_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_shmget_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5029 long sys_shmat ['int shmid', 'char __user *shmaddr', 'int shmflg']
	case 5029: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_shmat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5030 long sys_old_shmctl ['int shmid', 'int cmd', 'struct shmid_ds __user *buf']
	case 5030: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_old_shmctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_old_shmctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5031 long sys_dup ['unsigned int fildes']
	case 5031: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_dup_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_dup_enter, cpu, pc, arg0);
	}; break;
	// 5032 long sys_dup2 ['unsigned int oldfd', 'unsigned int newfd']
	case 5032: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_dup2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_dup2_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5033 long sys_pause ['void']
	case 5033: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_pause_enter, cpu, pc);
	}; break;
	// 5034 long sys_nanosleep ['struct __kernel_timespec __user *rqtp', 'struct __kernel_timespec __user *rmtp']
	case 5034: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nanosleep_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_nanosleep_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5035 long sys_getitimer ['int which', 'struct __kernel_old_itimerval __user *value']
	case 5035: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getitimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getitimer_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5036 long sys_setitimer ['int which', 'struct __kernel_old_itimerval __user *value', 'struct __kernel_old_itimerval __user *ovalue']
	case 5036: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setitimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setitimer_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5037 long sys_alarm ['unsigned int seconds']
	case 5037: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_alarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_alarm_enter, cpu, pc, arg0);
	}; break;
	// 5038 long sys_getpid ['void']
	case 5038: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getpid_enter, cpu, pc);
	}; break;
	// 5039 long sys_sendfile64 ['int out_fd', 'int in_fd', 'loff_t __user *offset', 'size_t count']
	case 5039: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5040 long sys_socket ['int', 'int', 'int']
	case 5040: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_socket_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_socket_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5041 long sys_connect ['int', 'struct sockaddr __user *', 'int']
	case 5041: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_connect_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_connect_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5042 long sys_accept ['int', 'struct sockaddr __user *', 'int __user *']
	case 5042: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_accept_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_accept_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5043 long sys_sendto ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int']
	case 5043: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		int32_t arg5 = get_s32(cpu, &ctx, 5);
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
	// 5044 long sys_recvfrom ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int __user *']
	case 5044: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
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
	// 5045 long sys_sendmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
	case 5045: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sendmsg_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5046 long sys_recvmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
	case 5046: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_recvmsg_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5047 long sys_shutdown ['int', 'int']
	case 5047: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shutdown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_shutdown_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5048 long sys_bind ['int', 'struct sockaddr __user *', 'int']
	case 5048: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_bind_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_bind_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5049 long sys_listen ['int', 'int']
	case 5049: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_listen_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_listen_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5050 long sys_getsockname ['int', 'struct sockaddr __user *', 'int __user *']
	case 5050: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getsockname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getsockname_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5051 long sys_getpeername ['int', 'struct sockaddr __user *', 'int __user *']
	case 5051: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getpeername_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getpeername_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5052 long sys_socketpair ['int', 'int', 'int', 'int __user *']
	case 5052: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5053 long sys_setsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int optlen']
	case 5053: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
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
	// 5054 long sys_getsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int __user *optlen']
	case 5054: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5055 long sys_clone ['unsigned long', 'unsigned long', 'int __user *', 'int __user *', 'unsigned long']
	case 5055: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5056 long sys_fork ['void']
	case 5056: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_fork_enter, cpu, pc);
	}; break;
	// 5057 long sys_execve ['const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp']
	case 5057: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_execve_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_execve_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5058 long sys_exit ['int error_code']
	case 5058: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_exit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_exit_enter, cpu, pc, arg0);
	}; break;
	// 5059 long sys_wait4 ['pid_t pid', 'int __user *stat_addr', 'int options', 'struct rusage __user *ru']
	case 5059: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5060 long sys_kill ['pid_t pid', 'int sig']
	case 5060: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kill_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_kill_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5061 long sys_newuname ['struct new_utsname __user *name']
	case 5061: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newuname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_newuname_enter, cpu, pc, arg0);
	}; break;
	// 5062 long sys_semget ['key_t key', 'int nsems', 'int semflg']
	case 5062: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semget_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_semget_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5063 long sys_semop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops']
	case 5063: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semop_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_semop_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5064 long sys_old_semctl ['int semid', 'int semnum', 'int cmd', 'unsigned long arg']
	case 5064: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_old_semctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_old_semctl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5065 long sys_shmdt ['char __user *shmaddr']
	case 5065: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmdt_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_shmdt_enter, cpu, pc, arg0);
	}; break;
	// 5066 long sys_msgget ['key_t key', 'int msgflg']
	case 5066: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_msgget_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_msgget_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5067 long sys_msgsnd ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'int msgflg']
	case 5067: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
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
	// 5068 long sys_msgrcv ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'long msgtyp', 'int msgflg']
	case 5068: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
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
	// 5069 long sys_old_msgctl ['int msqid', 'int cmd', 'struct msqid_ds __user *buf']
	case 5069: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_old_msgctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_old_msgctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5070 long sys_fcntl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
	case 5070: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fcntl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fcntl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5071 long sys_flock ['unsigned int fd', 'unsigned int cmd']
	case 5071: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_flock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_flock_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5072 long sys_fsync ['unsigned int fd']
	case 5072: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fsync_enter, cpu, pc, arg0);
	}; break;
	// 5073 long sys_fdatasync ['unsigned int fd']
	case 5073: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fdatasync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fdatasync_enter, cpu, pc, arg0);
	}; break;
	// 5074 long sys_truncate ['const char __user *path', 'long length']
	case 5074: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_truncate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_truncate_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5075 long sys_ftruncate ['unsigned int fd', 'unsigned long length']
	case 5075: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ftruncate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ftruncate_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5076 long sys_getdents ['unsigned int fd', 'struct linux_dirent __user *dirent', 'unsigned int count']
	case 5076: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdents_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getdents_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5077 long sys_getcwd ['char __user *buf', 'unsigned long size']
	case 5077: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getcwd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getcwd_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5078 long sys_chdir ['const char __user *filename']
	case 5078: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chdir_enter, cpu, pc, arg0);
	}; break;
	// 5079 long sys_fchdir ['unsigned int fd']
	case 5079: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchdir_enter, cpu, pc, arg0);
	}; break;
	// 5080 long sys_rename ['const char __user *oldname', 'const char __user *newname']
	case 5080: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rename_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rename_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5081 long sys_mkdir ['const char __user *pathname', 'umode_t mode']
	case 5081: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mkdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mkdir_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5082 long sys_rmdir ['const char __user *pathname']
	case 5082: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rmdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rmdir_enter, cpu, pc, arg0);
	}; break;
	// 5083 long sys_creat ['const char __user *pathname', 'umode_t mode']
	case 5083: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_creat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_creat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5084 long sys_link ['const char __user *oldname', 'const char __user *newname']
	case 5084: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_link_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_link_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5085 long sys_unlink ['const char __user *pathname']
	case 5085: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_unlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_unlink_enter, cpu, pc, arg0);
	}; break;
	// 5086 long sys_symlink ['const char __user *old', 'const char __user *new']
	case 5086: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_symlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_symlink_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5087 long sys_readlink ['const char __user *path', 'char __user *buf', 'int bufsiz']
	case 5087: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_readlink_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5088 long sys_chmod ['const char __user *filename', 'umode_t mode']
	case 5088: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chmod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chmod_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5089 long sys_fchmod ['unsigned int fd', 'umode_t mode']
	case 5089: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchmod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchmod_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5090 long sys_chown ['const char __user *filename', 'uid_t user', 'gid_t group']
	case 5090: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5091 long sys_fchown ['unsigned int fd', 'uid_t user', 'gid_t group']
	case 5091: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5092 long sys_lchown ['const char __user *filename', 'uid_t user', 'gid_t group']
	case 5092: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lchown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lchown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5093 long sys_umask ['int mask']
	case 5093: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_umask_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_umask_enter, cpu, pc, arg0);
	}; break;
	// 5094 long sys_gettimeofday ['struct __kernel_old_timeval __user *tv', 'struct timezone __user *tz']
	case 5094: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_gettimeofday_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_gettimeofday_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5095 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
	case 5095: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getrlimit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getrlimit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5096 long sys_getrusage ['int who', 'struct rusage __user *ru']
	case 5096: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getrusage_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getrusage_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5097 long sys_sysinfo ['struct sysinfo __user *info']
	case 5097: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sysinfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sysinfo_enter, cpu, pc, arg0);
	}; break;
	// 5098 long sys_times ['struct tms __user *tbuf']
	case 5098: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_times_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_times_enter, cpu, pc, arg0);
	}; break;
	// 5099 long sys_ptrace ['long request', 'long pid', 'unsigned long addr', 'unsigned long data']
	case 5099: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5100 long sys_getuid ['void']
	case 5100: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getuid_enter, cpu, pc);
	}; break;
	// 5101 long sys_syslog ['int type', 'char __user *buf', 'int len']
	case 5101: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_syslog_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_syslog_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5102 long sys_getgid ['void']
	case 5102: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getgid_enter, cpu, pc);
	}; break;
	// 5103 long sys_setuid ['uid_t uid']
	case 5103: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setuid_enter, cpu, pc, arg0);
	}; break;
	// 5104 long sys_setgid ['gid_t gid']
	case 5104: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setgid_enter, cpu, pc, arg0);
	}; break;
	// 5105 long sys_geteuid ['void']
	case 5105: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_geteuid_enter, cpu, pc);
	}; break;
	// 5106 long sys_getegid ['void']
	case 5106: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getegid_enter, cpu, pc);
	}; break;
	// 5107 long sys_setpgid ['pid_t pid', 'pid_t pgid']
	case 5107: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setpgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setpgid_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5108 long sys_getppid ['void']
	case 5108: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getppid_enter, cpu, pc);
	}; break;
	// 5109 long sys_getpgrp ['void']
	case 5109: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getpgrp_enter, cpu, pc);
	}; break;
	// 5110 long sys_setsid ['void']
	case 5110: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_setsid_enter, cpu, pc);
	}; break;
	// 5111 long sys_setreuid ['uid_t ruid', 'uid_t euid']
	case 5111: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setreuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setreuid_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5112 long sys_setregid ['gid_t rgid', 'gid_t egid']
	case 5112: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setregid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setregid_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5113 long sys_getgroups ['int gidsetsize', 'gid_t __user *grouplist']
	case 5113: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getgroups_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getgroups_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5114 long sys_setgroups ['int gidsetsize', 'gid_t __user *grouplist']
	case 5114: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setgroups_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setgroups_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5115 long sys_setresuid ['uid_t ruid', 'uid_t euid', 'uid_t suid']
	case 5115: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setresuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setresuid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5116 long sys_getresuid ['uid_t __user *ruid', 'uid_t __user *euid', 'uid_t __user *suid']
	case 5116: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getresuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getresuid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5117 long sys_setresgid ['gid_t rgid', 'gid_t egid', 'gid_t sgid']
	case 5117: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setresgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setresgid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5118 long sys_getresgid ['gid_t __user *rgid', 'gid_t __user *egid', 'gid_t __user *sgid']
	case 5118: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getresgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getresgid_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5119 long sys_getpgid ['pid_t pid']
	case 5119: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getpgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getpgid_enter, cpu, pc, arg0);
	}; break;
	// 5120 long sys_setfsuid ['uid_t uid']
	case 5120: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setfsuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setfsuid_enter, cpu, pc, arg0);
	}; break;
	// 5121 long sys_setfsgid ['gid_t gid']
	case 5121: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setfsgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setfsgid_enter, cpu, pc, arg0);
	}; break;
	// 5122 long sys_getsid ['pid_t pid']
	case 5122: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getsid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getsid_enter, cpu, pc, arg0);
	}; break;
	// 5123 long sys_capget ['cap_user_header_t header', 'cap_user_data_t dataptr']
	case 5123: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_capget_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_capget_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5124 long sys_capset ['cap_user_header_t header', 'const cap_user_data_t data']
	case 5124: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_capset_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_capset_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5125 long sys_rt_sigpending ['sigset_t __user *set', 'size_t sigsetsize']
	case 5125: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigpending_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigpending_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5126 long sys_rt_sigtimedwait ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct __kernel_timespec __user *uts', 'size_t sigsetsize']
	case 5126: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5127 long sys_rt_sigqueueinfo ['pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
	case 5127: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigqueueinfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigqueueinfo_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5128 long sys_rt_sigsuspend ['sigset_t __user *unewset', 'size_t sigsetsize']
	case 5128: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigsuspend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigsuspend_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5129 long sys_sigaltstack ['const struct sigaltstack __user *uss', 'struct sigaltstack __user *uoss']
	case 5129: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sigaltstack_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sigaltstack_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5130 long sys_utime ['char __user *filename', 'struct utimbuf __user *times']
	case 5130: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_utime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5131 long sys_mknod ['const char __user *filename', 'umode_t mode', 'unsigned dev']
	case 5131: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mknod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mknod_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5132 long sys_personality ['unsigned int personality']
	case 5132: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_personality_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_personality_enter, cpu, pc, arg0);
	}; break;
	// 5133 long sys_ustat ['unsigned dev', 'struct ustat __user *ubuf']
	case 5133: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ustat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ustat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5134 long sys_statfs ['const char __user *path', 'struct statfs __user *buf']
	case 5134: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_statfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_statfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5135 long sys_fstatfs ['unsigned int fd', 'struct statfs __user *buf']
	case 5135: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fstatfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5136 long sys_sysfs ['int option', 'unsigned long arg1', 'unsigned long arg2']
	case 5136: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sysfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sysfs_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5137 long sys_getpriority ['int which', 'int who']
	case 5137: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getpriority_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_getpriority_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5138 long sys_setpriority ['int which', 'int who', 'int niceval']
	case 5138: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setpriority_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setpriority_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5139 long sys_sched_setparam ['pid_t pid', 'struct sched_param __user *param']
	case 5139: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setparam_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_setparam_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5140 long sys_sched_getparam ['pid_t pid', 'struct sched_param __user *param']
	case 5140: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getparam_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_getparam_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5141 long sys_sched_setscheduler ['pid_t pid', 'int policy', 'struct sched_param __user *param']
	case 5141: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setscheduler_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_setscheduler_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5142 long sys_sched_getscheduler ['pid_t pid']
	case 5142: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getscheduler_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sched_getscheduler_enter, cpu, pc, arg0);
	}; break;
	// 5143 long sys_sched_get_priority_max ['int policy']
	case 5143: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_get_priority_max_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sched_get_priority_max_enter, cpu, pc, arg0);
	}; break;
	// 5144 long sys_sched_get_priority_min ['int policy']
	case 5144: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_get_priority_min_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sched_get_priority_min_enter, cpu, pc, arg0);
	}; break;
	// 5145 long sys_sched_rr_get_interval ['pid_t pid', 'struct __kernel_timespec __user *interval']
	case 5145: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_rr_get_interval_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_rr_get_interval_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5146 long sys_mlock ['unsigned long start', 'size_t len']
	case 5146: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mlock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mlock_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5147 long sys_munlock ['unsigned long start', 'size_t len']
	case 5147: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_munlock_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_munlock_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5148 long sys_mlockall ['int flags']
	case 5148: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mlockall_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_mlockall_enter, cpu, pc, arg0);
	}; break;
	// 5149 long sys_munlockall ['void']
	case 5149: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_munlockall_enter, cpu, pc);
	}; break;
	// 5150 long sys_vhangup ['void']
	case 5150: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_vhangup_enter, cpu, pc);
	}; break;
	// 5151 long sys_pivot_root ['const char __user *new_root', 'const char __user *put_old']
	case 5151: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pivot_root_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pivot_root_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5152 long sys_sysctl ['struct __sysctl_args __user *args']
	case 5152: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sysctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sysctl_enter, cpu, pc, arg0);
	}; break;
	// 5153 long sys_prctl ['int option', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
	case 5153: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5154 long sys_adjtimex ['struct __kernel_timex __user *txc_p']
	case 5154: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_adjtimex_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_adjtimex_enter, cpu, pc, arg0);
	}; break;
	// 5155 long sys_setrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
	case 5155: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setrlimit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setrlimit_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5156 long sys_chroot ['const char __user *filename']
	case 5156: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chroot_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chroot_enter, cpu, pc, arg0);
	}; break;
	// 5157 long sys_sync ['void']
	case 5157: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_sync_enter, cpu, pc);
	}; break;
	// 5158 long sys_acct ['const char __user *name']
	case 5158: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_acct_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_acct_enter, cpu, pc, arg0);
	}; break;
	// 5159 long sys_settimeofday ['struct __kernel_old_timeval __user *tv', 'struct timezone __user *tz']
	case 5159: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_settimeofday_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_settimeofday_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5160 long sys_mount ['char __user *dev_name', 'char __user *dir_name', 'char __user *type', 'unsigned long flags', 'void __user *data']
	case 5160: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5161 long sys_umount ['char __user *name', 'int flags']
	case 5161: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_umount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_umount_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5162 long sys_swapon ['const char __user *specialfile', 'int swap_flags']
	case 5162: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_swapon_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_swapon_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5163 long sys_swapoff ['const char __user *specialfile']
	case 5163: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_swapoff_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_swapoff_enter, cpu, pc, arg0);
	}; break;
	// 5164 long sys_reboot ['int magic1', 'int magic2', 'unsigned int cmd', 'void __user *arg']
	case 5164: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5165 long sys_sethostname ['char __user *name', 'int len']
	case 5165: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sethostname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sethostname_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5166 long sys_setdomainname ['char __user *name', 'int len']
	case 5166: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setdomainname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setdomainname_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5167, 5170, 5171, 5173, 5174, 5175, 5176, 5177, 5193, 5236, 5277 long sys_ni_syscall ['void']
	case 5167: case 5170: case 5171: case 5173: case 5174: case 5175: case 5176: case 5177: case 5193: case 5236: case 5277: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_ni_syscall_enter, cpu, pc);
	}; break;
	// 5168 long sys_init_module ['void __user *umod', 'unsigned long len', 'const char __user *uargs']
	case 5168: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_init_module_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_init_module_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5169 long sys_delete_module ['const char __user *name_user', 'unsigned int flags']
	case 5169: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_delete_module_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_delete_module_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5172 long sys_quotactl ['unsigned int cmd', 'const char __user *special', 'qid_t id', 'void __user *addr']
	case 5172: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5178 long sys_gettid ['void']
	case 5178: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_gettid_enter, cpu, pc);
	}; break;
	// 5179 long sys_readahead ['int fd', 'loff_t offset', 'size_t count']
	case 5179: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint64_t arg1 = (uint64_t)get_32(cpu, &ctx, 2) << 32 | (uint64_t)get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readahead_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_readahead_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5180 long sys_setxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
	case 5180: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
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
	// 5181 long sys_lsetxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
	case 5181: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
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
	// 5182 long sys_fsetxattr ['int fd', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
	case 5182: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
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
	// 5183 long sys_getxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
	case 5183: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5184 long sys_lgetxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
	case 5184: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5185 long sys_fgetxattr ['int fd', 'const char __user *name', 'void __user *value', 'size_t size']
	case 5185: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5186 long sys_listxattr ['const char __user *path', 'char __user *list', 'size_t size']
	case 5186: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_listxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_listxattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5187 long sys_llistxattr ['const char __user *path', 'char __user *list', 'size_t size']
	case 5187: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_llistxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_llistxattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5188 long sys_flistxattr ['int fd', 'char __user *list', 'size_t size']
	case 5188: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_flistxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_flistxattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5189 long sys_removexattr ['const char __user *path', 'const char __user *name']
	case 5189: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_removexattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_removexattr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5190 long sys_lremovexattr ['const char __user *path', 'const char __user *name']
	case 5190: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lremovexattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lremovexattr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5191 long sys_fremovexattr ['int fd', 'const char __user *name']
	case 5191: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fremovexattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fremovexattr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5192 long sys_tkill ['pid_t pid', 'int sig']
	case 5192: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_tkill_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_tkill_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5194 long sys_futex ['u32 __user *uaddr', 'int op', 'u32 val', 'struct __kernel_timespec __user *utime', 'u32 __user *uaddr2', 'u32 val3']
	case 5194: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
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
	// 5195 long sys_sched_setaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
	case 5195: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setaffinity_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_setaffinity_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5196 long sys_sched_getaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
	case 5196: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getaffinity_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_getaffinity_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5200 long sys_io_setup ['unsigned nr_reqs', 'aio_context_t __user *ctx']
	case 5200: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_setup_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_setup_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5201 long sys_io_destroy ['aio_context_t ctx']
	case 5201: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_destroy_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_destroy_enter, cpu, pc, arg0);
	}; break;
	// 5202 long sys_io_getevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct __kernel_timespec __user *timeout']
	case 5202: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5203 long sys_io_submit ['aio_context_t', 'long', 'struct iocb __user * __user *']
	case 5203: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_submit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_submit_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5204 long sys_io_cancel ['aio_context_t ctx_id', 'struct iocb __user *iocb', 'struct io_event __user *result']
	case 5204: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_cancel_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_cancel_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5205 long sys_exit_group ['int error_code']
	case 5205: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_exit_group_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_exit_group_enter, cpu, pc, arg0);
	}; break;
	// 5206 long sys_lookup_dcookie ['u64 cookie64', 'char __user *buf', 'size_t len']
	case 5206: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = (uint64_t)get_32(cpu, &ctx, 1) << 32 | (uint64_t)get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 2);
		uint32_t arg2 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lookup_dcookie_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lookup_dcookie_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5207 long sys_epoll_create ['int size']
	case 5207: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_epoll_create_enter, cpu, pc, arg0);
	}; break;
	// 5208 long sys_epoll_ctl ['int epfd', 'int op', 'int fd', 'struct epoll_event __user *event']
	case 5208: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5209 long sys_epoll_wait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout']
	case 5209: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
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
	// 5210 long sys_remap_file_pages ['unsigned long start', 'unsigned long size', 'unsigned long prot', 'unsigned long pgoff', 'unsigned long flags']
	case 5210: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5211 void sys_rt_sigreturn ['void']
	case 5211: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_rt_sigreturn_enter, cpu, pc);
	}; break;
	// 5212 long sys_set_tid_address ['int __user *tidptr']
	case 5212: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_set_tid_address_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_set_tid_address_enter, cpu, pc, arg0);
	}; break;
	// 5213 long sys_restart_syscall ['void']
	case 5213: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_restart_syscall_enter, cpu, pc);
	}; break;
	// 5214 long sys_semtimedop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops', 'const struct __kernel_timespec __user *timeout']
	case 5214: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5215 long sys_fadvise64_64 ['int fd', 'loff_t offset', 'loff_t len', 'int advice']
	case 5215: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint64_t arg1 = (uint64_t)get_32(cpu, &ctx, 2) << 32 | (uint64_t)get_32(cpu, &ctx, 1);
		uint64_t arg2 = (uint64_t)get_32(cpu, &ctx, 4) << 32 | (uint64_t)get_32(cpu, &ctx, 3);
		int32_t arg3 = get_s32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fadvise64_64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fadvise64_64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5216 long sys_timer_create ['clockid_t which_clock', 'struct sigevent __user *timer_event_spec', 'timer_t __user *created_timer_id']
	case 5216: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_create_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5217 long sys_timer_settime ['timer_t timer_id', 'int flags', 'const struct __kernel_itimerspec __user *new_setting', 'struct __kernel_itimerspec __user *old_setting']
	case 5217: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5218 long sys_timer_gettime ['timer_t timer_id', 'struct __kernel_itimerspec __user *setting']
	case 5218: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_gettime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5219 long sys_timer_getoverrun ['timer_t timer_id']
	case 5219: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_getoverrun_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_getoverrun_enter, cpu, pc, arg0);
	}; break;
	// 5220 long sys_timer_delete ['timer_t timer_id']
	case 5220: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_delete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_delete_enter, cpu, pc, arg0);
	}; break;
	// 5221 long sys_clock_settime ['clockid_t which_clock', 'const struct __kernel_timespec __user *tp']
	case 5221: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_settime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clock_settime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5222 long sys_clock_gettime ['clockid_t which_clock', 'struct __kernel_timespec __user *tp']
	case 5222: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clock_gettime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5223 long sys_clock_getres ['clockid_t which_clock', 'struct __kernel_timespec __user *tp']
	case 5223: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_getres_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clock_getres_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5224 long sys_clock_nanosleep ['clockid_t which_clock', 'int flags', 'const struct __kernel_timespec __user *rqtp', 'struct __kernel_timespec __user *rmtp']
	case 5224: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5225 long sys_tgkill ['pid_t tgid', 'pid_t pid', 'int sig']
	case 5225: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_tgkill_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_tgkill_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5226 long sys_utimes ['char __user *filename', 'struct __kernel_old_timeval __user *utimes']
	case 5226: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utimes_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_utimes_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5227 long sys_mbind ['unsigned long start', 'unsigned long len', 'unsigned long mode', 'const unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned flags']
	case 5227: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
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
	// 5228 long sys_get_mempolicy ['int __user *policy', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned long addr', 'unsigned long flags']
	case 5228: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5229 long sys_set_mempolicy ['int mode', 'const unsigned long __user *nmask', 'unsigned long maxnode']
	case 5229: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_set_mempolicy_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_set_mempolicy_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5230 long sys_mq_open ['const char __user *name', 'int oflag', 'umode_t mode', 'struct mq_attr __user *attr']
	case 5230: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5231 long sys_mq_unlink ['const char __user *name']
	case 5231: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_unlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mq_unlink_enter, cpu, pc, arg0);
	}; break;
	// 5232 long sys_mq_timedsend ['mqd_t mqdes', 'const char __user *msg_ptr', 'size_t msg_len', 'unsigned int msg_prio', 'const struct __kernel_timespec __user *abs_timeout']
	case 5232: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5233 long sys_mq_timedreceive ['mqd_t mqdes', 'char __user *msg_ptr', 'size_t msg_len', 'unsigned int __user *msg_prio', 'const struct __kernel_timespec __user *abs_timeout']
	case 5233: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5234 long sys_mq_notify ['mqd_t mqdes', 'const struct sigevent __user *notification']
	case 5234: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_notify_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mq_notify_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5235 long sys_mq_getsetattr ['mqd_t mqdes', 'const struct mq_attr __user *mqstat', 'struct mq_attr __user *omqstat']
	case 5235: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_getsetattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mq_getsetattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5237 long sys_waitid ['int which', 'pid_t pid', 'struct siginfo __user *infop', 'int options', 'struct rusage __user *ru']
	case 5237: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5239 long sys_add_key ['const char __user *_type', 'const char __user *_description', 'const void __user *_payload', 'size_t plen', 'key_serial_t destringid']
	case 5239: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5240 long sys_request_key ['const char __user *_type', 'const char __user *_description', 'const char __user *_callout_info', 'key_serial_t destringid']
	case 5240: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5241 long sys_keyctl ['int cmd', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
	case 5241: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5243 long sys_inotify_init ['void']
	case 5243: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_inotify_init_enter, cpu, pc);
	}; break;
	// 5244 long sys_inotify_add_watch ['int fd', 'const char __user *path', 'u32 mask']
	case 5244: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_inotify_add_watch_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_inotify_add_watch_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5245 long sys_inotify_rm_watch ['int fd', '__s32 wd']
	case 5245: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_inotify_rm_watch_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_inotify_rm_watch_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5246 long sys_migrate_pages ['pid_t pid', 'unsigned long maxnode', 'const unsigned long __user *from', 'const unsigned long __user *to']
	case 5246: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_migrate_pages_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_migrate_pages_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5247 long sys_openat ['int dfd', 'const char __user *filename', 'int flags', 'umode_t mode']
	case 5247: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5248 long sys_mkdirat ['int dfd', 'const char __user *pathname', 'umode_t mode']
	case 5248: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mkdirat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mkdirat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5249 long sys_mknodat ['int dfd', 'const char __user *filename', 'umode_t mode', 'unsigned dev']
	case 5249: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5250 long sys_fchownat ['int dfd', 'const char __user *filename', 'uid_t user', 'gid_t group', 'int flag']
	case 5250: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
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
	// 5251 long sys_futimesat ['int dfd', 'const char __user *filename', 'struct __kernel_old_timeval __user *utimes']
	case 5251: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_futimesat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_futimesat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5252 long sys_newfstatat ['int dfd', 'const char __user *filename', 'struct stat __user *statbuf', 'int flag']
	case 5252: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newfstatat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_newfstatat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5253 long sys_unlinkat ['int dfd', 'const char __user *pathname', 'int flag']
	case 5253: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_unlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_unlinkat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5254 long sys_renameat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname']
	case 5254: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5255 long sys_linkat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'int flags']
	case 5255: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
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
	// 5256 long sys_symlinkat ['const char __user *oldname', 'int newdfd', 'const char __user *newname']
	case 5256: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_symlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_symlinkat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5257 long sys_readlinkat ['int dfd', 'const char __user *path', 'char __user *buf', 'int bufsiz']
	case 5257: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
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
	// 5258 long sys_fchmodat ['int dfd', 'const char __user *filename', 'umode_t mode']
	case 5258: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchmodat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchmodat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5259 long sys_faccessat ['int dfd', 'const char __user *filename', 'int mode']
	case 5259: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_faccessat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_faccessat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5260 long sys_pselect6 ['int', 'fd_set __user *', 'fd_set __user *', 'fd_set __user *', 'struct __kernel_timespec __user *', 'void __user *']
	case 5260: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
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
	// 5261 long sys_ppoll ['struct pollfd __user *', 'unsigned int', 'struct __kernel_timespec __user *', 'const sigset_t __user *', 'size_t']
	case 5261: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5262 long sys_unshare ['unsigned long unshare_flags']
	case 5262: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_unshare_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_unshare_enter, cpu, pc, arg0);
	}; break;
	// 5263 long sys_splice ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
	case 5263: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
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
	// 5264 long sys_sync_file_range ['int fd', 'loff_t offset', 'loff_t nbytes', 'unsigned int flags']
	case 5264: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint64_t arg1 = (uint64_t)get_32(cpu, &ctx, 2) << 32 | (uint64_t)get_32(cpu, &ctx, 1);
		uint64_t arg2 = (uint64_t)get_32(cpu, &ctx, 4) << 32 | (uint64_t)get_32(cpu, &ctx, 3);
		uint32_t arg3 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sync_file_range_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sync_file_range_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5265 long sys_tee ['int fdin', 'int fdout', 'size_t len', 'unsigned int flags']
	case 5265: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5266 long sys_vmsplice ['int fd', 'const struct iovec __user *iov', 'unsigned long nr_segs', 'unsigned int flags']
	case 5266: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5267 long sys_move_pages ['pid_t pid', 'unsigned long nr_pages', 'const void __user * __user *pages', 'const int __user *nodes', 'int __user *status', 'int flags']
	case 5267: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		int32_t arg5 = get_s32(cpu, &ctx, 5);
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
	// 5268 long sys_set_robust_list ['struct robust_list_head __user *head', 'size_t len']
	case 5268: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_set_robust_list_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_set_robust_list_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5269 long sys_get_robust_list ['int pid', 'struct robust_list_head __user * __user *head_ptr', 'size_t __user *len_ptr']
	case 5269: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_get_robust_list_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_get_robust_list_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5270 long sys_kexec_load ['unsigned long entry', 'unsigned long nr_segments', 'struct kexec_segment __user *segments', 'unsigned long flags']
	case 5270: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5271 long sys_getcpu ['unsigned __user *cpu', 'unsigned __user *node', 'struct getcpu_cache __user *cache']
	case 5271: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getcpu_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getcpu_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5272 long sys_epoll_pwait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout', 'const sigset_t __user *sigmask', 'size_t sigsetsize']
	case 5272: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
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
	// 5273 long sys_ioprio_set ['int which', 'int who', 'int ioprio']
	case 5273: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ioprio_set_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_ioprio_set_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5274 long sys_ioprio_get ['int which', 'int who']
	case 5274: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ioprio_get_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_ioprio_get_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5275 long sys_utimensat ['int dfd', 'const char __user *filename', 'struct __kernel_timespec __user *utimes', 'int flags']
	case 5275: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
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
	// 5276 long sys_signalfd ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask']
	case 5276: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_signalfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_signalfd_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5278 long sys_eventfd ['unsigned int count']
	case 5278: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_eventfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_eventfd_enter, cpu, pc, arg0);
	}; break;
	// 5279 long sys_fallocate ['int fd', 'int mode', 'loff_t offset', 'loff_t len']
	case 5279: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint64_t arg2 = (uint64_t)get_32(cpu, &ctx, 3) << 32 | (uint64_t)get_32(cpu, &ctx, 2);
		uint64_t arg3 = (uint64_t)get_32(cpu, &ctx, 5) << 32 | (uint64_t)get_32(cpu, &ctx, 4);
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
	// 5280 long sys_timerfd_create ['int clockid', 'int flags']
	case 5280: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timerfd_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_timerfd_create_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5281 long sys_timerfd_gettime ['int ufd', 'struct __kernel_itimerspec __user *otmr']
	case 5281: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timerfd_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timerfd_gettime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5282 long sys_timerfd_settime ['int ufd', 'int flags', 'const struct __kernel_itimerspec __user *utmr', 'struct __kernel_itimerspec __user *otmr']
	case 5282: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5283 long sys_signalfd4 ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask', 'int flags']
	case 5283: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
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
	// 5284 long sys_eventfd2 ['unsigned int count', 'int flags']
	case 5284: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_eventfd2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_eventfd2_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5285 long sys_epoll_create1 ['int flags']
	case 5285: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_create1_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_epoll_create1_enter, cpu, pc, arg0);
	}; break;
	// 5286 long sys_dup3 ['unsigned int oldfd', 'unsigned int newfd', 'int flags']
	case 5286: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_dup3_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_dup3_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5287 long sys_pipe2 ['int __user *fildes', 'int flags']
	case 5287: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pipe2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_pipe2_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5288 long sys_inotify_init1 ['int flags']
	case 5288: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_inotify_init1_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_inotify_init1_enter, cpu, pc, arg0);
	}; break;
	// 5289 long sys_preadv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
	case 5289: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5290 long sys_pwritev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
	case 5290: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5291 long sys_rt_tgsigqueueinfo ['pid_t tgid', 'pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
	case 5291: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5292 long sys_perf_event_open ['struct perf_event_attr __user *attr_uptr', 'pid_t pid', 'int cpu', 'int group_fd', 'unsigned long flags']
	case 5292: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5293 long sys_accept4 ['int', 'struct sockaddr __user *', 'int __user *', 'int']
	case 5293: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
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
	// 5294 long sys_recvmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags', 'struct __kernel_timespec __user *timeout']
	case 5294: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5295 long sys_fanotify_init ['unsigned int flags', 'unsigned int event_f_flags']
	case 5295: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fanotify_init_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fanotify_init_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5296 long sys_fanotify_mark ['int fanotify_fd', 'unsigned int flags', 'u64 mask', 'int fd', 'const char __user *pathname']
	case 5296: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint64_t arg2 = (uint64_t)get_32(cpu, &ctx, 3) << 32 | (uint64_t)get_32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 4);
		uint32_t arg4 = get_32(cpu, &ctx, 5);
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
	// 5297 long sys_prlimit64 ['pid_t pid', 'unsigned int resource', 'const struct rlimit64 __user *new_rlim', 'struct rlimit64 __user *old_rlim']
	case 5297: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5298 long sys_name_to_handle_at ['int dfd', 'const char __user *name', 'struct file_handle __user *handle', 'int __user *mnt_id', 'int flag']
	case 5298: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
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
	// 5299 long sys_open_by_handle_at ['int mountdirfd', 'struct file_handle __user *handle', 'int flags']
	case 5299: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_open_by_handle_at_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_open_by_handle_at_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5300 long sys_clock_adjtime ['clockid_t which_clock', 'struct __kernel_timex __user *tx']
	case 5300: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_adjtime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clock_adjtime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5301 long sys_syncfs ['int fd']
	case 5301: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_syncfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_syncfs_enter, cpu, pc, arg0);
	}; break;
	// 5302 long sys_sendmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags']
	case 5302: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5303 long sys_setns ['int fd', 'int nstype']
	case 5303: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setns_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setns_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5304 long sys_process_vm_readv ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
	case 5304: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
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
	// 5305 long sys_process_vm_writev ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
	case 5305: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
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
	// 5306 long sys_kcmp ['pid_t pid1', 'pid_t pid2', 'int type', 'unsigned long idx1', 'unsigned long idx2']
	case 5306: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5307 long sys_finit_module ['int fd', 'const char __user *uargs', 'int flags']
	case 5307: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_finit_module_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_finit_module_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5308 long sys_getdents64 ['unsigned int fd', 'struct linux_dirent64 __user *dirent', 'unsigned int count']
	case 5308: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdents64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getdents64_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5309 long sys_sched_setattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int flags']
	case 5309: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_setattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5310 long sys_sched_getattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int size', 'unsigned int flags']
	case 5310: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
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
	// 5311 long sys_renameat2 ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'unsigned int flags']
	case 5311: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
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
	// 5312 long sys_seccomp ['unsigned int op', 'unsigned int flags', 'void __user *uargs']
	case 5312: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_seccomp_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_seccomp_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5313 long sys_getrandom ['char __user *buf', 'size_t count', 'unsigned int flags']
	case 5313: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getrandom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getrandom_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5314 long sys_memfd_create ['const char __user *uname_ptr', 'unsigned int flags']
	case 5314: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_memfd_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_memfd_create_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5315 long sys_bpf ['int cmd', 'union bpf_attr *attr', 'unsigned int size']
	case 5315: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_bpf_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_bpf_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5316 long sys_execveat ['int dfd', 'const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp', 'int flags']
	case 5316: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
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
	// 5317 long sys_userfaultfd ['int flags']
	case 5317: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_userfaultfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_userfaultfd_enter, cpu, pc, arg0);
	}; break;
	// 5318 long sys_membarrier ['int cmd', 'int flags']
	case 5318: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_membarrier_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_membarrier_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5319 long sys_mlock2 ['unsigned long start', 'size_t len', 'int flags']
	case 5319: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mlock2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_mlock2_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5320 long sys_copy_file_range ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
	case 5320: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_copy_file_range_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_copy_file_range_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5321 long sys_preadv2 ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h', 'rwf_t flags']
	case 5321: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_preadv2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_preadv2_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5322 long sys_pwritev2 ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h', 'rwf_t flags']
	case 5322: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pwritev2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pwritev2_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5323 long sys_pkey_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot', 'int pkey']
	case 5323: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pkey_mprotect_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_pkey_mprotect_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5324 long sys_pkey_alloc ['unsigned long flags', 'unsigned long init_val']
	case 5324: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pkey_alloc_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pkey_alloc_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5325 long sys_pkey_free ['int pkey']
	case 5325: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pkey_free_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_pkey_free_enter, cpu, pc, arg0);
	}; break;
	// 5326 long sys_statx ['int dfd', 'const char __user *path', 'unsigned flags', 'unsigned mask', 'struct statx __user *buffer']
	case 5326: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_statx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_statx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5327 long sys_rseq ['struct rseq __user *rseq', 'uint32_t rseq_len', 'int flags', 'uint32_t sig']
	case 5327: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rseq_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_rseq_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5328 long sys_io_pgetevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct __kernel_timespec __user *timeout', 'const struct __aio_sigset *sig']
	case 5328: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_pgetevents_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_pgetevents_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5424 long sys_pidfd_send_signal ['int pidfd', 'int sig', 'siginfo_t __user *info', 'unsigned int flags']
	case 5424: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pidfd_send_signal_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pidfd_send_signal_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5425 long sys_io_uring_setup ['u32 entries', 'struct io_uring_params __user *p']
	case 5425: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_uring_setup_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_uring_setup_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5426 long sys_io_uring_enter ['unsigned int fd', 'u32 to_submit', 'u32 min_complete', 'u32 flags', 'const sigset_t __user *sig', 'size_t sigsz']
	case 5426: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		uint32_t arg5 = get_32(cpu, &ctx, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_uring_enter_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_uring_enter_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5427 long sys_io_uring_register ['unsigned int fd', 'unsigned int op', 'void __user *arg', 'unsigned int nr_args']
	case 5427: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_uring_register_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_uring_register_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5428 long sys_open_tree ['int dfd', 'const char __user *path', 'unsigned flags']
	case 5428: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_open_tree_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_open_tree_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5429 long sys_move_mount ['int from_dfd', 'const char __user *from_path', 'int to_dfd', 'const char __user *to_path', 'unsigned int ms_flags']
	case 5429: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		uint32_t arg4 = get_32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_move_mount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_move_mount_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5430 long sys_fsopen ['const char __user *fs_name', 'unsigned int flags']
	case 5430: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsopen_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fsopen_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5431 long sys_fsconfig ['int fs_fd', 'unsigned int cmd', 'const char __user *key', 'const void __user *value', 'int aux']
	case 5431: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		int32_t arg4 = get_s32(cpu, &ctx, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsconfig_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fsconfig_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5432 long sys_fsmount ['int fs_fd', 'unsigned int flags', 'unsigned int ms_flags']
	case 5432: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsmount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fsmount_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5433 long sys_fspick ['int dfd', 'const char __user *path', 'unsigned int flags']
	case 5433: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fspick_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fspick_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5434 long sys_pidfd_open ['pid_t pid', 'unsigned int flags']
	case 5434: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pidfd_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pidfd_open_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5435 long sys_clone3 ['struct clone_args __user *uargs', 'size_t size']
	case 5435: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clone3_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clone3_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5437 long sys_openat2 ['int dfd', 'const char __user *filename', 'struct open_how *how', 'size_t size']
	case 5437: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		uint32_t arg3 = get_32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_openat2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_openat2_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5438 long sys_pidfd_getfd ['int pidfd', 'int fd', 'unsigned int flags']
	case 5438: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		int32_t arg1 = get_s32(cpu, &ctx, 1);
		uint32_t arg2 = get_32(cpu, &ctx, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pidfd_getfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pidfd_getfd_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5439 long sys_faccessat2 ['int dfd', 'const char __user *filename', 'int mode', 'int flags']
	case 5439: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, &ctx, 0);
		uint32_t arg1 = get_32(cpu, &ctx, 1);
		int32_t arg2 = get_s32(cpu, &ctx, 2);
		int32_t arg3 = get_s32(cpu, &ctx, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_faccessat2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_faccessat2_enter, cpu, pc, arg0, arg1, arg2, arg3);
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
		h.cb.before_tcg_codegen = hook_syscall_return;
		h.type = PANDA_CB_BEFORE_TCG_CODEGEN;
		h.enabled = true;
		h.km = MODE_ANY; //you'd expect this to be user only
		hooks_add_hook(&h);

		running_syscalls[std::make_pair(ctx.retaddr, ctx.asid)] = ctx;
	}
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */