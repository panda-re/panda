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
void syscall_enter_switch_linux_mips64(CPUState *cpu, target_ptr_t pc, int static_callno) {
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
	// 5000, 6000 long sys_read ['unsigned int fd', 'char __user *buf', 'size_t count']
	case 5000: case 6000: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_read_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_read_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5001, 6001 long sys_write ['unsigned int fd', 'const char __user *buf', 'size_t count']
	case 5001: case 6001: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_write_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_write_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5002, 6002 long sys_open ['const char __user *filename', 'int flags', 'umode_t mode']
	case 5002: case 6002: {
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
	// 5003, 6003 long sys_close ['unsigned int fd']
	case 5003: case 6003: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_close_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_close_enter, cpu, pc, arg0);
	}; break;
	// 5004, 6004 long sys_newstat ['const char __user *filename', 'struct stat __user *statbuf']
	case 5004: case 6004: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_newstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5005, 6005 long sys_newfstat ['unsigned int fd', 'struct stat __user *statbuf']
	case 5005: case 6005: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newfstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_newfstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5006, 6006 long sys_newlstat ['const char __user *filename', 'struct stat __user *statbuf']
	case 5006: case 6006: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newlstat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_newlstat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5007, 6007 long sys_poll ['struct pollfd __user *ufds', 'unsigned int nfds', 'int timeout']
	case 5007: case 6007: {
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
	// 5008, 6008 long sys_lseek ['unsigned int fd', 'off_t offset', 'unsigned int whence']
	case 5008: case 6008: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lseek_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lseek_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5009, 6009 long sys_old_mmap ['struct mmap_arg_struct __user *arg']
	case 5009: case 6009: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_old_mmap_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_old_mmap_enter, cpu, pc, arg0);
	}; break;
	// 5010, 6010 long sys_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot']
	case 5010: case 6010: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mprotect_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mprotect_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5011, 6011 long sys_munmap ['unsigned long addr', 'size_t len']
	case 5011: case 6011: {
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
	// 5012, 6012 long sys_brk ['unsigned long brk']
	case 5012: case 6012: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_brk_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_brk_enter, cpu, pc, arg0);
	}; break;
	// 5013, 6013 long sys_rt_sigaction ['int', 'const struct sigaction __user *', 'struct sigaction __user *', 'size_t']
	case 5013: case 6013: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigaction_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigaction_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5014, 6014 long sys_rt_sigprocmask ['int how', 'sigset_t __user *set', 'sigset_t __user *oset', 'size_t sigsetsize']
	case 5014: case 6014: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigprocmask_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigprocmask_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5015, 6015 long sys_ioctl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
	case 5015: case 6015: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ioctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ioctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5016, 6016 long sys_pread64 ['unsigned int fd', 'char __user *buf', 'size_t count', 'loff_t pos']
	case 5016: case 6016: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pread64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pread64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5017, 6017 long sys_pwrite64 ['unsigned int fd', 'const char __user *buf', 'size_t count', 'loff_t pos']
	case 5017: case 6017: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pwrite64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pwrite64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5018, 6018 long sys_readv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
	case 5018: case 6018: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_readv_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5019, 6019 long sys_writev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
	case 5019: case 6019: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_writev_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_writev_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5020, 6020 long sys_access ['const char __user *filename', 'int mode']
	case 5020: case 6020: {
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
	// 5021, 6021 long sys_pipe ['int __user *fildes']
	case 5021: case 6021: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pipe_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pipe_enter, cpu, pc, arg0);
	}; break;
	// 5022, 6022 long sys_select ['int n', 'fd_set __user *inp', 'fd_set __user *outp', 'fd_set __user *exp', 'struct __kernel_old_timeval __user *tvp']
	case 5022: case 6022: {
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
	// 5023, 6023 long sys_sched_yield ['void']
	case 5023: case 6023: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_sched_yield_enter, cpu, pc);
	}; break;
	// 5024, 6024 long sys_mremap ['unsigned long addr', 'unsigned long old_len', 'unsigned long new_len', 'unsigned long flags', 'unsigned long new_addr']
	case 5024: case 6024: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mremap_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mremap_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5025, 6025 long sys_msync ['unsigned long start', 'size_t len', 'int flags']
	case 5025: case 6025: {
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
	// 5026, 6026 long sys_mincore ['unsigned long start', 'size_t len', 'unsigned char __user *vec']
	case 5026: case 6026: {
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
	// 5027, 6027 long sys_madvise ['unsigned long start', 'size_t len', 'int behavior']
	case 5027: case 6027: {
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
	// 5028, 6028 long sys_shmget ['key_t key', 'size_t size', 'int flag']
	case 5028: case 6028: {
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
	// 5029, 6029 long sys_shmat ['int shmid', 'char __user *shmaddr', 'int shmflg']
	case 5029: case 6029: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_shmat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_shmat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5030, 6030 long sys_old_shmctl ['int shmid', 'int cmd', 'struct shmid_ds __user *buf']
	case 5030: case 6030: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_old_shmctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_old_shmctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5031, 6031 long sys_dup ['unsigned int fildes']
	case 5031: case 6031: {
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
	// 5032, 6032 long sys_dup2 ['unsigned int oldfd', 'unsigned int newfd']
	case 5032: case 6032: {
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
	// 5033, 6033 long sys_pause ['void']
	case 5033: case 6033: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_pause_enter, cpu, pc);
	}; break;
	// 5034 long sys_nanosleep ['struct __kernel_timespec __user *rqtp', 'struct __kernel_timespec __user *rmtp']
	case 5034: {
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
	// 5035, 6035 long sys_getitimer ['int which', 'struct __kernel_old_itimerval __user *value']
	case 5035: case 6035: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getitimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getitimer_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5036, 6036 long sys_setitimer ['int which', 'struct __kernel_old_itimerval __user *value', 'struct __kernel_old_itimerval __user *ovalue']
	case 5036: case 6036: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setitimer_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setitimer_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5037, 6037 long sys_alarm ['unsigned int seconds']
	case 5037: case 6037: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_alarm_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_alarm_enter, cpu, pc, arg0);
	}; break;
	// 5038, 6038 long sys_getpid ['void']
	case 5038: case 6038: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getpid_enter, cpu, pc);
	}; break;
	// 5039, 6219 long sys_sendfile64 ['int out_fd', 'int in_fd', 'loff_t __user *offset', 'size_t count']
	case 5039: case 6219: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendfile64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sendfile64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5040, 6040 long sys_socket ['int', 'int', 'int']
	case 5040: case 6040: {
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
	// 5041, 6041 long sys_connect ['int', 'struct sockaddr __user *', 'int']
	case 5041: case 6041: {
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
	// 5042, 6042 long sys_accept ['int', 'struct sockaddr __user *', 'int __user *']
	case 5042: case 6042: {
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
	// 5043, 6043 long sys_sendto ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int']
	case 5043: case 6043: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		int32_t arg5 = get_s32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendto_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sendto_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5044, 6044 long sys_recvfrom ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int __user *']
	case 5044: case 6044: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvfrom_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_recvfrom_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5045, 6045 long sys_sendmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
	case 5045: case 6045: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sendmsg_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5046, 6046 long sys_recvmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
	case 5046: case 6046: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_recvmsg_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5047, 6047 long sys_shutdown ['int', 'int']
	case 5047: case 6047: {
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
	// 5048, 6048 long sys_bind ['int', 'struct sockaddr __user *', 'int']
	case 5048: case 6048: {
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
	// 5049, 6049 long sys_listen ['int', 'int']
	case 5049: case 6049: {
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
	// 5050, 6050 long sys_getsockname ['int', 'struct sockaddr __user *', 'int __user *']
	case 5050: case 6050: {
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
	// 5051, 6051 long sys_getpeername ['int', 'struct sockaddr __user *', 'int __user *']
	case 5051: case 6051: {
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
	// 5052, 6052 long sys_socketpair ['int', 'int', 'int', 'int __user *']
	case 5052: case 6052: {
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
	// 5053, 6053 long sys_setsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int optlen']
	case 5053: case 6053: {
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
	// 5054, 6054 long sys_getsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int __user *optlen']
	case 5054: case 6054: {
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
	// 5055, 6055 long sys_clone ['unsigned long', 'unsigned long', 'int __user *', 'int __user *', 'unsigned long']
	case 5055: case 6055: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clone_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clone_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5056, 6056 long sys_fork ['void']
	case 5056: case 6056: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_fork_enter, cpu, pc);
	}; break;
	// 5057, 6057 long sys_execve ['const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp']
	case 5057: case 6057: {
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
	// 5058, 6058 long sys_exit ['int error_code']
	case 5058: case 6058: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_exit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_exit_enter, cpu, pc, arg0);
	}; break;
	// 5059, 6059 long sys_wait4 ['pid_t pid', 'int __user *stat_addr', 'int options', 'struct rusage __user *ru']
	case 5059: case 6059: {
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
	// 5060, 6060 long sys_kill ['pid_t pid', 'int sig']
	case 5060: case 6060: {
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
	// 5061, 6061 long sys_newuname ['struct new_utsname __user *name']
	case 5061: case 6061: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newuname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_newuname_enter, cpu, pc, arg0);
	}; break;
	// 5062, 6062 long sys_semget ['key_t key', 'int nsems', 'int semflg']
	case 5062: case 6062: {
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
	// 5063, 6063 long sys_semop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops']
	case 5063: case 6063: {
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
	// 5064 long sys_old_semctl ['int semid', 'int semnum', 'int cmd', 'unsigned long arg']
	case 5064: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_old_semctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_old_semctl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5065, 6065 long sys_shmdt ['char __user *shmaddr']
	case 5065: case 6065: {
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
	// 5066, 6066 long sys_msgget ['key_t key', 'int msgflg']
	case 5066: case 6066: {
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
	// 5067, 6067 long sys_msgsnd ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'int msgflg']
	case 5067: case 6067: {
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
	// 5068, 6068 long sys_msgrcv ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'long msgtyp', 'int msgflg']
	case 5068: case 6068: {
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
	// 5069, 6069 long sys_old_msgctl ['int msqid', 'int cmd', 'struct msqid_ds __user *buf']
	case 5069: case 6069: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_old_msgctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_old_msgctl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5070, 6070 long sys_fcntl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
	case 5070: case 6070: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fcntl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fcntl_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5071, 6071 long sys_flock ['unsigned int fd', 'unsigned int cmd']
	case 5071: case 6071: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5072, 6072 long sys_fsync ['unsigned int fd']
	case 5072: case 6072: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fsync_enter, cpu, pc, arg0);
	}; break;
	// 5073, 6073 long sys_fdatasync ['unsigned int fd']
	case 5073: case 6073: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fdatasync_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fdatasync_enter, cpu, pc, arg0);
	}; break;
	// 5074, 6074 long sys_truncate ['const char __user *path', 'long length']
	case 5074: case 6074: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_truncate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
		}
		PPP_RUN_CB(on_sys_truncate_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5075, 6075 long sys_ftruncate ['unsigned int fd', 'unsigned long length']
	case 5075: case 6075: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ftruncate_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ftruncate_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5076, 6076 long sys_getdents ['unsigned int fd', 'struct linux_dirent __user *dirent', 'unsigned int count']
	case 5076: case 6076: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdents_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getdents_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5077, 6077 long sys_getcwd ['char __user *buf', 'unsigned long size']
	case 5077: case 6077: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getcwd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getcwd_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5078, 6078 long sys_chdir ['const char __user *filename']
	case 5078: case 6078: {
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
	// 5079, 6079 long sys_fchdir ['unsigned int fd']
	case 5079: case 6079: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchdir_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchdir_enter, cpu, pc, arg0);
	}; break;
	// 5080, 6080 long sys_rename ['const char __user *oldname', 'const char __user *newname']
	case 5080: case 6080: {
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
	// 5081, 6081 long sys_mkdir ['const char __user *pathname', 'umode_t mode']
	case 5081: case 6081: {
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
	// 5082, 6082 long sys_rmdir ['const char __user *pathname']
	case 5082: case 6082: {
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
	// 5083, 6083 long sys_creat ['const char __user *pathname', 'umode_t mode']
	case 5083: case 6083: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_creat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_creat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5084, 6084 long sys_link ['const char __user *oldname', 'const char __user *newname']
	case 5084: case 6084: {
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
	// 5085, 6085 long sys_unlink ['const char __user *pathname']
	case 5085: case 6085: {
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
	// 5086, 6086 long sys_symlink ['const char __user *old', 'const char __user *new']
	case 5086: case 6086: {
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
	// 5087, 6087 long sys_readlink ['const char __user *path', 'char __user *buf', 'int bufsiz']
	case 5087: case 6087: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_readlink_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5088, 6088 long sys_chmod ['const char __user *filename', 'umode_t mode']
	case 5088: case 6088: {
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
	// 5089, 6089 long sys_fchmod ['unsigned int fd', 'umode_t mode']
	case 5089: case 6089: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5090, 6090 long sys_chown ['const char __user *filename', 'uid_t user', 'gid_t group']
	case 5090: case 6090: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_chown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_chown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5091, 6091 long sys_fchown ['unsigned int fd', 'uid_t user', 'gid_t group']
	case 5091: case 6091: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5092, 6092 long sys_lchown ['const char __user *filename', 'uid_t user', 'gid_t group']
	case 5092: case 6092: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lchown_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lchown_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5093, 6093 long sys_umask ['int mask']
	case 5093: case 6093: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_umask_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_umask_enter, cpu, pc, arg0);
	}; break;
	// 5094, 6094 long sys_gettimeofday ['struct __kernel_old_timeval __user *tv', 'struct timezone __user *tz']
	case 5094: case 6094: {
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
	// 5095, 6095 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
	case 5095: case 6095: {
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
	// 5096, 6096 long sys_getrusage ['int who', 'struct rusage __user *ru']
	case 5096: case 6096: {
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
	// 5097, 6097 long sys_sysinfo ['struct sysinfo __user *info']
	case 5097: case 6097: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sysinfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sysinfo_enter, cpu, pc, arg0);
	}; break;
	// 5098, 6098 long sys_times ['struct tms __user *tbuf']
	case 5098: case 6098: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_times_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_times_enter, cpu, pc, arg0);
	}; break;
	// 5099, 6099 long sys_ptrace ['long request', 'long pid', 'unsigned long addr', 'unsigned long data']
	case 5099: case 6099: {
		panda_noreturn = false;
		ctx.double_return = false;
		int64_t arg0 = get_s64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ptrace_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ptrace_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5100, 6100 long sys_getuid ['void']
	case 5100: case 6100: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getuid_enter, cpu, pc);
	}; break;
	// 5101, 6101 long sys_syslog ['int type', 'char __user *buf', 'int len']
	case 5101: case 6101: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_syslog_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_syslog_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5102, 6102 long sys_getgid ['void']
	case 5102: case 6102: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getgid_enter, cpu, pc);
	}; break;
	// 5103, 6103 long sys_setuid ['uid_t uid']
	case 5103: case 6103: {
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
	// 5104, 6104 long sys_setgid ['gid_t gid']
	case 5104: case 6104: {
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
	// 5105, 6105 long sys_geteuid ['void']
	case 5105: case 6105: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_geteuid_enter, cpu, pc);
	}; break;
	// 5106, 6106 long sys_getegid ['void']
	case 5106: case 6106: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getegid_enter, cpu, pc);
	}; break;
	// 5107, 6107 long sys_setpgid ['pid_t pid', 'pid_t pgid']
	case 5107: case 6107: {
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
	// 5108, 6108 long sys_getppid ['void']
	case 5108: case 6108: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getppid_enter, cpu, pc);
	}; break;
	// 5109, 6109 long sys_getpgrp ['void']
	case 5109: case 6109: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_getpgrp_enter, cpu, pc);
	}; break;
	// 5110, 6110 long sys_setsid ['void']
	case 5110: case 6110: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_setsid_enter, cpu, pc);
	}; break;
	// 5111, 6111 long sys_setreuid ['uid_t ruid', 'uid_t euid']
	case 5111: case 6111: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5112, 6112 long sys_setregid ['gid_t rgid', 'gid_t egid']
	case 5112: case 6112: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5113, 6113 long sys_getgroups ['int gidsetsize', 'gid_t __user *grouplist']
	case 5113: case 6113: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getgroups_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getgroups_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5114, 6114 long sys_setgroups ['int gidsetsize', 'gid_t __user *grouplist']
	case 5114: case 6114: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setgroups_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_setgroups_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5115, 6115 long sys_setresuid ['uid_t ruid', 'uid_t euid', 'uid_t suid']
	case 5115: case 6115: {
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
	// 5116, 6116 long sys_getresuid ['uid_t __user *ruid', 'uid_t __user *euid', 'uid_t __user *suid']
	case 5116: case 6116: {
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
	// 5117, 6117 long sys_setresgid ['gid_t rgid', 'gid_t egid', 'gid_t sgid']
	case 5117: case 6117: {
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
	// 5118, 6118 long sys_getresgid ['gid_t __user *rgid', 'gid_t __user *egid', 'gid_t __user *sgid']
	case 5118: case 6118: {
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
	// 5119, 6119 long sys_getpgid ['pid_t pid']
	case 5119: case 6119: {
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
	// 5120, 6120 long sys_setfsuid ['uid_t uid']
	case 5120: case 6120: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setfsuid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setfsuid_enter, cpu, pc, arg0);
	}; break;
	// 5121, 6121 long sys_setfsgid ['gid_t gid']
	case 5121: case 6121: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setfsgid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_setfsgid_enter, cpu, pc, arg0);
	}; break;
	// 5122, 6122 long sys_getsid ['pid_t pid']
	case 5122: case 6122: {
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
	// 5123, 6123 long sys_capget ['cap_user_header_t header', 'cap_user_data_t dataptr']
	case 5123: case 6123: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_capget_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_capget_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5124, 6124 long sys_capset ['cap_user_header_t header', 'const cap_user_data_t data']
	case 5124: case 6124: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_capset_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_capset_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5125, 6125 long sys_rt_sigpending ['sigset_t __user *set', 'size_t sigsetsize']
	case 5125: case 6125: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigpending_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigpending_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5126 long sys_rt_sigtimedwait ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct __kernel_timespec __user *uts', 'size_t sigsetsize']
	case 5126: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigtimedwait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigtimedwait_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5127, 6127 long sys_rt_sigqueueinfo ['pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
	case 5127: case 6127: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigqueueinfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_rt_sigqueueinfo_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5128, 6128 long sys_rt_sigsuspend ['sigset_t __user *unewset', 'size_t sigsetsize']
	case 5128: case 6128: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_sigsuspend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_rt_sigsuspend_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5129, 6129 long sys_sigaltstack ['const struct sigaltstack __user *uss', 'struct sigaltstack __user *uoss']
	case 5129: case 6129: {
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
	// 5130 long sys_utime ['char __user *filename', 'struct utimbuf __user *times']
	case 5130: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_utime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5131, 6131 long sys_mknod ['const char __user *filename', 'umode_t mode', 'unsigned dev']
	case 5131: case 6131: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mknod_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mknod_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5132, 6132 long sys_personality ['unsigned int personality']
	case 5132: case 6132: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_personality_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_personality_enter, cpu, pc, arg0);
	}; break;
	// 5133, 6133 long sys_ustat ['unsigned dev', 'struct ustat __user *ubuf']
	case 5133: case 6133: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ustat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_ustat_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5134, 6134 long sys_statfs ['const char __user *path', 'struct statfs __user *buf']
	case 5134: case 6134: {
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
	// 5135, 6135 long sys_fstatfs ['unsigned int fd', 'struct statfs __user *buf']
	case 5135: case 6135: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fstatfs_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5136, 6136 long sys_sysfs ['int option', 'unsigned long arg1', 'unsigned long arg2']
	case 5136: case 6136: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sysfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sysfs_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5137, 6137 long sys_getpriority ['int which', 'int who']
	case 5137: case 6137: {
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
	// 5138, 6138 long sys_setpriority ['int which', 'int who', 'int niceval']
	case 5138: case 6138: {
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
	// 5139, 6139 long sys_sched_setparam ['pid_t pid', 'struct sched_param __user *param']
	case 5139: case 6139: {
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
	// 5140, 6140 long sys_sched_getparam ['pid_t pid', 'struct sched_param __user *param']
	case 5140: case 6140: {
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
	// 5141, 6141 long sys_sched_setscheduler ['pid_t pid', 'int policy', 'struct sched_param __user *param']
	case 5141: case 6141: {
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
	// 5142, 6142 long sys_sched_getscheduler ['pid_t pid']
	case 5142: case 6142: {
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
	// 5143, 6143 long sys_sched_get_priority_max ['int policy']
	case 5143: case 6143: {
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
	// 5144, 6144 long sys_sched_get_priority_min ['int policy']
	case 5144: case 6144: {
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
	// 5145, 6423 long sys_sched_rr_get_interval ['pid_t pid', 'struct __kernel_timespec __user *interval']
	case 5145: case 6423: {
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
	// 5146, 6146 long sys_mlock ['unsigned long start', 'size_t len']
	case 5146: case 6146: {
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
	// 5147, 6147 long sys_munlock ['unsigned long start', 'size_t len']
	case 5147: case 6147: {
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
	// 5148, 6148 long sys_mlockall ['int flags']
	case 5148: case 6148: {
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
	// 5149, 6149 long sys_munlockall ['void']
	case 5149: case 6149: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_munlockall_enter, cpu, pc);
	}; break;
	// 5150, 6150 long sys_vhangup ['void']
	case 5150: case 6150: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_vhangup_enter, cpu, pc);
	}; break;
	// 5151, 6151 long sys_pivot_root ['const char __user *new_root', 'const char __user *put_old']
	case 5151: case 6151: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pivot_root_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pivot_root_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5152, 6152 long sys_sysctl ['struct __sysctl_args __user *args']
	case 5152: case 6152: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sysctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sysctl_enter, cpu, pc, arg0);
	}; break;
	// 5153, 6153 long sys_prctl ['int option', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
	case 5153: case 6153: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_prctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_prctl_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5154 long sys_adjtimex ['struct __kernel_timex __user *txc_p']
	case 5154: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_adjtimex_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_adjtimex_enter, cpu, pc, arg0);
	}; break;
	// 5155, 6155 long sys_setrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
	case 5155: case 6155: {
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
	// 5156, 6156 long sys_chroot ['const char __user *filename']
	case 5156: case 6156: {
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
	// 5157, 6157 long sys_sync ['void']
	case 5157: case 6157: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_sync_enter, cpu, pc);
	}; break;
	// 5158, 6158 long sys_acct ['const char __user *name']
	case 5158: case 6158: {
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
	// 5159, 6159 long sys_settimeofday ['struct __kernel_old_timeval __user *tv', 'struct timezone __user *tz']
	case 5159: case 6159: {
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
	// 5160, 6160 long sys_mount ['char __user *dev_name', 'char __user *dir_name', 'char __user *type', 'unsigned long flags', 'void __user *data']
	case 5160: case 6160: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mount_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5161, 6161 long sys_umount ['char __user *name', 'int flags']
	case 5161: case 6161: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_umount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_umount_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5162, 6162 long sys_swapon ['const char __user *specialfile', 'int swap_flags']
	case 5162: case 6162: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_swapon_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_swapon_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5163, 6163 long sys_swapoff ['const char __user *specialfile']
	case 5163: case 6163: {
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
	// 5164, 6164 long sys_reboot ['int magic1', 'int magic2', 'unsigned int cmd', 'void __user *arg']
	case 5164: case 6164: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_reboot_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_reboot_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5165, 6165 long sys_sethostname ['char __user *name', 'int len']
	case 5165: case 6165: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sethostname_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_sethostname_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5166, 6166 long sys_setdomainname ['char __user *name', 'int len']
	case 5166: case 6166: {
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
	// 5167, 5170, 5171, 5173, 5174, 5175, 5176, 5177, 5193, 5236, 5277, 6167, 6170, 6171, 6173, 6174, 6175, 6176, 6177, 6193, 6240, 6281 long sys_ni_syscall ['void']
	case 5167: case 5170: case 5171: case 5173: case 5174: case 5175: case 5176: case 5177: case 5193: case 5236: case 5277: case 6167: case 6170: case 6171: case 6173: case 6174: case 6175: case 6176: case 6177: case 6193: case 6240: case 6281: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_ni_syscall_enter, cpu, pc);
	}; break;
	// 5168, 6168 long sys_init_module ['void __user *umod', 'unsigned long len', 'const char __user *uargs']
	case 5168: case 6168: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_init_module_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_init_module_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5169, 6169 long sys_delete_module ['const char __user *name_user', 'unsigned int flags']
	case 5169: case 6169: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_delete_module_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_delete_module_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5172, 6172 long sys_quotactl ['unsigned int cmd', 'const char __user *special', 'qid_t id', 'void __user *addr']
	case 5172: case 6172: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_quotactl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_quotactl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5178, 6178 long sys_gettid ['void']
	case 5178: case 6178: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_gettid_enter, cpu, pc);
	}; break;
	// 5179, 6179 long sys_readahead ['int fd', 'loff_t offset', 'size_t count']
	case 5179: case 6179: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5180, 6180 long sys_setxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
	case 5180: case 6180: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_setxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_setxattr_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5181, 6181 long sys_lsetxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
	case 5181: case 6181: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lsetxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_lsetxattr_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5182, 6182 long sys_fsetxattr ['int fd', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
	case 5182: case 6182: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsetxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fsetxattr_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5183, 6183 long sys_getxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
	case 5183: case 6183: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getxattr_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5184, 6184 long sys_lgetxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
	case 5184: case 6184: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lgetxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lgetxattr_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5185, 6185 long sys_fgetxattr ['int fd', 'const char __user *name', 'void __user *value', 'size_t size']
	case 5185: case 6185: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fgetxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fgetxattr_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5186, 6186 long sys_listxattr ['const char __user *path', 'char __user *list', 'size_t size']
	case 5186: case 6186: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_listxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_listxattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5187, 6187 long sys_llistxattr ['const char __user *path', 'char __user *list', 'size_t size']
	case 5187: case 6187: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_llistxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_llistxattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5188, 6188 long sys_flistxattr ['int fd', 'char __user *list', 'size_t size']
	case 5188: case 6188: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_flistxattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_flistxattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5189, 6189 long sys_removexattr ['const char __user *path', 'const char __user *name']
	case 5189: case 6189: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_removexattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_removexattr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5190, 6190 long sys_lremovexattr ['const char __user *path', 'const char __user *name']
	case 5190: case 6190: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lremovexattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_lremovexattr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5191, 6191 long sys_fremovexattr ['int fd', 'const char __user *name']
	case 5191: case 6191: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fremovexattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fremovexattr_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5192, 6192 long sys_tkill ['pid_t pid', 'int sig']
	case 5192: case 6192: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5194, 6422 long sys_futex ['u32 __user *uaddr', 'int op', 'u32 val', 'struct __kernel_timespec __user *utime', 'u32 __user *uaddr2', 'u32 val3']
	case 5194: case 6422: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_futex_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_futex_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5195, 6195 long sys_sched_setaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
	case 5195: case 6195: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setaffinity_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sched_setaffinity_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5196, 6196 long sys_sched_getaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
	case 5196: case 6196: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getaffinity_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sched_getaffinity_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5200, 6200 long sys_io_setup ['unsigned nr_reqs', 'aio_context_t __user *ctx']
	case 5200: case 6200: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_setup_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_io_setup_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5201, 6201 long sys_io_destroy ['aio_context_t ctx']
	case 5201: case 6201: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_destroy_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_io_destroy_enter, cpu, pc, arg0);
	}; break;
	// 5202 long sys_io_getevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct __kernel_timespec __user *timeout']
	case 5202: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		int64_t arg2 = get_s64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_getevents_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_io_getevents_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5203, 6203 long sys_io_submit ['aio_context_t', 'long', 'struct iocb __user * __user *']
	case 5203: case 6203: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_submit_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_io_submit_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5204, 6204 long sys_io_cancel ['aio_context_t ctx_id', 'struct iocb __user *iocb', 'struct io_event __user *result']
	case 5204: case 6204: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_cancel_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_io_cancel_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5205, 6205 long sys_exit_group ['int error_code']
	case 5205: case 6205: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_exit_group_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_exit_group_enter, cpu, pc, arg0);
	}; break;
	// 5206, 6206 long sys_lookup_dcookie ['u64 cookie64', 'char __user *buf', 'size_t len']
	case 5206: case 6206: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_lookup_dcookie_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_lookup_dcookie_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5207, 6207 long sys_epoll_create ['int size']
	case 5207: case 6207: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_epoll_create_enter, cpu, pc, arg0);
	}; break;
	// 5208, 6208 long sys_epoll_ctl ['int epfd', 'int op', 'int fd', 'struct epoll_event __user *event']
	case 5208: case 6208: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_ctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_epoll_ctl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5209, 6209 long sys_epoll_wait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout']
	case 5209: case 6209: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_wait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_epoll_wait_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5210, 6210 long sys_remap_file_pages ['unsigned long start', 'unsigned long size', 'unsigned long prot', 'unsigned long pgoff', 'unsigned long flags']
	case 5210: case 6210: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_remap_file_pages_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_remap_file_pages_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5211 void sys_rt_sigreturn ['void']
	case 5211: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_rt_sigreturn_enter, cpu, pc);
	}; break;
	// 5212, 6213 long sys_set_tid_address ['int __user *tidptr']
	case 5212: case 6213: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_set_tid_address_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_set_tid_address_enter, cpu, pc, arg0);
	}; break;
	// 5213, 6214 long sys_restart_syscall ['void']
	case 5213: case 6214: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_restart_syscall_enter, cpu, pc);
	}; break;
	// 5214, 6420 long sys_semtimedop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops', 'const struct __kernel_timespec __user *timeout']
	case 5214: case 6420: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semtimedop_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_semtimedop_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5215, 6216 long sys_fadvise64_64 ['int fd', 'loff_t offset', 'loff_t len', 'int advice']
	case 5215: case 6216: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
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
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_timer_create_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5217, 6409 long sys_timer_settime ['timer_t timer_id', 'int flags', 'const struct __kernel_itimerspec __user *new_setting', 'struct __kernel_itimerspec __user *old_setting']
	case 5217: case 6409: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_settime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_timer_settime_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5218, 6408 long sys_timer_gettime ['timer_t timer_id', 'struct __kernel_itimerspec __user *setting']
	case 5218: case 6408: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_timer_gettime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5219, 6223 long sys_timer_getoverrun ['timer_t timer_id']
	case 5219: case 6223: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_getoverrun_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_getoverrun_enter, cpu, pc, arg0);
	}; break;
	// 5220, 6224 long sys_timer_delete ['timer_t timer_id']
	case 5220: case 6224: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_delete_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_timer_delete_enter, cpu, pc, arg0);
	}; break;
	// 5221, 6404 long sys_clock_settime ['clockid_t which_clock', 'const struct __kernel_timespec __user *tp']
	case 5221: case 6404: {
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
	// 5222, 6403 long sys_clock_gettime ['clockid_t which_clock', 'struct __kernel_timespec __user *tp']
	case 5222: case 6403: {
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
	// 5223, 6406 long sys_clock_getres ['clockid_t which_clock', 'struct __kernel_timespec __user *tp']
	case 5223: case 6406: {
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
	// 5224, 6407 long sys_clock_nanosleep ['clockid_t which_clock', 'int flags', 'const struct __kernel_timespec __user *rqtp', 'struct __kernel_timespec __user *rmtp']
	case 5224: case 6407: {
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
	// 5225, 6229 long sys_tgkill ['pid_t tgid', 'pid_t pid', 'int sig']
	case 5225: case 6229: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5226 long sys_utimes ['char __user *filename', 'struct __kernel_old_timeval __user *utimes']
	case 5226: {
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
	// 5227, 6231 long sys_mbind ['unsigned long start', 'unsigned long len', 'unsigned long mode', 'const unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned flags']
	case 5227: case 6231: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mbind_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_mbind_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5228, 6232 long sys_get_mempolicy ['int __user *policy', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned long addr', 'unsigned long flags']
	case 5228: case 6232: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_get_mempolicy_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_get_mempolicy_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5229, 6233 long sys_set_mempolicy ['int mode', 'const unsigned long __user *nmask', 'unsigned long maxnode']
	case 5229: case 6233: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_set_mempolicy_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_set_mempolicy_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5230, 6234 long sys_mq_open ['const char __user *name', 'int oflag', 'umode_t mode', 'struct mq_attr __user *attr']
	case 5230: case 6234: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mq_open_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5231, 6235 long sys_mq_unlink ['const char __user *name']
	case 5231: case 6235: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_unlink_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mq_unlink_enter, cpu, pc, arg0);
	}; break;
	// 5232, 6418 long sys_mq_timedsend ['mqd_t mqdes', 'const char __user *msg_ptr', 'size_t msg_len', 'unsigned int msg_prio', 'const struct __kernel_timespec __user *abs_timeout']
	case 5232: case 6418: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_timedsend_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mq_timedsend_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5233, 6419 long sys_mq_timedreceive ['mqd_t mqdes', 'char __user *msg_ptr', 'size_t msg_len', 'unsigned int __user *msg_prio', 'const struct __kernel_timespec __user *abs_timeout']
	case 5233: case 6419: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_timedreceive_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mq_timedreceive_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5234, 6238 long sys_mq_notify ['mqd_t mqdes', 'const struct sigevent __user *notification']
	case 5234: case 6238: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_notify_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mq_notify_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5235, 6239 long sys_mq_getsetattr ['mqd_t mqdes', 'const struct mq_attr __user *mqstat', 'struct mq_attr __user *omqstat']
	case 5235: case 6239: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_getsetattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mq_getsetattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5237, 6241 long sys_waitid ['int which', 'pid_t pid', 'struct siginfo __user *infop', 'int options', 'struct rusage __user *ru']
	case 5237: case 6241: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_waitid_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_waitid_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5239, 6243 long sys_add_key ['const char __user *_type', 'const char __user *_description', 'const void __user *_payload', 'size_t plen', 'key_serial_t destringid']
	case 5239: case 6243: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_add_key_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_add_key_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5240, 6244 long sys_request_key ['const char __user *_type', 'const char __user *_description', 'const char __user *_callout_info', 'key_serial_t destringid']
	case 5240: case 6244: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_request_key_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_request_key_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5241, 6245 long sys_keyctl ['int cmd', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
	case 5241: case 6245: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_keyctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_keyctl_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5243, 6247 long sys_inotify_init ['void']
	case 5243: case 6247: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_inotify_init_enter, cpu, pc);
	}; break;
	// 5244, 6248 long sys_inotify_add_watch ['int fd', 'const char __user *path', 'u32 mask']
	case 5244: case 6248: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_inotify_add_watch_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_inotify_add_watch_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5245, 6249 long sys_inotify_rm_watch ['int fd', '__s32 wd']
	case 5245: case 6249: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5246, 6250 long sys_migrate_pages ['pid_t pid', 'unsigned long maxnode', 'const unsigned long __user *from', 'const unsigned long __user *to']
	case 5246: case 6250: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_migrate_pages_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_migrate_pages_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5247, 6251 long sys_openat ['int dfd', 'const char __user *filename', 'int flags', 'umode_t mode']
	case 5247: case 6251: {
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
	// 5248, 6252 long sys_mkdirat ['int dfd', 'const char __user *pathname', 'umode_t mode']
	case 5248: case 6252: {
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
	// 5249, 6253 long sys_mknodat ['int dfd', 'const char __user *filename', 'umode_t mode', 'unsigned dev']
	case 5249: case 6253: {
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
	// 5250, 6254 long sys_fchownat ['int dfd', 'const char __user *filename', 'uid_t user', 'gid_t group', 'int flag']
	case 5250: case 6254: {
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
	// 5251 long sys_futimesat ['int dfd', 'const char __user *filename', 'struct __kernel_old_timeval __user *utimes']
	case 5251: {
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
	// 5252, 6256 long sys_newfstatat ['int dfd', 'const char __user *filename', 'struct stat __user *statbuf', 'int flag']
	case 5252: case 6256: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_newfstatat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_newfstatat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5253, 6257 long sys_unlinkat ['int dfd', 'const char __user *pathname', 'int flag']
	case 5253: case 6257: {
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
	// 5254, 6258 long sys_renameat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname']
	case 5254: case 6258: {
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
	// 5255, 6259 long sys_linkat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'int flags']
	case 5255: case 6259: {
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
	// 5256, 6260 long sys_symlinkat ['const char __user *oldname', 'int newdfd', 'const char __user *newname']
	case 5256: case 6260: {
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
	// 5257, 6261 long sys_readlinkat ['int dfd', 'const char __user *path', 'char __user *buf', 'int bufsiz']
	case 5257: case 6261: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_readlinkat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_readlinkat_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5258, 6262 long sys_fchmodat ['int dfd', 'const char __user *filename', 'umode_t mode']
	case 5258: case 6262: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fchmodat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fchmodat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5259, 6263 long sys_faccessat ['int dfd', 'const char __user *filename', 'int mode']
	case 5259: case 6263: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_faccessat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_faccessat_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5260 long sys_pselect6 ['int', 'fd_set __user *', 'fd_set __user *', 'fd_set __user *', 'struct __kernel_timespec __user *', 'void __user *']
	case 5260: {
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
					PPP_CHECK_CB(on_sys_pselect6_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pselect6_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5261 long sys_ppoll ['struct pollfd __user *', 'unsigned int', 'struct __kernel_timespec __user *', 'const sigset_t __user *', 'size_t']
	case 5261: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ppoll_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ppoll_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5262, 6266 long sys_unshare ['unsigned long unshare_flags']
	case 5262: case 6266: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_unshare_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_unshare_enter, cpu, pc, arg0);
	}; break;
	// 5263, 6267 long sys_splice ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
	case 5263: case 6267: {
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
					PPP_CHECK_CB(on_sys_splice_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_splice_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5264, 6268 long sys_sync_file_range ['int fd', 'loff_t offset', 'loff_t nbytes', 'unsigned int flags']
	case 5264: case 6268: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
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
	// 5265, 6269 long sys_tee ['int fdin', 'int fdout', 'size_t len', 'unsigned int flags']
	case 5265: case 6269: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5266, 6270 long sys_vmsplice ['int fd', 'const struct iovec __user *iov', 'unsigned long nr_segs', 'unsigned int flags']
	case 5266: case 6270: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_vmsplice_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_vmsplice_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5267, 6271 long sys_move_pages ['pid_t pid', 'unsigned long nr_pages', 'const void __user * __user *pages', 'const int __user *nodes', 'int __user *status', 'int flags']
	case 5267: case 6271: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		int32_t arg5 = get_s32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_move_pages_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_move_pages_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5268, 6273 long sys_set_robust_list ['struct robust_list_head __user *head', 'size_t len']
	case 5268: case 6273: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_set_robust_list_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_set_robust_list_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5269, 6272 long sys_get_robust_list ['int pid', 'struct robust_list_head __user * __user *head_ptr', 'size_t __user *len_ptr']
	case 5269: case 6272: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_get_robust_list_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_get_robust_list_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5270, 6274 long sys_kexec_load ['unsigned long entry', 'unsigned long nr_segments', 'struct kexec_segment __user *segments', 'unsigned long flags']
	case 5270: case 6274: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kexec_load_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kexec_load_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5271, 6275 long sys_getcpu ['unsigned __user *cpu', 'unsigned __user *node', 'struct getcpu_cache __user *cache']
	case 5271: case 6275: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getcpu_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_getcpu_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5272, 6276 long sys_epoll_pwait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout', 'const sigset_t __user *sigmask', 'size_t sigsetsize']
	case 5272: case 6276: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_pwait_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_epoll_pwait_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5273, 6277 long sys_ioprio_set ['int which', 'int who', 'int ioprio']
	case 5273: case 6277: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5274, 6278 long sys_ioprio_get ['int which', 'int who']
	case 5274: case 6278: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5275, 6412 long sys_utimensat ['int dfd', 'const char __user *filename', 'struct __kernel_timespec __user *utimes', 'int flags']
	case 5275: case 6412: {
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
	// 5276, 6280 long sys_signalfd ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask']
	case 5276: case 6280: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_signalfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_signalfd_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5278, 6282 long sys_eventfd ['unsigned int count']
	case 5278: case 6282: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_eventfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_eventfd_enter, cpu, pc, arg0);
	}; break;
	// 5279, 6283 long sys_fallocate ['int fd', 'int mode', 'loff_t offset', 'loff_t len']
	case 5279: case 6283: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5280, 6220, 6284 long sys_timerfd_create ['int clockid', 'int flags']
	case 5280: case 6220: case 6284: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5281, 6410 long sys_timerfd_gettime ['int ufd', 'struct __kernel_itimerspec __user *otmr']
	case 5281: case 6410: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timerfd_gettime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_timerfd_gettime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5282, 6411 long sys_timerfd_settime ['int ufd', 'int flags', 'const struct __kernel_itimerspec __user *utmr', 'struct __kernel_itimerspec __user *otmr']
	case 5282: case 6411: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timerfd_settime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_timerfd_settime_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5283, 6287 long sys_signalfd4 ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask', 'int flags']
	case 5283: case 6287: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_signalfd4_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_signalfd4_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5284, 6288 long sys_eventfd2 ['unsigned int count', 'int flags']
	case 5284: case 6288: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5285, 6289 long sys_epoll_create1 ['int flags']
	case 5285: case 6289: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_epoll_create1_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_epoll_create1_enter, cpu, pc, arg0);
	}; break;
	// 5286, 6290 long sys_dup3 ['unsigned int oldfd', 'unsigned int newfd', 'int flags']
	case 5286: case 6290: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5287, 6291 long sys_pipe2 ['int __user *fildes', 'int flags']
	case 5287: case 6291: {
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
	// 5288, 6292 long sys_inotify_init1 ['int flags']
	case 5288: case 6292: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_inotify_init1_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_inotify_init1_enter, cpu, pc, arg0);
	}; break;
	// 5289, 6293 long sys_preadv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
	case 5289: case 6293: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_preadv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_preadv_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5290, 6294 long sys_pwritev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
	case 5290: case 6294: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pwritev_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pwritev_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5291, 6295 long sys_rt_tgsigqueueinfo ['pid_t tgid', 'pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
	case 5291: case 6295: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rt_tgsigqueueinfo_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_rt_tgsigqueueinfo_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5292, 6296 long sys_perf_event_open ['struct perf_event_attr __user *attr_uptr', 'pid_t pid', 'int cpu', 'int group_fd', 'unsigned long flags']
	case 5292: case 6296: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_perf_event_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_perf_event_open_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5293, 6297 long sys_accept4 ['int', 'struct sockaddr __user *', 'int __user *', 'int']
	case 5293: case 6297: {
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
	// 5294 long sys_recvmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags', 'struct __kernel_timespec __user *timeout']
	case 5294: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_recvmmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_recvmmsg_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5295, 6300 long sys_fanotify_init ['unsigned int flags', 'unsigned int event_f_flags']
	case 5295: case 6300: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5296, 6301 long sys_fanotify_mark ['int fanotify_fd', 'unsigned int flags', 'u64 mask', 'int fd', 'const char __user *pathname']
	case 5296: case 6301: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fanotify_mark_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fanotify_mark_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5297, 6302 long sys_prlimit64 ['pid_t pid', 'unsigned int resource', 'const struct rlimit64 __user *new_rlim', 'struct rlimit64 __user *old_rlim']
	case 5297: case 6302: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_prlimit64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_prlimit64_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5298, 6303 long sys_name_to_handle_at ['int dfd', 'const char __user *name', 'struct file_handle __user *handle', 'int __user *mnt_id', 'int flag']
	case 5298: case 6303: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_name_to_handle_at_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_name_to_handle_at_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5299, 6304 long sys_open_by_handle_at ['int mountdirfd', 'struct file_handle __user *handle', 'int flags']
	case 5299: case 6304: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_open_by_handle_at_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_open_by_handle_at_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5300, 6405 long sys_clock_adjtime ['clockid_t which_clock', 'struct __kernel_timex __user *tx']
	case 5300: case 6405: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_adjtime_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_adjtime_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5301, 6306 long sys_syncfs ['int fd']
	case 5301: case 6306: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_syncfs_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_syncfs_enter, cpu, pc, arg0);
	}; break;
	// 5302, 6307 long sys_sendmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags']
	case 5302: case 6307: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendmmsg_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sendmmsg_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5303, 6308 long sys_setns ['int fd', 'int nstype']
	case 5303: case 6308: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5304, 6309 long sys_process_vm_readv ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
	case 5304: case 6309: {
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
					PPP_CHECK_CB(on_sys_process_vm_readv_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_process_vm_readv_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5305, 6310 long sys_process_vm_writev ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
	case 5305: case 6310: {
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
					PPP_CHECK_CB(on_sys_process_vm_writev_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_process_vm_writev_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5306, 6311 long sys_kcmp ['pid_t pid1', 'pid_t pid2', 'int type', 'unsigned long idx1', 'unsigned long idx2']
	case 5306: case 6311: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_kcmp_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_kcmp_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5307, 6312 long sys_finit_module ['int fd', 'const char __user *uargs', 'int flags']
	case 5307: case 6312: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_finit_module_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_finit_module_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5308, 6299 long sys_getdents64 ['unsigned int fd', 'struct linux_dirent64 __user *dirent', 'unsigned int count']
	case 5308: case 6299: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_getdents64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_getdents64_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5309, 6313 long sys_sched_setattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int flags']
	case 5309: case 6313: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_setattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_setattr_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5310, 6314 long sys_sched_getattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int size', 'unsigned int flags']
	case 5310: case 6314: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_getattr_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sched_getattr_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5311, 6315 long sys_renameat2 ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'unsigned int flags']
	case 5311: case 6315: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_renameat2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_renameat2_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5312, 6316 long sys_seccomp ['unsigned int op', 'unsigned int flags', 'void __user *uargs']
	case 5312: case 6316: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_seccomp_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_seccomp_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5313, 6317 long sys_getrandom ['char __user *buf', 'size_t count', 'unsigned int flags']
	case 5313: case 6317: {
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
	// 5314, 6318 long sys_memfd_create ['const char __user *uname_ptr', 'unsigned int flags']
	case 5314: case 6318: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_memfd_create_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_memfd_create_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5315, 6319 long sys_bpf ['int cmd', 'union bpf_attr *attr', 'unsigned int size']
	case 5315: case 6319: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_bpf_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_bpf_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5316, 6320 long sys_execveat ['int dfd', 'const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp', 'int flags']
	case 5316: case 6320: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_execveat_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_execveat_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5317, 6321 long sys_userfaultfd ['int flags']
	case 5317: case 6321: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_userfaultfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_userfaultfd_enter, cpu, pc, arg0);
	}; break;
	// 5318, 6322 long sys_membarrier ['int cmd', 'int flags']
	case 5318: case 6322: {
		panda_noreturn = false;
		ctx.double_return = false;
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
	// 5319, 6323 long sys_mlock2 ['unsigned long start', 'size_t len', 'int flags']
	case 5319: case 6323: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mlock2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_mlock2_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5320, 6324 long sys_copy_file_range ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
	case 5320: case 6324: {
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
	// 5321, 6325 long sys_preadv2 ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h', 'rwf_t flags']
	case 5321: case 6325: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_preadv2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_preadv2_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5322, 6326 long sys_pwritev2 ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h', 'rwf_t flags']
	case 5322: case 6326: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pwritev2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pwritev2_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5323, 6327 long sys_pkey_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot', 'int pkey']
	case 5323: case 6327: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pkey_mprotect_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_pkey_mprotect_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5324, 6328 long sys_pkey_alloc ['unsigned long flags', 'unsigned long init_val']
	case 5324: case 6328: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pkey_alloc_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pkey_alloc_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5325, 6329 long sys_pkey_free ['int pkey']
	case 5325: case 6329: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pkey_free_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_pkey_free_enter, cpu, pc, arg0);
	}; break;
	// 5326, 6330 long sys_statx ['int dfd', 'const char __user *path', 'unsigned flags', 'unsigned mask', 'struct statx __user *buffer']
	case 5326: case 6330: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_statx_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_statx_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5327, 6331 long sys_rseq ['struct rseq __user *rseq', 'uint32_t rseq_len', 'int flags', 'uint32_t sig']
	case 5327: case 6331: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_rseq_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_rseq_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5328, 6332, 6416 long sys_io_pgetevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct __kernel_timespec __user *timeout', 'const struct __aio_sigset *sig']
	case 5328: case 6332: case 6416: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		int64_t arg2 = get_s64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_pgetevents_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_io_pgetevents_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5424, 6424 long sys_pidfd_send_signal ['int pidfd', 'int sig', 'siginfo_t __user *info', 'unsigned int flags']
	case 5424: case 6424: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pidfd_send_signal_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pidfd_send_signal_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5425, 6425 long sys_io_uring_setup ['u32 entries', 'struct io_uring_params __user *p']
	case 5425: case 6425: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_uring_setup_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_io_uring_setup_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5426, 6426 long sys_io_uring_enter ['unsigned int fd', 'u32 to_submit', 'u32 min_complete', 'u32 flags', 'const sigset_t __user *sig', 'size_t sigsz']
	case 5426: case 6426: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_uring_enter_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_uring_enter_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 5427, 6427 long sys_io_uring_register ['unsigned int fd', 'unsigned int op', 'void __user *arg', 'unsigned int nr_args']
	case 5427: case 6427: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_uring_register_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_io_uring_register_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5428, 6428 long sys_open_tree ['int dfd', 'const char __user *path', 'unsigned flags']
	case 5428: case 6428: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_open_tree_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_open_tree_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5429, 6429 long sys_move_mount ['int from_dfd', 'const char __user *from_path', 'int to_dfd', 'const char __user *to_path', 'unsigned int ms_flags']
	case 5429: case 6429: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_move_mount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_move_mount_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5430, 6430 long sys_fsopen ['const char __user *fs_name', 'unsigned int flags']
	case 5430: case 6430: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsopen_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fsopen_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5431, 6431 long sys_fsconfig ['int fs_fd', 'unsigned int cmd', 'const char __user *key', 'const void __user *value', 'int aux']
	case 5431: case 6431: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		int32_t arg4 = get_s32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsconfig_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_fsconfig_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 5432, 6432 long sys_fsmount ['int fs_fd', 'unsigned int flags', 'unsigned int ms_flags']
	case 5432: case 6432: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fsmount_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fsmount_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5433, 6433 long sys_fspick ['int dfd', 'const char __user *path', 'unsigned int flags']
	case 5433: case 6433: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fspick_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_fspick_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5434, 6434 long sys_pidfd_open ['pid_t pid', 'unsigned int flags']
	case 5434: case 6434: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pidfd_open_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pidfd_open_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5435, 6435 long sys_clone3 ['struct clone_args __user *uargs', 'size_t size']
	case 5435: case 6435: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clone3_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_clone3_enter, cpu, pc, arg0, arg1);
	}; break;
	// 5437, 6437 long sys_openat2 ['int dfd', 'const char __user *filename', 'struct open_how *how', 'size_t size']
	case 5437: case 6437: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_openat2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_openat2_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 5438, 6438 long sys_pidfd_getfd ['int pidfd', 'int fd', 'unsigned int flags']
	case 5438: case 6438: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_pidfd_getfd_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_pidfd_getfd_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 5439, 6439 long sys_faccessat2 ['int dfd', 'const char __user *filename', 'int mode', 'int flags']
	case 5439: case 6439: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_faccessat2_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_faccessat2_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 6034 long sys_nanosleep_time32 ['struct old_timespec32 __user *rqtp', 'struct old_timespec32 __user *rmtp']
	case 6034: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_nanosleep_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_nanosleep_time32_enter, cpu, pc, arg0, arg1);
	}; break;
	// 6039 long sys_sendfile ['int out_fd', 'int in_fd', 'off_t __user *offset', 'size_t count']
	case 6039: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sendfile_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_sendfile_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 6064 long sys_semctl ['int semid', 'int semnum', 'int cmd', 'unsigned long arg']
	case 6064: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semctl_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_semctl_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 6126, 6202 long sys_io_getevents_time32 ['__u32 ctx_id', '__s32 min_nr', '__s32 nr', 'struct io_event __user *events', 'struct old_timespec32 __user *timeout']
	case 6126: case 6202: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		int32_t arg2 = get_s32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_getevents_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(int32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_io_getevents_time32_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 6130 long sys_utime32 ['const char __user *filename', 'struct old_utimbuf32 __user *t']
	case 6130: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utime32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_utime32_enter, cpu, pc, arg0, arg1);
	}; break;
	// 6145 long sys_sched_rr_get_interval_time32 ['pid_t pid', 'struct old_timespec32 __user *interval']
	case 6145: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_sched_rr_get_interval_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_sched_rr_get_interval_time32_enter, cpu, pc, arg0, arg1);
	}; break;
	// 6154 long sys_adjtimex_time32 ['struct old_timex32 __user *txc_p']
	case 6154: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_adjtimex_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_adjtimex_time32_enter, cpu, pc, arg0);
	}; break;
	// 6194 long sys_futex_time32 ['u32 __user *uaddr', 'int op', 'u32 val', 'struct old_timespec32 __user *utime', 'u32 __user *uaddr2', 'u32 val3']
	case 6194: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint32_t arg5 = get_32(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_futex_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_futex_time32_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 6211 void sys_sigreturn ['void']
	case 6211: {
		panda_noreturn = false;
		ctx.double_return = false;
		PPP_RUN_CB(on_sys_sigreturn_enter, cpu, pc);
	}; break;
	// 6212 long sys_fcntl64 ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
	case 6212: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fcntl64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fcntl64_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 6215 long sys_semtimedop_time32 ['int semid', 'struct sembuf __user *sops', 'unsigned nsops', 'const struct old_timespec32 __user *timeout']
	case 6215: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_semtimedop_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_semtimedop_time32_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 6217 long sys_statfs64 ['const char __user *path', 'size_t sz', 'struct statfs64 __user *buf']
	case 6217: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_statfs64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_statfs64_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 6218 long sys_fstatfs64 ['unsigned int fd', 'size_t sz', 'struct statfs64 __user *buf']
	case 6218: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_fstatfs64_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_fstatfs64_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 6221 long sys_timer_settime32 ['timer_t timer_id', 'int flags', 'struct old_itimerspec32 __user *new', 'struct old_itimerspec32 __user *old']
	case 6221: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_settime32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_timer_settime32_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 6222 long sys_timer_gettime32 ['timer_t timer_id', 'struct old_itimerspec32 __user *setting']
	case 6222: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timer_gettime32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_timer_gettime32_enter, cpu, pc, arg0, arg1);
	}; break;
	// 6225 long sys_clock_settime32 ['clockid_t which_clock', 'struct old_timespec32 __user *tp']
	case 6225: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_settime32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_settime32_enter, cpu, pc, arg0, arg1);
	}; break;
	// 6226 long sys_clock_gettime32 ['clockid_t which_clock', 'struct old_timespec32 __user *tp']
	case 6226: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_gettime32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_gettime32_enter, cpu, pc, arg0, arg1);
	}; break;
	// 6227 long sys_clock_getres_time32 ['clockid_t which_clock', 'struct old_timespec32 __user *tp']
	case 6227: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_getres_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_getres_time32_enter, cpu, pc, arg0, arg1);
	}; break;
	// 6228 long sys_clock_nanosleep_time32 ['clockid_t which_clock', 'int flags', 'struct old_timespec32 __user *rqtp', 'struct old_timespec32 __user *rmtp']
	case 6228: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_nanosleep_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_nanosleep_time32_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 6230 long sys_utimes_time32 ['const char __user *filename', 'struct old_timeval32 __user *t']
	case 6230: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utimes_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_utimes_time32_enter, cpu, pc, arg0, arg1);
	}; break;
	// 6236 long sys_mq_timedsend_time32 ['mqd_t mqdes', 'const char __user *u_msg_ptr', 'unsigned int msg_len', 'unsigned int msg_prio', 'const struct old_timespec32 __user *u_abs_timeout']
	case 6236: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint32_t arg3 = get_32(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_timedsend_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint32_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mq_timedsend_time32_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 6237 long sys_mq_timedreceive_time32 ['mqd_t mqdes', 'char __user *u_msg_ptr', 'unsigned int msg_len', 'unsigned int __user *u_msg_prio', 'const struct old_timespec32 __user *u_abs_timeout']
	case 6237: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint32_t arg2 = get_32(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_mq_timedreceive_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint32_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_mq_timedreceive_time32_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 6255 long sys_futimesat_time32 ['unsigned int dfd', 'const char __user *filename', 'struct old_timeval32 __user *t']
	case 6255: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_futimesat_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_futimesat_time32_enter, cpu, pc, arg0, arg1, arg2);
	}; break;
	// 6264 long sys_io_pgetevents_time32 ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct old_timespec32 __user *timeout', 'const struct __aio_sigset *sig']
	case 6264: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		int64_t arg1 = get_s64(cpu, 1);
		int64_t arg2 = get_s64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint64_t arg4 = get_64(cpu, 4);
		uint64_t arg5 = get_64(cpu, 5);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_io_pgetevents_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(int64_t));
			memcpy(ctx.args[2], &arg2, sizeof(int64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_io_pgetevents_time32_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 6265 long sys_pselect6_time32 ['int', 'fd_set __user *', 'fd_set __user *', 'fd_set __user *', 'struct old_timespec32 __user *', 'void __user *']
	case 6265: {
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
					PPP_CHECK_CB(on_sys_pselect6_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint64_t));
			memcpy(ctx.args[5], &arg5, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_pselect6_time32_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5);
	}; break;
	// 6279 long sys_utimensat_time32 ['unsigned int dfd', 'const char __user *filename', 'struct old_timespec32 __user *t', 'int flags']
	case 6279: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		int32_t arg3 = get_s32(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_utimensat_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(int32_t));
		}
		PPP_RUN_CB(on_sys_utimensat_time32_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 6285 long sys_timerfd_gettime32 ['int ufd', 'struct old_itimerspec32 __user *otmr']
	case 6285: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timerfd_gettime32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_timerfd_gettime32_enter, cpu, pc, arg0, arg1);
	}; break;
	// 6286 long sys_timerfd_settime32 ['int ufd', 'int flags', 'const struct old_itimerspec32 __user *utmr', 'struct old_itimerspec32 __user *otmr']
	case 6286: {
		panda_noreturn = false;
		ctx.double_return = false;
		int32_t arg0 = get_s32(cpu, 0);
		int32_t arg1 = get_s32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_timerfd_settime32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(int32_t));
			memcpy(ctx.args[1], &arg1, sizeof(int32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_timerfd_settime32_enter, cpu, pc, arg0, arg1, arg2, arg3);
	}; break;
	// 6298 long sys_ppoll_time32 ['struct pollfd __user *', 'unsigned int', 'struct old_timespec32 __user *', 'const sigset_t __user *', 'size_t']
	case 6298: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint64_t arg0 = get_64(cpu, 0);
		uint32_t arg1 = get_32(cpu, 1);
		uint64_t arg2 = get_64(cpu, 2);
		uint64_t arg3 = get_64(cpu, 3);
		uint32_t arg4 = get_32(cpu, 4);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_ppoll_time32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint64_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint32_t));
			memcpy(ctx.args[2], &arg2, sizeof(uint64_t));
			memcpy(ctx.args[3], &arg3, sizeof(uint64_t));
			memcpy(ctx.args[4], &arg4, sizeof(uint32_t));
		}
		PPP_RUN_CB(on_sys_ppoll_time32_enter, cpu, pc, arg0, arg1, arg2, arg3, arg4);
	}; break;
	// 6305 long sys_clock_adjtime32 ['clockid_t which_clock', 'struct old_timex32 __user *tx']
	case 6305: {
		panda_noreturn = false;
		ctx.double_return = false;
		uint32_t arg0 = get_32(cpu, 0);
		uint64_t arg1 = get_64(cpu, 1);
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_sys_clock_adjtime32_return)))) {
			memcpy(ctx.args[0], &arg0, sizeof(uint32_t));
			memcpy(ctx.args[1], &arg1, sizeof(uint64_t));
		}
		PPP_RUN_CB(on_sys_clock_adjtime32_enter, cpu, pc, arg0, arg1);
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