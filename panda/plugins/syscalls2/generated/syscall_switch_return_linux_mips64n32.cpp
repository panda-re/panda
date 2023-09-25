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

void syscall_return_switch_linux_mips64n32(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx) {
#if defined(TARGET_MIPS) && defined(TARGET_MIPS64)
	const syscall_info_t *call = NULL;
	syscall_info_t zero = {0};
	if (syscall_meta != NULL && ctx->no <= syscall_meta->max_generic) {
	  // If the syscall_info object from dso_info_....c doesn't have an entry
	  // for this syscall, we want to leave it as a NULL pointer
	  if (memcmp(&syscall_info[ctx->no], &zero, sizeof(syscall_info_t)) != 0) {
		call = &syscall_info[ctx->no];
	  }
	}
	switch (ctx->no) {
		// 5000 long sys_read ['unsigned int fd', 'char __user *buf', 'size_t count']
		case 5000: {
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
		// 5001 long sys_write ['unsigned int fd', 'const char __user *buf', 'size_t count']
		case 5001: {
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
		// 5002 long sys_open ['const char __user *filename', 'int flags', 'umode_t mode']
		case 5002: {
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
		// 5003 long sys_close ['unsigned int fd']
		case 5003: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_close_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_close_return, cpu, pc, arg0) ;
		}; break;
		// 5004 long sys_newstat ['const char __user *filename', 'struct stat __user *statbuf']
		case 5004: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_newstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5005 long sys_newfstat ['unsigned int fd', 'struct stat __user *statbuf']
		case 5005: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_newfstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newfstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5006 long sys_newlstat ['const char __user *filename', 'struct stat __user *statbuf']
		case 5006: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_newlstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newlstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5007 long sys_poll ['struct pollfd __user *ufds', 'unsigned int nfds', 'int timeout']
		case 5007: {
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
		// 5008 long sys_lseek ['unsigned int fd', 'off_t offset', 'unsigned int whence']
		case 5008: {
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
		// 5009 long sys_old_mmap ['struct mmap_arg_struct __user *arg']
		case 5009: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_old_mmap_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_old_mmap_return, cpu, pc, arg0) ;
		}; break;
		// 5010 long sys_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot']
		case 5010: {
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
		// 5011 long sys_munmap ['unsigned long addr', 'size_t len']
		case 5011: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_munmap_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_munmap_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5012 long sys_brk ['unsigned long brk']
		case 5012: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_brk_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_brk_return, cpu, pc, arg0) ;
		}; break;
		// 5013 long sys_rt_sigaction ['int', 'const struct sigaction __user *', 'struct sigaction __user *', 'size_t']
		case 5013: {
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
		// 5014 long sys_rt_sigprocmask ['int how', 'sigset_t __user *set', 'sigset_t __user *oset', 'size_t sigsetsize']
		case 5014: {
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
		// 5015 long sys_ioctl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
		case 5015: {
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
		// 5016 long sys_pread64 ['unsigned int fd', 'char __user *buf', 'size_t count', 'loff_t pos']
		case 5016: {
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
		// 5017 long sys_pwrite64 ['unsigned int fd', 'const char __user *buf', 'size_t count', 'loff_t pos']
		case 5017: {
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
		// 5018 long sys_readv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
		case 5018: {
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
		// 5019 long sys_writev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
		case 5019: {
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
		// 5020 long sys_access ['const char __user *filename', 'int mode']
		case 5020: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_access_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_access_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5021 long sys_pipe ['int __user *fildes']
		case 5021: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_pipe_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pipe_return, cpu, pc, arg0) ;
		}; break;
		// 5022 long sys_select ['int n', 'fd_set __user *inp', 'fd_set __user *outp', 'fd_set __user *exp', 'struct __kernel_old_timeval __user *tvp']
		case 5022: {
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
		// 5023 long sys_sched_yield ['void']
		case 5023: {
			if (PPP_CHECK_CB(on_sys_sched_yield_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sched_yield_return, cpu, pc) ;
		}; break;
		// 5024 long sys_mremap ['unsigned long addr', 'unsigned long old_len', 'unsigned long new_len', 'unsigned long flags', 'unsigned long new_addr']
		case 5024: {
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
		// 5025 long sys_msync ['unsigned long start', 'size_t len', 'int flags']
		case 5025: {
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
		// 5026 long sys_mincore ['unsigned long start', 'size_t len', 'unsigned char __user *vec']
		case 5026: {
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
		// 5027 long sys_madvise ['unsigned long start', 'size_t len', 'int behavior']
		case 5027: {
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
		// 5028 long sys_shmget ['key_t key', 'size_t size', 'int flag']
		case 5028: {
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
		// 5029 long sys_shmat ['int shmid', 'char __user *shmaddr', 'int shmflg']
		case 5029: {
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
		// 5030 long sys_old_shmctl ['int shmid', 'int cmd', 'struct shmid_ds __user *buf']
		case 5030: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_old_shmctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_old_shmctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 5031 long sys_dup ['unsigned int fildes']
		case 5031: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_dup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_dup_return, cpu, pc, arg0) ;
		}; break;
		// 5032 long sys_dup2 ['unsigned int oldfd', 'unsigned int newfd']
		case 5032: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_dup2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_dup2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5033 long sys_pause ['void']
		case 5033: {
			if (PPP_CHECK_CB(on_sys_pause_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_pause_return, cpu, pc) ;
		}; break;
		// 5034 long sys_nanosleep ['struct __kernel_timespec __user *rqtp', 'struct __kernel_timespec __user *rmtp']
		case 5034: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_nanosleep_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_nanosleep_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5035 long sys_getitimer ['int which', 'struct __kernel_old_itimerval __user *value']
		case 5035: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getitimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getitimer_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5036 long sys_setitimer ['int which', 'struct __kernel_old_itimerval __user *value', 'struct __kernel_old_itimerval __user *ovalue']
		case 5036: {
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
		// 5037 long sys_alarm ['unsigned int seconds']
		case 5037: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_alarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_alarm_return, cpu, pc, arg0) ;
		}; break;
		// 5038 long sys_getpid ['void']
		case 5038: {
			if (PPP_CHECK_CB(on_sys_getpid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpid_return, cpu, pc) ;
		}; break;
		// 5039 long sys_sendfile64 ['int out_fd', 'int in_fd', 'loff_t __user *offset', 'size_t count']
		case 5039: {
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
		// 5040 long sys_socket ['int', 'int', 'int']
		case 5040: {
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
		// 5041 long sys_connect ['int', 'struct sockaddr __user *', 'int']
		case 5041: {
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
		// 5042 long sys_accept ['int', 'struct sockaddr __user *', 'int __user *']
		case 5042: {
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
		// 5043 long sys_sendto ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int']
		case 5043: {
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
		// 5044 long sys_recvfrom ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int __user *']
		case 5044: {
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
		// 5045 long sys_sendmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
		case 5045: {
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
		// 5046 long sys_recvmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
		case 5046: {
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
		// 5047 long sys_shutdown ['int', 'int']
		case 5047: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_shutdown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shutdown_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5048 long sys_bind ['int', 'struct sockaddr __user *', 'int']
		case 5048: {
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
		// 5049 long sys_listen ['int', 'int']
		case 5049: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_listen_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_listen_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5050 long sys_getsockname ['int', 'struct sockaddr __user *', 'int __user *']
		case 5050: {
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
		// 5051 long sys_getpeername ['int', 'struct sockaddr __user *', 'int __user *']
		case 5051: {
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
		// 5052 long sys_socketpair ['int', 'int', 'int', 'int __user *']
		case 5052: {
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
		// 5053 long sys_setsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int optlen']
		case 5053: {
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
		// 5054 long sys_getsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int __user *optlen']
		case 5054: {
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
		// 5055 long sys_clone ['unsigned long', 'unsigned long', 'int __user *', 'int __user *', 'unsigned long']
		case 5055: {
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
		// 5056 long sys_fork ['void']
		case 5056: {
			if (PPP_CHECK_CB(on_sys_fork_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_fork_return, cpu, pc) ;
		}; break;
		// 5057 long sys_execve ['const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp']
		case 5057: {
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
		// 5058 long sys_exit ['int error_code']
		case 5058: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_exit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_exit_return, cpu, pc, arg0) ;
		}; break;
		// 5059 long sys_wait4 ['pid_t pid', 'int __user *stat_addr', 'int options', 'struct rusage __user *ru']
		case 5059: {
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
		// 5060 long sys_kill ['pid_t pid', 'int sig']
		case 5060: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_kill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_kill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5061 long sys_newuname ['struct new_utsname __user *name']
		case 5061: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_newuname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_newuname_return, cpu, pc, arg0) ;
		}; break;
		// 5062 long sys_semget ['key_t key', 'int nsems', 'int semflg']
		case 5062: {
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
		// 5063 long sys_semop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops']
		case 5063: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_semop_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_semop_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 5064 long sys_old_semctl ['int semid', 'int semnum', 'int cmd', 'unsigned long arg']
		case 5064: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_old_semctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_old_semctl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 5065 long sys_shmdt ['char __user *shmaddr']
		case 5065: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_shmdt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_shmdt_return, cpu, pc, arg0) ;
		}; break;
		// 5066 long sys_msgget ['key_t key', 'int msgflg']
		case 5066: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_msgget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgget_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5067 long sys_msgsnd ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'int msgflg']
		case 5067: {
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
		// 5068 long sys_msgrcv ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'long msgtyp', 'int msgflg']
		case 5068: {
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
		// 5069 long sys_old_msgctl ['int msqid', 'int cmd', 'struct msqid_ds __user *buf']
		case 5069: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_old_msgctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_old_msgctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 5070 long sys_fcntl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
		case 5070: {
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
		// 5071 long sys_flock ['unsigned int fd', 'unsigned int cmd']
		case 5071: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_flock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_flock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5072 long sys_fsync ['unsigned int fd']
		case 5072: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_fsync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fsync_return, cpu, pc, arg0) ;
		}; break;
		// 5073 long sys_fdatasync ['unsigned int fd']
		case 5073: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_fdatasync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fdatasync_return, cpu, pc, arg0) ;
		}; break;
		// 5074 long sys_truncate ['const char __user *path', 'long length']
		case 5074: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_truncate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_truncate_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5075 long sys_ftruncate ['unsigned int fd', 'unsigned long length']
		case 5075: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ftruncate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ftruncate_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5076 long sys_getdents ['unsigned int fd', 'struct linux_dirent __user *dirent', 'unsigned int count']
		case 5076: {
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
		// 5077 long sys_getcwd ['char __user *buf', 'unsigned long size']
		case 5077: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getcwd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getcwd_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5078 long sys_chdir ['const char __user *filename']
		case 5078: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_chdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chdir_return, cpu, pc, arg0) ;
		}; break;
		// 5079 long sys_fchdir ['unsigned int fd']
		case 5079: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_fchdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchdir_return, cpu, pc, arg0) ;
		}; break;
		// 5080 long sys_rename ['const char __user *oldname', 'const char __user *newname']
		case 5080: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_rename_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rename_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5081 long sys_mkdir ['const char __user *pathname', 'umode_t mode']
		case 5081: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_mkdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkdir_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5082 long sys_rmdir ['const char __user *pathname']
		case 5082: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_rmdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rmdir_return, cpu, pc, arg0) ;
		}; break;
		// 5083 long sys_creat ['const char __user *pathname', 'umode_t mode']
		case 5083: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_creat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_creat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5084 long sys_link ['const char __user *oldname', 'const char __user *newname']
		case 5084: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_link_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5085 long sys_unlink ['const char __user *pathname']
		case 5085: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 5086 long sys_symlink ['const char __user *old', 'const char __user *new']
		case 5086: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_symlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_symlink_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5087 long sys_readlink ['const char __user *path', 'char __user *buf', 'int bufsiz']
		case 5087: {
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
		// 5088 long sys_chmod ['const char __user *filename', 'umode_t mode']
		case 5088: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_chmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5089 long sys_fchmod ['unsigned int fd', 'umode_t mode']
		case 5089: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fchmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5090 long sys_chown ['const char __user *filename', 'uid_t user', 'gid_t group']
		case 5090: {
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
		// 5091 long sys_fchown ['unsigned int fd', 'uid_t user', 'gid_t group']
		case 5091: {
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
		// 5092 long sys_lchown ['const char __user *filename', 'uid_t user', 'gid_t group']
		case 5092: {
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
		// 5093 long sys_umask ['int mask']
		case 5093: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_umask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_umask_return, cpu, pc, arg0) ;
		}; break;
		// 5094 long sys_gettimeofday ['struct __kernel_old_timeval __user *tv', 'struct timezone __user *tz']
		case 5094: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_gettimeofday_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_gettimeofday_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5095 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
		case 5095: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5096 long sys_getrusage ['int who', 'struct rusage __user *ru']
		case 5096: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getrusage_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getrusage_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5097 long sys_sysinfo ['struct sysinfo __user *info']
		case 5097: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sysinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sysinfo_return, cpu, pc, arg0) ;
		}; break;
		// 5098 long sys_times ['struct tms __user *tbuf']
		case 5098: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_times_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_times_return, cpu, pc, arg0) ;
		}; break;
		// 5099 long sys_ptrace ['long request', 'long pid', 'unsigned long addr', 'unsigned long data']
		case 5099: {
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
		// 5100 long sys_getuid ['void']
		case 5100: {
			if (PPP_CHECK_CB(on_sys_getuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getuid_return, cpu, pc) ;
		}; break;
		// 5101 long sys_syslog ['int type', 'char __user *buf', 'int len']
		case 5101: {
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
		// 5102 long sys_getgid ['void']
		case 5102: {
			if (PPP_CHECK_CB(on_sys_getgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getgid_return, cpu, pc) ;
		}; break;
		// 5103 long sys_setuid ['uid_t uid']
		case 5103: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setuid_return, cpu, pc, arg0) ;
		}; break;
		// 5104 long sys_setgid ['gid_t gid']
		case 5104: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setgid_return, cpu, pc, arg0) ;
		}; break;
		// 5105 long sys_geteuid ['void']
		case 5105: {
			if (PPP_CHECK_CB(on_sys_geteuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_geteuid_return, cpu, pc) ;
		}; break;
		// 5106 long sys_getegid ['void']
		case 5106: {
			if (PPP_CHECK_CB(on_sys_getegid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getegid_return, cpu, pc) ;
		}; break;
		// 5107 long sys_setpgid ['pid_t pid', 'pid_t pgid']
		case 5107: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setpgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setpgid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5108 long sys_getppid ['void']
		case 5108: {
			if (PPP_CHECK_CB(on_sys_getppid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getppid_return, cpu, pc) ;
		}; break;
		// 5109 long sys_getpgrp ['void']
		case 5109: {
			if (PPP_CHECK_CB(on_sys_getpgrp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpgrp_return, cpu, pc) ;
		}; break;
		// 5110 long sys_setsid ['void']
		case 5110: {
			if (PPP_CHECK_CB(on_sys_setsid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_setsid_return, cpu, pc) ;
		}; break;
		// 5111 long sys_setreuid ['uid_t ruid', 'uid_t euid']
		case 5111: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setreuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setreuid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5112 long sys_setregid ['gid_t rgid', 'gid_t egid']
		case 5112: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setregid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setregid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5113 long sys_getgroups ['int gidsetsize', 'gid_t __user *grouplist']
		case 5113: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getgroups_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getgroups_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5114 long sys_setgroups ['int gidsetsize', 'gid_t __user *grouplist']
		case 5114: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setgroups_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setgroups_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5115 long sys_setresuid ['uid_t ruid', 'uid_t euid', 'uid_t suid']
		case 5115: {
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
		// 5116 long sys_getresuid ['uid_t __user *ruid', 'uid_t __user *euid', 'uid_t __user *suid']
		case 5116: {
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
		// 5117 long sys_setresgid ['gid_t rgid', 'gid_t egid', 'gid_t sgid']
		case 5117: {
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
		// 5118 long sys_getresgid ['gid_t __user *rgid', 'gid_t __user *egid', 'gid_t __user *sgid']
		case 5118: {
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
		// 5119 long sys_getpgid ['pid_t pid']
		case 5119: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_getpgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getpgid_return, cpu, pc, arg0) ;
		}; break;
		// 5120 long sys_setfsuid ['uid_t uid']
		case 5120: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setfsuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setfsuid_return, cpu, pc, arg0) ;
		}; break;
		// 5121 long sys_setfsgid ['gid_t gid']
		case 5121: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setfsgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setfsgid_return, cpu, pc, arg0) ;
		}; break;
		// 5122 long sys_getsid ['pid_t pid']
		case 5122: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_getsid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getsid_return, cpu, pc, arg0) ;
		}; break;
		// 5123 long sys_capget ['cap_user_header_t header', 'cap_user_data_t dataptr']
		case 5123: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_capget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_capget_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5124 long sys_capset ['cap_user_header_t header', 'const cap_user_data_t data']
		case 5124: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_capset_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_capset_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5125 long sys_rt_sigpending ['sigset_t __user *set', 'size_t sigsetsize']
		case 5125: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_rt_sigpending_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigpending_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5126 long sys_rt_sigtimedwait ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct __kernel_timespec __user *uts', 'size_t sigsetsize']
		case 5126: {
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
		// 5127 long sys_rt_sigqueueinfo ['pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
		case 5127: {
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
		// 5128 long sys_rt_sigsuspend ['sigset_t __user *unewset', 'size_t sigsetsize']
		case 5128: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_rt_sigsuspend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigsuspend_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5129 long sys_sigaltstack ['const struct sigaltstack __user *uss', 'struct sigaltstack __user *uoss']
		case 5129: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sigaltstack_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigaltstack_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5130 long sys_utime ['char __user *filename', 'struct utimbuf __user *times']
		case 5130: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_utime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_utime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5131 long sys_mknod ['const char __user *filename', 'umode_t mode', 'unsigned dev']
		case 5131: {
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
		// 5132 long sys_personality ['unsigned int personality']
		case 5132: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_personality_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_personality_return, cpu, pc, arg0) ;
		}; break;
		// 5133 long sys_ustat ['unsigned dev', 'struct ustat __user *ubuf']
		case 5133: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ustat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ustat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5134 long sys_statfs ['const char __user *path', 'struct statfs __user *buf']
		case 5134: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_statfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_statfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5135 long sys_fstatfs ['unsigned int fd', 'struct statfs __user *buf']
		case 5135: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fstatfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fstatfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5136 long sys_sysfs ['int option', 'unsigned long arg1', 'unsigned long arg2']
		case 5136: {
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
		// 5137 long sys_getpriority ['int which', 'int who']
		case 5137: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getpriority_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getpriority_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5138 long sys_setpriority ['int which', 'int who', 'int niceval']
		case 5138: {
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
		// 5139 long sys_sched_setparam ['pid_t pid', 'struct sched_param __user *param']
		case 5139: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sched_setparam_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_setparam_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5140 long sys_sched_getparam ['pid_t pid', 'struct sched_param __user *param']
		case 5140: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sched_getparam_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_getparam_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5141 long sys_sched_setscheduler ['pid_t pid', 'int policy', 'struct sched_param __user *param']
		case 5141: {
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
		// 5142 long sys_sched_getscheduler ['pid_t pid']
		case 5142: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sched_getscheduler_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_getscheduler_return, cpu, pc, arg0) ;
		}; break;
		// 5143 long sys_sched_get_priority_max ['int policy']
		case 5143: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sched_get_priority_max_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_get_priority_max_return, cpu, pc, arg0) ;
		}; break;
		// 5144 long sys_sched_get_priority_min ['int policy']
		case 5144: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sched_get_priority_min_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_get_priority_min_return, cpu, pc, arg0) ;
		}; break;
		// 5145 long sys_sched_rr_get_interval ['pid_t pid', 'struct __kernel_timespec __user *interval']
		case 5145: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sched_rr_get_interval_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_rr_get_interval_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5146 long sys_mlock ['unsigned long start', 'size_t len']
		case 5146: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_mlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mlock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5147 long sys_munlock ['unsigned long start', 'size_t len']
		case 5147: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_munlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_munlock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5148 long sys_mlockall ['int flags']
		case 5148: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_mlockall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_mlockall_return, cpu, pc, arg0) ;
		}; break;
		// 5149 long sys_munlockall ['void']
		case 5149: {
			if (PPP_CHECK_CB(on_sys_munlockall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_munlockall_return, cpu, pc) ;
		}; break;
		// 5150 long sys_vhangup ['void']
		case 5150: {
			if (PPP_CHECK_CB(on_sys_vhangup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_vhangup_return, cpu, pc) ;
		}; break;
		// 5151 long sys_pivot_root ['const char __user *new_root', 'const char __user *put_old']
		case 5151: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pivot_root_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pivot_root_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5152 long sys_sysctl ['struct __sysctl_args __user *args']
		case 5152: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sysctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sysctl_return, cpu, pc, arg0) ;
		}; break;
		// 5153 long sys_prctl ['int option', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
		case 5153: {
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
		// 5154 long sys_adjtimex ['struct __kernel_timex __user *txc_p']
		case 5154: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_adjtimex_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_adjtimex_return, cpu, pc, arg0) ;
		}; break;
		// 5155 long sys_setrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
		case 5155: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5156 long sys_chroot ['const char __user *filename']
		case 5156: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_chroot_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chroot_return, cpu, pc, arg0) ;
		}; break;
		// 5157 long sys_sync ['void']
		case 5157: {
			if (PPP_CHECK_CB(on_sys_sync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sync_return, cpu, pc) ;
		}; break;
		// 5158 long sys_acct ['const char __user *name']
		case 5158: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_acct_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_acct_return, cpu, pc, arg0) ;
		}; break;
		// 5159 long sys_settimeofday ['struct __kernel_old_timeval __user *tv', 'struct timezone __user *tz']
		case 5159: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_settimeofday_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_settimeofday_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5160 long sys_mount ['char __user *dev_name', 'char __user *dir_name', 'char __user *type', 'unsigned long flags', 'void __user *data']
		case 5160: {
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
		// 5161 long sys_umount ['char __user *name', 'int flags']
		case 5161: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_umount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_umount_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5162 long sys_swapon ['const char __user *specialfile', 'int swap_flags']
		case 5162: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_swapon_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_swapon_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5163 long sys_swapoff ['const char __user *specialfile']
		case 5163: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_swapoff_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_swapoff_return, cpu, pc, arg0) ;
		}; break;
		// 5164 long sys_reboot ['int magic1', 'int magic2', 'unsigned int cmd', 'void __user *arg']
		case 5164: {
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
		// 5165 long sys_sethostname ['char __user *name', 'int len']
		case 5165: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sethostname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sethostname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5166 long sys_setdomainname ['char __user *name', 'int len']
		case 5166: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setdomainname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setdomainname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5167, 5170, 5171, 5173, 5174, 5175, 5176, 5177, 5193, 5236, 5277 long sys_ni_syscall ['void']
		case 5167:case 5170:case 5171:case 5173:case 5174:case 5175:case 5176:case 5177:case 5193:case 5236:case 5277: {
			if (PPP_CHECK_CB(on_sys_ni_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_ni_syscall_return, cpu, pc) ;
		}; break;
		// 5168 long sys_init_module ['void __user *umod', 'unsigned long len', 'const char __user *uargs']
		case 5168: {
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
		// 5169 long sys_delete_module ['const char __user *name_user', 'unsigned int flags']
		case 5169: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_delete_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_delete_module_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5172 long sys_quotactl ['unsigned int cmd', 'const char __user *special', 'qid_t id', 'void __user *addr']
		case 5172: {
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
		// 5178 long sys_gettid ['void']
		case 5178: {
			if (PPP_CHECK_CB(on_sys_gettid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_gettid_return, cpu, pc) ;
		}; break;
		// 5179 long sys_readahead ['int fd', 'loff_t offset', 'size_t count']
		case 5179: {
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
		// 5180 long sys_setxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 5180: {
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
		// 5181 long sys_lsetxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 5181: {
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
		// 5182 long sys_fsetxattr ['int fd', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 5182: {
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
		// 5183 long sys_getxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
		case 5183: {
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
		// 5184 long sys_lgetxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
		case 5184: {
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
		// 5185 long sys_fgetxattr ['int fd', 'const char __user *name', 'void __user *value', 'size_t size']
		case 5185: {
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
		// 5186 long sys_listxattr ['const char __user *path', 'char __user *list', 'size_t size']
		case 5186: {
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
		// 5187 long sys_llistxattr ['const char __user *path', 'char __user *list', 'size_t size']
		case 5187: {
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
		// 5188 long sys_flistxattr ['int fd', 'char __user *list', 'size_t size']
		case 5188: {
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
		// 5189 long sys_removexattr ['const char __user *path', 'const char __user *name']
		case 5189: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_removexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_removexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5190 long sys_lremovexattr ['const char __user *path', 'const char __user *name']
		case 5190: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lremovexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lremovexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5191 long sys_fremovexattr ['int fd', 'const char __user *name']
		case 5191: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fremovexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fremovexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5192 long sys_tkill ['pid_t pid', 'int sig']
		case 5192: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_tkill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_tkill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5194 long sys_futex ['u32 __user *uaddr', 'int op', 'u32 val', 'struct __kernel_timespec __user *utime', 'u32 __user *uaddr2', 'u32 val3']
		case 5194: {
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
		// 5195 long sys_sched_setaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
		case 5195: {
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
		// 5196 long sys_sched_getaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
		case 5196: {
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
		// 5200 long sys_io_setup ['unsigned nr_reqs', 'aio_context_t __user *ctx']
		case 5200: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_io_setup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_setup_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5201 long sys_io_destroy ['aio_context_t ctx']
		case 5201: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_io_destroy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_destroy_return, cpu, pc, arg0) ;
		}; break;
		// 5202 long sys_io_getevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct __kernel_timespec __user *timeout']
		case 5202: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_io_getevents_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_getevents_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 5203 long sys_io_submit ['aio_context_t', 'long', 'struct iocb __user * __user *']
		case 5203: {
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
		// 5204 long sys_io_cancel ['aio_context_t ctx_id', 'struct iocb __user *iocb', 'struct io_event __user *result']
		case 5204: {
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
		// 5205 long sys_exit_group ['int error_code']
		case 5205: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_exit_group_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_exit_group_return, cpu, pc, arg0) ;
		}; break;
		// 5206 long sys_lookup_dcookie ['u64 cookie64', 'char __user *buf', 'size_t len']
		case 5206: {
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
		// 5207 long sys_epoll_create ['int size']
		case 5207: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_epoll_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_epoll_create_return, cpu, pc, arg0) ;
		}; break;
		// 5208 long sys_epoll_ctl ['int epfd', 'int op', 'int fd', 'struct epoll_event __user *event']
		case 5208: {
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
		// 5209 long sys_epoll_wait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout']
		case 5209: {
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
		// 5210 long sys_remap_file_pages ['unsigned long start', 'unsigned long size', 'unsigned long prot', 'unsigned long pgoff', 'unsigned long flags']
		case 5210: {
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
		// 5211 void sys_rt_sigreturn ['void']
		case 5211: {
			if (PPP_CHECK_CB(on_sys_rt_sigreturn_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_rt_sigreturn_return, cpu, pc) ;
		}; break;
		// 5212 long sys_set_tid_address ['int __user *tidptr']
		case 5212: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_set_tid_address_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_set_tid_address_return, cpu, pc, arg0) ;
		}; break;
		// 5213 long sys_restart_syscall ['void']
		case 5213: {
			if (PPP_CHECK_CB(on_sys_restart_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_restart_syscall_return, cpu, pc) ;
		}; break;
		// 5214 long sys_semtimedop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops', 'const struct __kernel_timespec __user *timeout']
		case 5214: {
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
		// 5215 long sys_fadvise64_64 ['int fd', 'loff_t offset', 'loff_t len', 'int advice']
		case 5215: {
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
		// 5216 long sys_timer_create ['clockid_t which_clock', 'struct sigevent __user *timer_event_spec', 'timer_t __user *created_timer_id']
		case 5216: {
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
		// 5217 long sys_timer_settime ['timer_t timer_id', 'int flags', 'const struct __kernel_itimerspec __user *new_setting', 'struct __kernel_itimerspec __user *old_setting']
		case 5217: {
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
		// 5218 long sys_timer_gettime ['timer_t timer_id', 'struct __kernel_itimerspec __user *setting']
		case 5218: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_timer_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5219 long sys_timer_getoverrun ['timer_t timer_id']
		case 5219: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_timer_getoverrun_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_getoverrun_return, cpu, pc, arg0) ;
		}; break;
		// 5220 long sys_timer_delete ['timer_t timer_id']
		case 5220: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_timer_delete_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_delete_return, cpu, pc, arg0) ;
		}; break;
		// 5221 long sys_clock_settime ['clockid_t which_clock', 'const struct __kernel_timespec __user *tp']
		case 5221: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_settime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5222 long sys_clock_gettime ['clockid_t which_clock', 'struct __kernel_timespec __user *tp']
		case 5222: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5223 long sys_clock_getres ['clockid_t which_clock', 'struct __kernel_timespec __user *tp']
		case 5223: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_getres_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_getres_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5224 long sys_clock_nanosleep ['clockid_t which_clock', 'int flags', 'const struct __kernel_timespec __user *rqtp', 'struct __kernel_timespec __user *rmtp']
		case 5224: {
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
		// 5225 long sys_tgkill ['pid_t tgid', 'pid_t pid', 'int sig']
		case 5225: {
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
		// 5226 long sys_utimes ['char __user *filename', 'struct __kernel_old_timeval __user *utimes']
		case 5226: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_utimes_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_utimes_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5227 long sys_mbind ['unsigned long start', 'unsigned long len', 'unsigned long mode', 'const unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned flags']
		case 5227: {
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
		// 5228 long sys_get_mempolicy ['int __user *policy', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned long addr', 'unsigned long flags']
		case 5228: {
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
		// 5229 long sys_set_mempolicy ['int mode', 'const unsigned long __user *nmask', 'unsigned long maxnode']
		case 5229: {
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
		// 5230 long sys_mq_open ['const char __user *name', 'int oflag', 'umode_t mode', 'struct mq_attr __user *attr']
		case 5230: {
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
		// 5231 long sys_mq_unlink ['const char __user *name']
		case 5231: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_mq_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 5232 long sys_mq_timedsend ['mqd_t mqdes', 'const char __user *msg_ptr', 'size_t msg_len', 'unsigned int msg_prio', 'const struct __kernel_timespec __user *abs_timeout']
		case 5232: {
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
		// 5233 long sys_mq_timedreceive ['mqd_t mqdes', 'char __user *msg_ptr', 'size_t msg_len', 'unsigned int __user *msg_prio', 'const struct __kernel_timespec __user *abs_timeout']
		case 5233: {
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
		// 5234 long sys_mq_notify ['mqd_t mqdes', 'const struct sigevent __user *notification']
		case 5234: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_mq_notify_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mq_notify_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5235 long sys_mq_getsetattr ['mqd_t mqdes', 'const struct mq_attr __user *mqstat', 'struct mq_attr __user *omqstat']
		case 5235: {
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
		// 5237 long sys_waitid ['int which', 'pid_t pid', 'struct siginfo __user *infop', 'int options', 'struct rusage __user *ru']
		case 5237: {
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
		// 5239 long sys_add_key ['const char __user *_type', 'const char __user *_description', 'const void __user *_payload', 'size_t plen', 'key_serial_t destringid']
		case 5239: {
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
		// 5240 long sys_request_key ['const char __user *_type', 'const char __user *_description', 'const char __user *_callout_info', 'key_serial_t destringid']
		case 5240: {
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
		// 5241 long sys_keyctl ['int cmd', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
		case 5241: {
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
		// 5243 long sys_inotify_init ['void']
		case 5243: {
			if (PPP_CHECK_CB(on_sys_inotify_init_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_inotify_init_return, cpu, pc) ;
		}; break;
		// 5244 long sys_inotify_add_watch ['int fd', 'const char __user *path', 'u32 mask']
		case 5244: {
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
		// 5245 long sys_inotify_rm_watch ['int fd', '__s32 wd']
		case 5245: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_inotify_rm_watch_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_inotify_rm_watch_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5246 long sys_migrate_pages ['pid_t pid', 'unsigned long maxnode', 'const unsigned long __user *from', 'const unsigned long __user *to']
		case 5246: {
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
		// 5247 long sys_openat ['int dfd', 'const char __user *filename', 'int flags', 'umode_t mode']
		case 5247: {
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
		// 5248 long sys_mkdirat ['int dfd', 'const char __user *pathname', 'umode_t mode']
		case 5248: {
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
		// 5249 long sys_mknodat ['int dfd', 'const char __user *filename', 'umode_t mode', 'unsigned dev']
		case 5249: {
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
		// 5250 long sys_fchownat ['int dfd', 'const char __user *filename', 'uid_t user', 'gid_t group', 'int flag']
		case 5250: {
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
		// 5251 long sys_futimesat ['int dfd', 'const char __user *filename', 'struct __kernel_old_timeval __user *utimes']
		case 5251: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_futimesat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_futimesat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 5252 long sys_newfstatat ['int dfd', 'const char __user *filename', 'struct stat __user *statbuf', 'int flag']
		case 5252: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_newfstatat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_newfstatat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 5253 long sys_unlinkat ['int dfd', 'const char __user *pathname', 'int flag']
		case 5253: {
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
		// 5254 long sys_renameat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname']
		case 5254: {
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
		// 5255 long sys_linkat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'int flags']
		case 5255: {
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
		// 5256 long sys_symlinkat ['const char __user *oldname', 'int newdfd', 'const char __user *newname']
		case 5256: {
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
		// 5257 long sys_readlinkat ['int dfd', 'const char __user *path', 'char __user *buf', 'int bufsiz']
		case 5257: {
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
		// 5258 long sys_fchmodat ['int dfd', 'const char __user *filename', 'umode_t mode']
		case 5258: {
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
		// 5259 long sys_faccessat ['int dfd', 'const char __user *filename', 'int mode']
		case 5259: {
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
		// 5260 long sys_pselect6 ['int', 'fd_set __user *', 'fd_set __user *', 'fd_set __user *', 'struct __kernel_timespec __user *', 'void __user *']
		case 5260: {
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
		// 5261 long sys_ppoll ['struct pollfd __user *', 'unsigned int', 'struct __kernel_timespec __user *', 'const sigset_t __user *', 'size_t']
		case 5261: {
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
		// 5262 long sys_unshare ['unsigned long unshare_flags']
		case 5262: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_unshare_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_unshare_return, cpu, pc, arg0) ;
		}; break;
		// 5263 long sys_splice ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
		case 5263: {
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
		// 5264 long sys_sync_file_range ['int fd', 'loff_t offset', 'loff_t nbytes', 'unsigned int flags']
		case 5264: {
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
		// 5265 long sys_tee ['int fdin', 'int fdout', 'size_t len', 'unsigned int flags']
		case 5265: {
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
		// 5266 long sys_vmsplice ['int fd', 'const struct iovec __user *iov', 'unsigned long nr_segs', 'unsigned int flags']
		case 5266: {
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
		// 5267 long sys_move_pages ['pid_t pid', 'unsigned long nr_pages', 'const void __user * __user *pages', 'const int __user *nodes', 'int __user *status', 'int flags']
		case 5267: {
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
		// 5268 long sys_set_robust_list ['struct robust_list_head __user *head', 'size_t len']
		case 5268: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_set_robust_list_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_set_robust_list_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5269 long sys_get_robust_list ['int pid', 'struct robust_list_head __user * __user *head_ptr', 'size_t __user *len_ptr']
		case 5269: {
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
		// 5270 long sys_kexec_load ['unsigned long entry', 'unsigned long nr_segments', 'struct kexec_segment __user *segments', 'unsigned long flags']
		case 5270: {
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
		// 5271 long sys_getcpu ['unsigned __user *cpu', 'unsigned __user *node', 'struct getcpu_cache __user *cache']
		case 5271: {
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
		// 5272 long sys_epoll_pwait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout', 'const sigset_t __user *sigmask', 'size_t sigsetsize']
		case 5272: {
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
		// 5273 long sys_ioprio_set ['int which', 'int who', 'int ioprio']
		case 5273: {
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
		// 5274 long sys_ioprio_get ['int which', 'int who']
		case 5274: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ioprio_get_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ioprio_get_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5275 long sys_utimensat ['int dfd', 'const char __user *filename', 'struct __kernel_timespec __user *utimes', 'int flags']
		case 5275: {
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
		// 5276 long sys_signalfd ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask']
		case 5276: {
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
		// 5278 long sys_eventfd ['unsigned int count']
		case 5278: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_eventfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_eventfd_return, cpu, pc, arg0) ;
		}; break;
		// 5279 long sys_fallocate ['int fd', 'int mode', 'loff_t offset', 'loff_t len']
		case 5279: {
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
		// 5280 long sys_timerfd_create ['int clockid', 'int flags']
		case 5280: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_timerfd_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_create_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5281 long sys_timerfd_gettime ['int ufd', 'struct __kernel_itimerspec __user *otmr']
		case 5281: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_timerfd_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5282 long sys_timerfd_settime ['int ufd', 'int flags', 'const struct __kernel_itimerspec __user *utmr', 'struct __kernel_itimerspec __user *otmr']
		case 5282: {
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
		// 5283 long sys_signalfd4 ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask', 'int flags']
		case 5283: {
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
		// 5284 long sys_eventfd2 ['unsigned int count', 'int flags']
		case 5284: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_eventfd2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_eventfd2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5285 long sys_epoll_create1 ['int flags']
		case 5285: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_epoll_create1_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_epoll_create1_return, cpu, pc, arg0) ;
		}; break;
		// 5286 long sys_dup3 ['unsigned int oldfd', 'unsigned int newfd', 'int flags']
		case 5286: {
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
		// 5287 long sys_pipe2 ['int __user *fildes', 'int flags']
		case 5287: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pipe2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pipe2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5288 long sys_inotify_init1 ['int flags']
		case 5288: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_inotify_init1_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_inotify_init1_return, cpu, pc, arg0) ;
		}; break;
		// 5289 long sys_preadv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
		case 5289: {
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
		// 5290 long sys_pwritev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
		case 5290: {
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
		// 5291 long sys_rt_tgsigqueueinfo ['pid_t tgid', 'pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
		case 5291: {
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
		// 5292 long sys_perf_event_open ['struct perf_event_attr __user *attr_uptr', 'pid_t pid', 'int cpu', 'int group_fd', 'unsigned long flags']
		case 5292: {
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
		// 5293 long sys_accept4 ['int', 'struct sockaddr __user *', 'int __user *', 'int']
		case 5293: {
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
		// 5294 long sys_recvmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags', 'struct __kernel_timespec __user *timeout']
		case 5294: {
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
		// 5295 long sys_fanotify_init ['unsigned int flags', 'unsigned int event_f_flags']
		case 5295: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fanotify_init_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fanotify_init_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5296 long sys_fanotify_mark ['int fanotify_fd', 'unsigned int flags', 'u64 mask', 'int fd', 'const char __user *pathname']
		case 5296: {
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
		// 5297 long sys_prlimit64 ['pid_t pid', 'unsigned int resource', 'const struct rlimit64 __user *new_rlim', 'struct rlimit64 __user *old_rlim']
		case 5297: {
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
		// 5298 long sys_name_to_handle_at ['int dfd', 'const char __user *name', 'struct file_handle __user *handle', 'int __user *mnt_id', 'int flag']
		case 5298: {
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
		// 5299 long sys_open_by_handle_at ['int mountdirfd', 'struct file_handle __user *handle', 'int flags']
		case 5299: {
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
		// 5300 long sys_clock_adjtime ['clockid_t which_clock', 'struct __kernel_timex __user *tx']
		case 5300: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_adjtime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clock_adjtime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5301 long sys_syncfs ['int fd']
		case 5301: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_syncfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_syncfs_return, cpu, pc, arg0) ;
		}; break;
		// 5302 long sys_sendmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags']
		case 5302: {
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
		// 5303 long sys_setns ['int fd', 'int nstype']
		case 5303: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setns_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setns_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5304 long sys_process_vm_readv ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
		case 5304: {
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
		// 5305 long sys_process_vm_writev ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
		case 5305: {
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
		// 5306 long sys_kcmp ['pid_t pid1', 'pid_t pid2', 'int type', 'unsigned long idx1', 'unsigned long idx2']
		case 5306: {
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
		// 5307 long sys_finit_module ['int fd', 'const char __user *uargs', 'int flags']
		case 5307: {
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
		// 5308 long sys_getdents64 ['unsigned int fd', 'struct linux_dirent64 __user *dirent', 'unsigned int count']
		case 5308: {
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
		// 5309 long sys_sched_setattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int flags']
		case 5309: {
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
		// 5310 long sys_sched_getattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int size', 'unsigned int flags']
		case 5310: {
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
		// 5311 long sys_renameat2 ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'unsigned int flags']
		case 5311: {
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
		// 5312 long sys_seccomp ['unsigned int op', 'unsigned int flags', 'void __user *uargs']
		case 5312: {
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
		// 5313 long sys_getrandom ['char __user *buf', 'size_t count', 'unsigned int flags']
		case 5313: {
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
		// 5314 long sys_memfd_create ['const char __user *uname_ptr', 'unsigned int flags']
		case 5314: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_memfd_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_memfd_create_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5315 long sys_bpf ['int cmd', 'union bpf_attr *attr', 'unsigned int size']
		case 5315: {
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
		// 5316 long sys_execveat ['int dfd', 'const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp', 'int flags']
		case 5316: {
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
		// 5317 long sys_userfaultfd ['int flags']
		case 5317: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_userfaultfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_userfaultfd_return, cpu, pc, arg0) ;
		}; break;
		// 5318 long sys_membarrier ['int cmd', 'int flags']
		case 5318: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_membarrier_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_membarrier_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5319 long sys_mlock2 ['unsigned long start', 'size_t len', 'int flags']
		case 5319: {
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
		// 5320 long sys_copy_file_range ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
		case 5320: {
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
		// 5321 long sys_preadv2 ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h', 'rwf_t flags']
		case 5321: {
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
		// 5322 long sys_pwritev2 ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h', 'rwf_t flags']
		case 5322: {
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
		// 5323 long sys_pkey_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot', 'int pkey']
		case 5323: {
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
		// 5324 long sys_pkey_alloc ['unsigned long flags', 'unsigned long init_val']
		case 5324: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pkey_alloc_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pkey_alloc_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5325 long sys_pkey_free ['int pkey']
		case 5325: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_pkey_free_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pkey_free_return, cpu, pc, arg0) ;
		}; break;
		// 5326 long sys_statx ['int dfd', 'const char __user *path', 'unsigned flags', 'unsigned mask', 'struct statx __user *buffer']
		case 5326: {
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
		// 5327 long sys_rseq ['struct rseq __user *rseq', 'uint32_t rseq_len', 'int flags', 'uint32_t sig']
		case 5327: {
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
		// 5328 long sys_io_pgetevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct __kernel_timespec __user *timeout', 'const struct __aio_sigset *sig']
		case 5328: {
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
		// 5424 long sys_pidfd_send_signal ['int pidfd', 'int sig', 'siginfo_t __user *info', 'unsigned int flags']
		case 5424: {
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
		// 5425 long sys_io_uring_setup ['u32 entries', 'struct io_uring_params __user *p']
		case 5425: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_io_uring_setup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_io_uring_setup_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5426 long sys_io_uring_enter ['unsigned int fd', 'u32 to_submit', 'u32 min_complete', 'u32 flags', 'const sigset_t __user *sig', 'size_t sigsz']
		case 5426: {
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
		// 5427 long sys_io_uring_register ['unsigned int fd', 'unsigned int op', 'void __user *arg', 'unsigned int nr_args']
		case 5427: {
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
		// 5428 long sys_open_tree ['int dfd', 'const char __user *path', 'unsigned flags']
		case 5428: {
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
		// 5429 long sys_move_mount ['int from_dfd', 'const char __user *from_path', 'int to_dfd', 'const char __user *to_path', 'unsigned int ms_flags']
		case 5429: {
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
		// 5430 long sys_fsopen ['const char __user *fs_name', 'unsigned int flags']
		case 5430: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fsopen_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fsopen_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5431 long sys_fsconfig ['int fs_fd', 'unsigned int cmd', 'const char __user *key', 'const void __user *value', 'int aux']
		case 5431: {
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
		// 5432 long sys_fsmount ['int fs_fd', 'unsigned int flags', 'unsigned int ms_flags']
		case 5432: {
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
		// 5433 long sys_fspick ['int dfd', 'const char __user *path', 'unsigned int flags']
		case 5433: {
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
		// 5434 long sys_pidfd_open ['pid_t pid', 'unsigned int flags']
		case 5434: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pidfd_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_pidfd_open_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5435 long sys_clone3 ['struct clone_args __user *uargs', 'size_t size']
		case 5435: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clone3_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_clone3_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 5437 long sys_openat2 ['int dfd', 'const char __user *filename', 'struct open_how *how', 'size_t size']
		case 5437: {
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
		// 5438 long sys_pidfd_getfd ['int pidfd', 'int fd', 'unsigned int flags']
		case 5438: {
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
		// 5439 long sys_faccessat2 ['int dfd', 'const char __user *filename', 'int mode', 'int flags']
		case 5439: {
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