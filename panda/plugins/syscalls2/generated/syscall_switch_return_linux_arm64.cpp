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

void syscall_return_switch_linux_arm64(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx) {
#if defined(TARGET_ARM) && defined(TARGET_AARCH64)
	const syscall_info_t *call = (syscall_meta == NULL || ctx->no > syscall_meta->max_generic) ? NULL : &syscall_info[ctx->no];
	switch (ctx->no) {
		// 0 long sys_io_setup ['unsigned nr_reqs', 'aio_context_t __user *ctx']
		case 0: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_io_setup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_io_setup_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 1 long sys_io_destroy ['aio_context_t ctx']
		case 1: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_io_destroy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_io_destroy_return, cpu, pc, arg0) ;
		}; break;
		// 2 long sys_io_submit ['aio_context_t', 'long', 'struct iocb __user * __user *']
		case 2: {
			uint64_t arg0;
			int64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_io_submit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_io_submit_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 3 long sys_io_cancel ['aio_context_t ctx_id', 'struct iocb __user *iocb', 'struct io_event __user *result']
		case 3: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_io_cancel_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_io_cancel_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4 long sys_io_getevents ['aio_context_t ctx_id', 'long min_nr', 'long nr', 'struct io_event __user *events', 'struct timespec __user *timeout']
		case 4: {
			uint64_t arg0;
			int64_t arg1;
			int64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_io_getevents_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_io_getevents_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 5 long sys_setxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 5: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_setxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setxattr_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 6 long sys_lsetxattr ['const char __user *path', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 6: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_lsetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_lsetxattr_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 7 long sys_fsetxattr ['int fd', 'const char __user *name', 'const void __user *value', 'size_t size', 'int flags']
		case 7: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_fsetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fsetxattr_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 8 long sys_getxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
		case 8: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_getxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getxattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 9 long sys_lgetxattr ['const char __user *path', 'const char __user *name', 'void __user *value', 'size_t size']
		case 9: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_lgetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lgetxattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 10 long sys_fgetxattr ['int fd', 'const char __user *name', 'void __user *value', 'size_t size']
		case 10: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_fgetxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fgetxattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 11 long sys_listxattr ['const char __user *path', 'char __user *list', 'size_t size']
		case 11: {
			uint64_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_listxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_listxattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 12 long sys_llistxattr ['const char __user *path', 'char __user *list', 'size_t size']
		case 12: {
			uint64_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_llistxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_llistxattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 13 long sys_flistxattr ['int fd', 'char __user *list', 'size_t size']
		case 13: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_flistxattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_flistxattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 14 long sys_removexattr ['const char __user *path', 'const char __user *name']
		case 14: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_removexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_removexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 15 long sys_lremovexattr ['const char __user *path', 'const char __user *name']
		case 15: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_lremovexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_lremovexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 16 long sys_fremovexattr ['int fd', 'const char __user *name']
		case 16: {
			int32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_fremovexattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fremovexattr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 17 long sys_getcwd ['char __user *buf', 'unsigned long size']
		case 17: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_getcwd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getcwd_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 18 long sys_lookup_dcookie ['u64 cookie64', 'char __user *buf', 'size_t len']
		case 18: {
			uint64_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_lookup_dcookie_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lookup_dcookie_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 19 long sys_epoll_ctl ['int epfd', 'int op', 'int fd', 'struct epoll_event __user *event']
		case 19: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_epoll_ctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_epoll_ctl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 20 long sys_epoll_pwait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout', 'const sigset_t __user *sigmask', 'size_t sigsetsize']
		case 20: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			int32_t arg3;
			uint64_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_epoll_pwait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_epoll_pwait_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 21 long sys_dup ['unsigned int fildes']
		case 21: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_dup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_dup_return, cpu, pc, arg0) ;
		}; break;
		// 22 long sys_inotify_add_watch ['int fd', 'const char __user *path', 'u32 mask']
		case 22: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_inotify_add_watch_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_inotify_add_watch_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 23 long sys_inotify_rm_watch ['int fd', '__s32 wd']
		case 23: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_inotify_rm_watch_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_inotify_rm_watch_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 24 long sys_ioctl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
		case 24: {
			uint32_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_ioctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ioctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 25 long sys_ioprio_set ['int which', 'int who', 'int ioprio']
		case 25: {
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
		// 26 long sys_ioprio_get ['int which', 'int who']
		case 26: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_ioprio_get_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ioprio_get_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 27 long sys_flock ['unsigned int fd', 'unsigned int cmd']
		case 27: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_flock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_flock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 28 long sys_mknodat ['int dfd', 'const char __user *filename', 'umode_t mode', 'unsigned dev']
		case 28: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_mknodat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mknodat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 29 long sys_mkdirat ['int dfd', 'const char __user *pathname', 'umode_t mode']
		case 29: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_mkdirat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkdirat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 30 long sys_unlinkat ['int dfd', 'const char __user *pathname', 'int flag']
		case 30: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_unlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_unlinkat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 31 long sys_symlinkat ['const char __user *oldname', 'int newdfd', 'const char __user *newname']
		case 31: {
			uint64_t arg0;
			int32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_symlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_symlinkat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 32 long sys_linkat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname', 'int flags']
		case 32: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			uint64_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_linkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_linkat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 33 long sys_renameat ['int olddfd', 'const char __user *oldname', 'int newdfd', 'const char __user *newname']
		case 33: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_renameat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_renameat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 34 long sys_mount ['char __user *dev_name', 'char __user *dir_name', 'char __user *type', 'unsigned long flags', 'void __user *data']
		case 34: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_mount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mount_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 35 long sys_pivot_root ['const char __user *new_root', 'const char __user *put_old']
		case 35: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_pivot_root_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pivot_root_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 37 long sys_fallocate ['int fd', 'int mode', 'loff_t offset', 'loff_t len']
		case 37: {
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
		// 38 long sys_faccessat ['int dfd', 'const char __user *filename', 'int mode']
		case 38: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_faccessat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_faccessat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 39 long sys_chdir ['const char __user *filename']
		case 39: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_chdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_chdir_return, cpu, pc, arg0) ;
		}; break;
		// 40 long sys_fchdir ['unsigned int fd']
		case 40: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_fchdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchdir_return, cpu, pc, arg0) ;
		}; break;
		// 41 long sys_chroot ['const char __user *filename']
		case 41: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_chroot_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_chroot_return, cpu, pc, arg0) ;
		}; break;
		// 42 long sys_fchmod ['unsigned int fd', 'umode_t mode']
		case 42: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_fchmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 43 long sys_fchmodat ['int dfd', 'const char __user *filename', 'umode_t mode']
		case 43: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_fchmodat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchmodat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 44 long sys_fchownat ['int dfd', 'const char __user *filename', 'uid_t user', 'gid_t group', 'int flag']
		case 44: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_fchownat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fchownat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 45 long sys_fchown ['unsigned int fd', 'uid_t user', 'gid_t group']
		case 45: {
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
		// 46 long sys_openat ['int dfd', 'const char __user *filename', 'int flags', 'umode_t mode']
		case 46: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_openat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_openat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 47 long sys_close ['unsigned int fd']
		case 47: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_close_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_close_return, cpu, pc, arg0) ;
		}; break;
		// 48 long sys_vhangup ['void']
		case 48: {
			if (PPP_CHECK_CB(on_sys_vhangup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_vhangup_return, cpu, pc) ;
		}; break;
		// 49 long sys_quotactl ['unsigned int cmd', 'const char __user *special', 'qid_t id', 'void __user *addr']
		case 49: {
			uint32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_quotactl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_quotactl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 50 long sys_read ['unsigned int fd', 'char __user *buf', 'size_t count']
		case 50: {
			uint32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_read_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_read_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 51 long sys_write ['unsigned int fd', 'const char __user *buf', 'size_t count']
		case 51: {
			uint32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_write_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_write_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 52 long sys_readv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
		case 52: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_readv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_readv_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 53 long sys_writev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen']
		case 53: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_writev_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_writev_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 54 long sys_preadv ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
		case 54: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_preadv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_preadv_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 55 long sys_pwritev ['unsigned long fd', 'const struct iovec __user *vec', 'unsigned long vlen', 'unsigned long pos_l', 'unsigned long pos_h']
		case 55: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_pwritev_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pwritev_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 56 long sys_ppoll ['struct pollfd __user *', 'unsigned int', 'struct timespec __user *', 'const sigset_t __user *', 'size_t']
		case 56: {
			uint64_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_ppoll_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ppoll_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 57 long sys_vmsplice ['int fd', 'const struct iovec __user *iov', 'unsigned long nr_segs', 'unsigned int flags']
		case 57: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_vmsplice_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_vmsplice_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 58 long sys_splice ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
		case 58: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			uint64_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_splice_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_splice_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 59 long sys_tee ['int fdin', 'int fdout', 'size_t len', 'unsigned int flags']
		case 59: {
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
		// 60 long sys_readlinkat ['int dfd', 'const char __user *path', 'char __user *buf', 'int bufsiz']
		case 60: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_readlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_readlinkat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 61 long sys_sync ['void']
		case 61: {
			if (PPP_CHECK_CB(on_sys_sync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sync_return, cpu, pc) ;
		}; break;
		// 62 long sys_fsync ['unsigned int fd']
		case 62: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_fsync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fsync_return, cpu, pc, arg0) ;
		}; break;
		// 63 long sys_fdatasync ['unsigned int fd']
		case 63: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_fdatasync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fdatasync_return, cpu, pc, arg0) ;
		}; break;
		// 64 long sys_sync_file_range ['int fd', 'loff_t offset', 'loff_t nbytes', 'unsigned int flags']
		case 64: {
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
		// 65 long sys_timerfd_create ['int clockid', 'int flags']
		case 65: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_timerfd_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_timerfd_create_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 66 long sys_timerfd_settime ['int ufd', 'int flags', 'const struct itimerspec __user *utmr', 'struct itimerspec __user *otmr']
		case 66: {
			int32_t arg0;
			int32_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_timerfd_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_timerfd_settime_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 67 long sys_timerfd_gettime ['int ufd', 'struct itimerspec __user *otmr']
		case 67: {
			int32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_timerfd_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_timerfd_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 68 long sys_utimensat ['int dfd', 'const char __user *filename', 'struct timespec __user *utimes', 'int flags']
		case 68: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_utimensat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_utimensat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 69 long sys_acct ['const char __user *name']
		case 69: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_acct_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_acct_return, cpu, pc, arg0) ;
		}; break;
		// 70 long sys_capget ['cap_user_header_t header', 'cap_user_data_t dataptr']
		case 70: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_capget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_capget_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 71 long sys_capset ['cap_user_header_t header', 'const cap_user_data_t data']
		case 71: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_capset_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_capset_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 72 long sys_personality ['unsigned int personality']
		case 72: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_personality_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_personality_return, cpu, pc, arg0) ;
		}; break;
		// 73 long sys_exit ['int error_code']
		case 73: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_exit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_exit_return, cpu, pc, arg0) ;
		}; break;
		// 74 long sys_exit_group ['int error_code']
		case 74: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_exit_group_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_exit_group_return, cpu, pc, arg0) ;
		}; break;
		// 75 long sys_waitid ['int which', 'pid_t pid', 'struct siginfo __user *infop', 'int options', 'struct rusage __user *ru']
		case 75: {
			int32_t arg0;
			int32_t arg1;
			uint64_t arg2;
			int32_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_waitid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_waitid_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 76 long sys_set_tid_address ['int __user *tidptr']
		case 76: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_set_tid_address_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_set_tid_address_return, cpu, pc, arg0) ;
		}; break;
		// 77 long sys_unshare ['unsigned long unshare_flags']
		case 77: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_unshare_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_unshare_return, cpu, pc, arg0) ;
		}; break;
		// 78 long sys_futex ['u32 __user *uaddr', 'int op', 'u32 val', 'struct timespec __user *utime', 'u32 __user *uaddr2', 'u32 val3']
		case 78: {
			uint64_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_futex_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_futex_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 79 long sys_set_robust_list ['struct robust_list_head __user *head', 'size_t len']
		case 79: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_set_robust_list_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_set_robust_list_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 80 long sys_get_robust_list ['int pid', 'struct robust_list_head __user * __user *head_ptr', 'size_t __user *len_ptr']
		case 80: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_get_robust_list_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_get_robust_list_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 81 long sys_nanosleep ['struct timespec __user *rqtp', 'struct timespec __user *rmtp']
		case 81: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_nanosleep_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_nanosleep_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 82 long sys_getitimer ['int which', 'struct itimerval __user *value']
		case 82: {
			int32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_getitimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getitimer_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 83 long sys_setitimer ['int which', 'struct itimerval __user *value', 'struct itimerval __user *ovalue']
		case 83: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_setitimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setitimer_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 84 long sys_kexec_load ['unsigned long entry', 'unsigned long nr_segments', 'struct kexec_segment __user *segments', 'unsigned long flags']
		case 84: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_kexec_load_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kexec_load_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 85 long sys_init_module ['void __user *umod', 'unsigned long len', 'const char __user *uargs']
		case 85: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_init_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_init_module_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 86 long sys_delete_module ['const char __user *name_user', 'unsigned int flags']
		case 86: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_delete_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_delete_module_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 87 long sys_timer_create ['clockid_t which_clock', 'struct sigevent __user *timer_event_spec', 'timer_t __user *created_timer_id']
		case 87: {
			uint32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_timer_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_timer_create_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 88 long sys_timer_gettime ['timer_t timer_id', 'struct itimerspec __user *setting']
		case 88: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_timer_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_timer_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 89 long sys_timer_getoverrun ['timer_t timer_id']
		case 89: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_timer_getoverrun_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_getoverrun_return, cpu, pc, arg0) ;
		}; break;
		// 90 long sys_timer_settime ['timer_t timer_id', 'int flags', 'const struct itimerspec __user *new_setting', 'struct itimerspec __user *old_setting']
		case 90: {
			uint32_t arg0;
			int32_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_timer_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_timer_settime_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 91 long sys_timer_delete ['timer_t timer_id']
		case 91: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_timer_delete_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_timer_delete_return, cpu, pc, arg0) ;
		}; break;
		// 92 long sys_clock_settime ['clockid_t which_clock', 'const struct timespec __user *tp']
		case 92: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clock_settime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 93 long sys_clock_gettime ['clockid_t which_clock', 'struct timespec __user *tp']
		case 93: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clock_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 94 long sys_clock_getres ['clockid_t which_clock', 'struct timespec __user *tp']
		case 94: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_getres_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clock_getres_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 95 long sys_clock_nanosleep ['clockid_t which_clock', 'int flags', 'const struct timespec __user *rqtp', 'struct timespec __user *rmtp']
		case 95: {
			uint32_t arg0;
			int32_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_clock_nanosleep_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clock_nanosleep_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 96 long sys_syslog ['int type', 'char __user *buf', 'int len']
		case 96: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_syslog_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_syslog_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 97 long sys_ptrace ['long request', 'long pid', 'unsigned long addr', 'unsigned long data']
		case 97: {
			int64_t arg0;
			int64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_ptrace_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ptrace_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 98 long sys_sched_setparam ['pid_t pid', 'struct sched_param __user *param']
		case 98: {
			int32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_sched_setparam_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sched_setparam_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 99 long sys_sched_setscheduler ['pid_t pid', 'int policy', 'struct sched_param __user *param']
		case 99: {
			int32_t arg0;
			int32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_sched_setscheduler_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sched_setscheduler_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 100 long sys_sched_getscheduler ['pid_t pid']
		case 100: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_sched_getscheduler_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_getscheduler_return, cpu, pc, arg0) ;
		}; break;
		// 101 long sys_sched_getparam ['pid_t pid', 'struct sched_param __user *param']
		case 101: {
			int32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_sched_getparam_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sched_getparam_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 102 long sys_sched_setaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
		case 102: {
			int32_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_sched_setaffinity_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sched_setaffinity_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 103 long sys_sched_getaffinity ['pid_t pid', 'unsigned int len', 'unsigned long __user *user_mask_ptr']
		case 103: {
			int32_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_sched_getaffinity_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sched_getaffinity_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 104 long sys_sched_yield ['void']
		case 104: {
			if (PPP_CHECK_CB(on_sys_sched_yield_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sched_yield_return, cpu, pc) ;
		}; break;
		// 105 long sys_sched_get_priority_max ['int policy']
		case 105: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_sched_get_priority_max_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_get_priority_max_return, cpu, pc, arg0) ;
		}; break;
		// 106 long sys_sched_get_priority_min ['int policy']
		case 106: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_sched_get_priority_min_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_get_priority_min_return, cpu, pc, arg0) ;
		}; break;
		// 107 long sys_sched_rr_get_interval ['pid_t pid', 'struct timespec __user *interval']
		case 107: {
			int32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_sched_rr_get_interval_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sched_rr_get_interval_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 108 long sys_restart_syscall ['void']
		case 108: {
			if (PPP_CHECK_CB(on_sys_restart_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_restart_syscall_return, cpu, pc) ;
		}; break;
		// 109 long sys_kill ['pid_t pid', 'int sig']
		case 109: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_kill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_kill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 110 long sys_tkill ['pid_t pid', 'int sig']
		case 110: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_tkill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_tkill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 111 long sys_tgkill ['pid_t tgid', 'pid_t pid', 'int sig']
		case 111: {
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
		// 112 long sys_sigaltstack ['const struct sigaltstack __user *uss', 'struct sigaltstack __user *uoss']
		case 112: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_sigaltstack_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigaltstack_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 113 long sys_rt_sigsuspend ['sigset_t __user *unewset', 'size_t sigsetsize']
		case 113: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_rt_sigsuspend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigsuspend_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 114 long sys_rt_sigaction ['int', 'const struct sigaction __user *', 'struct sigaction __user *', 'size_t']
		case 114: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_rt_sigaction_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigaction_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 115 long sys_rt_sigprocmask ['int how', 'sigset_t __user *set', 'sigset_t __user *oset', 'size_t sigsetsize']
		case 115: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_rt_sigprocmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigprocmask_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 116 long sys_rt_sigpending ['sigset_t __user *set', 'size_t sigsetsize']
		case 116: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_rt_sigpending_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigpending_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 117 long sys_rt_sigtimedwait ['const sigset_t __user *uthese', 'siginfo_t __user *uinfo', 'const struct timespec __user *uts', 'size_t sigsetsize']
		case 117: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_rt_sigtimedwait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rt_sigtimedwait_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 118 long sys_rt_sigqueueinfo ['pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
		case 118: {
			int32_t arg0;
			int32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_rt_sigqueueinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_rt_sigqueueinfo_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 119 long sys_rt_sigreturn ['struct pt_regs *regs']
		case 119: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_rt_sigreturn_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_rt_sigreturn_return, cpu, pc, arg0) ;
		}; break;
		// 120 long sys_setpriority ['int which', 'int who', 'int niceval']
		case 120: {
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
		// 121 long sys_getpriority ['int which', 'int who']
		case 121: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_getpriority_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getpriority_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 122 long sys_reboot ['int magic1', 'int magic2', 'unsigned int cmd', 'void __user *arg']
		case 122: {
			int32_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_reboot_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_reboot_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 123 long sys_setregid ['gid_t rgid', 'gid_t egid']
		case 123: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_setregid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setregid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 124 long sys_setgid ['gid_t gid']
		case 124: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_setgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setgid_return, cpu, pc, arg0) ;
		}; break;
		// 125 long sys_setreuid ['uid_t ruid', 'uid_t euid']
		case 125: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_setreuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setreuid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 126 long sys_setuid ['uid_t uid']
		case 126: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_setuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setuid_return, cpu, pc, arg0) ;
		}; break;
		// 127 long sys_setresuid ['uid_t ruid', 'uid_t euid', 'uid_t suid']
		case 127: {
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
		// 128 long sys_getresuid ['uid_t __user *ruid', 'uid_t __user *euid', 'uid_t __user *suid']
		case 128: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_getresuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getresuid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 129 long sys_setresgid ['gid_t rgid', 'gid_t egid', 'gid_t sgid']
		case 129: {
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
		// 130 long sys_getresgid ['gid_t __user *rgid', 'gid_t __user *egid', 'gid_t __user *sgid']
		case 130: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_getresgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getresgid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 131 long sys_setfsuid ['uid_t uid']
		case 131: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_setfsuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setfsuid_return, cpu, pc, arg0) ;
		}; break;
		// 132 long sys_setfsgid ['gid_t gid']
		case 132: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_setfsgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setfsgid_return, cpu, pc, arg0) ;
		}; break;
		// 133 long sys_times ['struct tms __user *tbuf']
		case 133: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_times_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_times_return, cpu, pc, arg0) ;
		}; break;
		// 134 long sys_setpgid ['pid_t pid', 'pid_t pgid']
		case 134: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_setpgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setpgid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 135 long sys_getpgid ['pid_t pid']
		case 135: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_getpgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getpgid_return, cpu, pc, arg0) ;
		}; break;
		// 136 long sys_getsid ['pid_t pid']
		case 136: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_getsid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getsid_return, cpu, pc, arg0) ;
		}; break;
		// 137 long sys_setsid ['void']
		case 137: {
			if (PPP_CHECK_CB(on_sys_setsid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_setsid_return, cpu, pc) ;
		}; break;
		// 138 long sys_getgroups ['int gidsetsize', 'gid_t __user *grouplist']
		case 138: {
			int32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_getgroups_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getgroups_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 139 long sys_setgroups ['int gidsetsize', 'gid_t __user *grouplist']
		case 139: {
			int32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_setgroups_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setgroups_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 140 long sys_newuname ['struct new_utsname __user *name']
		case 140: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_newuname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_newuname_return, cpu, pc, arg0) ;
		}; break;
		// 141 long sys_sethostname ['char __user *name', 'int len']
		case 141: {
			uint64_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_sethostname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sethostname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 142 long sys_setdomainname ['char __user *name', 'int len']
		case 142: {
			uint64_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_setdomainname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setdomainname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 143 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
		case 143: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_getrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 144 long sys_setrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
		case 144: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_setrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 145 long sys_getrusage ['int who', 'struct rusage __user *ru']
		case 145: {
			int32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_getrusage_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getrusage_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 146 long sys_umask ['int mask']
		case 146: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_umask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_umask_return, cpu, pc, arg0) ;
		}; break;
		// 147 long sys_prctl ['int option', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
		case 147: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_prctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_prctl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 148 long sys_getcpu ['unsigned __user *cpu', 'unsigned __user *node', 'struct getcpu_cache __user *cache']
		case 148: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_getcpu_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getcpu_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 149 long sys_gettimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
		case 149: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_gettimeofday_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_gettimeofday_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 150 long sys_settimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
		case 150: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_settimeofday_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_settimeofday_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 151 long sys_adjtimex ['struct timex __user *txc_p']
		case 151: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_adjtimex_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_adjtimex_return, cpu, pc, arg0) ;
		}; break;
		// 152 long sys_getpid ['void']
		case 152: {
			if (PPP_CHECK_CB(on_sys_getpid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpid_return, cpu, pc) ;
		}; break;
		// 153 long sys_getppid ['void']
		case 153: {
			if (PPP_CHECK_CB(on_sys_getppid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getppid_return, cpu, pc) ;
		}; break;
		// 154 long sys_getuid ['void']
		case 154: {
			if (PPP_CHECK_CB(on_sys_getuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getuid_return, cpu, pc) ;
		}; break;
		// 155 long sys_geteuid ['void']
		case 155: {
			if (PPP_CHECK_CB(on_sys_geteuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_geteuid_return, cpu, pc) ;
		}; break;
		// 156 long sys_getgid ['void']
		case 156: {
			if (PPP_CHECK_CB(on_sys_getgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getgid_return, cpu, pc) ;
		}; break;
		// 157 long sys_getegid ['void']
		case 157: {
			if (PPP_CHECK_CB(on_sys_getegid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getegid_return, cpu, pc) ;
		}; break;
		// 158 long sys_gettid ['void']
		case 158: {
			if (PPP_CHECK_CB(on_sys_gettid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_gettid_return, cpu, pc) ;
		}; break;
		// 159 long sys_sysinfo ['struct sysinfo __user *info']
		case 159: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_sysinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sysinfo_return, cpu, pc, arg0) ;
		}; break;
		// 160 long sys_mq_open ['const char __user *name', 'int oflag', 'umode_t mode', 'struct mq_attr __user *attr']
		case 160: {
			uint64_t arg0;
			int32_t arg1;
			uint32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_mq_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mq_open_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 161 long sys_mq_unlink ['const char __user *name']
		case 161: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_mq_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mq_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 162 long sys_mq_timedsend ['mqd_t mqdes', 'const char __user *msg_ptr', 'size_t msg_len', 'unsigned int msg_prio', 'const struct timespec __user *abs_timeout']
		case 162: {
			uint32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_mq_timedsend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mq_timedsend_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 163 long sys_mq_timedreceive ['mqd_t mqdes', 'char __user *msg_ptr', 'size_t msg_len', 'unsigned int __user *msg_prio', 'const struct timespec __user *abs_timeout']
		case 163: {
			uint32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_mq_timedreceive_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mq_timedreceive_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 164 long sys_mq_notify ['mqd_t mqdes', 'const struct sigevent __user *notification']
		case 164: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_mq_notify_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mq_notify_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 165 long sys_mq_getsetattr ['mqd_t mqdes', 'const struct mq_attr __user *mqstat', 'struct mq_attr __user *omqstat']
		case 165: {
			uint32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_mq_getsetattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mq_getsetattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 166 long sys_msgget ['key_t key', 'int msgflg']
		case 166: {
			uint32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_msgget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgget_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 167 long sys_msgctl ['int msqid', 'int cmd', 'struct msqid_ds __user *buf']
		case 167: {
			int32_t arg0;
			int32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_msgctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_msgctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 168 long sys_msgrcv ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'long msgtyp', 'int msgflg']
		case 168: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			int64_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_msgrcv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgrcv_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 169 long sys_msgsnd ['int msqid', 'struct msgbuf __user *msgp', 'size_t msgsz', 'int msgflg']
		case 169: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_msgsnd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgsnd_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 170 long sys_semget ['key_t key', 'int nsems', 'int semflg']
		case 170: {
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
		// 171 long sys_semctl ['int semid', 'int semnum', 'int cmd', 'unsigned long arg']
		case 171: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_semctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_semctl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 172 long sys_semtimedop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops', 'const struct timespec __user *timeout']
		case 172: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_semtimedop_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_semtimedop_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 173 long sys_semop ['int semid', 'struct sembuf __user *sops', 'unsigned nsops']
		case 173: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_semop_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_semop_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 174 long sys_shmget ['key_t key', 'size_t size', 'int flag']
		case 174: {
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
		// 175 long sys_shmctl ['int shmid', 'int cmd', 'struct shmid_ds __user *buf']
		case 175: {
			int32_t arg0;
			int32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_shmctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_shmctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 176 long sys_shmat ['int shmid', 'char __user *shmaddr', 'int shmflg']
		case 176: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_shmat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shmat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 177 long sys_shmdt ['char __user *shmaddr']
		case 177: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_shmdt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_shmdt_return, cpu, pc, arg0) ;
		}; break;
		// 178 long sys_socket ['int', 'int', 'int']
		case 178: {
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
		// 179 long sys_socketpair ['int', 'int', 'int', 'int __user *']
		case 179: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_socketpair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_socketpair_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 180 long sys_bind ['int', 'struct sockaddr __user *', 'int']
		case 180: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_bind_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_bind_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 181 long sys_listen ['int', 'int']
		case 181: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_listen_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_listen_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 182 long sys_accept ['int', 'struct sockaddr __user *', 'int __user *']
		case 182: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_accept_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_accept_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 183 long sys_connect ['int', 'struct sockaddr __user *', 'int']
		case 183: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_connect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_connect_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 184 long sys_getsockname ['int', 'struct sockaddr __user *', 'int __user *']
		case 184: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_getsockname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getsockname_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 185 long sys_getpeername ['int', 'struct sockaddr __user *', 'int __user *']
		case 185: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_getpeername_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getpeername_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 186 long sys_sendto ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int']
		case 186: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint64_t arg4;
			int32_t arg5;
			if (PPP_CHECK_CB(on_sys_sendto_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sendto_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 187 long sys_recvfrom ['int', 'void __user *', 'size_t', 'unsigned', 'struct sockaddr __user *', 'int __user *']
		case 187: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint64_t arg4;
			uint64_t arg5;
			if (PPP_CHECK_CB(on_sys_recvfrom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_recvfrom_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 188 long sys_setsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int optlen']
		case 188: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint64_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_setsockopt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setsockopt_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 189 long sys_getsockopt ['int fd', 'int level', 'int optname', 'char __user *optval', 'int __user *optlen']
		case 189: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_getsockopt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getsockopt_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 190 long sys_shutdown ['int', 'int']
		case 190: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_shutdown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shutdown_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 191 long sys_sendmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
		case 191: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sendmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendmsg_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 192 long sys_recvmsg ['int fd', 'struct user_msghdr __user *msg', 'unsigned flags']
		case 192: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_recvmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recvmsg_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 193 long sys_readahead ['int fd', 'loff_t offset', 'size_t count']
		case 193: {
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
		// 194 long sys_brk ['unsigned long brk']
		case 194: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_brk_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_brk_return, cpu, pc, arg0) ;
		}; break;
		// 195 long sys_munmap ['unsigned long addr', 'size_t len']
		case 195: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_munmap_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_munmap_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 196 long sys_mremap ['unsigned long addr', 'unsigned long old_len', 'unsigned long new_len', 'unsigned long flags', 'unsigned long new_addr']
		case 196: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_mremap_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mremap_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 197 long sys_add_key ['const char __user *_type', 'const char __user *_description', 'const void __user *_payload', 'size_t plen', 'key_serial_t destringid']
		case 197: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			uint32_t arg4;
			if (PPP_CHECK_CB(on_sys_add_key_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_add_key_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 198 long sys_request_key ['const char __user *_type', 'const char __user *_description', 'const char __user *_callout_info', 'key_serial_t destringid']
		case 198: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_request_key_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_request_key_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 199 long sys_keyctl ['int cmd', 'unsigned long arg2', 'unsigned long arg3', 'unsigned long arg4', 'unsigned long arg5']
		case 199: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_keyctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_keyctl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 200 long sys_clone ['unsigned long', 'unsigned long', 'int __user *', 'int __user *', 'unsigned long']
		case 200: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_clone_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clone_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 201 long sys_execve ['const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp']
		case 201: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_execve_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_execve_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 202 long sys_swapon ['const char __user *specialfile', 'int swap_flags']
		case 202: {
			uint64_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_swapon_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_swapon_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 203 long sys_swapoff ['const char __user *specialfile']
		case 203: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_swapoff_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_swapoff_return, cpu, pc, arg0) ;
		}; break;
		// 204 long sys_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot']
		case 204: {
			uint64_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_mprotect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mprotect_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 205 long sys_msync ['unsigned long start', 'size_t len', 'int flags']
		case 205: {
			uint64_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_msync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msync_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 206 long sys_mlock ['unsigned long start', 'size_t len']
		case 206: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_mlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mlock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 207 long sys_munlock ['unsigned long start', 'size_t len']
		case 207: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_munlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_munlock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 208 long sys_mlockall ['int flags']
		case 208: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_mlockall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_mlockall_return, cpu, pc, arg0) ;
		}; break;
		// 209 long sys_munlockall ['void']
		case 209: {
			if (PPP_CHECK_CB(on_sys_munlockall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_munlockall_return, cpu, pc) ;
		}; break;
		// 210 long sys_mincore ['unsigned long start', 'size_t len', 'unsigned char __user *vec']
		case 210: {
			uint64_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_mincore_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mincore_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 211 long sys_madvise ['unsigned long start', 'size_t len', 'int behavior']
		case 211: {
			uint64_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_madvise_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_madvise_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 212 long sys_remap_file_pages ['unsigned long start', 'unsigned long size', 'unsigned long prot', 'unsigned long pgoff', 'unsigned long flags']
		case 212: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_remap_file_pages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_remap_file_pages_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 213 long sys_mbind ['unsigned long start', 'unsigned long len', 'unsigned long mode', 'const unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned flags']
		case 213: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_mbind_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mbind_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 214 long sys_get_mempolicy ['int __user *policy', 'unsigned long __user *nmask', 'unsigned long maxnode', 'unsigned long addr', 'unsigned long flags']
		case 214: {
			uint64_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_get_mempolicy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_get_mempolicy_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 215 long sys_set_mempolicy ['int mode', 'const unsigned long __user *nmask', 'unsigned long maxnode']
		case 215: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_set_mempolicy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_set_mempolicy_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 216 long sys_migrate_pages ['pid_t pid', 'unsigned long maxnode', 'const unsigned long __user *from', 'const unsigned long __user *to']
		case 216: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_migrate_pages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_migrate_pages_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 217 long sys_move_pages ['pid_t pid', 'unsigned long nr_pages', 'const void __user * __user *pages', 'const int __user *nodes', 'int __user *status', 'int flags']
		case 217: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			int32_t arg5;
			if (PPP_CHECK_CB(on_sys_move_pages_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_move_pages_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 218 long sys_rt_tgsigqueueinfo ['pid_t tgid', 'pid_t pid', 'int sig', 'siginfo_t __user *uinfo']
		case 218: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint64_t arg3;
			if (PPP_CHECK_CB(on_sys_rt_tgsigqueueinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_rt_tgsigqueueinfo_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 219 long sys_perf_event_open ['struct perf_event_attr __user *attr_uptr', 'pid_t pid', 'int cpu', 'int group_fd', 'unsigned long flags']
		case 219: {
			uint64_t arg0;
			int32_t arg1;
			int32_t arg2;
			int32_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_perf_event_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_perf_event_open_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 220 long sys_recvmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags', 'struct timespec __user *timeout']
		case 220: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_recvmmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_recvmmsg_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 221 long sys_fanotify_init ['unsigned int flags', 'unsigned int event_f_flags']
		case 221: {
			uint32_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_fanotify_init_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fanotify_init_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 222 long sys_fanotify_mark ['int fanotify_fd', 'unsigned int flags', 'u64 mask', 'int fd', 'const char __user *pathname']
		case 222: {
			int32_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			int32_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_fanotify_mark_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fanotify_mark_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 223 long sys_name_to_handle_at ['int dfd', 'const char __user *name', 'struct file_handle __user *handle', 'int __user *mnt_id', 'int flag']
		case 223: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_name_to_handle_at_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_name_to_handle_at_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 224 long sys_open_by_handle_at ['int mountdirfd', 'struct file_handle __user *handle', 'int flags']
		case 224: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_open_by_handle_at_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_open_by_handle_at_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 225 long sys_clock_adjtime ['clockid_t which_clock', 'struct timex __user *tx']
		case 225: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_clock_adjtime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clock_adjtime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 226 long sys_syncfs ['int fd']
		case 226: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_syncfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_syncfs_return, cpu, pc, arg0) ;
		}; break;
		// 227 long sys_setns ['int fd', 'int nstype']
		case 227: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_setns_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setns_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 228 long sys_sendmmsg ['int fd', 'struct mmsghdr __user *msg', 'unsigned int vlen', 'unsigned flags']
		case 228: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_sendmmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendmmsg_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 229 long sys_process_vm_readv ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
		case 229: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			uint64_t arg5;
			if (PPP_CHECK_CB(on_sys_process_vm_readv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_process_vm_readv_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 230 long sys_process_vm_writev ['pid_t pid', 'const struct iovec __user *lvec', 'unsigned long liovcnt', 'const struct iovec __user *rvec', 'unsigned long riovcnt', 'unsigned long flags']
		case 230: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			uint64_t arg5;
			if (PPP_CHECK_CB(on_sys_process_vm_writev_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_process_vm_writev_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 231 long sys_kcmp ['pid_t pid1', 'pid_t pid2', 'int type', 'unsigned long idx1', 'unsigned long idx2']
		case 231: {
			int32_t arg0;
			int32_t arg1;
			int32_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_kcmp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kcmp_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 232 long sys_finit_module ['int fd', 'const char __user *uargs', 'int flags']
		case 232: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_finit_module_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_finit_module_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 233 long sys_sched_setattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int flags']
		case 233: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_sched_setattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_setattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 234 long sys_sched_getattr ['pid_t pid', 'struct sched_attr __user *attr', 'unsigned int size', 'unsigned int flags']
		case 234: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_sched_getattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sched_getattr_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 235 long sys_seccomp ['unsigned int op', 'unsigned int flags', 'const char __user *uargs']
		case 235: {
			uint32_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_seccomp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_seccomp_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 236 long sys_getrandom ['char __user *buf', 'size_t count', 'unsigned int flags']
		case 236: {
			uint64_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_getrandom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getrandom_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 237 long sys_memfd_create ['const char __user *uname_ptr', 'unsigned int flags']
		case 237: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_memfd_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_memfd_create_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 238 long sys_bpf ['int cmd', 'union bpf_attr *attr', 'unsigned int size']
		case 238: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_bpf_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_bpf_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 239 long sys_execveat ['int dfd', 'const char __user *filename', 'const char __user *const __user *argv', 'const char __user *const __user *envp', 'int flags']
		case 239: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			int32_t arg4;
			if (PPP_CHECK_CB(on_sys_execveat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_execveat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 240 long sys_userfaultfd ['int flags']
		case 240: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_userfaultfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_userfaultfd_return, cpu, pc, arg0) ;
		}; break;
		// 241 long sys_membarrier ['int cmd', 'int flags']
		case 241: {
			int32_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_membarrier_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_membarrier_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 242 long sys_copy_file_range ['int fd_in', 'loff_t __user *off_in', 'int fd_out', 'loff_t __user *off_out', 'size_t len', 'unsigned int flags']
		case 242: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			uint64_t arg3;
			uint32_t arg4;
			uint32_t arg5;
			if (PPP_CHECK_CB(on_sys_copy_file_range_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_copy_file_range_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 243 long sys_pkey_mprotect ['unsigned long start', 'size_t len', 'unsigned long prot', 'int pkey']
		case 243: {
			uint64_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_pkey_mprotect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pkey_mprotect_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 244 long sys_open ['const char __user *filename', 'int flags', 'umode_t mode']
		case 244: {
			uint64_t arg0;
			int32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_open_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 245 long sys_link ['const char __user *oldname', 'const char __user *newname']
		case 245: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_link_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 246 long sys_unlink ['const char __user *pathname']
		case 246: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 247 long sys_mknod ['const char __user *filename', 'umode_t mode', 'unsigned dev']
		case 247: {
			uint64_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_mknod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mknod_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 248 long sys_chmod ['const char __user *filename', 'umode_t mode']
		case 248: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_chmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 249 long sys_chown ['const char __user *filename', 'uid_t user', 'gid_t group']
		case 249: {
			uint64_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_chown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 250 long sys_mkdir ['const char __user *pathname', 'umode_t mode']
		case 250: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_mkdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkdir_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 251 long sys_rmdir ['const char __user *pathname']
		case 251: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_rmdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_rmdir_return, cpu, pc, arg0) ;
		}; break;
		// 252 long sys_lchown ['const char __user *filename', 'uid_t user', 'gid_t group']
		case 252: {
			uint64_t arg0;
			uint32_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_lchown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lchown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 253 long sys_access ['const char __user *filename', 'int mode']
		case 253: {
			uint64_t arg0;
			int32_t arg1;
			if (PPP_CHECK_CB(on_sys_access_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_access_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 254 long sys_rename ['const char __user *oldname', 'const char __user *newname']
		case 254: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_rename_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_rename_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 255 long sys_readlink ['const char __user *path', 'char __user *buf', 'int bufsiz']
		case 255: {
			uint64_t arg0;
			uint64_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_readlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_readlink_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 256 long sys_symlink ['const char __user *old', 'const char __user *new']
		case 256: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_symlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_symlink_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 257 long sys_utimes ['char __user *filename', 'struct timeval __user *utimes']
		case 257: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_utimes_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_utimes_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 258 long sys_pipe ['int __user *fildes']
		case 258: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_pipe_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pipe_return, cpu, pc, arg0) ;
		}; break;
		// 259 long sys_epoll_create ['int size']
		case 259: {
			int32_t arg0;
			if (PPP_CHECK_CB(on_sys_epoll_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_epoll_create_return, cpu, pc, arg0) ;
		}; break;
		// 260 long sys_inotify_init ['void']
		case 260: {
			if (PPP_CHECK_CB(on_sys_inotify_init_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_inotify_init_return, cpu, pc) ;
		}; break;
		// 261 long sys_eventfd ['unsigned int count']
		case 261: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_eventfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_eventfd_return, cpu, pc, arg0) ;
		}; break;
		// 262 long sys_signalfd ['int ufd', 'sigset_t __user *user_mask', 'size_t sizemask']
		case 262: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_signalfd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_signalfd_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 263 long sys_sendfile ['int out_fd', 'int in_fd', 'off_t __user *offset', 'size_t count']
		case 263: {
			int32_t arg0;
			int32_t arg1;
			uint64_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_sendfile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sendfile_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 264 long sys_ftruncate ['unsigned int fd', 'unsigned long length']
		case 264: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_ftruncate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ftruncate_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 265 long sys_truncate ['const char __user *path', 'long length']
		case 265: {
			uint64_t arg0;
			int64_t arg1;
			if (PPP_CHECK_CB(on_sys_truncate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
			}
			PPP_RUN_CB(on_sys_truncate_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 266 long sys_newstat ['const char __user *filename', 'struct stat __user *statbuf']
		case 266: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_newstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_newstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 267 long sys_newlstat ['const char __user *filename', 'struct stat __user *statbuf']
		case 267: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_newlstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_newlstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 268 long sys_newfstat ['unsigned int fd', 'struct stat __user *statbuf']
		case 268: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_newfstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_newfstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 269 long sys_fcntl ['unsigned int fd', 'unsigned int cmd', 'unsigned long arg']
		case 269: {
			uint32_t arg0;
			uint32_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_fcntl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fcntl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 270 long sys_newfstatat ['int dfd', 'const char __user *filename', 'struct stat __user *statbuf', 'int flag']
		case 270: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_newfstatat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_newfstatat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 271 long sys_fstatfs ['unsigned int fd', 'struct statfs __user *buf']
		case 271: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_fstatfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fstatfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 272 long sys_statfs ['const char __user *path', 'struct statfs __user *buf']
		case 272: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_statfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_statfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 273 long sys_lseek ['unsigned int fd', 'off_t offset', 'unsigned int whence']
		case 273: {
			uint32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_lseek_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lseek_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 275 long sys_alarm ['unsigned int seconds']
		case 275: {
			uint32_t arg0;
			if (PPP_CHECK_CB(on_sys_alarm_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_alarm_return, cpu, pc, arg0) ;
		}; break;
		// 276 long sys_getpgrp ['void']
		case 276: {
			if (PPP_CHECK_CB(on_sys_getpgrp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpgrp_return, cpu, pc) ;
		}; break;
		// 277 long sys_pause ['void']
		case 277: {
			if (PPP_CHECK_CB(on_sys_pause_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_pause_return, cpu, pc) ;
		}; break;
		// 278 long sys_time ['time_t __user *tloc']
		case 278: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_time_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_time_return, cpu, pc, arg0) ;
		}; break;
		// 279 long sys_utime ['char __user *filename', 'struct utimbuf __user *times']
		case 279: {
			uint64_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_utime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_utime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 280 long sys_creat ['const char __user *pathname', 'umode_t mode']
		case 280: {
			uint64_t arg0;
			uint32_t arg1;
			if (PPP_CHECK_CB(on_sys_creat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_creat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 281 long sys_getdents ['unsigned int fd', 'struct linux_dirent __user *dirent', 'unsigned int count']
		case 281: {
			uint32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			if (PPP_CHECK_CB(on_sys_getdents_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getdents_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 282 long sys_futimesat ['int dfd', 'const char __user *filename', 'struct timeval __user *utimes']
		case 282: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			if (PPP_CHECK_CB(on_sys_futimesat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_futimesat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 283 long sys_select ['int n', 'fd_set __user *inp', 'fd_set __user *outp', 'fd_set __user *exp', 'struct timeval __user *tvp']
		case 283: {
			int32_t arg0;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			if (PPP_CHECK_CB(on_sys_select_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_select_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 284 long sys_poll ['struct pollfd __user *ufds', 'unsigned int nfds', 'int timeout']
		case 284: {
			uint64_t arg0;
			uint32_t arg1;
			int32_t arg2;
			if (PPP_CHECK_CB(on_sys_poll_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_poll_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 285 long sys_epoll_wait ['int epfd', 'struct epoll_event __user *events', 'int maxevents', 'int timeout']
		case 285: {
			int32_t arg0;
			uint64_t arg1;
			int32_t arg2;
			int32_t arg3;
			if (PPP_CHECK_CB(on_sys_epoll_wait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_epoll_wait_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 286 long sys_ustat ['unsigned dev', 'struct ustat __user *ubuf']
		case 286: {
			uint32_t arg0;
			uint64_t arg1;
			if (PPP_CHECK_CB(on_sys_ustat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ustat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 287 long sys_vfork ['void']
		case 287: {
			if (PPP_CHECK_CB(on_sys_vfork_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_vfork_return, cpu, pc) ;
		}; break;
		// 288 long sys_recv ['int', 'void __user *', 'size_t', 'unsigned']
		case 288: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_recv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_recv_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 289 long sys_send ['int', 'void __user *', 'size_t', 'unsigned']
		case 289: {
			int32_t arg0;
			uint64_t arg1;
			uint32_t arg2;
			uint32_t arg3;
			if (PPP_CHECK_CB(on_sys_send_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_send_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 290 long sys_bdflush ['int func', 'long data']
		case 290: {
			int32_t arg0;
			int64_t arg1;
			if (PPP_CHECK_CB(on_sys_bdflush_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
			}
			PPP_RUN_CB(on_sys_bdflush_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 291 long sys_oldumount ['char __user *name']
		case 291: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_oldumount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_oldumount_return, cpu, pc, arg0) ;
		}; break;
		// 292 long sys_uselib ['const char __user *library']
		case 292: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_uselib_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_uselib_return, cpu, pc, arg0) ;
		}; break;
		// 293 long sys_sysctl ['struct __sysctl_args __user *args']
		case 293: {
			uint64_t arg0;
			if (PPP_CHECK_CB(on_sys_sysctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sysctl_return, cpu, pc, arg0) ;
		}; break;
		// 294 long sys_fork ['void']
		case 294: {
			if (PPP_CHECK_CB(on_sys_fork_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_fork_return, cpu, pc) ;
		}; break;
		// 295 long sys_ni_syscall ['void']
		case 295: {
			if (PPP_CHECK_CB(on_sys_ni_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_ni_syscall_return, cpu, pc) ;
		}; break;
		default:
			PPP_RUN_CB(on_unknown_sys_return, cpu, pc, ctx->no);
	}
	PPP_RUN_CB(on_all_sys_return, cpu, pc, ctx->no);
	PPP_RUN_CB(on_all_sys_return2, cpu, pc, call, ctx);
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */