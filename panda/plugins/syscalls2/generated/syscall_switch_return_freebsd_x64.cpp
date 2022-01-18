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

void syscall_return_switch_freebsd_x64(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx) {
#if defined(TARGET_X86_64)
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
		// 0 int sys_nosys ['void']
		case 0: {
			if (PPP_CHECK_CB(on_sys_nosys_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_nosys_return, cpu, pc) ;
		}; break;
		// 1 void sys_exit ['int rval']
		case 1: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_exit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_exit_return, cpu, pc, arg0) ;
		}; break;
		// 2 int sys_fork ['void']
		case 2: {
			if (PPP_CHECK_CB(on_sys_fork_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_fork_return, cpu, pc) ;
		}; break;
		// 3 ssize_t sys_read ['int fd', 'void *buf', 'size_t nbyte']
		case 3: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_read_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_read_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 4 ssize_t sys_write ['int fd', 'const void *buf', 'size_t nbyte']
		case 4: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_write_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_write_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 5 int sys_open ['const char *path', 'int flags', 'mode_t mode']
		case 5: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_open_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 6 int sys_close ['int fd']
		case 6: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_close_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_close_return, cpu, pc, arg0) ;
		}; break;
		// 7 int sys_wait4 ['int pid', 'int *status', 'int options', 'struct rusage *rusage']
		case 7: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_wait4_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_wait4_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 8 int sys_creat ['const char *path', 'int mode']
		case 8: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_creat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_creat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 9 int sys_link ['const char *path', 'const char *link']
		case 9: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_link_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 10 int sys_unlink ['const char *path']
		case 10: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 12 int sys_chdir ['const char *path']
		case 12: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_chdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_chdir_return, cpu, pc, arg0) ;
		}; break;
		// 13 int sys_fchdir ['int fd']
		case 13: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_fchdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fchdir_return, cpu, pc, arg0) ;
		}; break;
		// 14 int sys_mknod ['const char *path', 'int mode', 'uint32_t dev']
		case 14: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mknod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_mknod_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 15 int sys_chmod ['const char *path', 'mode_t mode']
		case 15: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_chmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_chmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 16 int sys_chown ['const char *path', 'int uid', 'int gid']
		case 16: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_chown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_chown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 18 int sys_getfsstat ['struct ostatfs *buf', 'long bufsize', 'int mode']
		case 18: {
			uint64_t arg0 = 0;
			int64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getfsstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getfsstat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 20 pid_t sys_getpid ['void']
		case 20: {
			if (PPP_CHECK_CB(on_sys_getpid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpid_return, cpu, pc) ;
		}; break;
		// 21 int sys_mount ['const char *type', 'const char *path', 'int flags', 'void *data']
		case 21: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_mount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mount_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 22 int sys_unmount ['const char *path', 'int flags']
		case 22: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_unmount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_unmount_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 23 int sys_setuid ['uid_t uid']
		case 23: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setuid_return, cpu, pc, arg0) ;
		}; break;
		// 24 uid_t sys_getuid ['void']
		case 24: {
			if (PPP_CHECK_CB(on_sys_getuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getuid_return, cpu, pc) ;
		}; break;
		// 25 uid_t sys_geteuid ['void']
		case 25: {
			if (PPP_CHECK_CB(on_sys_geteuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_geteuid_return, cpu, pc) ;
		}; break;
		// 26 int sys_ptrace ['int req', 'pid_t pid', 'caddr_t addr', 'int data']
		case 26: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_ptrace_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ptrace_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 27 int sys_recvmsg ['int s', 'struct msghdr *msg', 'int flags']
		case 27: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_recvmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_recvmsg_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 28 int sys_sendmsg ['int s', 'struct msghdr *msg', 'int flags']
		case 28: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sendmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sendmsg_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 29 int sys_recvfrom ['int s', 'void *buf', 'size_t len', 'int flags', 'struct sockaddr *from', '__socklen_t *fromlenaddr']
		case 29: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			uint64_t arg4 = 0;
			uint64_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys_recvfrom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_recvfrom_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 30 int sys_accept ['int s', 'struct sockaddr *name', '__socklen_t *anamelen']
		case 30: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_accept_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_accept_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 31 int sys_getpeername ['int fdes', 'struct sockaddr *asa', '__socklen_t *alen']
		case 31: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getpeername_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getpeername_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 32 int sys_getsockname ['int fdes', 'struct sockaddr *asa', '__socklen_t *alen']
		case 32: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getsockname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getsockname_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 33 int sys_access ['const char *path', 'int amode']
		case 33: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_access_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_access_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 34 int sys_chflags ['const char *path', 'u_long flags']
		case 34: {
			uint64_t arg0 = 0;
			int64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_chflags_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
			}
			PPP_RUN_CB(on_sys_chflags_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 35 int sys_fchflags ['int fd', 'u_long flags']
		case 35: {
			int32_t arg0 = 0;
			int64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fchflags_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
			}
			PPP_RUN_CB(on_sys_fchflags_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 36 int sys_sync ['void']
		case 36: {
			if (PPP_CHECK_CB(on_sys_sync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sync_return, cpu, pc) ;
		}; break;
		// 37 int sys_kill ['int pid', 'int signum']
		case 37: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_kill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_kill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 38 int sys_stat ['const char *path', 'struct ostat *ub']
		case 38: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_stat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_stat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 39 pid_t sys_getppid ['void']
		case 39: {
			if (PPP_CHECK_CB(on_sys_getppid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getppid_return, cpu, pc) ;
		}; break;
		// 40 int sys_lstat ['const char *path', 'struct ostat *ub']
		case 40: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_lstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 41 int sys_dup ['unsigned fd']
		case 41: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_dup_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_dup_return, cpu, pc, arg0) ;
		}; break;
		// 42 int sys_pipe ['void']
		case 42: {
			if (PPP_CHECK_CB(on_sys_pipe_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_pipe_return, cpu, pc) ;
		}; break;
		// 43 gid_t sys_getegid ['void']
		case 43: {
			if (PPP_CHECK_CB(on_sys_getegid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getegid_return, cpu, pc) ;
		}; break;
		// 44 int sys_profil ['char *samples', 'size_t size', 'size_t offset', 'unsigned scale']
		case 44: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_profil_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_profil_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 45 int sys_ktrace ['const char *fname', 'int ops', 'int facs', 'int pid']
		case 45: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_ktrace_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ktrace_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 46 int sys_sigaction ['int signum', 'struct osigaction *nsa', 'struct osigaction *osa']
		case 46: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sigaction_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigaction_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 47 gid_t sys_getgid ['void']
		case 47: {
			if (PPP_CHECK_CB(on_sys_getgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getgid_return, cpu, pc) ;
		}; break;
		// 49 int sys_getlogin ['char *namebuf', 'unsigned namelen']
		case 49: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getlogin_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getlogin_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 50 int sys_setlogin ['const char *namebuf']
		case 50: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setlogin_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setlogin_return, cpu, pc, arg0) ;
		}; break;
		// 51 int sys_acct ['const char *path']
		case 51: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_acct_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_acct_return, cpu, pc, arg0) ;
		}; break;
		// 53 int sys_sigaltstack ['stack_t *ss', 'stack_t *oss']
		case 53: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sigaltstack_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigaltstack_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 54 int sys_ioctl ['int fd', 'u_long com', 'char *data']
		case 54: {
			int32_t arg0 = 0;
			int64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_ioctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ioctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 55 int sys_reboot ['int opt']
		case 55: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_reboot_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_reboot_return, cpu, pc, arg0) ;
		}; break;
		// 56 int sys_revoke ['const char *path']
		case 56: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_revoke_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_revoke_return, cpu, pc, arg0) ;
		}; break;
		// 57 int sys_symlink ['const char *path', 'const char *link']
		case 57: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_symlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_symlink_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 58 ssize_t sys_readlink ['const char *path', 'char *buf', 'size_t count']
		case 58: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_readlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_readlink_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 59 int sys_execve ['const char *fname', 'char **argv', 'char **envv']
		case 59: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_execve_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_execve_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 60 int sys_umask ['mode_t newmask']
		case 60: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_umask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_umask_return, cpu, pc, arg0) ;
		}; break;
		// 61 int sys_chroot ['const char *path']
		case 61: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_chroot_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_chroot_return, cpu, pc, arg0) ;
		}; break;
		// 62 int sys_fstat ['int fd', 'struct ostat *sb']
		case 62: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 63 int sys_getkerninfo ['int op', 'char *where', 'size_t *size', 'int arg']
		case 63: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_getkerninfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getkerninfo_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 64 int sys_getpagesize ['void']
		case 64: {
			if (PPP_CHECK_CB(on_sys_getpagesize_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpagesize_return, cpu, pc) ;
		}; break;
		// 65 int sys_msync ['void *addr', 'size_t len', 'int flags']
		case 65: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_msync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msync_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 66 int sys_vfork ['void']
		case 66: {
			if (PPP_CHECK_CB(on_sys_vfork_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_vfork_return, cpu, pc) ;
		}; break;
		// 69 int sys_sbrk ['int incr']
		case 69: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sbrk_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sbrk_return, cpu, pc, arg0) ;
		}; break;
		// 70 int sys_sstk ['int incr']
		case 70: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sstk_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sstk_return, cpu, pc, arg0) ;
		}; break;
		// 72 int sys_vadvise ['int anom']
		case 72: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_vadvise_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_vadvise_return, cpu, pc, arg0) ;
		}; break;
		// 73 int sys_munmap ['void *addr', 'size_t len']
		case 73: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_munmap_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_munmap_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 74 int sys_mprotect ['void *addr', 'size_t len', 'int prot']
		case 74: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mprotect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_mprotect_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 75 int sys_madvise ['void *addr', 'size_t len', 'int behav']
		case 75: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_madvise_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_madvise_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 78 int sys_mincore ['const void *addr', 'size_t len', 'char *vec']
		case 78: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mincore_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mincore_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 79 int sys_getgroups ['unsigned gidsetsize', 'gid_t *gidset']
		case 79: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getgroups_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getgroups_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 80 int sys_setgroups ['unsigned gidsetsize', 'gid_t *gidset']
		case 80: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setgroups_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setgroups_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 81 int sys_getpgrp ['void']
		case 81: {
			if (PPP_CHECK_CB(on_sys_getpgrp_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getpgrp_return, cpu, pc) ;
		}; break;
		// 82 int sys_setpgid ['int pid', 'int pgid']
		case 82: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setpgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setpgid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 83 int sys_setitimer ['unsigned which', 'struct itimerval *itv', 'struct itimerval *oitv']
		case 83: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_setitimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setitimer_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 84 int sys_wait ['void']
		case 84: {
			if (PPP_CHECK_CB(on_sys_wait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_wait_return, cpu, pc) ;
		}; break;
		// 85 int sys_swapon ['const char *name']
		case 85: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_swapon_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_swapon_return, cpu, pc, arg0) ;
		}; break;
		// 86 int sys_getitimer ['unsigned which', 'struct itimerval *itv']
		case 86: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getitimer_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getitimer_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 87 int sys_gethostname ['char *hostname', 'unsigned len']
		case 87: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_gethostname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_gethostname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 88 int sys_sethostname ['char *hostname', 'unsigned len']
		case 88: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sethostname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sethostname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 89 int sys_getdtablesize ['void']
		case 89: {
			if (PPP_CHECK_CB(on_sys_getdtablesize_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_getdtablesize_return, cpu, pc) ;
		}; break;
		// 90 int sys_dup2 ['unsigned from', 'unsigned to']
		case 90: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_dup2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_dup2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 92 int sys_fcntl ['int fd', 'int cmd', 'long arg']
		case 92: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fcntl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int64_t));
			}
			PPP_RUN_CB(on_sys_fcntl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 93 int sys_select ['int nd', 'fd_set *in', 'fd_set *ou', 'fd_set *ex', 'struct timeval *tv']
		case 93: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint64_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_select_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_select_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 95 int sys_fsync ['int fd']
		case 95: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_fsync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fsync_return, cpu, pc, arg0) ;
		}; break;
		// 96 int sys_setpriority ['int which', 'int who', 'int prio']
		case 96: {
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
		// 97 int sys_socket ['int domain', 'int type', 'int protocol']
		case 97: {
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
		// 98 int sys_connect ['int s', 'const struct sockaddr *name', 'int namelen']
		case 98: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_connect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_connect_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 99 int sys_accept ['int s', 'struct sockaddr *name', 'int *anamelen']
		case 99: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_accept_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_accept_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 100 int sys_getpriority ['int which', 'int who']
		case 100: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getpriority_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getpriority_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 101 int sys_send ['int s', 'const void *buf', 'int len', 'int flags']
		case 101: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_send_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_send_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 102 int sys_recv ['int s', 'void *buf', 'int len', 'int flags']
		case 102: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_recv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_recv_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 103 int sys_sigreturn ['struct osigcontext *sigcntxp']
		case 103: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sigreturn_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigreturn_return, cpu, pc, arg0) ;
		}; break;
		// 104 int sys_bind ['int s', 'const struct sockaddr *name', 'int namelen']
		case 104: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_bind_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_bind_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 105 int sys_setsockopt ['int s', 'int level', 'int name', 'const void *val', 'int valsize']
		case 105: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_setsockopt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setsockopt_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 106 int sys_listen ['int s', 'int backlog']
		case 106: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_listen_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_listen_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 108 int sys_sigvec ['int signum', 'struct sigvec *nsv', 'struct sigvec *osv']
		case 108: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sigvec_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigvec_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 109 int sys_sigblock ['int mask']
		case 109: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sigblock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sigblock_return, cpu, pc, arg0) ;
		}; break;
		// 110 int sys_sigsetmask ['int mask']
		case 110: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sigsetmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sigsetmask_return, cpu, pc, arg0) ;
		}; break;
		// 111 int sys_sigsuspend ['osigset_t mask']
		case 111: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sigsuspend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_sigsuspend_return, cpu, pc, arg0) ;
		}; break;
		// 112 int sys_sigstack ['struct sigstack *nss', 'struct sigstack *oss']
		case 112: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sigstack_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigstack_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 113 int sys_recvmsg ['int s', 'struct omsghdr *msg', 'int flags']
		case 113: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_recvmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_recvmsg_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 114 int sys_sendmsg ['int s', 'const void *msg', 'int flags']
		case 114: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sendmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sendmsg_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 116 int sys_gettimeofday ['struct timeval *tp', 'struct timezone *tzp']
		case 116: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_gettimeofday_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_gettimeofday_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 117 int sys_getrusage ['int who', 'struct rusage *rusage']
		case 117: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getrusage_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getrusage_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 118 int sys_getsockopt ['int s', 'int level', 'int name', 'void *val', 'int *avalsize']
		case 118: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			uint64_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_getsockopt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getsockopt_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 120 int sys_readv ['int fd', 'struct iovec *iovp', 'unsigned iovcnt']
		case 120: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_readv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_readv_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 121 int sys_writev ['int fd', 'struct iovec *iovp', 'unsigned iovcnt']
		case 121: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_writev_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_writev_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 122 int sys_settimeofday ['struct timeval *tv', 'struct timezone *tzp']
		case 122: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_settimeofday_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_settimeofday_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 123 int sys_fchown ['int fd', 'int uid', 'int gid']
		case 123: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fchown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fchown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 124 int sys_fchmod ['int fd', 'mode_t mode']
		case 124: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fchmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fchmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 125 int sys_recvfrom ['int s', 'void *buf', 'size_t len', 'int flags', 'struct sockaddr *from', 'int *fromlenaddr']
		case 125: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			uint64_t arg4 = 0;
			uint64_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys_recvfrom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_recvfrom_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 126 int sys_setreuid ['int ruid', 'int euid']
		case 126: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setreuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setreuid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 127 int sys_setregid ['int rgid', 'int egid']
		case 127: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setregid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setregid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 128 int sys_rename ['const char *from', 'const char *to']
		case 128: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_rename_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_rename_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 131 int sys_flock ['int fd', 'int how']
		case 131: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_flock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_flock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 132 int sys_mkfifo ['const char *path', 'mode_t mode']
		case 132: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_mkfifo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkfifo_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 133 int sys_sendto ['int s', 'const void *buf', 'size_t len', 'int flags', 'const struct sockaddr *to', 'int tolen']
		case 133: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			uint64_t arg4 = 0;
			int32_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys_sendto_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sendto_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 134 int sys_shutdown ['int s', 'int how']
		case 134: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_shutdown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shutdown_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 135 int sys_socketpair ['int domain', 'int type', 'int protocol', 'int *rsv']
		case 135: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_socketpair_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_socketpair_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 136 int sys_mkdir ['const char *path', 'mode_t mode']
		case 136: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_mkdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkdir_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 137 int sys_rmdir ['const char *path']
		case 137: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_rmdir_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_rmdir_return, cpu, pc, arg0) ;
		}; break;
		// 138 int sys_utimes ['const char *path', 'struct timeval *tptr']
		case 138: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_utimes_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_utimes_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 140 int sys_adjtime ['struct timeval *delta', 'struct timeval *olddelta']
		case 140: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_adjtime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_adjtime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 141 int sys_getpeername ['int fdes', 'struct sockaddr *asa', 'int *alen']
		case 141: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getpeername_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getpeername_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 142 long sys_gethostid ['void']
		case 142: {
			if (PPP_CHECK_CB(on_sys_gethostid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_gethostid_return, cpu, pc) ;
		}; break;
		// 143 int sys_sethostid ['long hostid']
		case 143: {
			int64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sethostid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int64_t));
			}
			PPP_RUN_CB(on_sys_sethostid_return, cpu, pc, arg0) ;
		}; break;
		// 144 int sys_getrlimit ['unsigned which', 'struct orlimit *rlp']
		case 144: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 145 int sys_setrlimit ['unsigned which', 'struct orlimit *rlp']
		case 145: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 146 int sys_killpg ['int pgid', 'int signum']
		case 146: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_killpg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_killpg_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 147 int sys_setsid ['void']
		case 147: {
			if (PPP_CHECK_CB(on_sys_setsid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_setsid_return, cpu, pc) ;
		}; break;
		// 148 int sys_quotactl ['const char *path', 'int cmd', 'int uid', 'void *arg']
		case 148: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_quotactl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_quotactl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 149 int sys_quota ['void']
		case 149: {
			if (PPP_CHECK_CB(on_sys_quota_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_quota_return, cpu, pc) ;
		}; break;
		// 150 int sys_getsockname ['int fdec', 'struct sockaddr *asa', 'int *alen']
		case 150: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getsockname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getsockname_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 154 int sys_nlm_syscall ['int debug_level', 'int grace_period', 'int addr_count', 'char **addrs']
		case 154: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_nlm_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_nlm_syscall_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 155 int sys_nfssvc ['int flag', 'void *argp']
		case 155: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_nfssvc_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_nfssvc_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 156 int sys_getdirentries ['int fd', 'char *buf', 'unsigned count', 'long *basep']
		case 156: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_getdirentries_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getdirentries_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 157 int sys_statfs ['const char *path', 'struct ostatfs *buf']
		case 157: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_statfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_statfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 158 int sys_fstatfs ['int fd', 'struct ostatfs *buf']
		case 158: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fstatfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fstatfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 160 int sys_lgetfh ['const char *fname', 'struct fhandle *fhp']
		case 160: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lgetfh_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_lgetfh_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 161 int sys_getfh ['const char *fname', 'struct fhandle *fhp']
		case 161: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getfh_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getfh_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 162 int sys_getdomainname ['char *domainname', 'int len']
		case 162: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getdomainname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getdomainname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 163 int sys_setdomainname ['char *domainname', 'int len']
		case 163: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setdomainname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setdomainname_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 164 int sys_uname ['struct utsname *name']
		case 164: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_uname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_uname_return, cpu, pc, arg0) ;
		}; break;
		// 165 int sys_sysarch ['int op', 'char *parms']
		case 165: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sysarch_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sysarch_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 166 int sys_rtprio ['int function', 'pid_t pid', 'struct rtprio *rtp']
		case 166: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_rtprio_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_rtprio_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 169 int sys_semsys ['int which', 'int a2', 'int a3', 'int a4', 'int a5']
		case 169: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_semsys_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_semsys_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 175 int sys_setfib ['int fibnum']
		case 175: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setfib_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_setfib_return, cpu, pc, arg0) ;
		}; break;
		// 176 int sys_ntp_adjtime ['struct timex *tp']
		case 176: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ntp_adjtime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ntp_adjtime_return, cpu, pc, arg0) ;
		}; break;
		// 181 int sys_setgid ['gid_t gid']
		case 181: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setgid_return, cpu, pc, arg0) ;
		}; break;
		// 182 int sys_setegid ['gid_t egid']
		case 182: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setegid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setegid_return, cpu, pc, arg0) ;
		}; break;
		// 183 int sys_seteuid ['uid_t euid']
		case 183: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_seteuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_seteuid_return, cpu, pc, arg0) ;
		}; break;
		// 188 int sys_stat ['const char *path', 'struct freebsd11_stat *ub']
		case 188: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_stat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_stat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 189 int sys_fstat ['int fd', 'struct freebsd11_stat *sb']
		case 189: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 190 int sys_lstat ['const char *path', 'struct freebsd11_stat *ub']
		case 190: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_lstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 191 int sys_pathconf ['const char *path', 'int name']
		case 191: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pathconf_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pathconf_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 192 int sys_fpathconf ['int fd', 'int name']
		case 192: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fpathconf_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fpathconf_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 194 int sys_getrlimit ['unsigned which', 'struct rlimit *rlp']
		case 194: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 195 int sys_setrlimit ['unsigned which', 'struct rlimit *rlp']
		case 195: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setrlimit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setrlimit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 196 int sys_getdirentries ['int fd', 'char *buf', 'unsigned count', 'long *basep']
		case 196: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_getdirentries_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getdirentries_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 198 int sys_nosys ['void']
		case 198: {
			if (PPP_CHECK_CB(on_sys_nosys_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_nosys_return, cpu, pc) ;
		}; break;
		// 202 int sys___sysctl ['int *name', 'unsigned namelen', 'void *old', 'size_t *oldlenp', 'const void *new', 'size_t newlen']
		case 202: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint64_t arg4 = 0;
			uint32_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys___sysctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys___sysctl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 203 int sys_mlock ['const void *addr', 'size_t len']
		case 203: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_mlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mlock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 204 int sys_munlock ['const void *addr', 'size_t len']
		case 204: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_munlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_munlock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 205 int sys_undelete ['const char *path']
		case 205: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_undelete_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_undelete_return, cpu, pc, arg0) ;
		}; break;
		// 206 int sys_futimes ['int fd', 'struct timeval *tptr']
		case 206: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_futimes_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_futimes_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 207 int sys_getpgid ['pid_t pid']
		case 207: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_getpgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getpgid_return, cpu, pc, arg0) ;
		}; break;
		// 209 int sys_poll ['struct pollfd *fds', 'unsigned nfds', 'int timeout']
		case 209: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_poll_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_poll_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 220 int sys___semctl ['int semid', 'int semnum', 'int cmd', 'union semun_old *arg']
		case 220: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys___semctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___semctl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 221 int sys_semget ['key_t key', 'int nsems', 'int semflg']
		case 221: {
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
		// 222 int sys_semop ['int semid', 'struct sembuf *sops', 'size_t nsops']
		case 222: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_semop_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_semop_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 224 int sys_msgctl ['int msqid', 'int cmd', 'struct msqid_ds_old *buf']
		case 224: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_msgctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_msgctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 225 int sys_msgget ['key_t key', 'int msgflg']
		case 225: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_msgget_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgget_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 226 int sys_msgsnd ['int msqid', 'const void *msgp', 'size_t msgsz', 'int msgflg']
		case 226: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_msgsnd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgsnd_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 227 ssize_t sys_msgrcv ['int msqid', 'void *msgp', 'size_t msgsz', 'long msgtyp', 'int msgflg']
		case 227: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			int64_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_msgrcv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_msgrcv_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 229 int sys_shmctl ['int shmid', 'int cmd', 'struct shmid_ds_old *buf']
		case 229: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_shmctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_shmctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 230 int sys_shmdt ['const void *shmaddr']
		case 230: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_shmdt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_shmdt_return, cpu, pc, arg0) ;
		}; break;
		// 231 int sys_shmget ['key_t key', 'size_t size', 'int shmflg']
		case 231: {
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
		// 232 int sys_clock_gettime ['clockid_t clock_id', 'struct timespec *tp']
		case 232: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clock_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 233 int sys_clock_settime ['clockid_t clock_id', 'const struct timespec *tp']
		case 233: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clock_settime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 234 int sys_clock_getres ['clockid_t clock_id', 'struct timespec *tp']
		case 234: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_clock_getres_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clock_getres_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 235 int sys_ktimer_create ['clockid_t clock_id', 'struct sigevent *evp', 'int *timerid']
		case 235: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_ktimer_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ktimer_create_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 236 int sys_ktimer_delete ['int timerid']
		case 236: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ktimer_delete_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ktimer_delete_return, cpu, pc, arg0) ;
		}; break;
		// 237 int sys_ktimer_settime ['int timerid', 'int flags', 'const struct itimerspec *value', 'struct itimerspec *ovalue']
		case 237: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_ktimer_settime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ktimer_settime_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 238 int sys_ktimer_gettime ['int timerid', 'struct itimerspec *value']
		case 238: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ktimer_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ktimer_gettime_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 239 int sys_ktimer_getoverrun ['int timerid']
		case 239: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ktimer_getoverrun_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_ktimer_getoverrun_return, cpu, pc, arg0) ;
		}; break;
		// 240 int sys_nanosleep ['const struct timespec *rqtp', 'struct timespec *rmtp']
		case 240: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_nanosleep_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_nanosleep_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 241 int sys_ffclock_getcounter ['ffcounter *ffcount']
		case 241: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ffclock_getcounter_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ffclock_getcounter_return, cpu, pc, arg0) ;
		}; break;
		// 242 int sys_ffclock_setestimate ['struct ffclock_estimate *cest']
		case 242: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ffclock_setestimate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ffclock_setestimate_return, cpu, pc, arg0) ;
		}; break;
		// 243 int sys_ffclock_getestimate ['struct ffclock_estimate *cest']
		case 243: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ffclock_getestimate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ffclock_getestimate_return, cpu, pc, arg0) ;
		}; break;
		// 244 int sys_clock_nanosleep ['clockid_t clock_id', 'int flags', 'const struct timespec *rqtp', 'struct timespec *rmtp']
		case 244: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_clock_nanosleep_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clock_nanosleep_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 247 int sys_clock_getcpuclockid2 ['id_t id', 'int which', 'clockid_t *clock_id']
		case 247: {
			uint32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_clock_getcpuclockid2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_clock_getcpuclockid2_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 248 int sys_ntp_gettime ['struct ntptimeval *ntvp']
		case 248: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ntp_gettime_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ntp_gettime_return, cpu, pc, arg0) ;
		}; break;
		// 250 int sys_minherit ['void *addr', 'size_t len', 'int inherit']
		case 250: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_minherit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_minherit_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 251 int sys_rfork ['int flags']
		case 251: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_rfork_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_rfork_return, cpu, pc, arg0) ;
		}; break;
		// 253 int sys_issetugid ['void']
		case 253: {
			if (PPP_CHECK_CB(on_sys_issetugid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_issetugid_return, cpu, pc) ;
		}; break;
		// 254 int sys_lchown ['const char *path', 'int uid', 'int gid']
		case 254: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_lchown_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_lchown_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 255 int sys_aio_read ['struct aiocb *aiocbp']
		case 255: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_aio_read_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_read_return, cpu, pc, arg0) ;
		}; break;
		// 256 int sys_aio_write ['struct aiocb *aiocbp']
		case 256: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_aio_write_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_write_return, cpu, pc, arg0) ;
		}; break;
		// 257 int sys_lio_listio ['int mode', 'struct aiocb * const *acb_list', 'int nent', 'struct sigevent *sig']
		case 257: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_lio_listio_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_lio_listio_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 272 int sys_getdents ['int fd', 'char *buf', 'size_t count']
		case 272: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getdents_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getdents_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 274 int sys_lchmod ['const char *path', 'mode_t mode']
		case 274: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lchmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_lchmod_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 276 int sys_lutimes ['const char *path', 'struct timeval *tptr']
		case 276: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lutimes_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_lutimes_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 278 int sys_nstat ['const char *path', 'struct nstat *ub']
		case 278: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_nstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_nstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 279 int sys_nfstat ['int fd', 'struct nstat *sb']
		case 279: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_nfstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_nfstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 280 int sys_nlstat ['const char *path', 'struct nstat *ub']
		case 280: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_nlstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_nlstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 289 ssize_t sys_preadv ['int fd', 'struct iovec *iovp', 'unsigned iovcnt', 'off_t offset']
		case 289: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_preadv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_preadv_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 290 ssize_t sys_pwritev ['int fd', 'struct iovec *iovp', 'unsigned iovcnt', 'off_t offset']
		case 290: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_pwritev_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pwritev_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 297 int sys_fhstatfs ['const struct fhandle *u_fhp', 'struct ostatfs *buf']
		case 297: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fhstatfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fhstatfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 298 int sys_fhopen ['const struct fhandle *u_fhp', 'int flags']
		case 298: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fhopen_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fhopen_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 299 int sys_fhstat ['const struct fhandle *u_fhp', 'struct freebsd11_stat *sb']
		case 299: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fhstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fhstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 300 int sys_modnext ['int modid']
		case 300: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_modnext_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_modnext_return, cpu, pc, arg0) ;
		}; break;
		// 301 int sys_modstat ['int modid', 'struct module_stat *stat']
		case 301: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_modstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_modstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 302 int sys_modfnext ['int modid']
		case 302: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_modfnext_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_modfnext_return, cpu, pc, arg0) ;
		}; break;
		// 303 int sys_modfind ['const char *name']
		case 303: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_modfind_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_modfind_return, cpu, pc, arg0) ;
		}; break;
		// 304 int sys_kldload ['const char *file']
		case 304: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_kldload_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kldload_return, cpu, pc, arg0) ;
		}; break;
		// 305 int sys_kldunload ['int fileid']
		case 305: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_kldunload_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_kldunload_return, cpu, pc, arg0) ;
		}; break;
		// 306 int sys_kldfind ['const char *file']
		case 306: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_kldfind_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kldfind_return, cpu, pc, arg0) ;
		}; break;
		// 307 int sys_kldnext ['int fileid']
		case 307: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_kldnext_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_kldnext_return, cpu, pc, arg0) ;
		}; break;
		// 308 int sys_kldstat ['int fileid', 'struct kld_file_stat *stat']
		case 308: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_kldstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kldstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 309 int sys_kldfirstmod ['int fileid']
		case 309: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_kldfirstmod_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_kldfirstmod_return, cpu, pc, arg0) ;
		}; break;
		// 310 int sys_getsid ['pid_t pid']
		case 310: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_getsid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getsid_return, cpu, pc, arg0) ;
		}; break;
		// 311 int sys_setresuid ['uid_t ruid', 'uid_t euid', 'uid_t suid']
		case 311: {
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
		// 312 int sys_setresgid ['gid_t rgid', 'gid_t egid', 'gid_t sgid']
		case 312: {
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
		// 314 ssize_t sys_aio_return ['struct aiocb *aiocbp']
		case 314: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_aio_return_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_return_return, cpu, pc, arg0) ;
		}; break;
		// 315 int sys_aio_suspend ['struct aiocb * const * aiocbp', 'int nent', 'const struct timespec *timeout']
		case 315: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_aio_suspend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_suspend_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 316 int sys_aio_cancel ['int fd', 'struct aiocb *aiocbp']
		case 316: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_aio_cancel_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_cancel_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 317 int sys_aio_error ['struct aiocb *aiocbp']
		case 317: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_aio_error_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_error_return, cpu, pc, arg0) ;
		}; break;
		// 318 int sys_aio_read ['struct oaiocb *aiocbp']
		case 318: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_aio_read_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_read_return, cpu, pc, arg0) ;
		}; break;
		// 319 int sys_aio_write ['struct oaiocb *aiocbp']
		case 319: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_aio_write_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_write_return, cpu, pc, arg0) ;
		}; break;
		// 320 int sys_lio_listio ['int mode', 'struct oaiocb * const *acb_list', 'int nent', 'struct osigevent *sig']
		case 320: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_lio_listio_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_lio_listio_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 321 int sys_yield ['void']
		case 321: {
			if (PPP_CHECK_CB(on_sys_yield_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_yield_return, cpu, pc) ;
		}; break;
		// 324 int sys_mlockall ['int how']
		case 324: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_mlockall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_mlockall_return, cpu, pc, arg0) ;
		}; break;
		// 325 int sys_munlockall(void); 326 int __getcwd ['char *buf', 'size_t buflen']
		case 325: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on___getcwd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on___getcwd_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 327 int sys_sched_setparam ['pid_t pid', 'const struct sched_param *param']
		case 327: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sched_setparam_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sched_setparam_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 328 int sys_sched_getparam ['pid_t pid', 'struct sched_param *param']
		case 328: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sched_getparam_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sched_getparam_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 329 int sys_sched_setscheduler ['pid_t pid', 'int policy', 'const struct sched_param *param']
		case 329: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sched_setscheduler_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sched_setscheduler_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 330 int sys_sched_getscheduler ['pid_t pid']
		case 330: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sched_getscheduler_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_getscheduler_return, cpu, pc, arg0) ;
		}; break;
		// 331 int sys_sched_yield ['void']
		case 331: {
			if (PPP_CHECK_CB(on_sys_sched_yield_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_sched_yield_return, cpu, pc) ;
		}; break;
		// 332 int sys_sched_get_priority_max ['int policy']
		case 332: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sched_get_priority_max_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_get_priority_max_return, cpu, pc, arg0) ;
		}; break;
		// 333 int sys_sched_get_priority_min ['int policy']
		case 333: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sched_get_priority_min_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sched_get_priority_min_return, cpu, pc, arg0) ;
		}; break;
		// 334 int sys_sched_rr_get_interval ['pid_t pid', 'struct timespec *interval']
		case 334: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sched_rr_get_interval_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sched_rr_get_interval_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 335 int sys_utrace ['const void *addr', 'size_t len']
		case 335: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_utrace_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_utrace_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 336 int sys_sendfile ['int fd', 'int s', 'off_t offset', 'size_t nbytes', 'struct sf_hdtr *hdtr', 'off_t *sbytes', 'int flags']
		case 336: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			uint64_t arg4 = 0;
			uint64_t arg5 = 0;
			int32_t arg6 = 0;
			if (PPP_CHECK_CB(on_sys_sendfile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
				memcpy(&arg6, ctx->args[6], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sendfile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 337 int sys_kldsym ['int fileid', 'int cmd', 'void *data']
		case 337: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_kldsym_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kldsym_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 338 int sys_jail ['struct jail *jail']
		case 338: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_jail_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_jail_return, cpu, pc, arg0) ;
		}; break;
		// 339 int sys_nnpfs_syscall ['int operation', 'char *a_pathP', 'int a_opcode', 'void *a_paramsP', 'int a_followSymlinks']
		case 339: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_nnpfs_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_nnpfs_syscall_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 340 int sys_sigprocmask ['int how', 'const sigset_t *set', 'sigset_t *oset']
		case 340: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sigprocmask_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigprocmask_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 341 int sys_sigsuspend ['const sigset_t *sigmask']
		case 341: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sigsuspend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigsuspend_return, cpu, pc, arg0) ;
		}; break;
		// 342 int sys_sigaction ['int sig', 'const struct sigaction *act', 'struct sigaction *oact']
		case 342: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sigaction_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigaction_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 343 int sys_sigpending ['sigset_t *set']
		case 343: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sigpending_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigpending_return, cpu, pc, arg0) ;
		}; break;
		// 344 int sys_sigreturn ['const struct ucontext4 *sigcntxp']
		case 344: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sigreturn_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigreturn_return, cpu, pc, arg0) ;
		}; break;
		// 345 int sys_sigtimedwait ['const sigset_t *set', 'siginfo_t *info', 'const struct timespec *timeout']
		case 345: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sigtimedwait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigtimedwait_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 346 int sys_sigwaitinfo ['const sigset_t *set', 'siginfo_t *info']
		case 346: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sigwaitinfo_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigwaitinfo_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 347 int sys___acl_get_file ['const char *path', 'acl_type_t type', 'struct acl *aclp']
		case 347: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys___acl_get_file_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___acl_get_file_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 348 int sys___acl_set_file ['const char *path', 'acl_type_t type', 'struct acl *aclp']
		case 348: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys___acl_set_file_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___acl_set_file_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 349 int sys___acl_get_fd ['int filedes', 'acl_type_t type', 'struct acl *aclp']
		case 349: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys___acl_get_fd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___acl_get_fd_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 350 int sys___acl_set_fd ['int filedes', 'acl_type_t type', 'struct acl *aclp']
		case 350: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys___acl_set_fd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___acl_set_fd_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 351 int sys___acl_delete_file ['const char *path', 'acl_type_t type']
		case 351: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys___acl_delete_file_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys___acl_delete_file_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 352 int sys___acl_delete_fd ['int filedes', 'acl_type_t type']
		case 352: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys___acl_delete_fd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys___acl_delete_fd_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 353 int sys___acl_aclcheck_file ['const char *path', 'acl_type_t type', 'struct acl *aclp']
		case 353: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys___acl_aclcheck_file_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___acl_aclcheck_file_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 354 int sys___acl_aclcheck_fd ['int filedes', 'acl_type_t type', 'struct acl *aclp']
		case 354: {
			int32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys___acl_aclcheck_fd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___acl_aclcheck_fd_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 355 int sys_extattrctl ['const char *path', 'int cmd', 'const char *filename', 'int attrnamespace', 'const char *attrname']
		case 355: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			uint64_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_extattrctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_extattrctl_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 356 ssize_t sys_extattr_set_file ['const char *path', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
		case 356: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_set_file_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_extattr_set_file_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 357 ssize_t sys_extattr_get_file ['const char *path', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
		case 357: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_get_file_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_extattr_get_file_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 358 int sys_extattr_delete_file ['const char *path', 'int attrnamespace', 'const char *attrname']
		case 358: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_delete_file_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_extattr_delete_file_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 359 ssize_t sys_aio_waitcomplete ['struct aiocb **aiocbp', 'struct timespec *timeout']
		case 359: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_aio_waitcomplete_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_waitcomplete_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 360 int sys_getresuid ['uid_t *ruid', 'uid_t *euid', 'uid_t *suid']
		case 360: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getresuid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getresuid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 361 int sys_getresgid ['gid_t *rgid', 'gid_t *egid', 'gid_t *sgid']
		case 361: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getresgid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getresgid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 362 int sys_kqueue ['void']
		case 362: {
			if (PPP_CHECK_CB(on_sys_kqueue_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_kqueue_return, cpu, pc) ;
		}; break;
		// 363 int sys_kevent ['int fd', 'struct kevent_freebsd11 *changelist', 'int nchanges', 'struct kevent_freebsd11 *eventlist', 'int nevents', 'const struct timespec *timeout']
		case 363: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			int32_t arg4 = 0;
			uint64_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys_kevent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kevent_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 371 ssize_t sys_extattr_set_fd ['int fd', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
		case 371: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_set_fd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_extattr_set_fd_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 372 ssize_t sys_extattr_get_fd ['int fd', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
		case 372: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_get_fd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_extattr_get_fd_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 373 int sys_extattr_delete_fd ['int fd', 'int attrnamespace', 'const char *attrname']
		case 373: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_delete_fd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_extattr_delete_fd_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 374 int sys___setugid ['int flag']
		case 374: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys___setugid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys___setugid_return, cpu, pc, arg0) ;
		}; break;
		// 376 int sys_eaccess ['const char *path', 'int amode']
		case 376: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_eaccess_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_eaccess_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 377 int sys_afs3_syscall ['long syscall', 'long parm1', 'long parm2', 'long parm3', 'long parm4', 'long parm5', 'long parm6']
		case 377: {
			int64_t arg0 = 0;
			int64_t arg1 = 0;
			int64_t arg2 = 0;
			int64_t arg3 = 0;
			int64_t arg4 = 0;
			int64_t arg5 = 0;
			int64_t arg6 = 0;
			if (PPP_CHECK_CB(on_sys_afs3_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int64_t));
				memcpy(&arg5, ctx->args[5], sizeof(int64_t));
				memcpy(&arg6, ctx->args[6], sizeof(int64_t));
			}
			PPP_RUN_CB(on_sys_afs3_syscall_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 378 int sys_nmount ['struct iovec *iovp', 'unsigned int iovcnt', 'int flags']
		case 378: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_nmount_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_nmount_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 384 int sys___mac_get_proc ['struct mac *mac_p']
		case 384: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys___mac_get_proc_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___mac_get_proc_return, cpu, pc, arg0) ;
		}; break;
		// 385 int sys___mac_set_proc ['struct mac *mac_p']
		case 385: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys___mac_set_proc_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___mac_set_proc_return, cpu, pc, arg0) ;
		}; break;
		// 386 int sys___mac_get_fd ['int fd', 'struct mac *mac_p']
		case 386: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys___mac_get_fd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___mac_get_fd_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 387 int sys___mac_get_file ['const char *path_p', 'struct mac *mac_p']
		case 387: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys___mac_get_file_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___mac_get_file_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 388 int sys___mac_set_fd ['int fd', 'struct mac *mac_p']
		case 388: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys___mac_set_fd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___mac_set_fd_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 389 int sys___mac_set_file ['const char *path_p', 'struct mac *mac_p']
		case 389: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys___mac_set_file_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___mac_set_file_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 390 int sys_kenv ['int what', 'const char *name', 'char *value', 'int len']
		case 390: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_kenv_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_kenv_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 391 int sys_lchflags ['const char *path', 'u_long flags']
		case 391: {
			uint64_t arg0 = 0;
			int64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lchflags_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
			}
			PPP_RUN_CB(on_sys_lchflags_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 392 int sys_uuidgen ['struct uuid *store', 'int count']
		case 392: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_uuidgen_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_uuidgen_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 393 int sys_sendfile ['int fd', 'int s', 'off_t offset', 'size_t nbytes', 'struct sf_hdtr *hdtr', 'off_t *sbytes', 'int flags']
		case 393: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			uint64_t arg4 = 0;
			uint64_t arg5 = 0;
			int32_t arg6 = 0;
			if (PPP_CHECK_CB(on_sys_sendfile_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
				memcpy(&arg6, ctx->args[6], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sendfile_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 394 int sys_mac_syscall ['const char *policy', 'int call', 'void *arg']
		case 394: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mac_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_mac_syscall_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 395 int sys_getfsstat ['struct freebsd11_statfs *buf', 'long bufsize', 'int mode']
		case 395: {
			uint64_t arg0 = 0;
			int64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getfsstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getfsstat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 396 int sys_statfs ['const char *path', 'struct freebsd11_statfs *buf']
		case 396: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_statfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_statfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 397 int sys_fstatfs ['int fd', 'struct freebsd11_statfs *buf']
		case 397: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fstatfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fstatfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 398 int sys_fhstatfs ['const struct fhandle *u_fhp', 'struct freebsd11_statfs *buf']
		case 398: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fhstatfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fhstatfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 400 int sys_ksem_close ['semid_t id']
		case 400: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ksem_close_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ksem_close_return, cpu, pc, arg0) ;
		}; break;
		// 401 int sys_ksem_post ['semid_t id']
		case 401: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ksem_post_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ksem_post_return, cpu, pc, arg0) ;
		}; break;
		// 402 int sys_ksem_wait ['semid_t id']
		case 402: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ksem_wait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ksem_wait_return, cpu, pc, arg0) ;
		}; break;
		// 403 int sys_ksem_trywait ['semid_t id']
		case 403: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ksem_trywait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ksem_trywait_return, cpu, pc, arg0) ;
		}; break;
		// 404 int sys_ksem_init ['semid_t *idp', 'unsigned int value']
		case 404: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ksem_init_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ksem_init_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 405 int sys_ksem_open ['semid_t *idp', 'const char *name', 'int oflag', 'mode_t mode', 'unsigned int value']
		case 405: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_ksem_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ksem_open_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 406 int sys_ksem_unlink ['const char *name']
		case 406: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ksem_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ksem_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 407 int sys_ksem_getvalue ['semid_t id', 'int *val']
		case 407: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ksem_getvalue_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ksem_getvalue_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 408 int sys_ksem_destroy ['semid_t id']
		case 408: {
			uint32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_ksem_destroy_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_ksem_destroy_return, cpu, pc, arg0) ;
		}; break;
		// 409 int sys___mac_get_pid ['pid_t pid', 'struct mac *mac_p']
		case 409: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys___mac_get_pid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___mac_get_pid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 410 int sys___mac_get_link ['const char *path_p', 'struct mac *mac_p']
		case 410: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys___mac_get_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___mac_get_link_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 411 int sys___mac_set_link ['const char *path_p', 'struct mac *mac_p']
		case 411: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys___mac_set_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___mac_set_link_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 412 ssize_t sys_extattr_set_link ['const char *path', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
		case 412: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_set_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_extattr_set_link_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 413 ssize_t sys_extattr_get_link ['const char *path', 'int attrnamespace', 'const char *attrname', 'void *data', 'size_t nbytes']
		case 413: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_get_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_extattr_get_link_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 414 int sys_extattr_delete_link ['const char *path', 'int attrnamespace', 'const char *attrname']
		case 414: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_delete_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_extattr_delete_link_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 415 int sys___mac_execve ['const char *fname', 'char **argv', 'char **envv', 'struct mac *mac_p']
		case 415: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys___mac_execve_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___mac_execve_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 416 int sys_sigaction ['int sig', 'const struct sigaction *act', 'struct sigaction *oact']
		case 416: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sigaction_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigaction_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 417 int sys_sigreturn ['const struct __ucontext *sigcntxp']
		case 417: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_sigreturn_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigreturn_return, cpu, pc, arg0) ;
		}; break;
		// 421 int sys_getcontext ['struct __ucontext *ucp']
		case 421: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_getcontext_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getcontext_return, cpu, pc, arg0) ;
		}; break;
		// 422 int sys_setcontext ['const struct __ucontext *ucp']
		case 422: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setcontext_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setcontext_return, cpu, pc, arg0) ;
		}; break;
		// 423 int sys_swapcontext ['struct __ucontext *oucp', 'const struct __ucontext *ucp']
		case 423: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_swapcontext_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_swapcontext_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 424 int sys_swapoff ['const char *name']
		case 424: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_swapoff_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_swapoff_return, cpu, pc, arg0) ;
		}; break;
		// 425 int sys___acl_get_link ['const char *path', 'acl_type_t type', 'struct acl *aclp']
		case 425: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys___acl_get_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___acl_get_link_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 426 int sys___acl_set_link ['const char *path', 'acl_type_t type', 'struct acl *aclp']
		case 426: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys___acl_set_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___acl_set_link_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 427 int sys___acl_delete_link ['const char *path', 'acl_type_t type']
		case 427: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys___acl_delete_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys___acl_delete_link_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 428 int sys___acl_aclcheck_link ['const char *path', 'acl_type_t type', 'struct acl *aclp']
		case 428: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys___acl_aclcheck_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___acl_aclcheck_link_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 429 int sys_sigwait ['const sigset_t *set', 'int *sig']
		case 429: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sigwait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigwait_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 430 int sys_thr_create ['ucontext_t *ctx', 'long *id', 'int flags']
		case 430: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_thr_create_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_thr_create_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 431 void sys_thr_exit ['long *state']
		case 431: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_thr_exit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_thr_exit_return, cpu, pc, arg0) ;
		}; break;
		// 432 int sys_thr_self ['long *id']
		case 432: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_thr_self_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_thr_self_return, cpu, pc, arg0) ;
		}; break;
		// 433 int sys_thr_kill ['long id', 'int sig']
		case 433: {
			int64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_thr_kill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_thr_kill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 436 int sys_jail_attach ['int jid']
		case 436: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_jail_attach_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_jail_attach_return, cpu, pc, arg0) ;
		}; break;
		// 437 ssize_t sys_extattr_list_fd ['int fd', 'int attrnamespace', 'void *data', 'size_t nbytes']
		case 437: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_list_fd_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_extattr_list_fd_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 438 ssize_t sys_extattr_list_file ['const char *path', 'int attrnamespace', 'void *data', 'size_t nbytes']
		case 438: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_list_file_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_extattr_list_file_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 439 ssize_t sys_extattr_list_link ['const char *path', 'int attrnamespace', 'void *data', 'size_t nbytes']
		case 439: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_extattr_list_link_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_extattr_list_link_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 441 int sys_ksem_timedwait ['semid_t id', 'const struct timespec *abstime']
		case 441: {
			uint32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ksem_timedwait_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ksem_timedwait_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 442 int sys_thr_suspend ['const struct timespec *timeout']
		case 442: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_thr_suspend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_thr_suspend_return, cpu, pc, arg0) ;
		}; break;
		// 443 int sys_thr_wake ['long id']
		case 443: {
			int64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_thr_wake_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int64_t));
			}
			PPP_RUN_CB(on_sys_thr_wake_return, cpu, pc, arg0) ;
		}; break;
		// 444 int sys_kldunloadf ['int fileid', 'int flags']
		case 444: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_kldunloadf_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_kldunloadf_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 445 int sys_audit ['const void *record', 'unsigned length']
		case 445: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_audit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_audit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 446 int sys_auditon ['int cmd', 'void *data', 'unsigned length']
		case 446: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_auditon_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_auditon_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 447 int sys_getauid ['uid_t *auid']
		case 447: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_getauid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getauid_return, cpu, pc, arg0) ;
		}; break;
		// 448 int sys_setauid ['uid_t *auid']
		case 448: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setauid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setauid_return, cpu, pc, arg0) ;
		}; break;
		// 449 int sys_getaudit ['struct auditinfo *auditinfo']
		case 449: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_getaudit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getaudit_return, cpu, pc, arg0) ;
		}; break;
		// 450 int sys_setaudit ['struct auditinfo *auditinfo']
		case 450: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setaudit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setaudit_return, cpu, pc, arg0) ;
		}; break;
		// 451 int sys_getaudit_addr ['struct auditinfo_addr *auditinfo_addr', 'unsigned length']
		case 451: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getaudit_addr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getaudit_addr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 452 int sys_setaudit_addr ['struct auditinfo_addr *auditinfo_addr', 'unsigned length']
		case 452: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_setaudit_addr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_setaudit_addr_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 453 int sys_auditctl ['const char *path']
		case 453: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_auditctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_auditctl_return, cpu, pc, arg0) ;
		}; break;
		// 454 int sys__umtx_op ['void *obj', 'int op', 'u_long val', 'void *uaddr1', 'void *uaddr2']
		case 454: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			int64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint64_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys__umtx_op_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys__umtx_op_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 455 int sys_thr_new ['struct thr_param *param', 'int param_size']
		case 455: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_thr_new_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_thr_new_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 456 int sys_sigqueue ['pid_t pid', 'int signum', 'void *value']
		case 456: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_sigqueue_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigqueue_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 457 int sys_kmq_open ['const char *path', 'int flags', 'mode_t mode', 'const struct mq_attr *attr']
		case 457: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_kmq_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kmq_open_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 458 int sys_kmq_setattr ['int mqd', 'const struct mq_attr *attr', 'struct mq_attr *oattr']
		case 458: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_kmq_setattr_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kmq_setattr_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 459 int sys_kmq_timedreceive ['int mqd', 'char *msg_ptr', 'size_t msg_len', 'unsigned *msg_prio', 'const struct timespec *abs_timeout']
		case 459: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			uint64_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_kmq_timedreceive_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kmq_timedreceive_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 460 int sys_kmq_timedsend ['int mqd', 'const char *msg_ptr', 'size_t msg_len', 'unsigned msg_prio', 'const struct timespec *abs_timeout']
		case 460: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint64_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_kmq_timedsend_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kmq_timedsend_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 461 int sys_kmq_notify ['int mqd', 'const struct sigevent *sigev']
		case 461: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_kmq_notify_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kmq_notify_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 462 int sys_kmq_unlink ['const char *path']
		case 462: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_kmq_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kmq_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 463 int sys_abort2 ['const char *why', 'int nargs', 'void **args']
		case 463: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_abort2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_abort2_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 464 int sys_thr_set_name ['long id', 'const char *name']
		case 464: {
			int64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_thr_set_name_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_thr_set_name_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 465 int sys_aio_fsync ['int op', 'struct aiocb *aiocbp']
		case 465: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_aio_fsync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_fsync_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 466 int sys_rtprio_thread ['int function', 'lwpid_t lwpid', 'struct rtprio *rtp']
		case 466: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_rtprio_thread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_rtprio_thread_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 471 int sys_sctp_peeloff ['int sd', 'uint32_t name']
		case 471: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sctp_peeloff_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sctp_peeloff_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 472 int sys_sctp_generic_sendmsg ['int sd', 'void *msg', 'int mlen', 'struct sockaddr *to', '__socklen_t tolen', 'struct sctp_sndrcvinfo *sinfo', 'int flags']
		case 472: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			uint32_t arg4 = 0;
			uint64_t arg5 = 0;
			int32_t arg6 = 0;
			if (PPP_CHECK_CB(on_sys_sctp_generic_sendmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
				memcpy(&arg6, ctx->args[6], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sctp_generic_sendmsg_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 473 int sys_sctp_generic_sendmsg_iov ['int sd', 'struct iovec *iov', 'int iovlen', 'struct sockaddr *to', '__socklen_t tolen', 'struct sctp_sndrcvinfo *sinfo', 'int flags']
		case 473: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			uint32_t arg4 = 0;
			uint64_t arg5 = 0;
			int32_t arg6 = 0;
			if (PPP_CHECK_CB(on_sys_sctp_generic_sendmsg_iov_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
				memcpy(&arg6, ctx->args[6], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_sctp_generic_sendmsg_iov_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 474 int sys_sctp_generic_recvmsg ['int sd', 'struct iovec *iov', 'int iovlen', 'struct sockaddr *from', '__socklen_t *fromlenaddr', 'struct sctp_sndrcvinfo *sinfo', 'int *msg_flags']
		case 474: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			uint64_t arg4 = 0;
			uint64_t arg5 = 0;
			uint64_t arg6 = 0;
			if (PPP_CHECK_CB(on_sys_sctp_generic_recvmsg_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
				memcpy(&arg6, ctx->args[6], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sctp_generic_recvmsg_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5, arg6) ;
		}; break;
		// 475 ssize_t sys_pread ['int fd', 'void *buf', 'size_t nbyte', 'off_t offset']
		case 475: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_pread_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pread_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 476 ssize_t sys_pwrite ['int fd', 'const void *buf', 'size_t nbyte', 'off_t offset']
		case 476: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_pwrite_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pwrite_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 478 off_t sys_lseek ['int fd', 'off_t offset', 'int whence']
		case 478: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_lseek_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_lseek_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 479 int sys_truncate ['const char *path', 'off_t length']
		case 479: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_truncate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_truncate_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 480 int sys_ftruncate ['int fd', 'off_t length']
		case 480: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_ftruncate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ftruncate_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 481 int sys_thr_kill2 ['pid_t pid', 'long id', 'int sig']
		case 481: {
			int32_t arg0 = 0;
			int64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_thr_kill2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_thr_kill2_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 482 int sys_shm_open ['const char *path', 'int flags', 'mode_t mode']
		case 482: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_shm_open_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_shm_open_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 483 int sys_shm_unlink ['const char *path']
		case 483: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_shm_unlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_shm_unlink_return, cpu, pc, arg0) ;
		}; break;
		// 484 int sys_cpuset ['cpusetid_t *setid']
		case 484: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_cpuset_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_cpuset_return, cpu, pc, arg0) ;
		}; break;
		// 485 int sys_cpuset_setid ['cpuwhich_t which', 'id_t id', 'cpusetid_t setid']
		case 485: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_cpuset_setid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_cpuset_setid_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 486 int sys_cpuset_getid ['cpulevel_t level', 'cpuwhich_t which', 'id_t id', 'cpusetid_t *setid']
		case 486: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_cpuset_getid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_cpuset_getid_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 487 int sys_cpuset_getaffinity ['cpulevel_t level', 'cpuwhich_t which', 'id_t id', 'size_t cpusetsize', 'cpuset_t *mask']
		case 487: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint64_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_cpuset_getaffinity_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_cpuset_getaffinity_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 488 int sys_cpuset_setaffinity ['cpulevel_t level', 'cpuwhich_t which', 'id_t id', 'size_t cpusetsize', 'const cpuset_t *mask']
		case 488: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint64_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_cpuset_setaffinity_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_cpuset_setaffinity_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 489 int sys_faccessat ['int fd', 'const char *path', 'int amode', 'int flag']
		case 489: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_faccessat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_faccessat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 490 int sys_fchmodat ['int fd', 'const char *path', 'mode_t mode', 'int flag']
		case 490: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_fchmodat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fchmodat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 491 int sys_fchownat ['int fd', 'const char *path', 'uid_t uid', 'gid_t gid', 'int flag']
		case 491: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_fchownat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fchownat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 492 int sys_fexecve ['int fd', 'char **argv', 'char **envv']
		case 492: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fexecve_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fexecve_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 493 int sys_fstatat ['int fd', 'const char *path', 'struct freebsd11_stat *buf', 'int flag']
		case 493: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_fstatat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fstatat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 494 int sys_futimesat ['int fd', 'const char *path', 'struct timeval *times']
		case 494: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_futimesat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_futimesat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 495 int sys_linkat ['int fd1', 'const char *path1', 'int fd2', 'const char *path2', 'int flag']
		case 495: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_linkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_linkat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 496 int sys_mkdirat ['int fd', 'const char *path', 'mode_t mode']
		case 496: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mkdirat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkdirat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 497 int sys_mkfifoat ['int fd', 'const char *path', 'mode_t mode']
		case 497: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_mkfifoat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mkfifoat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 498 int sys_mknodat ['int fd', 'const char *path', 'mode_t mode', 'uint32_t dev']
		case 498: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_mknodat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_mknodat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 499 int sys_openat ['int fd', 'const char *path', 'int flag', 'mode_t mode']
		case 499: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_openat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_openat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 500 ssize_t sys_readlinkat ['int fd', 'const char *path', 'char *buf', 'size_t bufsize']
		case 500: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_readlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_readlinkat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 501 int sys_renameat ['int oldfd', 'const char *old', 'int newfd', 'const char *new']
		case 501: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_renameat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_renameat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 502 int sys_symlinkat ['const char *path1', 'int fd', 'const char *path2']
		case 502: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_symlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_symlinkat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 503 int sys_unlinkat ['int fd', 'const char *path', 'int flag']
		case 503: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_unlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_unlinkat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 504 int sys_posix_openpt ['int flags']
		case 504: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_posix_openpt_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_posix_openpt_return, cpu, pc, arg0) ;
		}; break;
		// 505 int sys_gssd_syscall ['const char *path']
		case 505: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_gssd_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_gssd_syscall_return, cpu, pc, arg0) ;
		}; break;
		// 506 int sys_jail_get ['struct iovec *iovp', 'unsigned int iovcnt', 'int flags']
		case 506: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_jail_get_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_jail_get_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 507 int sys_jail_set ['struct iovec *iovp', 'unsigned int iovcnt', 'int flags']
		case 507: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_jail_set_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_jail_set_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 508 int sys_jail_remove ['int jid']
		case 508: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_jail_remove_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_jail_remove_return, cpu, pc, arg0) ;
		}; break;
		// 509 int sys_closefrom ['int lowfd']
		case 509: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_closefrom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_closefrom_return, cpu, pc, arg0) ;
		}; break;
		// 510 int sys___semctl ['int semid', 'int semnum', 'int cmd', 'union semun *arg']
		case 510: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys___semctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys___semctl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 511 int sys_msgctl ['int msqid', 'int cmd', 'struct msqid_ds *buf']
		case 511: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_msgctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_msgctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 512 int sys_shmctl ['int shmid', 'int cmd', 'struct shmid_ds *buf']
		case 512: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_shmctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_shmctl_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 513 int sys_lpathconf ['const char *path', 'int name']
		case 513: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_lpathconf_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_lpathconf_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 516 int sys_cap_enter ['void']
		case 516: {
			if (PPP_CHECK_CB(on_sys_cap_enter_return) || PPP_CHECK_CB(on_all_sys_return2)) {
			}
			PPP_RUN_CB(on_sys_cap_enter_return, cpu, pc) ;
		}; break;
		// 517 int sys_cap_getmode ['unsigned *modep']
		case 517: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_cap_getmode_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_cap_getmode_return, cpu, pc, arg0) ;
		}; break;
		// 518 int sys_pdfork ['int *fdp', 'int flags']
		case 518: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pdfork_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pdfork_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 519 int sys_pdkill ['int fd', 'int signum']
		case 519: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pdkill_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pdkill_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 520 int sys_pdgetpid ['int fd', 'pid_t *pidp']
		case 520: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pdgetpid_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pdgetpid_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 522 int sys_pselect ['int nd', 'fd_set *in', 'fd_set *ou', 'fd_set *ex', 'const struct timespec *ts', 'const sigset_t *sm']
		case 522: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint64_t arg4 = 0;
			uint64_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys_pselect_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_pselect_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 523 int sys_getloginclass ['char *namebuf', 'size_t namelen']
		case 523: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_getloginclass_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getloginclass_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 524 int sys_setloginclass ['const char *namebuf']
		case 524: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_setloginclass_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_setloginclass_return, cpu, pc, arg0) ;
		}; break;
		// 525 int sys_rctl_get_racct ['const void *inbufp', 'size_t inbuflen', 'void *outbufp', 'size_t outbuflen']
		case 525: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rctl_get_racct_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rctl_get_racct_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 526 int sys_rctl_get_rules ['const void *inbufp', 'size_t inbuflen', 'void *outbufp', 'size_t outbuflen']
		case 526: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rctl_get_rules_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rctl_get_rules_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 527 int sys_rctl_get_limits ['const void *inbufp', 'size_t inbuflen', 'void *outbufp', 'size_t outbuflen']
		case 527: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rctl_get_limits_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rctl_get_limits_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 528 int sys_rctl_add_rule ['const void *inbufp', 'size_t inbuflen', 'void *outbufp', 'size_t outbuflen']
		case 528: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rctl_add_rule_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rctl_add_rule_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 529 int sys_rctl_remove_rule ['const void *inbufp', 'size_t inbuflen', 'void *outbufp', 'size_t outbuflen']
		case 529: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_rctl_remove_rule_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_rctl_remove_rule_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 530 int sys_posix_fallocate ['int fd', 'off_t offset', 'off_t len']
		case 530: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_posix_fallocate_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_posix_fallocate_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 531 int sys_posix_fadvise ['int fd', 'off_t offset', 'off_t len', 'int advice']
		case 531: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_posix_fadvise_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_posix_fadvise_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 532 int sys_wait6 ['idtype_t idtype', 'id_t id', 'int *status', 'int options', 'struct __wrusage *wrusage', 'siginfo_t *info']
		case 532: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			uint64_t arg4 = 0;
			uint64_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys_wait6_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_wait6_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 533 int sys_cap_rights_limit ['int fd', 'cap_rights_t *rightsp']
		case 533: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_cap_rights_limit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_cap_rights_limit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 534 int sys_cap_ioctls_limit ['int fd', 'const u_long *cmds', 'size_t ncmds']
		case 534: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_cap_ioctls_limit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_cap_ioctls_limit_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 535 ssize_t sys_cap_ioctls_get ['int fd', 'u_long *cmds', 'size_t maxcmds']
		case 535: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_cap_ioctls_get_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_cap_ioctls_get_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 536 int sys_cap_fcntls_limit ['int fd', 'uint32_t fcntlrights']
		case 536: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_cap_fcntls_limit_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_cap_fcntls_limit_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 537 int sys_cap_fcntls_get ['int fd', 'uint32_t *fcntlrightsp']
		case 537: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_cap_fcntls_get_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_cap_fcntls_get_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 538 int sys_bindat ['int fd', 'int s', 'const struct sockaddr *name', 'int namelen']
		case 538: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_bindat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_bindat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 539 int sys_connectat ['int fd', 'int s', 'const struct sockaddr *name', 'int namelen']
		case 539: {
			int32_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_connectat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_connectat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 540 int sys_chflagsat ['int fd', 'const char *path', 'u_long flags', 'int atflag']
		case 540: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_chflagsat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_chflagsat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 541 int sys_accept4 ['int s', 'struct sockaddr *name', '__socklen_t *anamelen', 'int flags']
		case 541: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_accept4_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_accept4_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 542 int sys_pipe2 ['int *fildes', 'int flags']
		case 542: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_pipe2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_pipe2_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 543 int sys_aio_mlock ['struct aiocb *aiocbp']
		case 543: {
			uint64_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_aio_mlock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_aio_mlock_return, cpu, pc, arg0) ;
		}; break;
		// 544 int sys_procctl ['idtype_t idtype', 'id_t id', 'int com', 'void *data']
		case 544: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_procctl_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_procctl_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 545 int sys_ppoll ['struct pollfd *fds', 'unsigned nfds', 'const struct timespec *ts', 'const sigset_t *set']
		case 545: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_ppoll_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_ppoll_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 546 int sys_futimens ['int fd', 'struct timespec *times']
		case 546: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_futimens_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_futimens_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 547 int sys_utimensat ['int fd', 'const char *path', 'struct timespec *times', 'int flag']
		case 547: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_utimensat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_utimensat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 550 int sys_fdatasync ['int fd']
		case 550: {
			int32_t arg0 = 0;
			if (PPP_CHECK_CB(on_sys_fdatasync_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fdatasync_return, cpu, pc, arg0) ;
		}; break;
		// 551 int sys_fstat ['int fd', 'struct stat *sb']
		case 551: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 552 int sys_fstatat ['int fd', 'const char *path', 'struct stat *buf', 'int flag']
		case 552: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_fstatat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_fstatat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 553 int sys_fhstat ['const struct fhandle *u_fhp', 'struct stat *sb']
		case 553: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fhstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fhstat_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 554 ssize_t sys_getdirentries ['int fd', 'char *buf', 'size_t count', 'off_t *basep']
		case 554: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint64_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_getdirentries_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_getdirentries_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 555 int sys_statfs ['const char *path', 'struct statfs *buf']
		case 555: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_statfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_statfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 556 int sys_fstatfs ['int fd', 'struct statfs *buf']
		case 556: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fstatfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fstatfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 557 int sys_getfsstat ['struct statfs *buf', 'long bufsize', 'int mode']
		case 557: {
			uint64_t arg0 = 0;
			int64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getfsstat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getfsstat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 558 int sys_fhstatfs ['const struct fhandle *u_fhp', 'struct statfs *buf']
		case 558: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fhstatfs_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fhstatfs_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 559 int sys_mknodat ['int fd', 'const char *path', 'mode_t mode', 'dev_t dev']
		case 559: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_mknodat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_mknodat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 560 int sys_kevent ['int fd', 'struct kevent *changelist', 'int nchanges', 'struct kevent *eventlist', 'int nevents', 'const struct timespec *timeout']
		case 560: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			int32_t arg4 = 0;
			uint64_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys_kevent_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_kevent_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 561 int sys_cpuset_getdomain ['cpulevel_t level', 'cpuwhich_t which', 'id_t id', 'size_t domainsetsize', 'domainset_t *mask', 'int *policy']
		case 561: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint64_t arg4 = 0;
			uint64_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys_cpuset_getdomain_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_cpuset_getdomain_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 562 int sys_cpuset_setdomain ['cpulevel_t level', 'cpuwhich_t which', 'id_t id', 'size_t domainsetsize', 'domainset_t *mask', 'int policy']
		case 562: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			uint32_t arg3 = 0;
			uint64_t arg4 = 0;
			int32_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys_cpuset_setdomain_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_cpuset_setdomain_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 563 int sys_getrandom ['void *buf', 'size_t buflen', 'unsigned int flags']
		case 563: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_getrandom_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_getrandom_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 564 int sys_getfhat ['int fd', 'char *path', 'struct fhandle *fhp', 'int flags']
		case 564: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_getfhat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_getfhat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 565 int sys_fhlink ['struct fhandle *fhp', 'const char *to']
		case 565: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_fhlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fhlink_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 566 int sys_fhlinkat ['struct fhandle *fhp', 'int tofd', 'const char *to', '']
		case 566: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint64_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fhlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_fhlinkat_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 567 int sys_fhreadlink ['struct fhandle *fhp', 'char *buf', 'size_t bufsize']
		case 567: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			uint32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_fhreadlink_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys_fhreadlink_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 568 int sys_funlinkat ['int dfd', 'const char *path', 'int fd', 'int flag']
		case 568: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			int32_t arg3 = 0;
			if (PPP_CHECK_CB(on_sys_funlinkat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_funlinkat_return, cpu, pc, arg0, arg1, arg2, arg3) ;
		}; break;
		// 569 ssize_t sys_copy_file_range ['int infd', 'off_t *inoffp', 'int outfd', 'off_t *outoffp', 'size_t len', 'unsigned int flags']
		case 569: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			uint64_t arg3 = 0;
			uint32_t arg4 = 0;
			uint32_t arg5 = 0;
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
		// 570 int sys___sysctlbyname ['const char *name', 'size_t namelen', 'void *old', 'size_t *oldlenp', 'void *new', 'size_t newlen']
		case 570: {
			uint64_t arg0 = 0;
			uint32_t arg1 = 0;
			uint64_t arg2 = 0;
			uint64_t arg3 = 0;
			uint64_t arg4 = 0;
			uint32_t arg5 = 0;
			if (PPP_CHECK_CB(on_sys___sysctlbyname_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint64_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
				memcpy(&arg5, ctx->args[5], sizeof(uint32_t));
			}
			PPP_RUN_CB(on_sys___sysctlbyname_return, cpu, pc, arg0, arg1, arg2, arg3, arg4, arg5) ;
		}; break;
		// 571 int sys_shm_open2 ['const char *path', 'int flags', 'mode_t mode', 'int shmflags', 'const char *name']
		case 571: {
			uint64_t arg0 = 0;
			int32_t arg1 = 0;
			uint32_t arg2 = 0;
			int32_t arg3 = 0;
			uint64_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys_shm_open2_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(int32_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint32_t));
				memcpy(&arg3, ctx->args[3], sizeof(int32_t));
				memcpy(&arg4, ctx->args[4], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_shm_open2_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 572 int sys_shm_rename ['const char *path_from', 'const char *path_to', 'int flags']
		case 572: {
			uint64_t arg0 = 0;
			uint64_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_shm_rename_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint64_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_shm_rename_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 573 int sys_sigfastblock ['int cmd', 'uint32_t *ptr']
		case 573: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_sigfastblock_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_sigfastblock_return, cpu, pc, arg0, arg1) ;
		}; break;
		// 574 int sys___realpathat ['int fd', 'const char *path', 'char *buf', 'size_t size', 'int flags']
		case 574: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			uint64_t arg2 = 0;
			uint32_t arg3 = 0;
			int32_t arg4 = 0;
			if (PPP_CHECK_CB(on_sys___realpathat_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
				memcpy(&arg2, ctx->args[2], sizeof(uint64_t));
				memcpy(&arg3, ctx->args[3], sizeof(uint32_t));
				memcpy(&arg4, ctx->args[4], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys___realpathat_return, cpu, pc, arg0, arg1, arg2, arg3, arg4) ;
		}; break;
		// 575 int sys_close_range ['unsigned lowfd', 'unsigned highfd', 'int flags']
		case 575: {
			uint32_t arg0 = 0;
			uint32_t arg1 = 0;
			int32_t arg2 = 0;
			if (PPP_CHECK_CB(on_sys_close_range_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(uint32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint32_t));
				memcpy(&arg2, ctx->args[2], sizeof(int32_t));
			}
			PPP_RUN_CB(on_sys_close_range_return, cpu, pc, arg0, arg1, arg2) ;
		}; break;
		// 576 int sys_rpctls_syscall ['int op', 'const char *path']
		case 576: {
			int32_t arg0 = 0;
			uint64_t arg1 = 0;
			if (PPP_CHECK_CB(on_sys_rpctls_syscall_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				memcpy(&arg0, ctx->args[0], sizeof(int32_t));
				memcpy(&arg1, ctx->args[1], sizeof(uint64_t));
			}
			PPP_RUN_CB(on_sys_rpctls_syscall_return, cpu, pc, arg0, arg1) ;
		}; break;
		default:
			PPP_RUN_CB(on_unknown_sys_return, cpu, pc, ctx->no);
	}
	PPP_RUN_CB(on_all_sys_return, cpu, pc, ctx->no);
	PPP_RUN_CB(on_all_sys_return2, cpu, pc, call, ctx);
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */