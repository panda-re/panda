// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ARM_BREAKPOINT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ARM_BREAKPOINT_ENTER 1
PPP_CB_TYPEDEF(void, on_ARM_breakpoint_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ARM_BREAKPOINT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ARM_BREAKPOINT_RETURN 1
PPP_CB_TYPEDEF(void, on_ARM_breakpoint_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ARM_CACHEFLUSH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ARM_CACHEFLUSH_ENTER 1
PPP_CB_TYPEDEF(void, on_ARM_cacheflush_enter, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t end, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ARM_CACHEFLUSH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ARM_CACHEFLUSH_RETURN 1
PPP_CB_TYPEDEF(void, on_ARM_cacheflush_return, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t end, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ARM_SET_TLS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ARM_SET_TLS_ENTER 1
PPP_CB_TYPEDEF(void, on_ARM_set_tls_enter, CPUState* cpu, target_ulong pc, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ARM_SET_TLS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ARM_SET_TLS_RETURN 1
PPP_CB_TYPEDEF(void, on_ARM_set_tls_return, CPUState* cpu, target_ulong pc, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ARM_USER26_MODE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ARM_USER26_MODE_ENTER 1
PPP_CB_TYPEDEF(void, on_ARM_user26_mode_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ARM_USER26_MODE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ARM_USER26_MODE_RETURN 1
PPP_CB_TYPEDEF(void, on_ARM_user26_mode_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ARM_USR32_MODE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ARM_USR32_MODE_ENTER 1
PPP_CB_TYPEDEF(void, on_ARM_usr32_mode_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ARM_USR32_MODE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ARM_USR32_MODE_RETURN 1
PPP_CB_TYPEDEF(void, on_ARM_usr32_mode_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_DO_MMAP2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_DO_MMAP2_ENTER 1
PPP_CB_TYPEDEF(void, on_do_mmap2_enter, CPUState* cpu, target_ulong pc, uint32_t addr, uint32_t len, uint32_t prot, uint32_t flags, uint32_t fd, uint32_t pgoff);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_DO_MMAP2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_DO_MMAP2_RETURN 1
PPP_CB_TYPEDEF(void, on_do_mmap2_return, CPUState* cpu, target_ulong pc, uint32_t addr, uint32_t len, uint32_t prot, uint32_t flags, uint32_t fd, uint32_t pgoff);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_accept_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_accept_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT4_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT4_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_accept4_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, int32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT4_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT4_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_accept4_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, int32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_access_enter, CPUState* cpu, target_ulong pc, uint32_t filename, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_access_return, CPUState* cpu, target_ulong pc, uint32_t filename, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_acct_enter, CPUState* cpu, target_ulong pc, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_acct_return, CPUState* cpu, target_ulong pc, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ADD_KEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ADD_KEY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_add_key_enter, CPUState* cpu, target_ulong pc, uint32_t _type, uint32_t _description, uint32_t _payload, uint32_t plen, uint32_t destringid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ADD_KEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ADD_KEY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_add_key_return, CPUState* cpu, target_ulong pc, uint32_t _type, uint32_t _description, uint32_t _payload, uint32_t plen, uint32_t destringid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_adjtimex_enter, CPUState* cpu, target_ulong pc, uint32_t txc_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_adjtimex_return, CPUState* cpu, target_ulong pc, uint32_t txc_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_alarm_enter, CPUState* cpu, target_ulong pc, uint32_t seconds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_alarm_return, CPUState* cpu, target_ulong pc, uint32_t seconds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ARM_FADVISE64_64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ARM_FADVISE64_64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_arm_fadvise64_64_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t advice, uint64_t offset, uint64_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ARM_FADVISE64_64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ARM_FADVISE64_64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_arm_fadvise64_64_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t advice, uint64_t offset, uint64_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BDFLUSH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BDFLUSH_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_bdflush_enter, CPUState* cpu, target_ulong pc, int32_t func, int32_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BDFLUSH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BDFLUSH_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_bdflush_return, CPUState* cpu, target_ulong pc, int32_t func, int32_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BIND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BIND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_bind_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BIND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BIND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_bind_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BPF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BPF_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_bpf_enter, CPUState* cpu, target_ulong pc, int32_t cmd, uint32_t attr, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BPF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BPF_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_bpf_return, CPUState* cpu, target_ulong pc, int32_t cmd, uint32_t attr, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BRK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BRK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_brk_enter, CPUState* cpu, target_ulong pc, uint32_t brk);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BRK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BRK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_brk_return, CPUState* cpu, target_ulong pc, uint32_t brk);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPGET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPGET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_capget_enter, CPUState* cpu, target_ulong pc, uint32_t header, uint32_t dataptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPGET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPGET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_capget_return, CPUState* cpu, target_ulong pc, uint32_t header, uint32_t dataptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPSET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPSET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_capset_enter, CPUState* cpu, target_ulong pc, uint32_t header, uint32_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPSET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPSET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_capset_return, CPUState* cpu, target_ulong pc, uint32_t header, uint32_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_chdir_enter, CPUState* cpu, target_ulong pc, uint32_t filename);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_chdir_return, CPUState* cpu, target_ulong pc, uint32_t filename);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHMOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHMOD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_chmod_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHMOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHMOD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_chmod_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_chown_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_chown_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_chown16_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_chown16_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHROOT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHROOT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_chroot_enter, CPUState* cpu, target_ulong pc, uint32_t filename);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHROOT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHROOT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_chroot_return, CPUState* cpu, target_ulong pc, uint32_t filename);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_adjtime_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint32_t tx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_adjtime_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint32_t tx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_getres_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint32_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_getres_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint32_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_gettime_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint32_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_gettime_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint32_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_nanosleep_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, int32_t flags, uint32_t rqtp, uint32_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_nanosleep_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, int32_t flags, uint32_t rqtp, uint32_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_settime_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint32_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_settime_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint32_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clone_enter, CPUState* cpu, target_ulong pc, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clone_return, CPUState* cpu, target_ulong pc, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOSE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOSE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_close_enter, CPUState* cpu, target_ulong pc, uint32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOSE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOSE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_close_return, CPUState* cpu, target_ulong pc, uint32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CONNECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CONNECT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_connect_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CONNECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CONNECT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_connect_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CREAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CREAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_creat_enter, CPUState* cpu, target_ulong pc, uint32_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CREAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CREAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_creat_return, CPUState* cpu, target_ulong pc, uint32_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_DELETE_MODULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_DELETE_MODULE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_delete_module_enter, CPUState* cpu, target_ulong pc, uint32_t name_user, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_DELETE_MODULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_DELETE_MODULE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_delete_module_return, CPUState* cpu, target_ulong pc, uint32_t name_user, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_dup_enter, CPUState* cpu, target_ulong pc, uint32_t fildes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_dup_return, CPUState* cpu, target_ulong pc, uint32_t fildes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_dup2_enter, CPUState* cpu, target_ulong pc, uint32_t oldfd, uint32_t newfd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_dup2_return, CPUState* cpu, target_ulong pc, uint32_t oldfd, uint32_t newfd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP3_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP3_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_dup3_enter, CPUState* cpu, target_ulong pc, uint32_t oldfd, uint32_t newfd, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP3_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_DUP3_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_dup3_return, CPUState* cpu, target_ulong pc, uint32_t oldfd, uint32_t newfd, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CREATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CREATE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_epoll_create_enter, CPUState* cpu, target_ulong pc, int32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CREATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CREATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_epoll_create_return, CPUState* cpu, target_ulong pc, int32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CREATE1_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CREATE1_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_epoll_create1_enter, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CREATE1_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CREATE1_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_epoll_create1_return, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_epoll_ctl_enter, CPUState* cpu, target_ulong pc, int32_t epfd, int32_t op, int32_t fd, uint32_t event);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_epoll_ctl_return, CPUState* cpu, target_ulong pc, int32_t epfd, int32_t op, int32_t fd, uint32_t event);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_PWAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_PWAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_epoll_pwait_enter, CPUState* cpu, target_ulong pc, int32_t epfd, uint32_t events, int32_t maxevents, int32_t timeout, uint32_t sigmask, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_PWAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_PWAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_epoll_pwait_return, CPUState* cpu, target_ulong pc, int32_t epfd, uint32_t events, int32_t maxevents, int32_t timeout, uint32_t sigmask, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_WAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_WAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_epoll_wait_enter, CPUState* cpu, target_ulong pc, int32_t epfd, uint32_t events, int32_t maxevents, int32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_WAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_WAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_epoll_wait_return, CPUState* cpu, target_ulong pc, int32_t epfd, uint32_t events, int32_t maxevents, int32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EVENTFD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EVENTFD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_eventfd_enter, CPUState* cpu, target_ulong pc, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EVENTFD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EVENTFD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_eventfd_return, CPUState* cpu, target_ulong pc, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EVENTFD2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EVENTFD2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_eventfd2_enter, CPUState* cpu, target_ulong pc, uint32_t count, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EVENTFD2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EVENTFD2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_eventfd2_return, CPUState* cpu, target_ulong pc, uint32_t count, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_execve_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t argv, uint32_t envp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_execve_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t argv, uint32_t envp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVEAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVEAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_execveat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t argv, uint32_t envp, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVEAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVEAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_execveat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t argv, uint32_t envp, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_exit_enter, CPUState* cpu, target_ulong pc, int32_t error_code);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_exit_return, CPUState* cpu, target_ulong pc, int32_t error_code);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXIT_GROUP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXIT_GROUP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_exit_group_enter, CPUState* cpu, target_ulong pc, int32_t error_code);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXIT_GROUP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXIT_GROUP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_exit_group_return, CPUState* cpu, target_ulong pc, int32_t error_code);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FACCESSAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FACCESSAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_faccessat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FACCESSAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FACCESSAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_faccessat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FALLOCATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FALLOCATE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fallocate_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t mode, uint64_t offset, uint64_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FALLOCATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FALLOCATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fallocate_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t mode, uint64_t offset, uint64_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FANOTIFY_INIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FANOTIFY_INIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fanotify_init_enter, CPUState* cpu, target_ulong pc, uint32_t flags, uint32_t event_f_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FANOTIFY_INIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FANOTIFY_INIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fanotify_init_return, CPUState* cpu, target_ulong pc, uint32_t flags, uint32_t event_f_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FANOTIFY_MARK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FANOTIFY_MARK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fanotify_mark_enter, CPUState* cpu, target_ulong pc, int32_t fanotify_fd, uint32_t flags, uint64_t mask, int32_t fd, uint32_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FANOTIFY_MARK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FANOTIFY_MARK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fanotify_mark_return, CPUState* cpu, target_ulong pc, int32_t fanotify_fd, uint32_t flags, uint64_t mask, int32_t fd, uint32_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fchdir_enter, CPUState* cpu, target_ulong pc, uint32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fchdir_return, CPUState* cpu, target_ulong pc, uint32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHMOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHMOD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fchmod_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHMOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHMOD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fchmod_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHMODAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHMODAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fchmodat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHMODAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHMODAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fchmodat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fchown_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fchown_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fchown16_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fchown16_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWNAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWNAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fchownat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t user, uint32_t group, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWNAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWNAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fchownat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t user, uint32_t group, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fcntl_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fcntl_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fcntl64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fcntl64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FDATASYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FDATASYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fdatasync_enter, CPUState* cpu, target_ulong pc, uint32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FDATASYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FDATASYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fdatasync_return, CPUState* cpu, target_ulong pc, uint32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FGETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FGETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fgetxattr_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t name, uint32_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FGETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FGETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fgetxattr_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t name, uint32_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FINIT_MODULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FINIT_MODULE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_finit_module_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t uargs, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FINIT_MODULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FINIT_MODULE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_finit_module_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t uargs, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FLISTXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FLISTXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_flistxattr_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FLISTXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FLISTXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_flistxattr_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_flock_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_flock_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FORK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FORK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fork_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FORK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FORK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fork_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FREMOVEXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FREMOVEXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fremovexattr_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FREMOVEXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FREMOVEXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fremovexattr_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fsetxattr_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t name, uint32_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fsetxattr_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t name, uint32_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fstat64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fstat64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATAT64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATAT64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fstatat64_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t statbuf, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATAT64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATAT64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fstatat64_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t statbuf, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fstatfs_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fstatfs_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fstatfs64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t sz, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fstatfs64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t sz, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fsync_enter, CPUState* cpu, target_ulong pc, uint32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fsync_return, CPUState* cpu, target_ulong pc, uint32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FTRUNCATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FTRUNCATE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ftruncate_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FTRUNCATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FTRUNCATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ftruncate_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FTRUNCATE64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FTRUNCATE64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ftruncate64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FTRUNCATE64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FTRUNCATE64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ftruncate64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_futex_enter, CPUState* cpu, target_ulong pc, uint32_t uaddr, int32_t op, uint32_t val, uint32_t utime, uint32_t uaddr2, uint32_t val3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_futex_return, CPUState* cpu, target_ulong pc, uint32_t uaddr, int32_t op, uint32_t val, uint32_t utime, uint32_t uaddr2, uint32_t val3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_futimesat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t utimes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_futimesat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t utimes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_MEMPOLICY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_MEMPOLICY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_get_mempolicy_enter, CPUState* cpu, target_ulong pc, uint32_t policy, uint32_t nmask, uint32_t maxnode, uint32_t addr, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_MEMPOLICY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_MEMPOLICY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_get_mempolicy_return, CPUState* cpu, target_ulong pc, uint32_t policy, uint32_t nmask, uint32_t maxnode, uint32_t addr, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_ROBUST_LIST_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_ROBUST_LIST_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_get_robust_list_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t head_ptr, uint32_t len_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_ROBUST_LIST_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_ROBUST_LIST_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_get_robust_list_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t head_ptr, uint32_t len_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCPU_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCPU_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getcpu_enter, CPUState* cpu, target_ulong pc, uint32_t _cpu, uint32_t node, uint32_t cache);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCPU_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCPU_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getcpu_return, CPUState* cpu, target_ulong pc, uint32_t _cpu, uint32_t node, uint32_t cache);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCWD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCWD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getcwd_enter, CPUState* cpu, target_ulong pc, uint32_t buf, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCWD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCWD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getcwd_return, CPUState* cpu, target_ulong pc, uint32_t buf, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getdents_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t dirent, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getdents_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t dirent, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getdents64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t dirent, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getdents64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t dirent, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getegid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getegid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getegid16_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getegid16_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_geteuid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_geteuid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_geteuid16_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_geteuid16_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getgid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getgid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getgid16_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getgid16_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getgroups_enter, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint32_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getgroups_return, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint32_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getgroups16_enter, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint32_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getgroups16_return, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint32_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETITIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETITIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getitimer_enter, CPUState* cpu, target_ulong pc, int32_t which, uint32_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETITIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETITIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getitimer_return, CPUState* cpu, target_ulong pc, int32_t which, uint32_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPEERNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPEERNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getpeername_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPEERNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPEERNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getpeername_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getpgid_enter, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getpgid_return, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPGRP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPGRP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getpgrp_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPGRP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPGRP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getpgrp_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getpid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getpid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPPID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPPID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getppid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPPID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPPID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getppid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPRIORITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPRIORITY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getpriority_enter, CPUState* cpu, target_ulong pc, int32_t which, int32_t who);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPRIORITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPRIORITY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getpriority_return, CPUState* cpu, target_ulong pc, int32_t which, int32_t who);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRANDOM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRANDOM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getrandom_enter, CPUState* cpu, target_ulong pc, uint32_t buf, uint32_t count, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRANDOM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRANDOM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getrandom_return, CPUState* cpu, target_ulong pc, uint32_t buf, uint32_t count, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getresgid_enter, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getresgid_return, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getresgid16_enter, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getresgid16_return, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getresuid_enter, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getresuid_return, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getresuid16_enter, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getresuid16_return, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRLIMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRLIMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getrlimit_enter, CPUState* cpu, target_ulong pc, uint32_t resource, uint32_t rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRLIMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRLIMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getrlimit_return, CPUState* cpu, target_ulong pc, uint32_t resource, uint32_t rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRUSAGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRUSAGE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getrusage_enter, CPUState* cpu, target_ulong pc, int32_t who, uint32_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRUSAGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRUSAGE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getrusage_return, CPUState* cpu, target_ulong pc, int32_t who, uint32_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getsid_enter, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getsid_return, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getsockname_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getsockname_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKOPT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKOPT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getsockopt_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t level, int32_t optname, uint32_t optval, uint32_t optlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKOPT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKOPT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getsockopt_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t level, int32_t optname, uint32_t optval, uint32_t optlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETTID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETTID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_gettid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETTID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETTID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_gettid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETTIMEOFDAY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETTIMEOFDAY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_gettimeofday_enter, CPUState* cpu, target_ulong pc, uint32_t tv, uint32_t tz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETTIMEOFDAY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETTIMEOFDAY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_gettimeofday_return, CPUState* cpu, target_ulong pc, uint32_t tv, uint32_t tz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getuid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getuid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getuid16_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getuid16_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getxattr_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name, uint32_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getxattr_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name, uint32_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INIT_MODULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INIT_MODULE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_init_module_enter, CPUState* cpu, target_ulong pc, uint32_t umod, uint32_t len, uint32_t uargs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INIT_MODULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INIT_MODULE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_init_module_return, CPUState* cpu, target_ulong pc, uint32_t umod, uint32_t len, uint32_t uargs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_ADD_WATCH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_ADD_WATCH_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_inotify_add_watch_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t path, uint32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_ADD_WATCH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_ADD_WATCH_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_inotify_add_watch_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t path, uint32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_INIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_INIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_inotify_init_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_INIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_INIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_inotify_init_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_INIT1_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_INIT1_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_inotify_init1_enter, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_INIT1_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_INIT1_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_inotify_init1_return, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_RM_WATCH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_RM_WATCH_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_inotify_rm_watch_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t wd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_RM_WATCH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_RM_WATCH_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_inotify_rm_watch_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t wd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_CANCEL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_CANCEL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_cancel_enter, CPUState* cpu, target_ulong pc, uint32_t ctx_id, uint32_t iocb, uint32_t result);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_CANCEL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_CANCEL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_cancel_return, CPUState* cpu, target_ulong pc, uint32_t ctx_id, uint32_t iocb, uint32_t result);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_DESTROY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_DESTROY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_destroy_enter, CPUState* cpu, target_ulong pc, uint32_t ctx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_DESTROY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_DESTROY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_destroy_return, CPUState* cpu, target_ulong pc, uint32_t ctx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_getevents_enter, CPUState* cpu, target_ulong pc, uint32_t ctx_id, int32_t min_nr, int32_t nr, uint32_t events, uint32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_getevents_return, CPUState* cpu, target_ulong pc, uint32_t ctx_id, int32_t min_nr, int32_t nr, uint32_t events, uint32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SETUP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SETUP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_setup_enter, CPUState* cpu, target_ulong pc, uint32_t nr_reqs, uint32_t ctx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SETUP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SETUP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_setup_return, CPUState* cpu, target_ulong pc, uint32_t nr_reqs, uint32_t ctx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SUBMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SUBMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_submit_enter, CPUState* cpu, target_ulong pc, uint32_t arg0, int32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SUBMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SUBMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_submit_return, CPUState* cpu, target_ulong pc, uint32_t arg0, int32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ioctl_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ioctl_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPRIO_GET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPRIO_GET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ioprio_get_enter, CPUState* cpu, target_ulong pc, int32_t which, int32_t who);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPRIO_GET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPRIO_GET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ioprio_get_return, CPUState* cpu, target_ulong pc, int32_t which, int32_t who);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPRIO_SET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPRIO_SET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ioprio_set_enter, CPUState* cpu, target_ulong pc, int32_t which, int32_t who, int32_t ioprio);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPRIO_SET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPRIO_SET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ioprio_set_return, CPUState* cpu, target_ulong pc, int32_t which, int32_t who, int32_t ioprio);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IPC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IPC_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ipc_enter, CPUState* cpu, target_ulong pc, uint32_t call, int32_t first, uint32_t second, uint32_t third, uint32_t ptr, int32_t fifth);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IPC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IPC_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ipc_return, CPUState* cpu, target_ulong pc, uint32_t call, int32_t first, uint32_t second, uint32_t third, uint32_t ptr, int32_t fifth);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_kcmp_enter, CPUState* cpu, target_ulong pc, int32_t pid1, int32_t pid2, int32_t type, uint32_t idx1, uint32_t idx2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_kcmp_return, CPUState* cpu, target_ulong pc, int32_t pid1, int32_t pid2, int32_t type, uint32_t idx1, uint32_t idx2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_LOAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_LOAD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_kexec_load_enter, CPUState* cpu, target_ulong pc, uint32_t entry, uint32_t nr_segments, uint32_t segments, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_LOAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_LOAD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_kexec_load_return, CPUState* cpu, target_ulong pc, uint32_t entry, uint32_t nr_segments, uint32_t segments, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KEYCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KEYCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_keyctl_enter, CPUState* cpu, target_ulong pc, int32_t cmd, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KEYCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KEYCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_keyctl_return, CPUState* cpu, target_ulong pc, int32_t cmd, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KILL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KILL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_kill_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KILL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KILL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_kill_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LCHOWN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LCHOWN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lchown_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LCHOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LCHOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lchown_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LCHOWN16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LCHOWN16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lchown16_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LCHOWN16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LCHOWN16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lchown16_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LGETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LGETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lgetxattr_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name, uint32_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LGETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LGETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lgetxattr_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name, uint32_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_link_enter, CPUState* cpu, target_ulong pc, uint32_t oldname, uint32_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_link_return, CPUState* cpu, target_ulong pc, uint32_t oldname, uint32_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_linkat_enter, CPUState* cpu, target_ulong pc, int32_t olddfd, uint32_t oldname, int32_t newdfd, uint32_t newname, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_linkat_return, CPUState* cpu, target_ulong pc, int32_t olddfd, uint32_t oldname, int32_t newdfd, uint32_t newname, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LISTEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LISTEN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_listen_enter, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LISTEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LISTEN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_listen_return, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LISTXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LISTXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_listxattr_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LISTXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LISTXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_listxattr_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LLISTXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LLISTXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_llistxattr_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LLISTXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LLISTXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_llistxattr_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LLSEEK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LLSEEK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_llseek_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t offset_high, uint32_t offset_low, uint32_t result, uint32_t whence);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LLSEEK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LLSEEK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_llseek_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t offset_high, uint32_t offset_low, uint32_t result, uint32_t whence);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LOOKUP_DCOOKIE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LOOKUP_DCOOKIE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lookup_dcookie_enter, CPUState* cpu, target_ulong pc, uint64_t cookie64, uint32_t buf, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LOOKUP_DCOOKIE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LOOKUP_DCOOKIE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lookup_dcookie_return, CPUState* cpu, target_ulong pc, uint64_t cookie64, uint32_t buf, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LREMOVEXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LREMOVEXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lremovexattr_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LREMOVEXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LREMOVEXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lremovexattr_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSEEK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSEEK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lseek_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t offset, uint32_t whence);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSEEK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSEEK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lseek_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t offset, uint32_t whence);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lsetxattr_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name, uint32_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lsetxattr_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name, uint32_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lstat64_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lstat64_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MADVISE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MADVISE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_madvise_enter, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, int32_t behavior);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MADVISE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MADVISE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_madvise_return, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, int32_t behavior);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MBIND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MBIND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mbind_enter, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, uint32_t mode, uint32_t nmask, uint32_t maxnode, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MBIND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MBIND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mbind_return, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, uint32_t mode, uint32_t nmask, uint32_t maxnode, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MEMBARRIER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MEMBARRIER_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_membarrier_enter, CPUState* cpu, target_ulong pc, int32_t cmd, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MEMBARRIER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MEMBARRIER_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_membarrier_return, CPUState* cpu, target_ulong pc, int32_t cmd, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MEMFD_CREATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MEMFD_CREATE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_memfd_create_enter, CPUState* cpu, target_ulong pc, uint32_t uname_ptr, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MEMFD_CREATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MEMFD_CREATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_memfd_create_return, CPUState* cpu, target_ulong pc, uint32_t uname_ptr, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MINCORE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MINCORE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mincore_enter, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, uint32_t vec);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MINCORE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MINCORE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mincore_return, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, uint32_t vec);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mkdir_enter, CPUState* cpu, target_ulong pc, uint32_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mkdir_return, CPUState* cpu, target_ulong pc, uint32_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIRAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIRAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mkdirat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIRAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIRAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mkdirat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNOD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mknod_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t mode, uint32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNOD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mknod_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t mode, uint32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNODAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNODAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mknodat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t mode, uint32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNODAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNODAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mknodat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t mode, uint32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mlock_enter, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mlock_return, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mlock2_enter, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mlock2_return, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCKALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCKALL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mlockall_enter, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCKALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCKALL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mlockall_return, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mount_enter, CPUState* cpu, target_ulong pc, uint32_t dev_name, uint32_t dir_name, uint32_t type, uint32_t flags, uint32_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mount_return, CPUState* cpu, target_ulong pc, uint32_t dev_name, uint32_t dir_name, uint32_t type, uint32_t flags, uint32_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_PAGES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_PAGES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_move_pages_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t nr_pages, uint32_t pages, uint32_t nodes, uint32_t status, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_PAGES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_PAGES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_move_pages_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t nr_pages, uint32_t pages, uint32_t nodes, uint32_t status, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MPROTECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MPROTECT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mprotect_enter, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, uint32_t prot);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MPROTECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MPROTECT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mprotect_return, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, uint32_t prot);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_GETSETATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_GETSETATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_getsetattr_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint32_t mqstat, uint32_t omqstat);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_GETSETATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_GETSETATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_getsetattr_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint32_t mqstat, uint32_t omqstat);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_NOTIFY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_NOTIFY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_notify_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint32_t notification);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_NOTIFY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_NOTIFY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_notify_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint32_t notification);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_open_enter, CPUState* cpu, target_ulong pc, uint32_t name, int32_t oflag, uint32_t mode, uint32_t attr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_open_return, CPUState* cpu, target_ulong pc, uint32_t name, int32_t oflag, uint32_t mode, uint32_t attr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedreceive_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint32_t msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint32_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedreceive_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint32_t msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint32_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedsend_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint32_t msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint32_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedsend_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint32_t msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint32_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_UNLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_UNLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_unlink_enter, CPUState* cpu, target_ulong pc, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_UNLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_UNLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_unlink_return, CPUState* cpu, target_ulong pc, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MREMAP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MREMAP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mremap_enter, CPUState* cpu, target_ulong pc, uint32_t addr, uint32_t old_len, uint32_t new_len, uint32_t flags, uint32_t new_addr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MREMAP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MREMAP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mremap_return, CPUState* cpu, target_ulong pc, uint32_t addr, uint32_t old_len, uint32_t new_len, uint32_t flags, uint32_t new_addr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_msgctl_enter, CPUState* cpu, target_ulong pc, int32_t msqid, int32_t cmd, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_msgctl_return, CPUState* cpu, target_ulong pc, int32_t msqid, int32_t cmd, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGGET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGGET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_msgget_enter, CPUState* cpu, target_ulong pc, uint32_t key, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGGET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGGET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_msgget_return, CPUState* cpu, target_ulong pc, uint32_t key, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGRCV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGRCV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_msgrcv_enter, CPUState* cpu, target_ulong pc, int32_t msqid, uint32_t msgp, uint32_t msgsz, int32_t msgtyp, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGRCV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGRCV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_msgrcv_return, CPUState* cpu, target_ulong pc, int32_t msqid, uint32_t msgp, uint32_t msgsz, int32_t msgtyp, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGSND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGSND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_msgsnd_enter, CPUState* cpu, target_ulong pc, int32_t msqid, uint32_t msgp, uint32_t msgsz, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGSND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGSND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_msgsnd_return, CPUState* cpu, target_ulong pc, int32_t msqid, uint32_t msgp, uint32_t msgsz, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_msync_enter, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_msync_return, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_munlock_enter, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_munlock_return, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCKALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCKALL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_munlockall_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCKALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCKALL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_munlockall_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNMAP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNMAP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_munmap_enter, CPUState* cpu, target_ulong pc, uint32_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNMAP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNMAP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_munmap_return, CPUState* cpu, target_ulong pc, uint32_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NAME_TO_HANDLE_AT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NAME_TO_HANDLE_AT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_name_to_handle_at_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t name, uint32_t handle, uint32_t mnt_id, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NAME_TO_HANDLE_AT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NAME_TO_HANDLE_AT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_name_to_handle_at_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t name, uint32_t handle, uint32_t mnt_id, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_nanosleep_enter, CPUState* cpu, target_ulong pc, uint32_t rqtp, uint32_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_nanosleep_return, CPUState* cpu, target_ulong pc, uint32_t rqtp, uint32_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_newfstat_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_newfstat_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWLSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWLSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_newlstat_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWLSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWLSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_newlstat_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_newstat_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_newstat_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWUNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWUNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_newuname_enter, CPUState* cpu, target_ulong pc, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWUNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWUNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_newuname_return, CPUState* cpu, target_ulong pc, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NICE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NICE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_nice_enter, CPUState* cpu, target_ulong pc, int32_t increment);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NICE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NICE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_nice_return, CPUState* cpu, target_ulong pc, int32_t increment);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_open_enter, CPUState* cpu, target_ulong pc, uint32_t filename, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_open_return, CPUState* cpu, target_ulong pc, uint32_t filename, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_BY_HANDLE_AT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_BY_HANDLE_AT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_open_by_handle_at_enter, CPUState* cpu, target_ulong pc, int32_t mountdirfd, uint32_t handle, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_BY_HANDLE_AT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_BY_HANDLE_AT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_open_by_handle_at_return, CPUState* cpu, target_ulong pc, int32_t mountdirfd, uint32_t handle, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_openat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_openat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PAUSE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PAUSE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pause_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PAUSE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PAUSE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pause_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_IOBASE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_IOBASE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pciconfig_iobase_enter, CPUState* cpu, target_ulong pc, int32_t which, uint32_t bus, uint32_t devfn);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_IOBASE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_IOBASE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pciconfig_iobase_return, CPUState* cpu, target_ulong pc, int32_t which, uint32_t bus, uint32_t devfn);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_READ_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_READ_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pciconfig_read_enter, CPUState* cpu, target_ulong pc, uint32_t bus, uint32_t dfn, uint32_t off, uint32_t len, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_READ_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_READ_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pciconfig_read_return, CPUState* cpu, target_ulong pc, uint32_t bus, uint32_t dfn, uint32_t off, uint32_t len, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_WRITE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_WRITE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pciconfig_write_enter, CPUState* cpu, target_ulong pc, uint32_t bus, uint32_t dfn, uint32_t off, uint32_t len, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_WRITE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PCICONFIG_WRITE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pciconfig_write_return, CPUState* cpu, target_ulong pc, uint32_t bus, uint32_t dfn, uint32_t off, uint32_t len, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PERF_EVENT_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PERF_EVENT_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_perf_event_open_enter, CPUState* cpu, target_ulong pc, uint32_t attr_uptr, int32_t pid, int32_t _cpu, int32_t group_fd, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PERF_EVENT_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PERF_EVENT_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_perf_event_open_return, CPUState* cpu, target_ulong pc, uint32_t attr_uptr, int32_t pid, int32_t _cpu, int32_t group_fd, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PERSONALITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PERSONALITY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_personality_enter, CPUState* cpu, target_ulong pc, uint32_t personality);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PERSONALITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PERSONALITY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_personality_return, CPUState* cpu, target_ulong pc, uint32_t personality);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pipe_enter, CPUState* cpu, target_ulong pc, uint32_t fildes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pipe_return, CPUState* cpu, target_ulong pc, uint32_t fildes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pipe2_enter, CPUState* cpu, target_ulong pc, uint32_t fildes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pipe2_return, CPUState* cpu, target_ulong pc, uint32_t fildes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIVOT_ROOT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIVOT_ROOT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pivot_root_enter, CPUState* cpu, target_ulong pc, uint32_t new_root, uint32_t put_old);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIVOT_ROOT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIVOT_ROOT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pivot_root_return, CPUState* cpu, target_ulong pc, uint32_t new_root, uint32_t put_old);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_POLL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_POLL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_poll_enter, CPUState* cpu, target_ulong pc, uint32_t ufds, uint32_t nfds, int32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_POLL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_POLL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_poll_return, CPUState* cpu, target_ulong pc, uint32_t ufds, uint32_t nfds, int32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ppoll_enter, CPUState* cpu, target_ulong pc, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ppoll_return, CPUState* cpu, target_ulong pc, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PRCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PRCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_prctl_enter, CPUState* cpu, target_ulong pc, int32_t option, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PRCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PRCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_prctl_return, CPUState* cpu, target_ulong pc, int32_t option, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PREAD64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PREAD64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pread64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count, uint64_t pos);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PREAD64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PREAD64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pread64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count, uint64_t pos);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_preadv_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t vec, uint32_t vlen, uint32_t pos_l, uint32_t pos_h);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_preadv_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t vec, uint32_t vlen, uint32_t pos_l, uint32_t pos_h);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PRLIMIT64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PRLIMIT64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_prlimit64_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t resource, uint32_t new_rlim, uint32_t old_rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PRLIMIT64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PRLIMIT64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_prlimit64_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t resource, uint32_t new_rlim, uint32_t old_rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_READV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_READV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_process_vm_readv_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t lvec, uint32_t liovcnt, uint32_t rvec, uint32_t riovcnt, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_READV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_READV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_process_vm_readv_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t lvec, uint32_t liovcnt, uint32_t rvec, uint32_t riovcnt, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_WRITEV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_WRITEV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_process_vm_writev_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t lvec, uint32_t liovcnt, uint32_t rvec, uint32_t riovcnt, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_WRITEV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_WRITEV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_process_vm_writev_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t lvec, uint32_t liovcnt, uint32_t rvec, uint32_t riovcnt, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pselect6_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pselect6_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PTRACE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PTRACE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ptrace_enter, CPUState* cpu, target_ulong pc, int32_t request, int32_t pid, uint32_t addr, uint32_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PTRACE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PTRACE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ptrace_return, CPUState* cpu, target_ulong pc, int32_t request, int32_t pid, uint32_t addr, uint32_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITE64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITE64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pwrite64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count, uint64_t pos);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITE64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITE64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pwrite64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count, uint64_t pos);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pwritev_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t vec, uint32_t vlen, uint32_t pos_l, uint32_t pos_h);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pwritev_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t vec, uint32_t vlen, uint32_t pos_l, uint32_t pos_h);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_QUOTACTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_QUOTACTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_quotactl_enter, CPUState* cpu, target_ulong pc, uint32_t cmd, uint32_t special, uint32_t id, uint32_t addr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_QUOTACTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_QUOTACTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_quotactl_return, CPUState* cpu, target_ulong pc, uint32_t cmd, uint32_t special, uint32_t id, uint32_t addr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READ_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READ_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_read_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READ_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READ_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_read_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READAHEAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READAHEAD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_readahead_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READAHEAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READAHEAD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_readahead_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_readlink_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t buf, int32_t bufsiz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_readlink_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t buf, int32_t bufsiz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_readlinkat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t path, uint32_t buf, int32_t bufsiz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_readlinkat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t path, uint32_t buf, int32_t bufsiz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_readv_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t vec, uint32_t vlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_readv_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t vec, uint32_t vlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REBOOT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REBOOT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_reboot_enter, CPUState* cpu, target_ulong pc, int32_t magic1, int32_t magic2, uint32_t cmd, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REBOOT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REBOOT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_reboot_return, CPUState* cpu, target_ulong pc, int32_t magic1, int32_t magic2, uint32_t cmd, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_recv_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_recv_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVFROM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVFROM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_recvfrom_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVFROM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVFROM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_recvfrom_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_recvmmsg_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t msg, uint32_t vlen, uint32_t flags, uint32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_recvmmsg_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t msg, uint32_t vlen, uint32_t flags, uint32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_recvmsg_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t msg, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_recvmsg_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t msg, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REMAP_FILE_PAGES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REMAP_FILE_PAGES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_remap_file_pages_enter, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t size, uint32_t prot, uint32_t pgoff, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REMAP_FILE_PAGES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REMAP_FILE_PAGES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_remap_file_pages_return, CPUState* cpu, target_ulong pc, uint32_t start, uint32_t size, uint32_t prot, uint32_t pgoff, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REMOVEXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REMOVEXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_removexattr_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REMOVEXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REMOVEXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_removexattr_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rename_enter, CPUState* cpu, target_ulong pc, uint32_t oldname, uint32_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rename_return, CPUState* cpu, target_ulong pc, uint32_t oldname, uint32_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_renameat_enter, CPUState* cpu, target_ulong pc, int32_t olddfd, uint32_t oldname, int32_t newdfd, uint32_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_renameat_return, CPUState* cpu, target_ulong pc, int32_t olddfd, uint32_t oldname, int32_t newdfd, uint32_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_renameat2_enter, CPUState* cpu, target_ulong pc, int32_t olddfd, uint32_t oldname, int32_t newdfd, uint32_t newname, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_renameat2_return, CPUState* cpu, target_ulong pc, int32_t olddfd, uint32_t oldname, int32_t newdfd, uint32_t newname, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REQUEST_KEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REQUEST_KEY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_request_key_enter, CPUState* cpu, target_ulong pc, uint32_t _type, uint32_t _description, uint32_t _callout_info, uint32_t destringid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REQUEST_KEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REQUEST_KEY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_request_key_return, CPUState* cpu, target_ulong pc, uint32_t _type, uint32_t _description, uint32_t _callout_info, uint32_t destringid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RESTART_SYSCALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RESTART_SYSCALL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_restart_syscall_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RESTART_SYSCALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RESTART_SYSCALL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_restart_syscall_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RMDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RMDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rmdir_enter, CPUState* cpu, target_ulong pc, uint32_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RMDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RMDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rmdir_return, CPUState* cpu, target_ulong pc, uint32_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigaction_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigaction_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPENDING_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPENDING_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigpending_enter, CPUState* cpu, target_ulong pc, uint32_t set, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPENDING_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPENDING_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigpending_return, CPUState* cpu, target_ulong pc, uint32_t set, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPROCMASK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPROCMASK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigprocmask_enter, CPUState* cpu, target_ulong pc, int32_t how, uint32_t set, uint32_t oset, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPROCMASK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPROCMASK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigprocmask_return, CPUState* cpu, target_ulong pc, int32_t how, uint32_t set, uint32_t oset, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGQUEUEINFO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGQUEUEINFO_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigqueueinfo_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t sig, uint32_t uinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGQUEUEINFO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGQUEUEINFO_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigqueueinfo_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t sig, uint32_t uinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGRETURN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGRETURN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigreturn_enter, CPUState* cpu, target_ulong pc, uint32_t regs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGRETURN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGRETURN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigreturn_return, CPUState* cpu, target_ulong pc, uint32_t regs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGSUSPEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGSUSPEND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigsuspend_enter, CPUState* cpu, target_ulong pc, uint32_t unewset, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGSUSPEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGSUSPEND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigsuspend_return, CPUState* cpu, target_ulong pc, uint32_t unewset, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigtimedwait_enter, CPUState* cpu, target_ulong pc, uint32_t uthese, uint32_t uinfo, uint32_t uts, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigtimedwait_return, CPUState* cpu, target_ulong pc, uint32_t uthese, uint32_t uinfo, uint32_t uts, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_TGSIGQUEUEINFO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_TGSIGQUEUEINFO_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_tgsigqueueinfo_enter, CPUState* cpu, target_ulong pc, int32_t tgid, int32_t pid, int32_t sig, uint32_t uinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_TGSIGQUEUEINFO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_TGSIGQUEUEINFO_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_tgsigqueueinfo_return, CPUState* cpu, target_ulong pc, int32_t tgid, int32_t pid, int32_t sig, uint32_t uinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GET_PRIORITY_MAX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GET_PRIORITY_MAX_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_get_priority_max_enter, CPUState* cpu, target_ulong pc, int32_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GET_PRIORITY_MAX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GET_PRIORITY_MAX_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_get_priority_max_return, CPUState* cpu, target_ulong pc, int32_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GET_PRIORITY_MIN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GET_PRIORITY_MIN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_get_priority_min_enter, CPUState* cpu, target_ulong pc, int32_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GET_PRIORITY_MIN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GET_PRIORITY_MIN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_get_priority_min_return, CPUState* cpu, target_ulong pc, int32_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETAFFINITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETAFFINITY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_getaffinity_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t len, uint32_t user_mask_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETAFFINITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETAFFINITY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_getaffinity_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t len, uint32_t user_mask_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_getattr_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t attr, uint32_t size, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_getattr_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t attr, uint32_t size, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETPARAM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETPARAM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_getparam_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETPARAM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETPARAM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_getparam_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETSCHEDULER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETSCHEDULER_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_getscheduler_enter, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETSCHEDULER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETSCHEDULER_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_getscheduler_return, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_RR_GET_INTERVAL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_RR_GET_INTERVAL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_rr_get_interval_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t interval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_RR_GET_INTERVAL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_RR_GET_INTERVAL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_rr_get_interval_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t interval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETAFFINITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETAFFINITY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_setaffinity_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t len, uint32_t user_mask_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETAFFINITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETAFFINITY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_setaffinity_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t len, uint32_t user_mask_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_setattr_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t attr, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_setattr_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t attr, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETPARAM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETPARAM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_setparam_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETPARAM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETPARAM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_setparam_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETSCHEDULER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETSCHEDULER_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_setscheduler_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t policy, uint32_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETSCHEDULER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETSCHEDULER_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_setscheduler_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t policy, uint32_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_YIELD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_YIELD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_yield_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_YIELD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_YIELD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_yield_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SECCOMP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SECCOMP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_seccomp_enter, CPUState* cpu, target_ulong pc, uint32_t op, uint32_t flags, uint32_t uargs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SECCOMP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SECCOMP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_seccomp_return, CPUState* cpu, target_ulong pc, uint32_t op, uint32_t flags, uint32_t uargs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SELECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SELECT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_select_enter, CPUState* cpu, target_ulong pc, int32_t n, uint32_t inp, uint32_t outp, uint32_t exp, uint32_t tvp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SELECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SELECT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_select_return, CPUState* cpu, target_ulong pc, int32_t n, uint32_t inp, uint32_t outp, uint32_t exp, uint32_t tvp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_semctl_enter, CPUState* cpu, target_ulong pc, int32_t semid, int32_t semnum, int32_t cmd, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_semctl_return, CPUState* cpu, target_ulong pc, int32_t semid, int32_t semnum, int32_t cmd, uint32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMGET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMGET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_semget_enter, CPUState* cpu, target_ulong pc, uint32_t key, int32_t nsems, int32_t semflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMGET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMGET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_semget_return, CPUState* cpu, target_ulong pc, uint32_t key, int32_t nsems, int32_t semflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMOP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMOP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_semop_enter, CPUState* cpu, target_ulong pc, int32_t semid, uint32_t sops, uint32_t nsops);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMOP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMOP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_semop_return, CPUState* cpu, target_ulong pc, int32_t semid, uint32_t sops, uint32_t nsops);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_semtimedop_enter, CPUState* cpu, target_ulong pc, int32_t semid, uint32_t sops, uint32_t nsops, uint32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_semtimedop_return, CPUState* cpu, target_ulong pc, int32_t semid, uint32_t sops, uint32_t nsops, uint32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_send_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_send_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sendfile_enter, CPUState* cpu, target_ulong pc, int32_t out_fd, int32_t in_fd, uint32_t offset, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sendfile_return, CPUState* cpu, target_ulong pc, int32_t out_fd, int32_t in_fd, uint32_t offset, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sendfile64_enter, CPUState* cpu, target_ulong pc, int32_t out_fd, int32_t in_fd, uint32_t offset, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sendfile64_return, CPUState* cpu, target_ulong pc, int32_t out_fd, int32_t in_fd, uint32_t offset, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sendmmsg_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t msg, uint32_t vlen, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sendmmsg_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t msg, uint32_t vlen, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sendmsg_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t msg, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sendmsg_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t msg, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDTO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDTO_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sendto_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, int32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDTO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDTO_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sendto_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, int32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_MEMPOLICY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_MEMPOLICY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_set_mempolicy_enter, CPUState* cpu, target_ulong pc, int32_t mode, uint32_t nmask, uint32_t maxnode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_MEMPOLICY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_MEMPOLICY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_set_mempolicy_return, CPUState* cpu, target_ulong pc, int32_t mode, uint32_t nmask, uint32_t maxnode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_ROBUST_LIST_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_ROBUST_LIST_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_set_robust_list_enter, CPUState* cpu, target_ulong pc, uint32_t head, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_ROBUST_LIST_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_ROBUST_LIST_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_set_robust_list_return, CPUState* cpu, target_ulong pc, uint32_t head, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_TID_ADDRESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_TID_ADDRESS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_set_tid_address_enter, CPUState* cpu, target_ulong pc, uint32_t tidptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_TID_ADDRESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_TID_ADDRESS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_set_tid_address_return, CPUState* cpu, target_ulong pc, uint32_t tidptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETDOMAINNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETDOMAINNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setdomainname_enter, CPUState* cpu, target_ulong pc, uint32_t name, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETDOMAINNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETDOMAINNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setdomainname_return, CPUState* cpu, target_ulong pc, uint32_t name, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setfsgid_enter, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setfsgid_return, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setfsgid16_enter, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setfsgid16_return, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setfsuid_enter, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setfsuid_return, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setfsuid16_enter, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setfsuid16_return, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setgid_enter, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setgid_return, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setgid16_enter, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setgid16_return, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setgroups_enter, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint32_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setgroups_return, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint32_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setgroups16_enter, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint32_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setgroups16_return, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint32_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETHOSTNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETHOSTNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sethostname_enter, CPUState* cpu, target_ulong pc, uint32_t name, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETHOSTNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETHOSTNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sethostname_return, CPUState* cpu, target_ulong pc, uint32_t name, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETITIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETITIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setitimer_enter, CPUState* cpu, target_ulong pc, int32_t which, uint32_t value, uint32_t ovalue);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETITIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETITIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setitimer_return, CPUState* cpu, target_ulong pc, int32_t which, uint32_t value, uint32_t ovalue);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETNS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETNS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setns_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t nstype);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETNS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETNS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setns_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t nstype);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETPGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETPGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setpgid_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t pgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETPGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETPGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setpgid_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t pgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETPRIORITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETPRIORITY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setpriority_enter, CPUState* cpu, target_ulong pc, int32_t which, int32_t who, int32_t niceval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETPRIORITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETPRIORITY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setpriority_return, CPUState* cpu, target_ulong pc, int32_t which, int32_t who, int32_t niceval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setregid_enter, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setregid_return, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREGID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREGID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setregid16_enter, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREGID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREGID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setregid16_return, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setresgid_enter, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setresgid_return, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setresgid16_enter, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setresgid16_return, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setresuid_enter, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setresuid_return, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setresuid16_enter, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setresuid16_return, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setreuid_enter, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setreuid_return, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setreuid16_enter, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setreuid16_return, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRLIMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRLIMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setrlimit_enter, CPUState* cpu, target_ulong pc, uint32_t resource, uint32_t rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRLIMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRLIMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setrlimit_return, CPUState* cpu, target_ulong pc, uint32_t resource, uint32_t rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETSID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETSID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setsid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETSID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETSID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setsid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETSOCKOPT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETSOCKOPT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setsockopt_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t level, int32_t optname, uint32_t optval, int32_t optlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETSOCKOPT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETSOCKOPT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setsockopt_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t level, int32_t optname, uint32_t optval, int32_t optlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETTIMEOFDAY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETTIMEOFDAY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_settimeofday_enter, CPUState* cpu, target_ulong pc, uint32_t tv, uint32_t tz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETTIMEOFDAY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETTIMEOFDAY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_settimeofday_return, CPUState* cpu, target_ulong pc, uint32_t tv, uint32_t tz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setuid_enter, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setuid_return, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID16_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID16_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setuid16_enter, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID16_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID16_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setuid16_return, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setxattr_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name, uint32_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setxattr_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t name, uint32_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_shmat_enter, CPUState* cpu, target_ulong pc, int32_t shmid, uint32_t shmaddr, int32_t shmflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_shmat_return, CPUState* cpu, target_ulong pc, int32_t shmid, uint32_t shmaddr, int32_t shmflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_shmctl_enter, CPUState* cpu, target_ulong pc, int32_t shmid, int32_t cmd, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_shmctl_return, CPUState* cpu, target_ulong pc, int32_t shmid, int32_t cmd, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMDT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMDT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_shmdt_enter, CPUState* cpu, target_ulong pc, uint32_t shmaddr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMDT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMDT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_shmdt_return, CPUState* cpu, target_ulong pc, uint32_t shmaddr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMGET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMGET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_shmget_enter, CPUState* cpu, target_ulong pc, uint32_t key, uint32_t size, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMGET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMGET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_shmget_return, CPUState* cpu, target_ulong pc, uint32_t key, uint32_t size, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHUTDOWN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHUTDOWN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_shutdown_enter, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHUTDOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHUTDOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_shutdown_return, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigaction_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigaction_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigaltstack_enter, CPUState* cpu, target_ulong pc, uint32_t uss, uint32_t uoss);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigaltstack_return, CPUState* cpu, target_ulong pc, uint32_t uss, uint32_t uoss);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_signalfd_enter, CPUState* cpu, target_ulong pc, int32_t ufd, uint32_t user_mask, uint32_t sizemask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_signalfd_return, CPUState* cpu, target_ulong pc, int32_t ufd, uint32_t user_mask, uint32_t sizemask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD4_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD4_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_signalfd4_enter, CPUState* cpu, target_ulong pc, int32_t ufd, uint32_t user_mask, uint32_t sizemask, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD4_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD4_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_signalfd4_return, CPUState* cpu, target_ulong pc, int32_t ufd, uint32_t user_mask, uint32_t sizemask, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPENDING_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPENDING_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigpending_enter, CPUState* cpu, target_ulong pc, uint32_t set);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPENDING_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPENDING_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigpending_return, CPUState* cpu, target_ulong pc, uint32_t set);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPROCMASK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPROCMASK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigprocmask_enter, CPUState* cpu, target_ulong pc, int32_t how, uint32_t set, uint32_t oset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPROCMASK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPROCMASK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigprocmask_return, CPUState* cpu, target_ulong pc, int32_t how, uint32_t set, uint32_t oset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGRETURN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGRETURN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigreturn_enter, CPUState* cpu, target_ulong pc, uint32_t regs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGRETURN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGRETURN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigreturn_return, CPUState* cpu, target_ulong pc, uint32_t regs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGSUSPEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGSUSPEND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigsuspend_enter, CPUState* cpu, target_ulong pc, int32_t unused1, int32_t unused2, uint32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGSUSPEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGSUSPEND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigsuspend_return, CPUState* cpu, target_ulong pc, int32_t unused1, int32_t unused2, uint32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_socket_enter, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_socket_return, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETCALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETCALL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_socketcall_enter, CPUState* cpu, target_ulong pc, int32_t call, uint32_t args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETCALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETCALL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_socketcall_return, CPUState* cpu, target_ulong pc, int32_t call, uint32_t args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_socketpair_enter, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1, int32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_socketpair_return, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1, int32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SPLICE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SPLICE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_splice_enter, CPUState* cpu, target_ulong pc, int32_t fd_in, uint32_t off_in, int32_t fd_out, uint32_t off_out, uint32_t len, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SPLICE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SPLICE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_splice_return, CPUState* cpu, target_ulong pc, int32_t fd_in, uint32_t off_in, int32_t fd_out, uint32_t off_out, uint32_t len, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_stat64_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_stat64_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_statfs_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_statfs_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_statfs64_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t sz, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_statfs64_return, CPUState* cpu, target_ulong pc, uint32_t path, uint32_t sz, uint32_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_statx_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t path, uint32_t flags, uint32_t mask, uint32_t buffer);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_statx_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t path, uint32_t flags, uint32_t mask, uint32_t buffer);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_stime_enter, CPUState* cpu, target_ulong pc, uint32_t tptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_stime_return, CPUState* cpu, target_ulong pc, uint32_t tptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPOFF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPOFF_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_swapoff_enter, CPUState* cpu, target_ulong pc, uint32_t specialfile);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPOFF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPOFF_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_swapoff_return, CPUState* cpu, target_ulong pc, uint32_t specialfile);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPON_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPON_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_swapon_enter, CPUState* cpu, target_ulong pc, uint32_t specialfile, int32_t swap_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPON_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPON_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_swapon_return, CPUState* cpu, target_ulong pc, uint32_t specialfile, int32_t swap_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_symlink_enter, CPUState* cpu, target_ulong pc, uint32_t old, uint32_t _new);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_symlink_return, CPUState* cpu, target_ulong pc, uint32_t old, uint32_t _new);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_symlinkat_enter, CPUState* cpu, target_ulong pc, uint32_t oldname, int32_t newdfd, uint32_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_symlinkat_return, CPUState* cpu, target_ulong pc, uint32_t oldname, int32_t newdfd, uint32_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sync_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sync_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_FILE_RANGE2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_FILE_RANGE2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sync_file_range2_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t flags, uint64_t offset, uint64_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_FILE_RANGE2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_FILE_RANGE2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sync_file_range2_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t flags, uint64_t offset, uint64_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNCFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNCFS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_syncfs_enter, CPUState* cpu, target_ulong pc, int32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNCFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNCFS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_syncfs_return, CPUState* cpu, target_ulong pc, int32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sysctl_enter, CPUState* cpu, target_ulong pc, uint32_t args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sysctl_return, CPUState* cpu, target_ulong pc, uint32_t args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSFS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sysfs_enter, CPUState* cpu, target_ulong pc, int32_t option, uint32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSFS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sysfs_return, CPUState* cpu, target_ulong pc, int32_t option, uint32_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSINFO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSINFO_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sysinfo_enter, CPUState* cpu, target_ulong pc, uint32_t info);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSINFO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSINFO_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sysinfo_return, CPUState* cpu, target_ulong pc, uint32_t info);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSLOG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSLOG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_syslog_enter, CPUState* cpu, target_ulong pc, int32_t type, uint32_t buf, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSLOG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSLOG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_syslog_return, CPUState* cpu, target_ulong pc, int32_t type, uint32_t buf, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TEE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TEE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_tee_enter, CPUState* cpu, target_ulong pc, int32_t fdin, int32_t fdout, uint32_t len, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TEE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TEE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_tee_return, CPUState* cpu, target_ulong pc, int32_t fdin, int32_t fdout, uint32_t len, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TGKILL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TGKILL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_tgkill_enter, CPUState* cpu, target_ulong pc, int32_t tgid, int32_t pid, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TGKILL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TGKILL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_tgkill_return, CPUState* cpu, target_ulong pc, int32_t tgid, int32_t pid, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_time_enter, CPUState* cpu, target_ulong pc, uint32_t tloc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_time_return, CPUState* cpu, target_ulong pc, uint32_t tloc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_CREATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_CREATE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timer_create_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint32_t timer_event_spec, uint32_t created_timer_id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_CREATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_CREATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_create_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint32_t timer_event_spec, uint32_t created_timer_id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_DELETE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_DELETE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timer_delete_enter, CPUState* cpu, target_ulong pc, uint32_t timer_id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_DELETE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_DELETE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_delete_return, CPUState* cpu, target_ulong pc, uint32_t timer_id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETOVERRUN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETOVERRUN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timer_getoverrun_enter, CPUState* cpu, target_ulong pc, uint32_t timer_id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETOVERRUN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETOVERRUN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_getoverrun_return, CPUState* cpu, target_ulong pc, uint32_t timer_id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timer_gettime_enter, CPUState* cpu, target_ulong pc, uint32_t timer_id, uint32_t setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_gettime_return, CPUState* cpu, target_ulong pc, uint32_t timer_id, uint32_t setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timer_settime_enter, CPUState* cpu, target_ulong pc, uint32_t timer_id, int32_t flags, uint32_t new_setting, uint32_t old_setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_settime_return, CPUState* cpu, target_ulong pc, uint32_t timer_id, int32_t flags, uint32_t new_setting, uint32_t old_setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_CREATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_CREATE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_create_enter, CPUState* cpu, target_ulong pc, int32_t clockid, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_CREATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_CREATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_create_return, CPUState* cpu, target_ulong pc, int32_t clockid, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_GETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_GETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_gettime_enter, CPUState* cpu, target_ulong pc, int32_t ufd, uint32_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_GETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_GETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_gettime_return, CPUState* cpu, target_ulong pc, int32_t ufd, uint32_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_settime_enter, CPUState* cpu, target_ulong pc, int32_t ufd, int32_t flags, uint32_t utmr, uint32_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_settime_return, CPUState* cpu, target_ulong pc, int32_t ufd, int32_t flags, uint32_t utmr, uint32_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_times_enter, CPUState* cpu, target_ulong pc, uint32_t tbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_times_return, CPUState* cpu, target_ulong pc, uint32_t tbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TKILL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TKILL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_tkill_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TKILL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TKILL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_tkill_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_truncate_enter, CPUState* cpu, target_ulong pc, uint32_t path, int32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_truncate_return, CPUState* cpu, target_ulong pc, uint32_t path, int32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_truncate64_enter, CPUState* cpu, target_ulong pc, uint32_t path, uint64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_truncate64_return, CPUState* cpu, target_ulong pc, uint32_t path, uint64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UMASK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UMASK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_umask_enter, CPUState* cpu, target_ulong pc, int32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UMASK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UMASK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_umask_return, CPUState* cpu, target_ulong pc, int32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UMOUNT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UMOUNT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_umount_enter, CPUState* cpu, target_ulong pc, uint32_t name, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UMOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UMOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_umount_return, CPUState* cpu, target_ulong pc, uint32_t name, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_unlink_enter, CPUState* cpu, target_ulong pc, uint32_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_unlink_return, CPUState* cpu, target_ulong pc, uint32_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_unlinkat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t pathname, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_unlinkat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t pathname, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNSHARE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNSHARE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_unshare_enter, CPUState* cpu, target_ulong pc, uint32_t unshare_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNSHARE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNSHARE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_unshare_return, CPUState* cpu, target_ulong pc, uint32_t unshare_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_USELIB_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_USELIB_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_uselib_enter, CPUState* cpu, target_ulong pc, uint32_t library);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_USELIB_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_USELIB_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_uselib_return, CPUState* cpu, target_ulong pc, uint32_t library);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_USERFAULTFD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_USERFAULTFD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_userfaultfd_enter, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_USERFAULTFD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_USERFAULTFD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_userfaultfd_return, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_USTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_USTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ustat_enter, CPUState* cpu, target_ulong pc, uint32_t dev, uint32_t ubuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_USTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_USTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ustat_return, CPUState* cpu, target_ulong pc, uint32_t dev, uint32_t ubuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utime_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t times);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utime_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t times);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utimensat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t utimes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utimensat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint32_t filename, uint32_t utimes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utimes_enter, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t utimes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utimes_return, CPUState* cpu, target_ulong pc, uint32_t filename, uint32_t utimes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_VFORK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_VFORK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_vfork_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_VFORK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_VFORK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_vfork_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_VHANGUP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_VHANGUP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_vhangup_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_VHANGUP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_VHANGUP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_vhangup_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_VMSPLICE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_VMSPLICE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_vmsplice_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t iov, uint32_t nr_segs, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_VMSPLICE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_VMSPLICE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_vmsplice_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t iov, uint32_t nr_segs, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WAIT4_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WAIT4_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_wait4_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t stat_addr, int32_t options, uint32_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WAIT4_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WAIT4_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_wait4_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t stat_addr, int32_t options, uint32_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_waitid_enter, CPUState* cpu, target_ulong pc, int32_t which, int32_t pid, uint32_t infop, int32_t options, uint32_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_waitid_return, CPUState* cpu, target_ulong pc, int32_t which, int32_t pid, uint32_t infop, int32_t options, uint32_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_write_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_write_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITEV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITEV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_writev_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t vec, uint32_t vlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITEV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITEV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_writev_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t vec, uint32_t vlen);
#endif

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
