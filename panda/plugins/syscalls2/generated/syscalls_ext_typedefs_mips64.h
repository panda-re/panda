// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CREATE_MODULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CREATE_MODULE_ENTER 1
PPP_CB_TYPEDEF(void, on_create_module_enter, CPUState* cpu, target_ulong pc, uint64_t name, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CREATE_MODULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CREATE_MODULE_RETURN 1
PPP_CB_TYPEDEF(void, on_create_module_return, CPUState* cpu, target_ulong pc, uint64_t name, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GET_KERNEL_SYMS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GET_KERNEL_SYMS_ENTER 1
PPP_CB_TYPEDEF(void, on_get_kernel_syms_enter, CPUState* cpu, target_ulong pc, uint64_t table);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GET_KERNEL_SYMS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GET_KERNEL_SYMS_RETURN 1
PPP_CB_TYPEDEF(void, on_get_kernel_syms_return, CPUState* cpu, target_ulong pc, uint64_t table);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MMAP2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MMAP2_ENTER 1
PPP_CB_TYPEDEF(void, on_mmap2_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t length, int32_t prot, int32_t flags, int32_t fd, uint64_t pgoffset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MMAP2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MMAP2_RETURN 1
PPP_CB_TYPEDEF(void, on_mmap2_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t length, int32_t prot, int32_t flags, int32_t fd, uint64_t pgoffset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MODIFY_LDT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MODIFY_LDT_ENTER 1
PPP_CB_TYPEDEF(void, on_modify_ldt_enter, CPUState* cpu, target_ulong pc, int32_t func, uint64_t ptr, uint64_t bytecount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MODIFY_LDT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MODIFY_LDT_RETURN 1
PPP_CB_TYPEDEF(void, on_modify_ldt_return, CPUState* cpu, target_ulong pc, int32_t func, uint64_t ptr, uint64_t bytecount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SET_THREAD_AREA_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SET_THREAD_AREA_ENTER 1
PPP_CB_TYPEDEF(void, on_set_thread_area_enter, CPUState* cpu, target_ulong pc, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SET_THREAD_AREA_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SET_THREAD_AREA_RETURN 1
PPP_CB_TYPEDEF(void, on_set_thread_area_return, CPUState* cpu, target_ulong pc, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_accept_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_accept_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT4_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT4_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_accept4_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2, int32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT4_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCEPT4_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_accept4_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2, int32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_access_enter, CPUState* cpu, target_ulong pc, uint64_t filename, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_access_return, CPUState* cpu, target_ulong pc, uint64_t filename, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_acct_enter, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ACCT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_acct_return, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ADD_KEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ADD_KEY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_add_key_enter, CPUState* cpu, target_ulong pc, uint64_t _type, uint64_t _description, uint64_t _payload, uint32_t plen, uint32_t destringid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ADD_KEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ADD_KEY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_add_key_return, CPUState* cpu, target_ulong pc, uint64_t _type, uint64_t _description, uint64_t _payload, uint32_t plen, uint32_t destringid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_adjtimex_enter, CPUState* cpu, target_ulong pc, uint64_t txc_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_adjtimex_return, CPUState* cpu, target_ulong pc, uint64_t txc_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_adjtimex_time32_enter, CPUState* cpu, target_ulong pc, uint64_t txc_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ADJTIMEX_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_adjtimex_time32_return, CPUState* cpu, target_ulong pc, uint64_t txc_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_alarm_enter, CPUState* cpu, target_ulong pc, uint32_t seconds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_alarm_return, CPUState* cpu, target_ulong pc, uint32_t seconds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BDFLUSH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BDFLUSH_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_bdflush_enter, CPUState* cpu, target_ulong pc, int32_t func, int64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BDFLUSH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BDFLUSH_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_bdflush_return, CPUState* cpu, target_ulong pc, int32_t func, int64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BIND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BIND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_bind_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BIND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BIND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_bind_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BPF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BPF_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_bpf_enter, CPUState* cpu, target_ulong pc, int32_t cmd, uint64_t attr, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BPF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BPF_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_bpf_return, CPUState* cpu, target_ulong pc, int32_t cmd, uint64_t attr, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BRK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BRK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_brk_enter, CPUState* cpu, target_ulong pc, uint64_t brk);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_BRK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_BRK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_brk_return, CPUState* cpu, target_ulong pc, uint64_t brk);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CACHEFLUSH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CACHEFLUSH_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_cacheflush_enter, CPUState* cpu, target_ulong pc, uint64_t addr, int32_t nbytes, int32_t cache);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CACHEFLUSH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CACHEFLUSH_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_cacheflush_return, CPUState* cpu, target_ulong pc, uint64_t addr, int32_t nbytes, int32_t cache);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPGET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPGET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_capget_enter, CPUState* cpu, target_ulong pc, uint64_t header, uint64_t dataptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPGET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPGET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_capget_return, CPUState* cpu, target_ulong pc, uint64_t header, uint64_t dataptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPSET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPSET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_capset_enter, CPUState* cpu, target_ulong pc, uint64_t header, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPSET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CAPSET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_capset_return, CPUState* cpu, target_ulong pc, uint64_t header, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_chdir_enter, CPUState* cpu, target_ulong pc, uint64_t filename);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_chdir_return, CPUState* cpu, target_ulong pc, uint64_t filename);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHMOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHMOD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_chmod_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHMOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHMOD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_chmod_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_chown_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_chown_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHROOT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHROOT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_chroot_enter, CPUState* cpu, target_ulong pc, uint64_t filename);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CHROOT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CHROOT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_chroot_return, CPUState* cpu, target_ulong pc, uint64_t filename);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_adjtime_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_adjtime_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_adjtime32_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_ADJTIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_adjtime32_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_getres_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_getres_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_getres_time32_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_getres_time32_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_gettime_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_gettime_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_gettime32_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_gettime32_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_nanosleep_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, int32_t flags, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_nanosleep_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, int32_t flags, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_nanosleep_time32_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, int32_t flags, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_nanosleep_time32_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, int32_t flags, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_settime_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_settime_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_settime32_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_settime32_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clone_enter, CPUState* cpu, target_ulong pc, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clone_return, CPUState* cpu, target_ulong pc, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE3_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE3_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clone3_enter, CPUState* cpu, target_ulong pc, uint64_t uargs, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE3_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE3_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clone3_return, CPUState* cpu, target_ulong pc, uint64_t uargs, uint32_t size);
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
PPP_CB_TYPEDEF(void, on_sys_connect_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CONNECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CONNECT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_connect_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_COPY_FILE_RANGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_COPY_FILE_RANGE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_copy_file_range_enter, CPUState* cpu, target_ulong pc, int32_t fd_in, uint64_t off_in, int32_t fd_out, uint64_t off_out, uint32_t len, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_COPY_FILE_RANGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_COPY_FILE_RANGE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_copy_file_range_return, CPUState* cpu, target_ulong pc, int32_t fd_in, uint64_t off_in, int32_t fd_out, uint64_t off_out, uint32_t len, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CREAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CREAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_creat_enter, CPUState* cpu, target_ulong pc, uint64_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CREAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CREAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_creat_return, CPUState* cpu, target_ulong pc, uint64_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_DELETE_MODULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_DELETE_MODULE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_delete_module_enter, CPUState* cpu, target_ulong pc, uint64_t name_user, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_DELETE_MODULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_DELETE_MODULE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_delete_module_return, CPUState* cpu, target_ulong pc, uint64_t name_user, uint32_t flags);
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
PPP_CB_TYPEDEF(void, on_sys_epoll_ctl_enter, CPUState* cpu, target_ulong pc, int32_t epfd, int32_t op, int32_t fd, uint64_t event);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_CTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_epoll_ctl_return, CPUState* cpu, target_ulong pc, int32_t epfd, int32_t op, int32_t fd, uint64_t event);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_PWAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_PWAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_epoll_pwait_enter, CPUState* cpu, target_ulong pc, int32_t epfd, uint64_t events, int32_t maxevents, int32_t timeout, uint64_t sigmask, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_PWAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_PWAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_epoll_pwait_return, CPUState* cpu, target_ulong pc, int32_t epfd, uint64_t events, int32_t maxevents, int32_t timeout, uint64_t sigmask, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_WAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_WAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_epoll_wait_enter, CPUState* cpu, target_ulong pc, int32_t epfd, uint64_t events, int32_t maxevents, int32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_WAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EPOLL_WAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_epoll_wait_return, CPUState* cpu, target_ulong pc, int32_t epfd, uint64_t events, int32_t maxevents, int32_t timeout);
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
PPP_CB_TYPEDEF(void, on_sys_execve_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t argv, uint64_t envp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_execve_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t argv, uint64_t envp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVEAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVEAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_execveat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t argv, uint64_t envp, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVEAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_EXECVEAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_execveat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t argv, uint64_t envp, int32_t flags);
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
PPP_CB_TYPEDEF(void, on_sys_faccessat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FACCESSAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FACCESSAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_faccessat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FACCESSAT2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FACCESSAT2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_faccessat2_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, int32_t mode, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FACCESSAT2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FACCESSAT2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_faccessat2_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, int32_t mode, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FADVISE64_64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FADVISE64_64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fadvise64_64_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint64_t len, int32_t advice);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FADVISE64_64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FADVISE64_64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fadvise64_64_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint64_t len, int32_t advice);
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
PPP_CB_TYPEDEF(void, on_sys_fanotify_mark_enter, CPUState* cpu, target_ulong pc, int32_t fanotify_fd, uint32_t flags, uint64_t mask, int32_t fd, uint64_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FANOTIFY_MARK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FANOTIFY_MARK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fanotify_mark_return, CPUState* cpu, target_ulong pc, int32_t fanotify_fd, uint32_t flags, uint64_t mask, int32_t fd, uint64_t pathname);
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
PPP_CB_TYPEDEF(void, on_sys_fchmodat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHMODAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHMODAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fchmodat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fchown_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fchown_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWNAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWNAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fchownat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint32_t user, uint32_t group, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWNAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCHOWNAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fchownat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint32_t user, uint32_t group, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fcntl_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fcntl_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fcntl64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FCNTL64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fcntl64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg);
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
PPP_CB_TYPEDEF(void, on_sys_fgetxattr_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t name, uint64_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FGETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FGETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fgetxattr_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t name, uint64_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FINIT_MODULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FINIT_MODULE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_finit_module_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t uargs, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FINIT_MODULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FINIT_MODULE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_finit_module_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t uargs, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FLISTXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FLISTXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_flistxattr_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FLISTXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FLISTXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_flistxattr_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t list, uint32_t size);
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
PPP_CB_TYPEDEF(void, on_sys_fremovexattr_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FREMOVEXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FREMOVEXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fremovexattr_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSCONFIG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSCONFIG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fsconfig_enter, CPUState* cpu, target_ulong pc, int32_t fs_fd, uint32_t cmd, uint64_t key, uint64_t value, int32_t aux);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSCONFIG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSCONFIG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fsconfig_return, CPUState* cpu, target_ulong pc, int32_t fs_fd, uint32_t cmd, uint64_t key, uint64_t value, int32_t aux);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fsetxattr_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t name, uint64_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fsetxattr_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t name, uint64_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSMOUNT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSMOUNT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fsmount_enter, CPUState* cpu, target_ulong pc, int32_t fs_fd, uint32_t flags, uint32_t ms_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSMOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSMOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fsmount_return, CPUState* cpu, target_ulong pc, int32_t fs_fd, uint32_t flags, uint32_t ms_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSOPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSOPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fsopen_enter, CPUState* cpu, target_ulong pc, uint64_t fs_name, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSOPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSOPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fsopen_return, CPUState* cpu, target_ulong pc, uint64_t fs_name, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSPICK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSPICK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fspick_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSPICK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSPICK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fspick_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fstat_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fstat_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fstat64_enter, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTAT64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fstat64_return, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATAT64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATAT64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fstatat64_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t statbuf, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATAT64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATAT64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fstatat64_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t statbuf, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fstatfs_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fstatfs_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fstatfs64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t sz, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fstatfs64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t sz, uint64_t buf);
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
PPP_CB_TYPEDEF(void, on_sys_ftruncate_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FTRUNCATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FTRUNCATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ftruncate_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t length);
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
PPP_CB_TYPEDEF(void, on_sys_futex_enter, CPUState* cpu, target_ulong pc, uint64_t uaddr, int32_t op, uint32_t val, uint64_t utime, uint64_t uaddr2, uint32_t val3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_futex_return, CPUState* cpu, target_ulong pc, uint64_t uaddr, int32_t op, uint32_t val, uint64_t utime, uint64_t uaddr2, uint32_t val3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_futex_time32_enter, CPUState* cpu, target_ulong pc, uint64_t uaddr, int32_t op, uint32_t val, uint64_t utime, uint64_t uaddr2, uint32_t val3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_futex_time32_return, CPUState* cpu, target_ulong pc, uint64_t uaddr, int32_t op, uint32_t val, uint64_t utime, uint64_t uaddr2, uint32_t val3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_futimesat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t utimes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_futimesat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t utimes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_futimesat_time32_enter, CPUState* cpu, target_ulong pc, uint32_t dfd, uint64_t filename, uint64_t t);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_futimesat_time32_return, CPUState* cpu, target_ulong pc, uint32_t dfd, uint64_t filename, uint64_t t);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_MEMPOLICY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_MEMPOLICY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_get_mempolicy_enter, CPUState* cpu, target_ulong pc, uint64_t policy, uint64_t nmask, uint64_t maxnode, uint64_t addr, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_MEMPOLICY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_MEMPOLICY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_get_mempolicy_return, CPUState* cpu, target_ulong pc, uint64_t policy, uint64_t nmask, uint64_t maxnode, uint64_t addr, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_ROBUST_LIST_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_ROBUST_LIST_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_get_robust_list_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t head_ptr, uint64_t len_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_ROBUST_LIST_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GET_ROBUST_LIST_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_get_robust_list_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t head_ptr, uint64_t len_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCPU_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCPU_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getcpu_enter, CPUState* cpu, target_ulong pc, uint64_t _cpu, uint64_t node, uint64_t cache);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCPU_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCPU_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getcpu_return, CPUState* cpu, target_ulong pc, uint64_t _cpu, uint64_t node, uint64_t cache);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCWD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCWD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getcwd_enter, CPUState* cpu, target_ulong pc, uint64_t buf, uint64_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCWD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETCWD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getcwd_return, CPUState* cpu, target_ulong pc, uint64_t buf, uint64_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getdents_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t dirent, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getdents_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t dirent, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getdents64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t dirent, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETDENTS64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getdents64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t dirent, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getegid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getegid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_geteuid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETEUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_geteuid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getgid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getgid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getgroups_enter, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint64_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETGROUPS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getgroups_return, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint64_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETITIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETITIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getitimer_enter, CPUState* cpu, target_ulong pc, int32_t which, uint64_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETITIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETITIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getitimer_return, CPUState* cpu, target_ulong pc, int32_t which, uint64_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPEERNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPEERNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getpeername_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPEERNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETPEERNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getpeername_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2);
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
PPP_CB_TYPEDEF(void, on_sys_getrandom_enter, CPUState* cpu, target_ulong pc, uint64_t buf, uint32_t count, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRANDOM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRANDOM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getrandom_return, CPUState* cpu, target_ulong pc, uint64_t buf, uint32_t count, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getresgid_enter, CPUState* cpu, target_ulong pc, uint64_t rgid, uint64_t egid, uint64_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getresgid_return, CPUState* cpu, target_ulong pc, uint64_t rgid, uint64_t egid, uint64_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getresuid_enter, CPUState* cpu, target_ulong pc, uint64_t ruid, uint64_t euid, uint64_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRESUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getresuid_return, CPUState* cpu, target_ulong pc, uint64_t ruid, uint64_t euid, uint64_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRLIMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRLIMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getrlimit_enter, CPUState* cpu, target_ulong pc, uint32_t resource, uint64_t rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRLIMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRLIMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getrlimit_return, CPUState* cpu, target_ulong pc, uint32_t resource, uint64_t rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRUSAGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRUSAGE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getrusage_enter, CPUState* cpu, target_ulong pc, int32_t who, uint64_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRUSAGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETRUSAGE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getrusage_return, CPUState* cpu, target_ulong pc, int32_t who, uint64_t ru);
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
PPP_CB_TYPEDEF(void, on_sys_getsockname_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getsockname_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKOPT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKOPT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getsockopt_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t level, int32_t optname, uint64_t optval, uint64_t optlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKOPT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETSOCKOPT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getsockopt_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t level, int32_t optname, uint64_t optval, uint64_t optlen);
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
PPP_CB_TYPEDEF(void, on_sys_gettimeofday_enter, CPUState* cpu, target_ulong pc, uint64_t tv, uint64_t tz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETTIMEOFDAY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETTIMEOFDAY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_gettimeofday_return, CPUState* cpu, target_ulong pc, uint64_t tv, uint64_t tz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getuid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getuid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_getxattr_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name, uint64_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_GETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_GETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_getxattr_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name, uint64_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IDLE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IDLE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_idle_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IDLE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IDLE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_idle_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INIT_MODULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INIT_MODULE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_init_module_enter, CPUState* cpu, target_ulong pc, uint64_t umod, uint64_t len, uint64_t uargs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INIT_MODULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INIT_MODULE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_init_module_return, CPUState* cpu, target_ulong pc, uint64_t umod, uint64_t len, uint64_t uargs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_ADD_WATCH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_ADD_WATCH_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_inotify_add_watch_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_ADD_WATCH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_INOTIFY_ADD_WATCH_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_inotify_add_watch_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t mask);
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
PPP_CB_TYPEDEF(void, on_sys_io_cancel_enter, CPUState* cpu, target_ulong pc, uint64_t ctx_id, uint64_t iocb, uint64_t result);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_CANCEL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_CANCEL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_cancel_return, CPUState* cpu, target_ulong pc, uint64_t ctx_id, uint64_t iocb, uint64_t result);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_DESTROY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_DESTROY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_destroy_enter, CPUState* cpu, target_ulong pc, uint64_t ctx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_DESTROY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_DESTROY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_destroy_return, CPUState* cpu, target_ulong pc, uint64_t ctx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_getevents_enter, CPUState* cpu, target_ulong pc, uint64_t ctx_id, int64_t min_nr, int64_t nr, uint64_t events, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_getevents_return, CPUState* cpu, target_ulong pc, uint64_t ctx_id, int64_t min_nr, int64_t nr, uint64_t events, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_getevents_time32_enter, CPUState* cpu, target_ulong pc, uint32_t ctx_id, int32_t min_nr, int32_t nr, uint64_t events, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_GETEVENTS_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_getevents_time32_return, CPUState* cpu, target_ulong pc, uint32_t ctx_id, int32_t min_nr, int32_t nr, uint64_t events, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_PGETEVENTS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_PGETEVENTS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_pgetevents_enter, CPUState* cpu, target_ulong pc, uint64_t ctx_id, int64_t min_nr, int64_t nr, uint64_t events, uint64_t timeout, uint64_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_PGETEVENTS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_PGETEVENTS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_pgetevents_return, CPUState* cpu, target_ulong pc, uint64_t ctx_id, int64_t min_nr, int64_t nr, uint64_t events, uint64_t timeout, uint64_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_PGETEVENTS_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_PGETEVENTS_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_pgetevents_time32_enter, CPUState* cpu, target_ulong pc, uint64_t ctx_id, int64_t min_nr, int64_t nr, uint64_t events, uint64_t timeout, uint64_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_PGETEVENTS_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_PGETEVENTS_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_pgetevents_time32_return, CPUState* cpu, target_ulong pc, uint64_t ctx_id, int64_t min_nr, int64_t nr, uint64_t events, uint64_t timeout, uint64_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SETUP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SETUP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_setup_enter, CPUState* cpu, target_ulong pc, uint32_t nr_reqs, uint64_t ctx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SETUP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SETUP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_setup_return, CPUState* cpu, target_ulong pc, uint32_t nr_reqs, uint64_t ctx);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SUBMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SUBMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_submit_enter, CPUState* cpu, target_ulong pc, uint64_t arg0, int64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SUBMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_SUBMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_submit_return, CPUState* cpu, target_ulong pc, uint64_t arg0, int64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_ENTER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_ENTER_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_uring_enter_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t to_submit, uint32_t min_complete, uint32_t flags, uint64_t sig, uint32_t sigsz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_ENTER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_ENTER_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_uring_enter_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t to_submit, uint32_t min_complete, uint32_t flags, uint64_t sig, uint32_t sigsz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_REGISTER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_REGISTER_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_uring_register_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t op, uint64_t arg, uint32_t nr_args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_REGISTER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_REGISTER_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_uring_register_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t op, uint64_t arg, uint32_t nr_args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_SETUP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_SETUP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_io_uring_setup_enter, CPUState* cpu, target_ulong pc, uint32_t entries, uint64_t p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_SETUP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IO_URING_SETUP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_io_uring_setup_return, CPUState* cpu, target_ulong pc, uint32_t entries, uint64_t p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ioctl_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ioctl_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPERM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPERM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ioperm_enter, CPUState* cpu, target_ulong pc, uint64_t from, uint64_t num, int32_t on);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPERM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPERM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ioperm_return, CPUState* cpu, target_ulong pc, uint64_t from, uint64_t num, int32_t on);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_iopl_enter, CPUState* cpu, target_ulong pc, int32_t level);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_iopl_return, CPUState* cpu, target_ulong pc, int32_t level);
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
PPP_CB_TYPEDEF(void, on_sys_ipc_enter, CPUState* cpu, target_ulong pc, uint32_t call, int32_t first, uint64_t second, uint64_t third, uint64_t ptr, int64_t fifth);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IPC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IPC_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ipc_return, CPUState* cpu, target_ulong pc, uint32_t call, int32_t first, uint64_t second, uint64_t third, uint64_t ptr, int64_t fifth);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_kcmp_enter, CPUState* cpu, target_ulong pc, int32_t pid1, int32_t pid2, int32_t type, uint64_t idx1, uint64_t idx2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_kcmp_return, CPUState* cpu, target_ulong pc, int32_t pid1, int32_t pid2, int32_t type, uint64_t idx1, uint64_t idx2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_LOAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_LOAD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_kexec_load_enter, CPUState* cpu, target_ulong pc, uint64_t entry, uint64_t nr_segments, uint64_t segments, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_LOAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_LOAD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_kexec_load_return, CPUState* cpu, target_ulong pc, uint64_t entry, uint64_t nr_segments, uint64_t segments, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KEYCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KEYCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_keyctl_enter, CPUState* cpu, target_ulong pc, int32_t cmd, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KEYCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KEYCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_keyctl_return, CPUState* cpu, target_ulong pc, int32_t cmd, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
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
PPP_CB_TYPEDEF(void, on_sys_lchown_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LCHOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LCHOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lchown_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint32_t user, uint32_t group);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LGETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LGETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lgetxattr_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name, uint64_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LGETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LGETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lgetxattr_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name, uint64_t value, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_link_enter, CPUState* cpu, target_ulong pc, uint64_t oldname, uint64_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_link_return, CPUState* cpu, target_ulong pc, uint64_t oldname, uint64_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_linkat_enter, CPUState* cpu, target_ulong pc, int32_t olddfd, uint64_t oldname, int32_t newdfd, uint64_t newname, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_linkat_return, CPUState* cpu, target_ulong pc, int32_t olddfd, uint64_t oldname, int32_t newdfd, uint64_t newname, int32_t flags);
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
PPP_CB_TYPEDEF(void, on_sys_listxattr_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LISTXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LISTXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_listxattr_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LLISTXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LLISTXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_llistxattr_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LLISTXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LLISTXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_llistxattr_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t list, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LLSEEK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LLSEEK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_llseek_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t offset_high, uint64_t offset_low, uint64_t result, uint32_t whence);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LLSEEK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LLSEEK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_llseek_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t offset_high, uint64_t offset_low, uint64_t result, uint32_t whence);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LOOKUP_DCOOKIE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LOOKUP_DCOOKIE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lookup_dcookie_enter, CPUState* cpu, target_ulong pc, uint64_t cookie64, uint64_t buf, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LOOKUP_DCOOKIE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LOOKUP_DCOOKIE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lookup_dcookie_return, CPUState* cpu, target_ulong pc, uint64_t cookie64, uint64_t buf, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LREMOVEXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LREMOVEXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lremovexattr_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LREMOVEXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LREMOVEXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lremovexattr_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSEEK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSEEK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lseek_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t offset, uint32_t whence);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSEEK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSEEK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lseek_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t offset, uint32_t whence);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lsetxattr_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name, uint64_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lsetxattr_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name, uint64_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lstat_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lstat_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_lstat64_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_LSTAT64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_lstat64_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MADVISE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MADVISE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_madvise_enter, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, int32_t behavior);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MADVISE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MADVISE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_madvise_return, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, int32_t behavior);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MBIND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MBIND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mbind_enter, CPUState* cpu, target_ulong pc, uint64_t start, uint64_t len, uint64_t mode, uint64_t nmask, uint64_t maxnode, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MBIND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MBIND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mbind_return, CPUState* cpu, target_ulong pc, uint64_t start, uint64_t len, uint64_t mode, uint64_t nmask, uint64_t maxnode, uint32_t flags);
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
PPP_CB_TYPEDEF(void, on_sys_memfd_create_enter, CPUState* cpu, target_ulong pc, uint64_t uname_ptr, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MEMFD_CREATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MEMFD_CREATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_memfd_create_return, CPUState* cpu, target_ulong pc, uint64_t uname_ptr, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MIGRATE_PAGES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MIGRATE_PAGES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_migrate_pages_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t maxnode, uint64_t from, uint64_t to);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MIGRATE_PAGES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MIGRATE_PAGES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_migrate_pages_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t maxnode, uint64_t from, uint64_t to);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MINCORE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MINCORE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mincore_enter, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, uint64_t vec);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MINCORE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MINCORE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mincore_return, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, uint64_t vec);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mkdir_enter, CPUState* cpu, target_ulong pc, uint64_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mkdir_return, CPUState* cpu, target_ulong pc, uint64_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIRAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIRAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mkdirat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIRAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKDIRAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mkdirat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t pathname, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNOD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mknod_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint32_t mode, uint32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNOD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mknod_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint32_t mode, uint32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNODAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNODAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mknodat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint32_t mode, uint32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNODAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MKNODAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mknodat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint32_t mode, uint32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mlock_enter, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mlock_return, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mlock2_enter, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCK2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mlock2_return, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCKALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCKALL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mlockall_enter, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCKALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MLOCKALL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mlockall_return, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MMAP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MMAP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mmap_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t pgoff);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MMAP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MMAP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mmap_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t pgoff);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mount_enter, CPUState* cpu, target_ulong pc, uint64_t dev_name, uint64_t dir_name, uint64_t type, uint64_t flags, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mount_return, CPUState* cpu, target_ulong pc, uint64_t dev_name, uint64_t dir_name, uint64_t type, uint64_t flags, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_MOUNT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_MOUNT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_move_mount_enter, CPUState* cpu, target_ulong pc, int32_t from_dfd, uint64_t from_path, int32_t to_dfd, uint64_t to_path, uint32_t ms_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_MOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_MOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_move_mount_return, CPUState* cpu, target_ulong pc, int32_t from_dfd, uint64_t from_path, int32_t to_dfd, uint64_t to_path, uint32_t ms_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_PAGES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_PAGES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_move_pages_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t nr_pages, uint64_t pages, uint64_t nodes, uint64_t status, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_PAGES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOVE_PAGES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_move_pages_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t nr_pages, uint64_t pages, uint64_t nodes, uint64_t status, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MPROTECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MPROTECT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mprotect_enter, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, uint64_t prot);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MPROTECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MPROTECT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mprotect_return, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, uint64_t prot);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_GETSETATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_GETSETATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_getsetattr_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t mqstat, uint64_t omqstat);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_GETSETATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_GETSETATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_getsetattr_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t mqstat, uint64_t omqstat);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_NOTIFY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_NOTIFY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_notify_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t notification);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_NOTIFY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_NOTIFY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_notify_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t notification);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_open_enter, CPUState* cpu, target_ulong pc, uint64_t name, int32_t oflag, uint32_t mode, uint64_t attr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_open_return, CPUState* cpu, target_ulong pc, uint64_t name, int32_t oflag, uint32_t mode, uint64_t attr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedreceive_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t msg_ptr, uint32_t msg_len, uint64_t msg_prio, uint64_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedreceive_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t msg_ptr, uint32_t msg_len, uint64_t msg_prio, uint64_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedreceive_time32_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t u_msg_ptr, uint32_t msg_len, uint64_t u_msg_prio, uint64_t u_abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDRECEIVE_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedreceive_time32_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t u_msg_ptr, uint32_t msg_len, uint64_t u_msg_prio, uint64_t u_abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedsend_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint64_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedsend_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint64_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedsend_time32_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t u_msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint64_t u_abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedsend_time32_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t u_msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint64_t u_abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_UNLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_UNLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_unlink_enter, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_UNLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_UNLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_unlink_return, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MREMAP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MREMAP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mremap_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint64_t old_len, uint64_t new_len, uint64_t flags, uint64_t new_addr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MREMAP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MREMAP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mremap_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint64_t old_len, uint64_t new_len, uint64_t flags, uint64_t new_addr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_msgctl_enter, CPUState* cpu, target_ulong pc, int32_t msqid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_msgctl_return, CPUState* cpu, target_ulong pc, int32_t msqid, int32_t cmd, uint64_t buf);
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
PPP_CB_TYPEDEF(void, on_sys_msgrcv_enter, CPUState* cpu, target_ulong pc, int32_t msqid, uint64_t msgp, uint32_t msgsz, int64_t msgtyp, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGRCV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGRCV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_msgrcv_return, CPUState* cpu, target_ulong pc, int32_t msqid, uint64_t msgp, uint32_t msgsz, int64_t msgtyp, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGSND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGSND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_msgsnd_enter, CPUState* cpu, target_ulong pc, int32_t msqid, uint64_t msgp, uint32_t msgsz, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGSND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSGSND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_msgsnd_return, CPUState* cpu, target_ulong pc, int32_t msqid, uint64_t msgp, uint32_t msgsz, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_msync_enter, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MSYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MSYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_msync_return, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_munlock_enter, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_munlock_return, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len);
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
PPP_CB_TYPEDEF(void, on_sys_munmap_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNMAP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MUNMAP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_munmap_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NAME_TO_HANDLE_AT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NAME_TO_HANDLE_AT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_name_to_handle_at_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t name, uint64_t handle, uint64_t mnt_id, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NAME_TO_HANDLE_AT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NAME_TO_HANDLE_AT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_name_to_handle_at_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t name, uint64_t handle, uint64_t mnt_id, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_nanosleep_enter, CPUState* cpu, target_ulong pc, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_nanosleep_return, CPUState* cpu, target_ulong pc, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_nanosleep_time32_enter, CPUState* cpu, target_ulong pc, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NANOSLEEP_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_nanosleep_time32_return, CPUState* cpu, target_ulong pc, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_newfstat_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_newfstat_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTATAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTATAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_newfstatat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t statbuf, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTATAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWFSTATAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_newfstatat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t statbuf, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWLSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWLSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_newlstat_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWLSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWLSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_newlstat_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_newstat_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_newstat_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWUNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWUNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_newuname_enter, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWUNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NEWUNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_newuname_return, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NFSSERVCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NFSSERVCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_nfsservctl_enter, CPUState* cpu, target_ulong pc, int32_t cmd, uint64_t argp, uint64_t resp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NFSSERVCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NFSSERVCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_nfsservctl_return, CPUState* cpu, target_ulong pc, int32_t cmd, uint64_t argp, uint64_t resp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NI_SYSCALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NI_SYSCALL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ni_syscall_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NI_SYSCALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NI_SYSCALL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ni_syscall_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NICE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NICE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_nice_enter, CPUState* cpu, target_ulong pc, int32_t increment);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_NICE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_NICE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_nice_return, CPUState* cpu, target_ulong pc, int32_t increment);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_MMAP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_MMAP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_old_mmap_enter, CPUState* cpu, target_ulong pc, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_MMAP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_MMAP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_old_mmap_return, CPUState* cpu, target_ulong pc, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_MSGCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_MSGCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_old_msgctl_enter, CPUState* cpu, target_ulong pc, int32_t msqid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_MSGCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_MSGCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_old_msgctl_return, CPUState* cpu, target_ulong pc, int32_t msqid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_READDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_READDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_old_readdir_enter, CPUState* cpu, target_ulong pc, uint32_t arg0, uint64_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_READDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_READDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_old_readdir_return, CPUState* cpu, target_ulong pc, uint32_t arg0, uint64_t arg1, uint32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_SEMCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_SEMCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_old_semctl_enter, CPUState* cpu, target_ulong pc, int32_t semid, int32_t semnum, int32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_SEMCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_SEMCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_old_semctl_return, CPUState* cpu, target_ulong pc, int32_t semid, int32_t semnum, int32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_SHMCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_SHMCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_old_shmctl_enter, CPUState* cpu, target_ulong pc, int32_t shmid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_SHMCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLD_SHMCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_old_shmctl_return, CPUState* cpu, target_ulong pc, int32_t shmid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLDUMOUNT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLDUMOUNT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_oldumount_enter, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLDUMOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLDUMOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_oldumount_return, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLDUNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLDUNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_olduname_enter, CPUState* cpu, target_ulong pc, uint64_t arg0);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OLDUNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OLDUNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_olduname_return, CPUState* cpu, target_ulong pc, uint64_t arg0);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_open_enter, CPUState* cpu, target_ulong pc, uint64_t filename, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_open_return, CPUState* cpu, target_ulong pc, uint64_t filename, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_BY_HANDLE_AT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_BY_HANDLE_AT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_open_by_handle_at_enter, CPUState* cpu, target_ulong pc, int32_t mountdirfd, uint64_t handle, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_BY_HANDLE_AT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_BY_HANDLE_AT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_open_by_handle_at_return, CPUState* cpu, target_ulong pc, int32_t mountdirfd, uint64_t handle, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_TREE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_TREE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_open_tree_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_TREE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPEN_TREE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_open_tree_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_openat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_openat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_openat2_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t how, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_openat2_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t how, uint32_t size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PAUSE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PAUSE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pause_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PAUSE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PAUSE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pause_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PERF_EVENT_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PERF_EVENT_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_perf_event_open_enter, CPUState* cpu, target_ulong pc, uint64_t attr_uptr, int32_t pid, int32_t _cpu, int32_t group_fd, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PERF_EVENT_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PERF_EVENT_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_perf_event_open_return, CPUState* cpu, target_ulong pc, uint64_t attr_uptr, int32_t pid, int32_t _cpu, int32_t group_fd, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PERSONALITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PERSONALITY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_personality_enter, CPUState* cpu, target_ulong pc, uint32_t personality);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PERSONALITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PERSONALITY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_personality_return, CPUState* cpu, target_ulong pc, uint32_t personality);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_GETFD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_GETFD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pidfd_getfd_enter, CPUState* cpu, target_ulong pc, int32_t pidfd, int32_t fd, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_GETFD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_GETFD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pidfd_getfd_return, CPUState* cpu, target_ulong pc, int32_t pidfd, int32_t fd, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pidfd_open_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pidfd_open_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_SEND_SIGNAL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_SEND_SIGNAL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pidfd_send_signal_enter, CPUState* cpu, target_ulong pc, int32_t pidfd, int32_t sig, uint64_t info, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_SEND_SIGNAL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIDFD_SEND_SIGNAL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pidfd_send_signal_return, CPUState* cpu, target_ulong pc, int32_t pidfd, int32_t sig, uint64_t info, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pipe_enter, CPUState* cpu, target_ulong pc, uint64_t fildes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pipe_return, CPUState* cpu, target_ulong pc, uint64_t fildes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pipe2_enter, CPUState* cpu, target_ulong pc, uint64_t fildes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIPE2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pipe2_return, CPUState* cpu, target_ulong pc, uint64_t fildes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIVOT_ROOT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIVOT_ROOT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pivot_root_enter, CPUState* cpu, target_ulong pc, uint64_t new_root, uint64_t put_old);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PIVOT_ROOT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PIVOT_ROOT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pivot_root_return, CPUState* cpu, target_ulong pc, uint64_t new_root, uint64_t put_old);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_ALLOC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_ALLOC_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pkey_alloc_enter, CPUState* cpu, target_ulong pc, uint64_t flags, uint64_t init_val);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_ALLOC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_ALLOC_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pkey_alloc_return, CPUState* cpu, target_ulong pc, uint64_t flags, uint64_t init_val);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_FREE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_FREE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pkey_free_enter, CPUState* cpu, target_ulong pc, int32_t pkey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_FREE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_FREE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pkey_free_return, CPUState* cpu, target_ulong pc, int32_t pkey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_MPROTECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_MPROTECT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pkey_mprotect_enter, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, uint64_t prot, int32_t pkey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_MPROTECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PKEY_MPROTECT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pkey_mprotect_return, CPUState* cpu, target_ulong pc, uint64_t start, uint32_t len, uint64_t prot, int32_t pkey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_POLL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_POLL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_poll_enter, CPUState* cpu, target_ulong pc, uint64_t ufds, uint32_t nfds, int32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_POLL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_POLL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_poll_return, CPUState* cpu, target_ulong pc, uint64_t ufds, uint32_t nfds, int32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ppoll_enter, CPUState* cpu, target_ulong pc, uint64_t arg0, uint32_t arg1, uint64_t arg2, uint64_t arg3, uint32_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ppoll_return, CPUState* cpu, target_ulong pc, uint64_t arg0, uint32_t arg1, uint64_t arg2, uint64_t arg3, uint32_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ppoll_time32_enter, CPUState* cpu, target_ulong pc, uint64_t arg0, uint32_t arg1, uint64_t arg2, uint64_t arg3, uint32_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PPOLL_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ppoll_time32_return, CPUState* cpu, target_ulong pc, uint64_t arg0, uint32_t arg1, uint64_t arg2, uint64_t arg3, uint32_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PRCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PRCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_prctl_enter, CPUState* cpu, target_ulong pc, int32_t option, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PRCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PRCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_prctl_return, CPUState* cpu, target_ulong pc, int32_t option, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PREAD64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PREAD64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pread64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count, uint64_t pos);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PREAD64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PREAD64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pread64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count, uint64_t pos);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_preadv_enter, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen, uint64_t pos_l, uint64_t pos_h);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_preadv_return, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen, uint64_t pos_l, uint64_t pos_h);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_preadv2_enter, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen, uint64_t pos_l, uint64_t pos_h, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PREADV2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_preadv2_return, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen, uint64_t pos_l, uint64_t pos_h, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PRLIMIT64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PRLIMIT64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_prlimit64_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t resource, uint64_t new_rlim, uint64_t old_rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PRLIMIT64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PRLIMIT64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_prlimit64_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t resource, uint64_t new_rlim, uint64_t old_rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_READV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_READV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_process_vm_readv_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t lvec, uint64_t liovcnt, uint64_t rvec, uint64_t riovcnt, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_READV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_READV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_process_vm_readv_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t lvec, uint64_t liovcnt, uint64_t rvec, uint64_t riovcnt, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_WRITEV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_WRITEV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_process_vm_writev_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t lvec, uint64_t liovcnt, uint64_t rvec, uint64_t riovcnt, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_WRITEV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PROCESS_VM_WRITEV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_process_vm_writev_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t lvec, uint64_t liovcnt, uint64_t rvec, uint64_t riovcnt, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pselect6_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pselect6_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pselect6_time32_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PSELECT6_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pselect6_time32_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PTRACE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PTRACE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ptrace_enter, CPUState* cpu, target_ulong pc, int64_t request, int64_t pid, uint64_t addr, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PTRACE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PTRACE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ptrace_return, CPUState* cpu, target_ulong pc, int64_t request, int64_t pid, uint64_t addr, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITE64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITE64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pwrite64_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count, uint64_t pos);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITE64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITE64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pwrite64_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count, uint64_t pos);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pwritev_enter, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen, uint64_t pos_l, uint64_t pos_h);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pwritev_return, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen, uint64_t pos_l, uint64_t pos_h);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_pwritev2_enter, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen, uint64_t pos_l, uint64_t pos_h, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_PWRITEV2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_pwritev2_return, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen, uint64_t pos_l, uint64_t pos_h, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_QUERY_MODULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_QUERY_MODULE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_query_module_enter, CPUState* cpu, target_ulong pc, uint64_t name, int32_t which, uint64_t buf, uint32_t bufsize, uint64_t ret);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_QUERY_MODULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_QUERY_MODULE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_query_module_return, CPUState* cpu, target_ulong pc, uint64_t name, int32_t which, uint64_t buf, uint32_t bufsize, uint64_t ret);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_QUOTACTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_QUOTACTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_quotactl_enter, CPUState* cpu, target_ulong pc, uint32_t cmd, uint64_t special, uint32_t id, uint64_t addr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_QUOTACTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_QUOTACTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_quotactl_return, CPUState* cpu, target_ulong pc, uint32_t cmd, uint64_t special, uint32_t id, uint64_t addr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READ_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READ_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_read_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READ_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READ_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_read_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count);
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
PPP_CB_TYPEDEF(void, on_sys_readlink_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t buf, int32_t bufsiz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_readlink_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t buf, int32_t bufsiz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_readlinkat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, uint64_t buf, int32_t bufsiz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_readlinkat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, uint64_t buf, int32_t bufsiz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_readv_enter, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_READV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_READV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_readv_return, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REBOOT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REBOOT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_reboot_enter, CPUState* cpu, target_ulong pc, int32_t magic1, int32_t magic2, uint32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REBOOT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REBOOT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_reboot_return, CPUState* cpu, target_ulong pc, int32_t magic1, int32_t magic2, uint32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_recv_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_recv_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVFROM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVFROM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_recvfrom_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint32_t arg2, uint32_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVFROM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVFROM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_recvfrom_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint32_t arg2, uint32_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_recvmmsg_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t msg, uint32_t vlen, uint32_t flags, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_recvmmsg_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t msg, uint32_t vlen, uint32_t flags, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_recvmmsg_time32_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t msg, uint32_t vlen, uint32_t flags, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMMSG_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_recvmmsg_time32_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t msg, uint32_t vlen, uint32_t flags, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_recvmsg_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t msg, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RECVMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_recvmsg_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t msg, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REMAP_FILE_PAGES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REMAP_FILE_PAGES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_remap_file_pages_enter, CPUState* cpu, target_ulong pc, uint64_t start, uint64_t size, uint64_t prot, uint64_t pgoff, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REMAP_FILE_PAGES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REMAP_FILE_PAGES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_remap_file_pages_return, CPUState* cpu, target_ulong pc, uint64_t start, uint64_t size, uint64_t prot, uint64_t pgoff, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REMOVEXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REMOVEXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_removexattr_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REMOVEXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REMOVEXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_removexattr_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rename_enter, CPUState* cpu, target_ulong pc, uint64_t oldname, uint64_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rename_return, CPUState* cpu, target_ulong pc, uint64_t oldname, uint64_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_renameat_enter, CPUState* cpu, target_ulong pc, int32_t olddfd, uint64_t oldname, int32_t newdfd, uint64_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_renameat_return, CPUState* cpu, target_ulong pc, int32_t olddfd, uint64_t oldname, int32_t newdfd, uint64_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT2_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_renameat2_enter, CPUState* cpu, target_ulong pc, int32_t olddfd, uint64_t oldname, int32_t newdfd, uint64_t newname, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RENAMEAT2_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_renameat2_return, CPUState* cpu, target_ulong pc, int32_t olddfd, uint64_t oldname, int32_t newdfd, uint64_t newname, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REQUEST_KEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REQUEST_KEY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_request_key_enter, CPUState* cpu, target_ulong pc, uint64_t _type, uint64_t _description, uint64_t _callout_info, uint32_t destringid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_REQUEST_KEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_REQUEST_KEY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_request_key_return, CPUState* cpu, target_ulong pc, uint64_t _type, uint64_t _description, uint64_t _callout_info, uint32_t destringid);
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
PPP_CB_TYPEDEF(void, on_sys_rmdir_enter, CPUState* cpu, target_ulong pc, uint64_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RMDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RMDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rmdir_return, CPUState* cpu, target_ulong pc, uint64_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RSEQ_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RSEQ_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rseq_enter, CPUState* cpu, target_ulong pc, uint64_t rseq, int32_t rseq_len, int32_t flags, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RSEQ_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RSEQ_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rseq_return, CPUState* cpu, target_ulong pc, uint64_t rseq, int32_t rseq_len, int32_t flags, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigaction_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigaction_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPENDING_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPENDING_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigpending_enter, CPUState* cpu, target_ulong pc, uint64_t set, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPENDING_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPENDING_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigpending_return, CPUState* cpu, target_ulong pc, uint64_t set, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPROCMASK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPROCMASK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigprocmask_enter, CPUState* cpu, target_ulong pc, int32_t how, uint64_t set, uint64_t oset, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPROCMASK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGPROCMASK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigprocmask_return, CPUState* cpu, target_ulong pc, int32_t how, uint64_t set, uint64_t oset, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGQUEUEINFO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGQUEUEINFO_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigqueueinfo_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t sig, uint64_t uinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGQUEUEINFO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGQUEUEINFO_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigqueueinfo_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t sig, uint64_t uinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGRETURN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGRETURN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigreturn_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGRETURN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGRETURN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigreturn_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGSUSPEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGSUSPEND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigsuspend_enter, CPUState* cpu, target_ulong pc, uint64_t unewset, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGSUSPEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGSUSPEND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigsuspend_return, CPUState* cpu, target_ulong pc, uint64_t unewset, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigtimedwait_enter, CPUState* cpu, target_ulong pc, uint64_t uthese, uint64_t uinfo, uint64_t uts, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigtimedwait_return, CPUState* cpu, target_ulong pc, uint64_t uthese, uint64_t uinfo, uint64_t uts, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigtimedwait_time32_enter, CPUState* cpu, target_ulong pc, uint64_t uthese, uint64_t uinfo, uint64_t uts, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_SIGTIMEDWAIT_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_sigtimedwait_time32_return, CPUState* cpu, target_ulong pc, uint64_t uthese, uint64_t uinfo, uint64_t uts, uint32_t sigsetsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_TGSIGQUEUEINFO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_TGSIGQUEUEINFO_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_rt_tgsigqueueinfo_enter, CPUState* cpu, target_ulong pc, int32_t tgid, int32_t pid, int32_t sig, uint64_t uinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_TGSIGQUEUEINFO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_RT_TGSIGQUEUEINFO_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_rt_tgsigqueueinfo_return, CPUState* cpu, target_ulong pc, int32_t tgid, int32_t pid, int32_t sig, uint64_t uinfo);
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
PPP_CB_TYPEDEF(void, on_sys_sched_getaffinity_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t len, uint64_t user_mask_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETAFFINITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETAFFINITY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_getaffinity_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t len, uint64_t user_mask_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_getattr_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t attr, uint32_t size, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_getattr_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t attr, uint32_t size, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETPARAM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETPARAM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_getparam_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETPARAM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_GETPARAM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_getparam_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t param);
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
PPP_CB_TYPEDEF(void, on_sys_sched_rr_get_interval_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t interval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_RR_GET_INTERVAL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_RR_GET_INTERVAL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_rr_get_interval_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t interval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_RR_GET_INTERVAL_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_RR_GET_INTERVAL_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_rr_get_interval_time32_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t interval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_RR_GET_INTERVAL_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_RR_GET_INTERVAL_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_rr_get_interval_time32_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t interval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETAFFINITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETAFFINITY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_setaffinity_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t len, uint64_t user_mask_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETAFFINITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETAFFINITY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_setaffinity_return, CPUState* cpu, target_ulong pc, int32_t pid, uint32_t len, uint64_t user_mask_ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_setattr_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t attr, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_setattr_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t attr, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETPARAM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETPARAM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_setparam_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETPARAM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETPARAM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_setparam_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETSCHEDULER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETSCHEDULER_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sched_setscheduler_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t policy, uint64_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETSCHEDULER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SCHED_SETSCHEDULER_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sched_setscheduler_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t policy, uint64_t param);
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
PPP_CB_TYPEDEF(void, on_sys_seccomp_enter, CPUState* cpu, target_ulong pc, uint32_t op, uint32_t flags, uint64_t uargs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SECCOMP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SECCOMP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_seccomp_return, CPUState* cpu, target_ulong pc, uint32_t op, uint32_t flags, uint64_t uargs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SELECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SELECT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_select_enter, CPUState* cpu, target_ulong pc, int32_t n, uint64_t inp, uint64_t outp, uint64_t exp, uint64_t tvp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SELECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SELECT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_select_return, CPUState* cpu, target_ulong pc, int32_t n, uint64_t inp, uint64_t outp, uint64_t exp, uint64_t tvp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_semctl_enter, CPUState* cpu, target_ulong pc, int32_t semid, int32_t semnum, int32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_semctl_return, CPUState* cpu, target_ulong pc, int32_t semid, int32_t semnum, int32_t cmd, uint64_t arg);
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
PPP_CB_TYPEDEF(void, on_sys_semop_enter, CPUState* cpu, target_ulong pc, int32_t semid, uint64_t sops, uint32_t nsops);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMOP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMOP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_semop_return, CPUState* cpu, target_ulong pc, int32_t semid, uint64_t sops, uint32_t nsops);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_semtimedop_enter, CPUState* cpu, target_ulong pc, int32_t semid, uint64_t sops, uint32_t nsops, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_semtimedop_return, CPUState* cpu, target_ulong pc, int32_t semid, uint64_t sops, uint32_t nsops, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_semtimedop_time32_enter, CPUState* cpu, target_ulong pc, int32_t semid, uint64_t sops, uint32_t nsops, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEMTIMEDOP_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_semtimedop_time32_return, CPUState* cpu, target_ulong pc, int32_t semid, uint64_t sops, uint32_t nsops, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_send_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SEND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_send_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint32_t arg2, uint32_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sendfile_enter, CPUState* cpu, target_ulong pc, int32_t out_fd, int32_t in_fd, uint64_t offset, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sendfile_return, CPUState* cpu, target_ulong pc, int32_t out_fd, int32_t in_fd, uint64_t offset, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sendfile64_enter, CPUState* cpu, target_ulong pc, int32_t out_fd, int32_t in_fd, uint64_t offset, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDFILE64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sendfile64_return, CPUState* cpu, target_ulong pc, int32_t out_fd, int32_t in_fd, uint64_t offset, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sendmmsg_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t msg, uint32_t vlen, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sendmmsg_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t msg, uint32_t vlen, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sendmsg_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t msg, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sendmsg_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t msg, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDTO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDTO_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sendto_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint32_t arg2, uint32_t arg3, uint64_t arg4, int32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDTO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SENDTO_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sendto_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint32_t arg2, uint32_t arg3, uint64_t arg4, int32_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_MEMPOLICY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_MEMPOLICY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_set_mempolicy_enter, CPUState* cpu, target_ulong pc, int32_t mode, uint64_t nmask, uint64_t maxnode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_MEMPOLICY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_MEMPOLICY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_set_mempolicy_return, CPUState* cpu, target_ulong pc, int32_t mode, uint64_t nmask, uint64_t maxnode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_ROBUST_LIST_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_ROBUST_LIST_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_set_robust_list_enter, CPUState* cpu, target_ulong pc, uint64_t head, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_ROBUST_LIST_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_ROBUST_LIST_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_set_robust_list_return, CPUState* cpu, target_ulong pc, uint64_t head, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_TID_ADDRESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_TID_ADDRESS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_set_tid_address_enter, CPUState* cpu, target_ulong pc, uint64_t tidptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_TID_ADDRESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SET_TID_ADDRESS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_set_tid_address_return, CPUState* cpu, target_ulong pc, uint64_t tidptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETDOMAINNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETDOMAINNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setdomainname_enter, CPUState* cpu, target_ulong pc, uint64_t name, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETDOMAINNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETDOMAINNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setdomainname_return, CPUState* cpu, target_ulong pc, uint64_t name, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setfsgid_enter, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setfsgid_return, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setfsuid_enter, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETFSUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setfsuid_return, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setgid_enter, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setgid_return, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setgroups_enter, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint64_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETGROUPS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setgroups_return, CPUState* cpu, target_ulong pc, int32_t gidsetsize, uint64_t grouplist);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETHOSTNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETHOSTNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sethostname_enter, CPUState* cpu, target_ulong pc, uint64_t name, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETHOSTNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETHOSTNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sethostname_return, CPUState* cpu, target_ulong pc, uint64_t name, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETITIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETITIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setitimer_enter, CPUState* cpu, target_ulong pc, int32_t which, uint64_t value, uint64_t ovalue);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETITIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETITIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setitimer_return, CPUState* cpu, target_ulong pc, int32_t which, uint64_t value, uint64_t ovalue);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setresgid_enter, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESGID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setresgid_return, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setresuid_enter, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRESUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setresuid_return, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setreuid_enter, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETREUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setreuid_return, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRLIMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRLIMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setrlimit_enter, CPUState* cpu, target_ulong pc, uint32_t resource, uint64_t rlim);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRLIMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETRLIMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setrlimit_return, CPUState* cpu, target_ulong pc, uint32_t resource, uint64_t rlim);
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
PPP_CB_TYPEDEF(void, on_sys_setsockopt_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t level, int32_t optname, uint64_t optval, int32_t optlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETSOCKOPT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETSOCKOPT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setsockopt_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t level, int32_t optname, uint64_t optval, int32_t optlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETTIMEOFDAY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETTIMEOFDAY_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_settimeofday_enter, CPUState* cpu, target_ulong pc, uint64_t tv, uint64_t tz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETTIMEOFDAY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETTIMEOFDAY_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_settimeofday_return, CPUState* cpu, target_ulong pc, uint64_t tv, uint64_t tz);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setuid_enter, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setuid_return, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setup_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETUP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setup_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setxattr_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name, uint64_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setxattr_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name, uint64_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SGETMASK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SGETMASK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sgetmask_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SGETMASK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SGETMASK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sgetmask_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_shmat_enter, CPUState* cpu, target_ulong pc, int32_t shmid, uint64_t shmaddr, int32_t shmflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_shmat_return, CPUState* cpu, target_ulong pc, int32_t shmid, uint64_t shmaddr, int32_t shmflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_shmctl_enter, CPUState* cpu, target_ulong pc, int32_t shmid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_shmctl_return, CPUState* cpu, target_ulong pc, int32_t shmid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMDT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMDT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_shmdt_enter, CPUState* cpu, target_ulong pc, uint64_t shmaddr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMDT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SHMDT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_shmdt_return, CPUState* cpu, target_ulong pc, uint64_t shmaddr);
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
PPP_CB_TYPEDEF(void, on_sys_sigaction_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigaction_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigaltstack_enter, CPUState* cpu, target_ulong pc, uint64_t uss, uint64_t uoss);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigaltstack_return, CPUState* cpu, target_ulong pc, uint64_t uss, uint64_t uoss);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNAL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNAL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_signal_enter, CPUState* cpu, target_ulong pc, int32_t sig, uint64_t handler);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNAL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNAL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_signal_return, CPUState* cpu, target_ulong pc, int32_t sig, uint64_t handler);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_signalfd_enter, CPUState* cpu, target_ulong pc, int32_t ufd, uint64_t user_mask, uint32_t sizemask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_signalfd_return, CPUState* cpu, target_ulong pc, int32_t ufd, uint64_t user_mask, uint32_t sizemask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD4_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD4_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_signalfd4_enter, CPUState* cpu, target_ulong pc, int32_t ufd, uint64_t user_mask, uint32_t sizemask, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD4_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGNALFD4_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_signalfd4_return, CPUState* cpu, target_ulong pc, int32_t ufd, uint64_t user_mask, uint32_t sizemask, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPENDING_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPENDING_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigpending_enter, CPUState* cpu, target_ulong pc, uint64_t uset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPENDING_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPENDING_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigpending_return, CPUState* cpu, target_ulong pc, uint64_t uset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPROCMASK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPROCMASK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigprocmask_enter, CPUState* cpu, target_ulong pc, int32_t how, uint64_t set, uint64_t oset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPROCMASK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGPROCMASK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigprocmask_return, CPUState* cpu, target_ulong pc, int32_t how, uint64_t set, uint64_t oset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGRETURN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGRETURN_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigreturn_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGRETURN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGRETURN_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigreturn_return, CPUState* cpu, target_ulong pc);
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
PPP_CB_TYPEDEF(void, on_sys_socketcall_enter, CPUState* cpu, target_ulong pc, int32_t call, uint64_t args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETCALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETCALL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_socketcall_return, CPUState* cpu, target_ulong pc, int32_t call, uint64_t args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_socketpair_enter, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1, int32_t arg2, uint64_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKETPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_socketpair_return, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1, int32_t arg2, uint64_t arg3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SPLICE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SPLICE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_splice_enter, CPUState* cpu, target_ulong pc, int32_t fd_in, uint64_t off_in, int32_t fd_out, uint64_t off_out, uint32_t len, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SPLICE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SPLICE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_splice_return, CPUState* cpu, target_ulong pc, int32_t fd_in, uint64_t off_in, int32_t fd_out, uint64_t off_out, uint32_t len, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SSETMASK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SSETMASK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_ssetmask_enter, CPUState* cpu, target_ulong pc, int32_t newmask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SSETMASK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SSETMASK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ssetmask_return, CPUState* cpu, target_ulong pc, int32_t newmask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_stat_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_stat_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_stat64_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STAT64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_stat64_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t statbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_statfs_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_statfs_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_statfs64_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t sz, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_statfs64_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t sz, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_statx_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, uint32_t flags, uint32_t mask, uint64_t buffer);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_statx_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, uint32_t flags, uint32_t mask, uint64_t buffer);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_stime32_enter, CPUState* cpu, target_ulong pc, uint64_t tptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_stime32_return, CPUState* cpu, target_ulong pc, uint64_t tptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPOFF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPOFF_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_swapoff_enter, CPUState* cpu, target_ulong pc, uint64_t specialfile);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPOFF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPOFF_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_swapoff_return, CPUState* cpu, target_ulong pc, uint64_t specialfile);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPON_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPON_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_swapon_enter, CPUState* cpu, target_ulong pc, uint64_t specialfile, int32_t swap_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPON_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SWAPON_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_swapon_return, CPUState* cpu, target_ulong pc, uint64_t specialfile, int32_t swap_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_symlink_enter, CPUState* cpu, target_ulong pc, uint64_t old, uint64_t _new);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_symlink_return, CPUState* cpu, target_ulong pc, uint64_t old, uint64_t _new);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_symlinkat_enter, CPUState* cpu, target_ulong pc, uint64_t oldname, int32_t newdfd, uint64_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYMLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_symlinkat_return, CPUState* cpu, target_ulong pc, uint64_t oldname, int32_t newdfd, uint64_t newname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sync_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sync_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_FILE_RANGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_FILE_RANGE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sync_file_range_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint64_t nbytes, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_FILE_RANGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYNC_FILE_RANGE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sync_file_range_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint64_t nbytes, uint32_t flags);
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
PPP_CB_TYPEDEF(void, on_sys_sysctl_enter, CPUState* cpu, target_ulong pc, uint64_t args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sysctl_return, CPUState* cpu, target_ulong pc, uint64_t args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSFS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sysfs_enter, CPUState* cpu, target_ulong pc, int32_t option, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSFS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sysfs_return, CPUState* cpu, target_ulong pc, int32_t option, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSINFO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSINFO_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sysinfo_enter, CPUState* cpu, target_ulong pc, uint64_t info);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSINFO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSINFO_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sysinfo_return, CPUState* cpu, target_ulong pc, uint64_t info);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSLOG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSLOG_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_syslog_enter, CPUState* cpu, target_ulong pc, int32_t type, uint64_t buf, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSLOG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SYSLOG_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_syslog_return, CPUState* cpu, target_ulong pc, int32_t type, uint64_t buf, int32_t len);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_time32_enter, CPUState* cpu, target_ulong pc, uint64_t tloc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_time32_return, CPUState* cpu, target_ulong pc, uint64_t tloc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_CREATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_CREATE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timer_create_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t timer_event_spec, uint64_t created_timer_id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_CREATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_CREATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_create_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t timer_event_spec, uint64_t created_timer_id);
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
PPP_CB_TYPEDEF(void, on_sys_timer_gettime_enter, CPUState* cpu, target_ulong pc, uint32_t timer_id, uint64_t setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_gettime_return, CPUState* cpu, target_ulong pc, uint32_t timer_id, uint64_t setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETTIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETTIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timer_gettime32_enter, CPUState* cpu, target_ulong pc, uint32_t timer_id, uint64_t setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETTIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_GETTIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_gettime32_return, CPUState* cpu, target_ulong pc, uint32_t timer_id, uint64_t setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timer_settime_enter, CPUState* cpu, target_ulong pc, uint32_t timer_id, int32_t flags, uint64_t new_setting, uint64_t old_setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_settime_return, CPUState* cpu, target_ulong pc, uint32_t timer_id, int32_t flags, uint64_t new_setting, uint64_t old_setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timer_settime32_enter, CPUState* cpu, target_ulong pc, uint32_t timer_id, int32_t flags, uint64_t _new, uint64_t old);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_settime32_return, CPUState* cpu, target_ulong pc, uint32_t timer_id, int32_t flags, uint64_t _new, uint64_t old);
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
PPP_CB_TYPEDEF(void, on_sys_timerfd_gettime_enter, CPUState* cpu, target_ulong pc, int32_t ufd, uint64_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_GETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_GETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_gettime_return, CPUState* cpu, target_ulong pc, int32_t ufd, uint64_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_GETTIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_GETTIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_gettime32_enter, CPUState* cpu, target_ulong pc, int32_t ufd, uint64_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_GETTIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_GETTIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_gettime32_return, CPUState* cpu, target_ulong pc, int32_t ufd, uint64_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_settime_enter, CPUState* cpu, target_ulong pc, int32_t ufd, int32_t flags, uint64_t utmr, uint64_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_settime_return, CPUState* cpu, target_ulong pc, int32_t ufd, int32_t flags, uint64_t utmr, uint64_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_settime32_enter, CPUState* cpu, target_ulong pc, int32_t ufd, int32_t flags, uint64_t utmr, uint64_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_settime32_return, CPUState* cpu, target_ulong pc, int32_t ufd, int32_t flags, uint64_t utmr, uint64_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_times_enter, CPUState* cpu, target_ulong pc, uint64_t tbuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_times_return, CPUState* cpu, target_ulong pc, uint64_t tbuf);
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
PPP_CB_TYPEDEF(void, on_sys_truncate_enter, CPUState* cpu, target_ulong pc, uint64_t path, int64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_truncate_return, CPUState* cpu, target_ulong pc, uint64_t path, int64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_truncate64_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TRUNCATE64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_truncate64_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t length);
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
PPP_CB_TYPEDEF(void, on_sys_umount_enter, CPUState* cpu, target_ulong pc, uint64_t name, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UMOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UMOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_umount_return, CPUState* cpu, target_ulong pc, uint64_t name, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_uname_enter, CPUState* cpu, target_ulong pc, uint64_t arg0);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_uname_return, CPUState* cpu, target_ulong pc, uint64_t arg0);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_unlink_enter, CPUState* cpu, target_ulong pc, uint64_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_unlink_return, CPUState* cpu, target_ulong pc, uint64_t pathname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_unlinkat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t pathname, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_unlinkat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t pathname, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNSHARE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNSHARE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_unshare_enter, CPUState* cpu, target_ulong pc, uint64_t unshare_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UNSHARE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UNSHARE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_unshare_return, CPUState* cpu, target_ulong pc, uint64_t unshare_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_USELIB_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_USELIB_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_uselib_enter, CPUState* cpu, target_ulong pc, uint64_t library);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_USELIB_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_USELIB_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_uselib_return, CPUState* cpu, target_ulong pc, uint64_t library);
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
PPP_CB_TYPEDEF(void, on_sys_ustat_enter, CPUState* cpu, target_ulong pc, uint32_t dev, uint64_t ubuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_USTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_USTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ustat_return, CPUState* cpu, target_ulong pc, uint32_t dev, uint64_t ubuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utime_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t times);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utime_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t times);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utime32_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t t);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utime32_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t t);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utimensat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t utimes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utimensat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t utimes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utimensat_time32_enter, CPUState* cpu, target_ulong pc, uint32_t dfd, uint64_t filename, uint64_t t, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utimensat_time32_return, CPUState* cpu, target_ulong pc, uint32_t dfd, uint64_t filename, uint64_t t, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utimes_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t utimes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utimes_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t utimes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_TIME32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_TIME32_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utimes_time32_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t t);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_TIME32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_TIME32_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utimes_time32_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t t);
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
PPP_CB_TYPEDEF(void, on_sys_vmsplice_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t iov, uint64_t nr_segs, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_VMSPLICE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_VMSPLICE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_vmsplice_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t iov, uint64_t nr_segs, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WAIT4_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WAIT4_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_wait4_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t stat_addr, int32_t options, uint64_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WAIT4_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WAIT4_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_wait4_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t stat_addr, int32_t options, uint64_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_waitid_enter, CPUState* cpu, target_ulong pc, int32_t which, int32_t pid, uint64_t infop, int32_t options, uint64_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_waitid_return, CPUState* cpu, target_ulong pc, int32_t which, int32_t pid, uint64_t infop, int32_t options, uint64_t ru);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITPID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITPID_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_waitpid_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t stat_addr, int32_t options);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITPID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WAITPID_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_waitpid_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t stat_addr, int32_t options);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_write_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_write_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITEV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITEV_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_writev_enter, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITEV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_WRITEV_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_writev_return, CPUState* cpu, target_ulong pc, uint64_t fd, uint64_t vec, uint64_t vlen);
#endif

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
