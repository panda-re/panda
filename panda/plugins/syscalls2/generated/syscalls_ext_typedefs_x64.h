// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_FD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_FD_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_aclcheck_fd_enter, CPUState* cpu, target_ulong pc, int32_t filedes, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_FD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_FD_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_aclcheck_fd_return, CPUState* cpu, target_ulong pc, int32_t filedes, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_FILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_FILE_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_aclcheck_file_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_FILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_FILE_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_aclcheck_file_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_aclcheck_link_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_ACLCHECK_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_aclcheck_link_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_FD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_FD_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_delete_fd_enter, CPUState* cpu, target_ulong pc, int32_t filedes, uint32_t type);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_FD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_FD_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_delete_fd_return, CPUState* cpu, target_ulong pc, int32_t filedes, uint32_t type);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_FILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_FILE_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_delete_file_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_FILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_FILE_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_delete_file_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_delete_link_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_DELETE_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_delete_link_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_FD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_FD_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_get_fd_enter, CPUState* cpu, target_ulong pc, int32_t filedes, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_FD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_FD_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_get_fd_return, CPUState* cpu, target_ulong pc, int32_t filedes, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_FILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_FILE_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_get_file_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_FILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_FILE_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_get_file_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_get_link_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_GET_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_get_link_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_FD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_FD_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_set_fd_enter, CPUState* cpu, target_ulong pc, int32_t filedes, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_FD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_FD_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_set_fd_return, CPUState* cpu, target_ulong pc, int32_t filedes, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_FILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_FILE_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_set_file_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_FILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_FILE_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_set_file_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on___acl_set_link_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___ACL_SET_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on___acl_set_link_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t type, uint64_t aclp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___CAP_RIGHTS_GET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___CAP_RIGHTS_GET_ENTER 1
PPP_CB_TYPEDEF(void, on___cap_rights_get_enter, CPUState* cpu, target_ulong pc, int32_t version, int32_t fd, uint64_t rightsp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___CAP_RIGHTS_GET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___CAP_RIGHTS_GET_RETURN 1
PPP_CB_TYPEDEF(void, on___cap_rights_get_return, CPUState* cpu, target_ulong pc, int32_t version, int32_t fd, uint64_t rightsp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___GETCWD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___GETCWD_ENTER 1
PPP_CB_TYPEDEF(void, on___getcwd_enter, CPUState* cpu, target_ulong pc, uint64_t buf, uint32_t buflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___GETCWD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___GETCWD_RETURN 1
PPP_CB_TYPEDEF(void, on___getcwd_return, CPUState* cpu, target_ulong pc, uint64_t buf, uint32_t buflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_EXECVE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_EXECVE_ENTER 1
PPP_CB_TYPEDEF(void, on___mac_execve_enter, CPUState* cpu, target_ulong pc, uint64_t fname, uint64_t argv, uint64_t envv, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_EXECVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_EXECVE_RETURN 1
PPP_CB_TYPEDEF(void, on___mac_execve_return, CPUState* cpu, target_ulong pc, uint64_t fname, uint64_t argv, uint64_t envv, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_FD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_FD_ENTER 1
PPP_CB_TYPEDEF(void, on___mac_get_fd_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_FD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_FD_RETURN 1
PPP_CB_TYPEDEF(void, on___mac_get_fd_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_FILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_FILE_ENTER 1
PPP_CB_TYPEDEF(void, on___mac_get_file_enter, CPUState* cpu, target_ulong pc, uint64_t path_p, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_FILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_FILE_RETURN 1
PPP_CB_TYPEDEF(void, on___mac_get_file_return, CPUState* cpu, target_ulong pc, uint64_t path_p, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on___mac_get_link_enter, CPUState* cpu, target_ulong pc, uint64_t path_p, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on___mac_get_link_return, CPUState* cpu, target_ulong pc, uint64_t path_p, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_PID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_PID_ENTER 1
PPP_CB_TYPEDEF(void, on___mac_get_pid_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_PID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_PID_RETURN 1
PPP_CB_TYPEDEF(void, on___mac_get_pid_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_PROC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_PROC_ENTER 1
PPP_CB_TYPEDEF(void, on___mac_get_proc_enter, CPUState* cpu, target_ulong pc, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_PROC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_GET_PROC_RETURN 1
PPP_CB_TYPEDEF(void, on___mac_get_proc_return, CPUState* cpu, target_ulong pc, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_FD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_FD_ENTER 1
PPP_CB_TYPEDEF(void, on___mac_set_fd_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_FD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_FD_RETURN 1
PPP_CB_TYPEDEF(void, on___mac_set_fd_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_FILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_FILE_ENTER 1
PPP_CB_TYPEDEF(void, on___mac_set_file_enter, CPUState* cpu, target_ulong pc, uint64_t path_p, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_FILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_FILE_RETURN 1
PPP_CB_TYPEDEF(void, on___mac_set_file_return, CPUState* cpu, target_ulong pc, uint64_t path_p, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on___mac_set_link_enter, CPUState* cpu, target_ulong pc, uint64_t path_p, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on___mac_set_link_return, CPUState* cpu, target_ulong pc, uint64_t path_p, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_PROC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_PROC_ENTER 1
PPP_CB_TYPEDEF(void, on___mac_set_proc_enter, CPUState* cpu, target_ulong pc, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_PROC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___MAC_SET_PROC_RETURN 1
PPP_CB_TYPEDEF(void, on___mac_set_proc_return, CPUState* cpu, target_ulong pc, uint64_t mac_p);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___REALPATHAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___REALPATHAT_ENTER 1
PPP_CB_TYPEDEF(void, on___realpathat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t buf, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___REALPATHAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___REALPATHAT_RETURN 1
PPP_CB_TYPEDEF(void, on___realpathat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t buf, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___SEMCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___SEMCTL_ENTER 1
PPP_CB_TYPEDEF(void, on___semctl_enter, CPUState* cpu, target_ulong pc, int32_t semid, int32_t semnum, int32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___SEMCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___SEMCTL_RETURN 1
PPP_CB_TYPEDEF(void, on___semctl_return, CPUState* cpu, target_ulong pc, int32_t semid, int32_t semnum, int32_t cmd, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___SETUGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___SETUGID_ENTER 1
PPP_CB_TYPEDEF(void, on___setugid_enter, CPUState* cpu, target_ulong pc, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___SETUGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___SETUGID_RETURN 1
PPP_CB_TYPEDEF(void, on___setugid_return, CPUState* cpu, target_ulong pc, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___SYSCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___SYSCTL_ENTER 1
PPP_CB_TYPEDEF(void, on___sysctl_enter, CPUState* cpu, target_ulong pc, uint64_t name, uint32_t namelen, uint64_t old, uint64_t oldlenp, uint64_t _new, uint32_t newlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___SYSCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___SYSCTL_RETURN 1
PPP_CB_TYPEDEF(void, on___sysctl_return, CPUState* cpu, target_ulong pc, uint64_t name, uint32_t namelen, uint64_t old, uint64_t oldlenp, uint64_t _new, uint32_t newlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___SYSCTLBYNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON___SYSCTLBYNAME_ENTER 1
PPP_CB_TYPEDEF(void, on___sysctlbyname_enter, CPUState* cpu, target_ulong pc, uint64_t name, uint32_t namelen, uint64_t old, uint64_t oldlenp, uint64_t _new, uint32_t newlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON___SYSCTLBYNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON___SYSCTLBYNAME_RETURN 1
PPP_CB_TYPEDEF(void, on___sysctlbyname_return, CPUState* cpu, target_ulong pc, uint64_t name, uint32_t namelen, uint64_t old, uint64_t oldlenp, uint64_t _new, uint32_t newlen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON__UMTX_OP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON__UMTX_OP_ENTER 1
PPP_CB_TYPEDEF(void, on__umtx_op_enter, CPUState* cpu, target_ulong pc, uint64_t obj, int32_t op, int64_t val, uint64_t uaddr1, uint64_t uaddr2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON__UMTX_OP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON__UMTX_OP_RETURN 1
PPP_CB_TYPEDEF(void, on__umtx_op_return, CPUState* cpu, target_ulong pc, uint64_t obj, int32_t op, int64_t val, uint64_t uaddr1, uint64_t uaddr2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ABORT2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ABORT2_ENTER 1
PPP_CB_TYPEDEF(void, on_abort2_enter, CPUState* cpu, target_ulong pc, uint64_t why, int32_t nargs, uint64_t args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ABORT2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ABORT2_RETURN 1
PPP_CB_TYPEDEF(void, on_abort2_return, CPUState* cpu, target_ulong pc, uint64_t why, int32_t nargs, uint64_t args);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ACCEPT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ACCEPT_ENTER 1
PPP_CB_TYPEDEF(void, on_accept_enter, CPUState* cpu, target_ulong pc, int32_t s, uint64_t name, uint64_t anamelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ACCEPT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ACCEPT_RETURN 1
PPP_CB_TYPEDEF(void, on_accept_return, CPUState* cpu, target_ulong pc, int32_t s, uint64_t name, uint64_t anamelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ACCEPT4_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ACCEPT4_ENTER 1
PPP_CB_TYPEDEF(void, on_accept4_enter, CPUState* cpu, target_ulong pc, int32_t s, uint64_t name, uint64_t anamelen, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ACCEPT4_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ACCEPT4_RETURN 1
PPP_CB_TYPEDEF(void, on_accept4_return, CPUState* cpu, target_ulong pc, int32_t s, uint64_t name, uint64_t anamelen, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ACCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ACCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_access_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t amode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ACCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ACCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_access_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t amode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ACCT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ACCT_ENTER 1
PPP_CB_TYPEDEF(void, on_acct_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ACCT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ACCT_RETURN 1
PPP_CB_TYPEDEF(void, on_acct_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ADJTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ADJTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_adjtime_enter, CPUState* cpu, target_ulong pc, uint64_t delta, uint64_t olddelta);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ADJTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ADJTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_adjtime_return, CPUState* cpu, target_ulong pc, uint64_t delta, uint64_t olddelta);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AFS3_SYSCALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AFS3_SYSCALL_ENTER 1
PPP_CB_TYPEDEF(void, on_afs3_syscall_enter, CPUState* cpu, target_ulong pc, int64_t syscall, int64_t parm1, int64_t parm2, int64_t parm3, int64_t parm4, int64_t parm5, int64_t parm6);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AFS3_SYSCALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AFS3_SYSCALL_RETURN 1
PPP_CB_TYPEDEF(void, on_afs3_syscall_return, CPUState* cpu, target_ulong pc, int64_t syscall, int64_t parm1, int64_t parm2, int64_t parm3, int64_t parm4, int64_t parm5, int64_t parm6);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_CANCEL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_CANCEL_ENTER 1
PPP_CB_TYPEDEF(void, on_aio_cancel_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_CANCEL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_CANCEL_RETURN 1
PPP_CB_TYPEDEF(void, on_aio_cancel_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_ERROR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_ERROR_ENTER 1
PPP_CB_TYPEDEF(void, on_aio_error_enter, CPUState* cpu, target_ulong pc, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_ERROR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_ERROR_RETURN 1
PPP_CB_TYPEDEF(void, on_aio_error_return, CPUState* cpu, target_ulong pc, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_FSYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_FSYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_aio_fsync_enter, CPUState* cpu, target_ulong pc, int32_t op, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_FSYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_FSYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_aio_fsync_return, CPUState* cpu, target_ulong pc, int32_t op, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_MLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_MLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_aio_mlock_enter, CPUState* cpu, target_ulong pc, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_MLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_MLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_aio_mlock_return, CPUState* cpu, target_ulong pc, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_READ_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_READ_ENTER 1
PPP_CB_TYPEDEF(void, on_aio_read_enter, CPUState* cpu, target_ulong pc, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_READ_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_READ_RETURN 1
PPP_CB_TYPEDEF(void, on_aio_read_return, CPUState* cpu, target_ulong pc, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_RETURN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_RETURN_ENTER 1
PPP_CB_TYPEDEF(void, on_aio_return_enter, CPUState* cpu, target_ulong pc, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_RETURN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_RETURN_RETURN 1
PPP_CB_TYPEDEF(void, on_aio_return_return, CPUState* cpu, target_ulong pc, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_SUSPEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_SUSPEND_ENTER 1
PPP_CB_TYPEDEF(void, on_aio_suspend_enter, CPUState* cpu, target_ulong pc, uint64_t aiocbp, int32_t nent, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_SUSPEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_SUSPEND_RETURN 1
PPP_CB_TYPEDEF(void, on_aio_suspend_return, CPUState* cpu, target_ulong pc, uint64_t aiocbp, int32_t nent, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_WAITCOMPLETE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_WAITCOMPLETE_ENTER 1
PPP_CB_TYPEDEF(void, on_aio_waitcomplete_enter, CPUState* cpu, target_ulong pc, uint64_t aiocbp, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_WAITCOMPLETE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_WAITCOMPLETE_RETURN 1
PPP_CB_TYPEDEF(void, on_aio_waitcomplete_return, CPUState* cpu, target_ulong pc, uint64_t aiocbp, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_WRITE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_WRITE_ENTER 1
PPP_CB_TYPEDEF(void, on_aio_write_enter, CPUState* cpu, target_ulong pc, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AIO_WRITE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AIO_WRITE_RETURN 1
PPP_CB_TYPEDEF(void, on_aio_write_return, CPUState* cpu, target_ulong pc, uint64_t aiocbp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AUDIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AUDIT_ENTER 1
PPP_CB_TYPEDEF(void, on_audit_enter, CPUState* cpu, target_ulong pc, uint64_t record, uint32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AUDIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AUDIT_RETURN 1
PPP_CB_TYPEDEF(void, on_audit_return, CPUState* cpu, target_ulong pc, uint64_t record, uint32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AUDITCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AUDITCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_auditctl_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AUDITCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AUDITCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_auditctl_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AUDITON_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_AUDITON_ENTER 1
PPP_CB_TYPEDEF(void, on_auditon_enter, CPUState* cpu, target_ulong pc, int32_t cmd, uint64_t _data, uint32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_AUDITON_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_AUDITON_RETURN 1
PPP_CB_TYPEDEF(void, on_auditon_return, CPUState* cpu, target_ulong pc, int32_t cmd, uint64_t _data, uint32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_BIND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_BIND_ENTER 1
PPP_CB_TYPEDEF(void, on_bind_enter, CPUState* cpu, target_ulong pc, int32_t s, uint64_t name, int32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_BIND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_BIND_RETURN 1
PPP_CB_TYPEDEF(void, on_bind_return, CPUState* cpu, target_ulong pc, int32_t s, uint64_t name, int32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_BINDAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_BINDAT_ENTER 1
PPP_CB_TYPEDEF(void, on_bindat_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t s, uint64_t name, int32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_BINDAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_BINDAT_RETURN 1
PPP_CB_TYPEDEF(void, on_bindat_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t s, uint64_t name, int32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_ENTER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_ENTER_ENTER 1
PPP_CB_TYPEDEF(void, on_cap_enter_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_ENTER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_ENTER_RETURN 1
PPP_CB_TYPEDEF(void, on_cap_enter_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_FCNTLS_GET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_FCNTLS_GET_ENTER 1
PPP_CB_TYPEDEF(void, on_cap_fcntls_get_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t fcntlrightsp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_FCNTLS_GET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_FCNTLS_GET_RETURN 1
PPP_CB_TYPEDEF(void, on_cap_fcntls_get_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t fcntlrightsp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_FCNTLS_LIMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_FCNTLS_LIMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_cap_fcntls_limit_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t fcntlrights);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_FCNTLS_LIMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_FCNTLS_LIMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_cap_fcntls_limit_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t fcntlrights);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_GETMODE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_GETMODE_ENTER 1
PPP_CB_TYPEDEF(void, on_cap_getmode_enter, CPUState* cpu, target_ulong pc, uint64_t modep);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_GETMODE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_GETMODE_RETURN 1
PPP_CB_TYPEDEF(void, on_cap_getmode_return, CPUState* cpu, target_ulong pc, uint64_t modep);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_IOCTLS_GET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_IOCTLS_GET_ENTER 1
PPP_CB_TYPEDEF(void, on_cap_ioctls_get_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t cmds, uint32_t maxcmds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_IOCTLS_GET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_IOCTLS_GET_RETURN 1
PPP_CB_TYPEDEF(void, on_cap_ioctls_get_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t cmds, uint32_t maxcmds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_IOCTLS_LIMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_IOCTLS_LIMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_cap_ioctls_limit_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t cmds, uint32_t ncmds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_IOCTLS_LIMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_IOCTLS_LIMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_cap_ioctls_limit_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t cmds, uint32_t ncmds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_RIGHTS_LIMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_RIGHTS_LIMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_cap_rights_limit_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t rightsp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CAP_RIGHTS_LIMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CAP_RIGHTS_LIMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_cap_rights_limit_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t rightsp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CHDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_chdir_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CHDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_chdir_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHFLAGS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CHFLAGS_ENTER 1
PPP_CB_TYPEDEF(void, on_chflags_enter, CPUState* cpu, target_ulong pc, uint64_t path, int64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHFLAGS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CHFLAGS_RETURN 1
PPP_CB_TYPEDEF(void, on_chflags_return, CPUState* cpu, target_ulong pc, uint64_t path, int64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHFLAGSAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CHFLAGSAT_ENTER 1
PPP_CB_TYPEDEF(void, on_chflagsat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, int64_t flags, int32_t atflag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHFLAGSAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CHFLAGSAT_RETURN 1
PPP_CB_TYPEDEF(void, on_chflagsat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, int64_t flags, int32_t atflag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHMOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CHMOD_ENTER 1
PPP_CB_TYPEDEF(void, on_chmod_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHMOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CHMOD_RETURN 1
PPP_CB_TYPEDEF(void, on_chmod_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHOWN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CHOWN_ENTER 1
PPP_CB_TYPEDEF(void, on_chown_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t uid, int32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CHOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_chown_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t uid, int32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHROOT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CHROOT_ENTER 1
PPP_CB_TYPEDEF(void, on_chroot_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CHROOT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CHROOT_RETURN 1
PPP_CB_TYPEDEF(void, on_chroot_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETCPUCLOCKID2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETCPUCLOCKID2_ENTER 1
PPP_CB_TYPEDEF(void, on_clock_getcpuclockid2_enter, CPUState* cpu, target_ulong pc, uint32_t id, int32_t which, uint64_t clock_id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETCPUCLOCKID2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETCPUCLOCKID2_RETURN 1
PPP_CB_TYPEDEF(void, on_clock_getcpuclockid2_return, CPUState* cpu, target_ulong pc, uint32_t id, int32_t which, uint64_t clock_id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETRES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETRES_ENTER 1
PPP_CB_TYPEDEF(void, on_clock_getres_enter, CPUState* cpu, target_ulong pc, uint32_t clock_id, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETRES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETRES_RETURN 1
PPP_CB_TYPEDEF(void, on_clock_getres_return, CPUState* cpu, target_ulong pc, uint32_t clock_id, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_clock_gettime_enter, CPUState* cpu, target_ulong pc, uint32_t clock_id, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CLOCK_GETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_clock_gettime_return, CPUState* cpu, target_ulong pc, uint32_t clock_id, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOCK_NANOSLEEP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CLOCK_NANOSLEEP_ENTER 1
PPP_CB_TYPEDEF(void, on_clock_nanosleep_enter, CPUState* cpu, target_ulong pc, uint32_t clock_id, int32_t flags, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOCK_NANOSLEEP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CLOCK_NANOSLEEP_RETURN 1
PPP_CB_TYPEDEF(void, on_clock_nanosleep_return, CPUState* cpu, target_ulong pc, uint32_t clock_id, int32_t flags, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOCK_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CLOCK_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_clock_settime_enter, CPUState* cpu, target_ulong pc, uint32_t clock_id, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOCK_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CLOCK_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_clock_settime_return, CPUState* cpu, target_ulong pc, uint32_t clock_id, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOSE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CLOSE_ENTER 1
PPP_CB_TYPEDEF(void, on_close_enter, CPUState* cpu, target_ulong pc, int32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOSE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CLOSE_RETURN 1
PPP_CB_TYPEDEF(void, on_close_return, CPUState* cpu, target_ulong pc, int32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOSE_RANGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CLOSE_RANGE_ENTER 1
PPP_CB_TYPEDEF(void, on_close_range_enter, CPUState* cpu, target_ulong pc, uint32_t lowfd, uint32_t highfd, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOSE_RANGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CLOSE_RANGE_RETURN 1
PPP_CB_TYPEDEF(void, on_close_range_return, CPUState* cpu, target_ulong pc, uint32_t lowfd, uint32_t highfd, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOSEFROM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CLOSEFROM_ENTER 1
PPP_CB_TYPEDEF(void, on_closefrom_enter, CPUState* cpu, target_ulong pc, int32_t lowfd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CLOSEFROM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CLOSEFROM_RETURN 1
PPP_CB_TYPEDEF(void, on_closefrom_return, CPUState* cpu, target_ulong pc, int32_t lowfd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CONNECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CONNECT_ENTER 1
PPP_CB_TYPEDEF(void, on_connect_enter, CPUState* cpu, target_ulong pc, int32_t s, uint64_t name, int32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CONNECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CONNECT_RETURN 1
PPP_CB_TYPEDEF(void, on_connect_return, CPUState* cpu, target_ulong pc, int32_t s, uint64_t name, int32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CONNECTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CONNECTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_connectat_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t s, uint64_t name, int32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CONNECTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CONNECTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_connectat_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t s, uint64_t name, int32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_COPY_FILE_RANGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_COPY_FILE_RANGE_ENTER 1
PPP_CB_TYPEDEF(void, on_copy_file_range_enter, CPUState* cpu, target_ulong pc, int32_t infd, uint64_t inoffp, int32_t outfd, uint64_t outoffp, uint32_t len, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_COPY_FILE_RANGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_COPY_FILE_RANGE_RETURN 1
PPP_CB_TYPEDEF(void, on_copy_file_range_return, CPUState* cpu, target_ulong pc, int32_t infd, uint64_t inoffp, int32_t outfd, uint64_t outoffp, uint32_t len, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_ENTER 1
PPP_CB_TYPEDEF(void, on_cpuset_enter, CPUState* cpu, target_ulong pc, uint64_t setid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_RETURN 1
PPP_CB_TYPEDEF(void, on_cpuset_return, CPUState* cpu, target_ulong pc, uint64_t setid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETAFFINITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETAFFINITY_ENTER 1
PPP_CB_TYPEDEF(void, on_cpuset_getaffinity_enter, CPUState* cpu, target_ulong pc, uint32_t level, uint32_t which, uint32_t id, uint32_t cpusetsize, uint64_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETAFFINITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETAFFINITY_RETURN 1
PPP_CB_TYPEDEF(void, on_cpuset_getaffinity_return, CPUState* cpu, target_ulong pc, uint32_t level, uint32_t which, uint32_t id, uint32_t cpusetsize, uint64_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETDOMAIN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETDOMAIN_ENTER 1
PPP_CB_TYPEDEF(void, on_cpuset_getdomain_enter, CPUState* cpu, target_ulong pc, uint32_t level, uint32_t which, uint32_t id, uint32_t domainsetsize, uint64_t mask, uint64_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETDOMAIN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETDOMAIN_RETURN 1
PPP_CB_TYPEDEF(void, on_cpuset_getdomain_return, CPUState* cpu, target_ulong pc, uint32_t level, uint32_t which, uint32_t id, uint32_t domainsetsize, uint64_t mask, uint64_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETID_ENTER 1
PPP_CB_TYPEDEF(void, on_cpuset_getid_enter, CPUState* cpu, target_ulong pc, uint32_t level, uint32_t which, uint32_t id, uint64_t setid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_GETID_RETURN 1
PPP_CB_TYPEDEF(void, on_cpuset_getid_return, CPUState* cpu, target_ulong pc, uint32_t level, uint32_t which, uint32_t id, uint64_t setid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETAFFINITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETAFFINITY_ENTER 1
PPP_CB_TYPEDEF(void, on_cpuset_setaffinity_enter, CPUState* cpu, target_ulong pc, uint32_t level, uint32_t which, uint32_t id, uint32_t cpusetsize, uint64_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETAFFINITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETAFFINITY_RETURN 1
PPP_CB_TYPEDEF(void, on_cpuset_setaffinity_return, CPUState* cpu, target_ulong pc, uint32_t level, uint32_t which, uint32_t id, uint32_t cpusetsize, uint64_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETDOMAIN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETDOMAIN_ENTER 1
PPP_CB_TYPEDEF(void, on_cpuset_setdomain_enter, CPUState* cpu, target_ulong pc, uint32_t level, uint32_t which, uint32_t id, uint32_t domainsetsize, uint64_t mask, int32_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETDOMAIN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETDOMAIN_RETURN 1
PPP_CB_TYPEDEF(void, on_cpuset_setdomain_return, CPUState* cpu, target_ulong pc, uint32_t level, uint32_t which, uint32_t id, uint32_t domainsetsize, uint64_t mask, int32_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETID_ENTER 1
PPP_CB_TYPEDEF(void, on_cpuset_setid_enter, CPUState* cpu, target_ulong pc, uint32_t which, uint32_t id, uint32_t setid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CPUSET_SETID_RETURN 1
PPP_CB_TYPEDEF(void, on_cpuset_setid_return, CPUState* cpu, target_ulong pc, uint32_t which, uint32_t id, uint32_t setid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CREAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_CREAT_ENTER 1
PPP_CB_TYPEDEF(void, on_creat_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_CREAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_CREAT_RETURN 1
PPP_CB_TYPEDEF(void, on_creat_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_DUP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_DUP_ENTER 1
PPP_CB_TYPEDEF(void, on_dup_enter, CPUState* cpu, target_ulong pc, uint32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_DUP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_DUP_RETURN 1
PPP_CB_TYPEDEF(void, on_dup_return, CPUState* cpu, target_ulong pc, uint32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_DUP2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_DUP2_ENTER 1
PPP_CB_TYPEDEF(void, on_dup2_enter, CPUState* cpu, target_ulong pc, uint32_t from, uint32_t to);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_DUP2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_DUP2_RETURN 1
PPP_CB_TYPEDEF(void, on_dup2_return, CPUState* cpu, target_ulong pc, uint32_t from, uint32_t to);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EACCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EACCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_eaccess_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t amode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EACCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EACCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_eaccess_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t amode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXECVE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXECVE_ENTER 1
PPP_CB_TYPEDEF(void, on_execve_enter, CPUState* cpu, target_ulong pc, uint64_t fname, uint64_t argv, uint64_t envv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXECVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXECVE_RETURN 1
PPP_CB_TYPEDEF(void, on_execve_return, CPUState* cpu, target_ulong pc, uint64_t fname, uint64_t argv, uint64_t envv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_FD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_FD_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_delete_fd_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t attrnamespace, uint64_t attrname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_FD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_FD_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_delete_fd_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t attrnamespace, uint64_t attrname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_FILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_FILE_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_delete_file_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_FILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_FILE_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_delete_file_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_delete_link_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_DELETE_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_delete_link_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_FD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_FD_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_get_fd_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_FD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_FD_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_get_fd_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_FILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_FILE_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_get_file_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_FILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_FILE_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_get_file_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_get_link_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_GET_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_get_link_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_FD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_FD_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_list_fd_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t attrnamespace, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_FD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_FD_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_list_fd_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t attrnamespace, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_FILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_FILE_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_list_file_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_FILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_FILE_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_list_file_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_list_link_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_LIST_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_list_link_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_FD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_FD_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_set_fd_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_FD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_FD_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_set_fd_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_FILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_FILE_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_set_file_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_FILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_FILE_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_set_file_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on_extattr_set_link_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTR_SET_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on_extattr_set_link_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t attrnamespace, uint64_t attrname, uint64_t _data, uint32_t nbytes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTRCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTRCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_extattrctl_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t cmd, uint64_t filename, int32_t attrnamespace, uint64_t attrname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_EXTATTRCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_EXTATTRCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_extattrctl_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t cmd, uint64_t filename, int32_t attrnamespace, uint64_t attrname);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FACCESSAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FACCESSAT_ENTER 1
PPP_CB_TYPEDEF(void, on_faccessat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, int32_t amode, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FACCESSAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FACCESSAT_RETURN 1
PPP_CB_TYPEDEF(void, on_faccessat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, int32_t amode, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FCHDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_fchdir_enter, CPUState* cpu, target_ulong pc, int32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FCHDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_fchdir_return, CPUState* cpu, target_ulong pc, int32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHFLAGS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FCHFLAGS_ENTER 1
PPP_CB_TYPEDEF(void, on_fchflags_enter, CPUState* cpu, target_ulong pc, int32_t fd, int64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHFLAGS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FCHFLAGS_RETURN 1
PPP_CB_TYPEDEF(void, on_fchflags_return, CPUState* cpu, target_ulong pc, int32_t fd, int64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHMOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FCHMOD_ENTER 1
PPP_CB_TYPEDEF(void, on_fchmod_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHMOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FCHMOD_RETURN 1
PPP_CB_TYPEDEF(void, on_fchmod_return, CPUState* cpu, target_ulong pc, int32_t fd, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHMODAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FCHMODAT_ENTER 1
PPP_CB_TYPEDEF(void, on_fchmodat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t mode, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHMODAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FCHMODAT_RETURN 1
PPP_CB_TYPEDEF(void, on_fchmodat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t mode, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHOWN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FCHOWN_ENTER 1
PPP_CB_TYPEDEF(void, on_fchown_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t uid, int32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FCHOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_fchown_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t uid, int32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHOWNAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FCHOWNAT_ENTER 1
PPP_CB_TYPEDEF(void, on_fchownat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t uid, uint32_t gid, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCHOWNAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FCHOWNAT_RETURN 1
PPP_CB_TYPEDEF(void, on_fchownat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t uid, uint32_t gid, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCNTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FCNTL_ENTER 1
PPP_CB_TYPEDEF(void, on_fcntl_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t cmd, int64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FCNTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FCNTL_RETURN 1
PPP_CB_TYPEDEF(void, on_fcntl_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t cmd, int64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FDATASYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FDATASYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_fdatasync_enter, CPUState* cpu, target_ulong pc, int32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FDATASYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FDATASYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_fdatasync_return, CPUState* cpu, target_ulong pc, int32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FEXECVE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FEXECVE_ENTER 1
PPP_CB_TYPEDEF(void, on_fexecve_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t argv, uint64_t envv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FEXECVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FEXECVE_RETURN 1
PPP_CB_TYPEDEF(void, on_fexecve_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t argv, uint64_t envv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_GETCOUNTER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_GETCOUNTER_ENTER 1
PPP_CB_TYPEDEF(void, on_ffclock_getcounter_enter, CPUState* cpu, target_ulong pc, uint64_t ffcount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_GETCOUNTER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_GETCOUNTER_RETURN 1
PPP_CB_TYPEDEF(void, on_ffclock_getcounter_return, CPUState* cpu, target_ulong pc, uint64_t ffcount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_GETESTIMATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_GETESTIMATE_ENTER 1
PPP_CB_TYPEDEF(void, on_ffclock_getestimate_enter, CPUState* cpu, target_ulong pc, uint64_t cest);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_GETESTIMATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_GETESTIMATE_RETURN 1
PPP_CB_TYPEDEF(void, on_ffclock_getestimate_return, CPUState* cpu, target_ulong pc, uint64_t cest);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_SETESTIMATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_SETESTIMATE_ENTER 1
PPP_CB_TYPEDEF(void, on_ffclock_setestimate_enter, CPUState* cpu, target_ulong pc, uint64_t cest);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_SETESTIMATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FFCLOCK_SETESTIMATE_RETURN 1
PPP_CB_TYPEDEF(void, on_ffclock_setestimate_return, CPUState* cpu, target_ulong pc, uint64_t cest);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FHLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_fhlink_enter, CPUState* cpu, target_ulong pc, uint64_t fhp, uint64_t to);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FHLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_fhlink_return, CPUState* cpu, target_ulong pc, uint64_t fhp, uint64_t to);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FHLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_fhlinkat_enter, CPUState* cpu, target_ulong pc, uint64_t fhp, int32_t tofd, uint64_t to);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FHLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_fhlinkat_return, CPUState* cpu, target_ulong pc, uint64_t fhp, int32_t tofd, uint64_t to);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHOPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FHOPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_fhopen_enter, CPUState* cpu, target_ulong pc, uint64_t u_fhp, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHOPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FHOPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_fhopen_return, CPUState* cpu, target_ulong pc, uint64_t u_fhp, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHREADLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FHREADLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_fhreadlink_enter, CPUState* cpu, target_ulong pc, uint64_t fhp, uint64_t buf, uint32_t bufsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHREADLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FHREADLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_fhreadlink_return, CPUState* cpu, target_ulong pc, uint64_t fhp, uint64_t buf, uint32_t bufsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FHSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_fhstat_enter, CPUState* cpu, target_ulong pc, uint64_t u_fhp, uint64_t sb);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FHSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_fhstat_return, CPUState* cpu, target_ulong pc, uint64_t u_fhp, uint64_t sb);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHSTATFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FHSTATFS_ENTER 1
PPP_CB_TYPEDEF(void, on_fhstatfs_enter, CPUState* cpu, target_ulong pc, uint64_t u_fhp, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FHSTATFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FHSTATFS_RETURN 1
PPP_CB_TYPEDEF(void, on_fhstatfs_return, CPUState* cpu, target_ulong pc, uint64_t u_fhp, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_flock_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t how);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_flock_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t how);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FORK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FORK_ENTER 1
PPP_CB_TYPEDEF(void, on_fork_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FORK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FORK_RETURN 1
PPP_CB_TYPEDEF(void, on_fork_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FPATHCONF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FPATHCONF_ENTER 1
PPP_CB_TYPEDEF(void, on_fpathconf_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FPATHCONF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FPATHCONF_RETURN 1
PPP_CB_TYPEDEF(void, on_fpathconf_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_fstat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t sb);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_fstat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t sb);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FSTATAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FSTATAT_ENTER 1
PPP_CB_TYPEDEF(void, on_fstatat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t buf, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FSTATAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FSTATAT_RETURN 1
PPP_CB_TYPEDEF(void, on_fstatat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t buf, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FSTATFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FSTATFS_ENTER 1
PPP_CB_TYPEDEF(void, on_fstatfs_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FSTATFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FSTATFS_RETURN 1
PPP_CB_TYPEDEF(void, on_fstatfs_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FSYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FSYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_fsync_enter, CPUState* cpu, target_ulong pc, int32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FSYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FSYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_fsync_return, CPUState* cpu, target_ulong pc, int32_t fd);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FTRUNCATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FTRUNCATE_ENTER 1
PPP_CB_TYPEDEF(void, on_ftruncate_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FTRUNCATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FTRUNCATE_RETURN 1
PPP_CB_TYPEDEF(void, on_ftruncate_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FUNLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FUNLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_funlinkat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, int32_t fd, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FUNLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FUNLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_funlinkat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, int32_t fd, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FUTIMENS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FUTIMENS_ENTER 1
PPP_CB_TYPEDEF(void, on_futimens_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t times);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FUTIMENS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FUTIMENS_RETURN 1
PPP_CB_TYPEDEF(void, on_futimens_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t times);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FUTIMES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FUTIMES_ENTER 1
PPP_CB_TYPEDEF(void, on_futimes_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t tptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FUTIMES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FUTIMES_RETURN 1
PPP_CB_TYPEDEF(void, on_futimes_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t tptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FUTIMESAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_FUTIMESAT_ENTER 1
PPP_CB_TYPEDEF(void, on_futimesat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t times);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_FUTIMESAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_FUTIMESAT_RETURN 1
PPP_CB_TYPEDEF(void, on_futimesat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t times);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETAUDIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETAUDIT_ENTER 1
PPP_CB_TYPEDEF(void, on_getaudit_enter, CPUState* cpu, target_ulong pc, uint64_t auditinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETAUDIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETAUDIT_RETURN 1
PPP_CB_TYPEDEF(void, on_getaudit_return, CPUState* cpu, target_ulong pc, uint64_t auditinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETAUDIT_ADDR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETAUDIT_ADDR_ENTER 1
PPP_CB_TYPEDEF(void, on_getaudit_addr_enter, CPUState* cpu, target_ulong pc, uint64_t auditinfo_addr, uint32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETAUDIT_ADDR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETAUDIT_ADDR_RETURN 1
PPP_CB_TYPEDEF(void, on_getaudit_addr_return, CPUState* cpu, target_ulong pc, uint64_t auditinfo_addr, uint32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETAUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETAUID_ENTER 1
PPP_CB_TYPEDEF(void, on_getauid_enter, CPUState* cpu, target_ulong pc, uint64_t auid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETAUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETAUID_RETURN 1
PPP_CB_TYPEDEF(void, on_getauid_return, CPUState* cpu, target_ulong pc, uint64_t auid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETCONTEXT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETCONTEXT_ENTER 1
PPP_CB_TYPEDEF(void, on_getcontext_enter, CPUState* cpu, target_ulong pc, uint64_t ucp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETCONTEXT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETCONTEXT_RETURN 1
PPP_CB_TYPEDEF(void, on_getcontext_return, CPUState* cpu, target_ulong pc, uint64_t ucp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETDENTS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETDENTS_ENTER 1
PPP_CB_TYPEDEF(void, on_getdents_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETDENTS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETDENTS_RETURN 1
PPP_CB_TYPEDEF(void, on_getdents_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETDIRENTRIES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETDIRENTRIES_ENTER 1
PPP_CB_TYPEDEF(void, on_getdirentries_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t count, uint64_t basep);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETDIRENTRIES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETDIRENTRIES_RETURN 1
PPP_CB_TYPEDEF(void, on_getdirentries_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t count, uint64_t basep);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETDOMAINNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETDOMAINNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_getdomainname_enter, CPUState* cpu, target_ulong pc, uint64_t domainname, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETDOMAINNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETDOMAINNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_getdomainname_return, CPUState* cpu, target_ulong pc, uint64_t domainname, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETDTABLESIZE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETDTABLESIZE_ENTER 1
PPP_CB_TYPEDEF(void, on_getdtablesize_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETDTABLESIZE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETDTABLESIZE_RETURN 1
PPP_CB_TYPEDEF(void, on_getdtablesize_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETEGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETEGID_ENTER 1
PPP_CB_TYPEDEF(void, on_getegid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETEGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETEGID_RETURN 1
PPP_CB_TYPEDEF(void, on_getegid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETEUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETEUID_ENTER 1
PPP_CB_TYPEDEF(void, on_geteuid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETEUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETEUID_RETURN 1
PPP_CB_TYPEDEF(void, on_geteuid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETFH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETFH_ENTER 1
PPP_CB_TYPEDEF(void, on_getfh_enter, CPUState* cpu, target_ulong pc, uint64_t fname, uint64_t fhp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETFH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETFH_RETURN 1
PPP_CB_TYPEDEF(void, on_getfh_return, CPUState* cpu, target_ulong pc, uint64_t fname, uint64_t fhp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETFHAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETFHAT_ENTER 1
PPP_CB_TYPEDEF(void, on_getfhat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t fhp, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETFHAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETFHAT_RETURN 1
PPP_CB_TYPEDEF(void, on_getfhat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t fhp, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETFSSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETFSSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_getfsstat_enter, CPUState* cpu, target_ulong pc, uint64_t buf, int64_t bufsize, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETFSSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETFSSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_getfsstat_return, CPUState* cpu, target_ulong pc, uint64_t buf, int64_t bufsize, int32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETGID_ENTER 1
PPP_CB_TYPEDEF(void, on_getgid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETGID_RETURN 1
PPP_CB_TYPEDEF(void, on_getgid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETGROUPS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETGROUPS_ENTER 1
PPP_CB_TYPEDEF(void, on_getgroups_enter, CPUState* cpu, target_ulong pc, uint32_t gidsetsize, uint64_t gidset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETGROUPS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETGROUPS_RETURN 1
PPP_CB_TYPEDEF(void, on_getgroups_return, CPUState* cpu, target_ulong pc, uint32_t gidsetsize, uint64_t gidset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETHOSTID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETHOSTID_ENTER 1
PPP_CB_TYPEDEF(void, on_gethostid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETHOSTID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETHOSTID_RETURN 1
PPP_CB_TYPEDEF(void, on_gethostid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETHOSTNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETHOSTNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_gethostname_enter, CPUState* cpu, target_ulong pc, uint64_t hostname, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETHOSTNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETHOSTNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_gethostname_return, CPUState* cpu, target_ulong pc, uint64_t hostname, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETITIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETITIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_getitimer_enter, CPUState* cpu, target_ulong pc, uint32_t which, uint64_t itv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETITIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETITIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_getitimer_return, CPUState* cpu, target_ulong pc, uint32_t which, uint64_t itv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETKERNINFO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETKERNINFO_ENTER 1
PPP_CB_TYPEDEF(void, on_getkerninfo_enter, CPUState* cpu, target_ulong pc, int32_t op, uint64_t where, uint64_t size, int32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETKERNINFO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETKERNINFO_RETURN 1
PPP_CB_TYPEDEF(void, on_getkerninfo_return, CPUState* cpu, target_ulong pc, int32_t op, uint64_t where, uint64_t size, int32_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETLOGIN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETLOGIN_ENTER 1
PPP_CB_TYPEDEF(void, on_getlogin_enter, CPUState* cpu, target_ulong pc, uint64_t namebuf, uint32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETLOGIN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETLOGIN_RETURN 1
PPP_CB_TYPEDEF(void, on_getlogin_return, CPUState* cpu, target_ulong pc, uint64_t namebuf, uint32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETLOGINCLASS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETLOGINCLASS_ENTER 1
PPP_CB_TYPEDEF(void, on_getloginclass_enter, CPUState* cpu, target_ulong pc, uint64_t namebuf, uint32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETLOGINCLASS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETLOGINCLASS_RETURN 1
PPP_CB_TYPEDEF(void, on_getloginclass_return, CPUState* cpu, target_ulong pc, uint64_t namebuf, uint32_t namelen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPAGESIZE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETPAGESIZE_ENTER 1
PPP_CB_TYPEDEF(void, on_getpagesize_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPAGESIZE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETPAGESIZE_RETURN 1
PPP_CB_TYPEDEF(void, on_getpagesize_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPEERNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETPEERNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_getpeername_enter, CPUState* cpu, target_ulong pc, int32_t fdes, uint64_t asa, uint64_t alen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPEERNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETPEERNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_getpeername_return, CPUState* cpu, target_ulong pc, int32_t fdes, uint64_t asa, uint64_t alen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETPGID_ENTER 1
PPP_CB_TYPEDEF(void, on_getpgid_enter, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETPGID_RETURN 1
PPP_CB_TYPEDEF(void, on_getpgid_return, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPGRP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETPGRP_ENTER 1
PPP_CB_TYPEDEF(void, on_getpgrp_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPGRP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETPGRP_RETURN 1
PPP_CB_TYPEDEF(void, on_getpgrp_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETPID_ENTER 1
PPP_CB_TYPEDEF(void, on_getpid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETPID_RETURN 1
PPP_CB_TYPEDEF(void, on_getpid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPPID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETPPID_ENTER 1
PPP_CB_TYPEDEF(void, on_getppid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPPID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETPPID_RETURN 1
PPP_CB_TYPEDEF(void, on_getppid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPRIORITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETPRIORITY_ENTER 1
PPP_CB_TYPEDEF(void, on_getpriority_enter, CPUState* cpu, target_ulong pc, int32_t which, int32_t who);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETPRIORITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETPRIORITY_RETURN 1
PPP_CB_TYPEDEF(void, on_getpriority_return, CPUState* cpu, target_ulong pc, int32_t which, int32_t who);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETRANDOM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETRANDOM_ENTER 1
PPP_CB_TYPEDEF(void, on_getrandom_enter, CPUState* cpu, target_ulong pc, uint64_t buf, uint32_t buflen, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETRANDOM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETRANDOM_RETURN 1
PPP_CB_TYPEDEF(void, on_getrandom_return, CPUState* cpu, target_ulong pc, uint64_t buf, uint32_t buflen, uint32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETRESGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETRESGID_ENTER 1
PPP_CB_TYPEDEF(void, on_getresgid_enter, CPUState* cpu, target_ulong pc, uint64_t rgid, uint64_t egid, uint64_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETRESGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETRESGID_RETURN 1
PPP_CB_TYPEDEF(void, on_getresgid_return, CPUState* cpu, target_ulong pc, uint64_t rgid, uint64_t egid, uint64_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETRESUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETRESUID_ENTER 1
PPP_CB_TYPEDEF(void, on_getresuid_enter, CPUState* cpu, target_ulong pc, uint64_t ruid, uint64_t euid, uint64_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETRESUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETRESUID_RETURN 1
PPP_CB_TYPEDEF(void, on_getresuid_return, CPUState* cpu, target_ulong pc, uint64_t ruid, uint64_t euid, uint64_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETRLIMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETRLIMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_getrlimit_enter, CPUState* cpu, target_ulong pc, uint32_t which, uint64_t rlp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETRLIMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETRLIMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_getrlimit_return, CPUState* cpu, target_ulong pc, uint32_t which, uint64_t rlp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETRUSAGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETRUSAGE_ENTER 1
PPP_CB_TYPEDEF(void, on_getrusage_enter, CPUState* cpu, target_ulong pc, int32_t who, uint64_t rusage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETRUSAGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETRUSAGE_RETURN 1
PPP_CB_TYPEDEF(void, on_getrusage_return, CPUState* cpu, target_ulong pc, int32_t who, uint64_t rusage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETSID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETSID_ENTER 1
PPP_CB_TYPEDEF(void, on_getsid_enter, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETSID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETSID_RETURN 1
PPP_CB_TYPEDEF(void, on_getsid_return, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETSOCKNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETSOCKNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_getsockname_enter, CPUState* cpu, target_ulong pc, int32_t fdec, uint64_t asa, uint64_t alen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETSOCKNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETSOCKNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_getsockname_return, CPUState* cpu, target_ulong pc, int32_t fdec, uint64_t asa, uint64_t alen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETSOCKOPT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETSOCKOPT_ENTER 1
PPP_CB_TYPEDEF(void, on_getsockopt_enter, CPUState* cpu, target_ulong pc, int32_t s, int32_t level, int32_t name, uint64_t val, uint64_t avalsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETSOCKOPT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETSOCKOPT_RETURN 1
PPP_CB_TYPEDEF(void, on_getsockopt_return, CPUState* cpu, target_ulong pc, int32_t s, int32_t level, int32_t name, uint64_t val, uint64_t avalsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETTIMEOFDAY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETTIMEOFDAY_ENTER 1
PPP_CB_TYPEDEF(void, on_gettimeofday_enter, CPUState* cpu, target_ulong pc, uint64_t tp, uint64_t tzp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETTIMEOFDAY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETTIMEOFDAY_RETURN 1
PPP_CB_TYPEDEF(void, on_gettimeofday_return, CPUState* cpu, target_ulong pc, uint64_t tp, uint64_t tzp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GETUID_ENTER 1
PPP_CB_TYPEDEF(void, on_getuid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GETUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GETUID_RETURN 1
PPP_CB_TYPEDEF(void, on_getuid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GSSD_SYSCALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_GSSD_SYSCALL_ENTER 1
PPP_CB_TYPEDEF(void, on_gssd_syscall_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_GSSD_SYSCALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_GSSD_SYSCALL_RETURN 1
PPP_CB_TYPEDEF(void, on_gssd_syscall_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_IOCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_IOCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_ioctl_enter, CPUState* cpu, target_ulong pc, int32_t fd, int64_t com, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_IOCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_IOCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_ioctl_return, CPUState* cpu, target_ulong pc, int32_t fd, int64_t com, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ISSETUGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_ISSETUGID_ENTER 1
PPP_CB_TYPEDEF(void, on_issetugid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_ISSETUGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_ISSETUGID_RETURN 1
PPP_CB_TYPEDEF(void, on_issetugid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_JAIL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_JAIL_ENTER 1
PPP_CB_TYPEDEF(void, on_jail_enter, CPUState* cpu, target_ulong pc, uint64_t jail);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_JAIL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_JAIL_RETURN 1
PPP_CB_TYPEDEF(void, on_jail_return, CPUState* cpu, target_ulong pc, uint64_t jail);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_JAIL_ATTACH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_JAIL_ATTACH_ENTER 1
PPP_CB_TYPEDEF(void, on_jail_attach_enter, CPUState* cpu, target_ulong pc, int32_t jid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_JAIL_ATTACH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_JAIL_ATTACH_RETURN 1
PPP_CB_TYPEDEF(void, on_jail_attach_return, CPUState* cpu, target_ulong pc, int32_t jid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_JAIL_GET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_JAIL_GET_ENTER 1
PPP_CB_TYPEDEF(void, on_jail_get_enter, CPUState* cpu, target_ulong pc, uint64_t iovp, uint32_t iovcnt, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_JAIL_GET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_JAIL_GET_RETURN 1
PPP_CB_TYPEDEF(void, on_jail_get_return, CPUState* cpu, target_ulong pc, uint64_t iovp, uint32_t iovcnt, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_JAIL_REMOVE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_JAIL_REMOVE_ENTER 1
PPP_CB_TYPEDEF(void, on_jail_remove_enter, CPUState* cpu, target_ulong pc, int32_t jid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_JAIL_REMOVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_JAIL_REMOVE_RETURN 1
PPP_CB_TYPEDEF(void, on_jail_remove_return, CPUState* cpu, target_ulong pc, int32_t jid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_JAIL_SET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_JAIL_SET_ENTER 1
PPP_CB_TYPEDEF(void, on_jail_set_enter, CPUState* cpu, target_ulong pc, uint64_t iovp, uint32_t iovcnt, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_JAIL_SET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_JAIL_SET_RETURN 1
PPP_CB_TYPEDEF(void, on_jail_set_return, CPUState* cpu, target_ulong pc, uint64_t iovp, uint32_t iovcnt, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KENV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KENV_ENTER 1
PPP_CB_TYPEDEF(void, on_kenv_enter, CPUState* cpu, target_ulong pc, int32_t what, uint64_t name, uint64_t value, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KENV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KENV_RETURN 1
PPP_CB_TYPEDEF(void, on_kenv_return, CPUState* cpu, target_ulong pc, int32_t what, uint64_t name, uint64_t value, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_kevent_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t changelist, int32_t nchanges, uint64_t eventlist, int32_t nevents, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_kevent_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t changelist, int32_t nchanges, uint64_t eventlist, int32_t nevents, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KILL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KILL_ENTER 1
PPP_CB_TYPEDEF(void, on_kill_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t signum);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KILL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KILL_RETURN 1
PPP_CB_TYPEDEF(void, on_kill_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t signum);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KILLPG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KILLPG_ENTER 1
PPP_CB_TYPEDEF(void, on_killpg_enter, CPUState* cpu, target_ulong pc, int32_t pgid, int32_t signum);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KILLPG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KILLPG_RETURN 1
PPP_CB_TYPEDEF(void, on_killpg_return, CPUState* cpu, target_ulong pc, int32_t pgid, int32_t signum);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDFIND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KLDFIND_ENTER 1
PPP_CB_TYPEDEF(void, on_kldfind_enter, CPUState* cpu, target_ulong pc, uint64_t file);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDFIND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KLDFIND_RETURN 1
PPP_CB_TYPEDEF(void, on_kldfind_return, CPUState* cpu, target_ulong pc, uint64_t file);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDFIRSTMOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KLDFIRSTMOD_ENTER 1
PPP_CB_TYPEDEF(void, on_kldfirstmod_enter, CPUState* cpu, target_ulong pc, int32_t fileid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDFIRSTMOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KLDFIRSTMOD_RETURN 1
PPP_CB_TYPEDEF(void, on_kldfirstmod_return, CPUState* cpu, target_ulong pc, int32_t fileid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDLOAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KLDLOAD_ENTER 1
PPP_CB_TYPEDEF(void, on_kldload_enter, CPUState* cpu, target_ulong pc, uint64_t file);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDLOAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KLDLOAD_RETURN 1
PPP_CB_TYPEDEF(void, on_kldload_return, CPUState* cpu, target_ulong pc, uint64_t file);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDNEXT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KLDNEXT_ENTER 1
PPP_CB_TYPEDEF(void, on_kldnext_enter, CPUState* cpu, target_ulong pc, int32_t fileid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDNEXT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KLDNEXT_RETURN 1
PPP_CB_TYPEDEF(void, on_kldnext_return, CPUState* cpu, target_ulong pc, int32_t fileid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KLDSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_kldstat_enter, CPUState* cpu, target_ulong pc, int32_t fileid, uint64_t stat);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KLDSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_kldstat_return, CPUState* cpu, target_ulong pc, int32_t fileid, uint64_t stat);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDSYM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KLDSYM_ENTER 1
PPP_CB_TYPEDEF(void, on_kldsym_enter, CPUState* cpu, target_ulong pc, int32_t fileid, int32_t cmd, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDSYM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KLDSYM_RETURN 1
PPP_CB_TYPEDEF(void, on_kldsym_return, CPUState* cpu, target_ulong pc, int32_t fileid, int32_t cmd, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDUNLOAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KLDUNLOAD_ENTER 1
PPP_CB_TYPEDEF(void, on_kldunload_enter, CPUState* cpu, target_ulong pc, int32_t fileid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDUNLOAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KLDUNLOAD_RETURN 1
PPP_CB_TYPEDEF(void, on_kldunload_return, CPUState* cpu, target_ulong pc, int32_t fileid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDUNLOADF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KLDUNLOADF_ENTER 1
PPP_CB_TYPEDEF(void, on_kldunloadf_enter, CPUState* cpu, target_ulong pc, int32_t fileid, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KLDUNLOADF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KLDUNLOADF_RETURN 1
PPP_CB_TYPEDEF(void, on_kldunloadf_return, CPUState* cpu, target_ulong pc, int32_t fileid, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_NOTIFY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_NOTIFY_ENTER 1
PPP_CB_TYPEDEF(void, on_kmq_notify_enter, CPUState* cpu, target_ulong pc, int32_t mqd, uint64_t sigev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_NOTIFY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_NOTIFY_RETURN 1
PPP_CB_TYPEDEF(void, on_kmq_notify_return, CPUState* cpu, target_ulong pc, int32_t mqd, uint64_t sigev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_kmq_open_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t flags, uint32_t mode, uint64_t attr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_kmq_open_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t flags, uint32_t mode, uint64_t attr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_SETATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_SETATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_kmq_setattr_enter, CPUState* cpu, target_ulong pc, int32_t mqd, uint64_t attr, uint64_t oattr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_SETATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_SETATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_kmq_setattr_return, CPUState* cpu, target_ulong pc, int32_t mqd, uint64_t attr, uint64_t oattr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_TIMEDRECEIVE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_TIMEDRECEIVE_ENTER 1
PPP_CB_TYPEDEF(void, on_kmq_timedreceive_enter, CPUState* cpu, target_ulong pc, int32_t mqd, uint64_t msg_ptr, uint32_t msg_len, uint64_t msg_prio, uint64_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_TIMEDRECEIVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_TIMEDRECEIVE_RETURN 1
PPP_CB_TYPEDEF(void, on_kmq_timedreceive_return, CPUState* cpu, target_ulong pc, int32_t mqd, uint64_t msg_ptr, uint32_t msg_len, uint64_t msg_prio, uint64_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_TIMEDSEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_TIMEDSEND_ENTER 1
PPP_CB_TYPEDEF(void, on_kmq_timedsend_enter, CPUState* cpu, target_ulong pc, int32_t mqd, uint64_t msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint64_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_TIMEDSEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_TIMEDSEND_RETURN 1
PPP_CB_TYPEDEF(void, on_kmq_timedsend_return, CPUState* cpu, target_ulong pc, int32_t mqd, uint64_t msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint64_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_UNLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_UNLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_kmq_unlink_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KMQ_UNLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KMQ_UNLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_kmq_unlink_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KQUEUE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KQUEUE_ENTER 1
PPP_CB_TYPEDEF(void, on_kqueue_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KQUEUE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KQUEUE_RETURN 1
PPP_CB_TYPEDEF(void, on_kqueue_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_CLOSE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_CLOSE_ENTER 1
PPP_CB_TYPEDEF(void, on_ksem_close_enter, CPUState* cpu, target_ulong pc, uint32_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_CLOSE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_CLOSE_RETURN 1
PPP_CB_TYPEDEF(void, on_ksem_close_return, CPUState* cpu, target_ulong pc, uint32_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_DESTROY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_DESTROY_ENTER 1
PPP_CB_TYPEDEF(void, on_ksem_destroy_enter, CPUState* cpu, target_ulong pc, uint32_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_DESTROY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_DESTROY_RETURN 1
PPP_CB_TYPEDEF(void, on_ksem_destroy_return, CPUState* cpu, target_ulong pc, uint32_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_GETVALUE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_GETVALUE_ENTER 1
PPP_CB_TYPEDEF(void, on_ksem_getvalue_enter, CPUState* cpu, target_ulong pc, uint32_t id, uint64_t val);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_GETVALUE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_GETVALUE_RETURN 1
PPP_CB_TYPEDEF(void, on_ksem_getvalue_return, CPUState* cpu, target_ulong pc, uint32_t id, uint64_t val);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_INIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_INIT_ENTER 1
PPP_CB_TYPEDEF(void, on_ksem_init_enter, CPUState* cpu, target_ulong pc, uint64_t idp, uint32_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_INIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_INIT_RETURN 1
PPP_CB_TYPEDEF(void, on_ksem_init_return, CPUState* cpu, target_ulong pc, uint64_t idp, uint32_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_ksem_open_enter, CPUState* cpu, target_ulong pc, uint64_t idp, uint64_t name, int32_t oflag, uint32_t mode, uint32_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_ksem_open_return, CPUState* cpu, target_ulong pc, uint64_t idp, uint64_t name, int32_t oflag, uint32_t mode, uint32_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_POST_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_POST_ENTER 1
PPP_CB_TYPEDEF(void, on_ksem_post_enter, CPUState* cpu, target_ulong pc, uint32_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_POST_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_POST_RETURN 1
PPP_CB_TYPEDEF(void, on_ksem_post_return, CPUState* cpu, target_ulong pc, uint32_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_TIMEDWAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_TIMEDWAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_ksem_timedwait_enter, CPUState* cpu, target_ulong pc, uint32_t id, uint64_t abstime);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_TIMEDWAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_TIMEDWAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_ksem_timedwait_return, CPUState* cpu, target_ulong pc, uint32_t id, uint64_t abstime);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_TRYWAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_TRYWAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_ksem_trywait_enter, CPUState* cpu, target_ulong pc, uint32_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_TRYWAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_TRYWAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_ksem_trywait_return, CPUState* cpu, target_ulong pc, uint32_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_UNLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_UNLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_ksem_unlink_enter, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_UNLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_UNLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_ksem_unlink_return, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_WAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_WAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_ksem_wait_enter, CPUState* cpu, target_ulong pc, uint32_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KSEM_WAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KSEM_WAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_ksem_wait_return, CPUState* cpu, target_ulong pc, uint32_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTIMER_CREATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KTIMER_CREATE_ENTER 1
PPP_CB_TYPEDEF(void, on_ktimer_create_enter, CPUState* cpu, target_ulong pc, uint32_t clock_id, uint64_t evp, uint64_t timerid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTIMER_CREATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KTIMER_CREATE_RETURN 1
PPP_CB_TYPEDEF(void, on_ktimer_create_return, CPUState* cpu, target_ulong pc, uint32_t clock_id, uint64_t evp, uint64_t timerid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTIMER_DELETE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KTIMER_DELETE_ENTER 1
PPP_CB_TYPEDEF(void, on_ktimer_delete_enter, CPUState* cpu, target_ulong pc, int32_t timerid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTIMER_DELETE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KTIMER_DELETE_RETURN 1
PPP_CB_TYPEDEF(void, on_ktimer_delete_return, CPUState* cpu, target_ulong pc, int32_t timerid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTIMER_GETOVERRUN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KTIMER_GETOVERRUN_ENTER 1
PPP_CB_TYPEDEF(void, on_ktimer_getoverrun_enter, CPUState* cpu, target_ulong pc, int32_t timerid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTIMER_GETOVERRUN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KTIMER_GETOVERRUN_RETURN 1
PPP_CB_TYPEDEF(void, on_ktimer_getoverrun_return, CPUState* cpu, target_ulong pc, int32_t timerid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTIMER_GETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KTIMER_GETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_ktimer_gettime_enter, CPUState* cpu, target_ulong pc, int32_t timerid, uint64_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTIMER_GETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KTIMER_GETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_ktimer_gettime_return, CPUState* cpu, target_ulong pc, int32_t timerid, uint64_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTIMER_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KTIMER_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_ktimer_settime_enter, CPUState* cpu, target_ulong pc, int32_t timerid, int32_t flags, uint64_t value, uint64_t ovalue);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTIMER_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KTIMER_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_ktimer_settime_return, CPUState* cpu, target_ulong pc, int32_t timerid, int32_t flags, uint64_t value, uint64_t ovalue);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTRACE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_KTRACE_ENTER 1
PPP_CB_TYPEDEF(void, on_ktrace_enter, CPUState* cpu, target_ulong pc, uint64_t fname, int32_t ops, int32_t facs, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_KTRACE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_KTRACE_RETURN 1
PPP_CB_TYPEDEF(void, on_ktrace_return, CPUState* cpu, target_ulong pc, uint64_t fname, int32_t ops, int32_t facs, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LCHFLAGS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LCHFLAGS_ENTER 1
PPP_CB_TYPEDEF(void, on_lchflags_enter, CPUState* cpu, target_ulong pc, uint64_t path, int64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LCHFLAGS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LCHFLAGS_RETURN 1
PPP_CB_TYPEDEF(void, on_lchflags_return, CPUState* cpu, target_ulong pc, uint64_t path, int64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LCHMOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LCHMOD_ENTER 1
PPP_CB_TYPEDEF(void, on_lchmod_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LCHMOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LCHMOD_RETURN 1
PPP_CB_TYPEDEF(void, on_lchmod_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LCHOWN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LCHOWN_ENTER 1
PPP_CB_TYPEDEF(void, on_lchown_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t uid, int32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LCHOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LCHOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_lchown_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t uid, int32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LGETFH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LGETFH_ENTER 1
PPP_CB_TYPEDEF(void, on_lgetfh_enter, CPUState* cpu, target_ulong pc, uint64_t fname, uint64_t fhp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LGETFH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LGETFH_RETURN 1
PPP_CB_TYPEDEF(void, on_lgetfh_return, CPUState* cpu, target_ulong pc, uint64_t fname, uint64_t fhp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LINK_ENTER 1
PPP_CB_TYPEDEF(void, on_link_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t link);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LINK_RETURN 1
PPP_CB_TYPEDEF(void, on_link_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t link);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_linkat_enter, CPUState* cpu, target_ulong pc, int32_t fd1, uint64_t path1, int32_t fd2, uint64_t path2, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_linkat_return, CPUState* cpu, target_ulong pc, int32_t fd1, uint64_t path1, int32_t fd2, uint64_t path2, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LIO_LISTIO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LIO_LISTIO_ENTER 1
PPP_CB_TYPEDEF(void, on_lio_listio_enter, CPUState* cpu, target_ulong pc, int32_t mode, uint64_t acb_list, int32_t nent, uint64_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LIO_LISTIO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LIO_LISTIO_RETURN 1
PPP_CB_TYPEDEF(void, on_lio_listio_return, CPUState* cpu, target_ulong pc, int32_t mode, uint64_t acb_list, int32_t nent, uint64_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LISTEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LISTEN_ENTER 1
PPP_CB_TYPEDEF(void, on_listen_enter, CPUState* cpu, target_ulong pc, int32_t s, int32_t backlog);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LISTEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LISTEN_RETURN 1
PPP_CB_TYPEDEF(void, on_listen_return, CPUState* cpu, target_ulong pc, int32_t s, int32_t backlog);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LPATHCONF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LPATHCONF_ENTER 1
PPP_CB_TYPEDEF(void, on_lpathconf_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LPATHCONF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LPATHCONF_RETURN 1
PPP_CB_TYPEDEF(void, on_lpathconf_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LSEEK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LSEEK_ENTER 1
PPP_CB_TYPEDEF(void, on_lseek_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, int32_t whence);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LSEEK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LSEEK_RETURN 1
PPP_CB_TYPEDEF(void, on_lseek_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, int32_t whence);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_lstat_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t ub);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_lstat_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t ub);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LUTIMES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_LUTIMES_ENTER 1
PPP_CB_TYPEDEF(void, on_lutimes_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t tptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_LUTIMES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_LUTIMES_RETURN 1
PPP_CB_TYPEDEF(void, on_lutimes_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t tptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MAC_SYSCALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MAC_SYSCALL_ENTER 1
PPP_CB_TYPEDEF(void, on_mac_syscall_enter, CPUState* cpu, target_ulong pc, uint64_t policy, int32_t call, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MAC_SYSCALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MAC_SYSCALL_RETURN 1
PPP_CB_TYPEDEF(void, on_mac_syscall_return, CPUState* cpu, target_ulong pc, uint64_t policy, int32_t call, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MADVISE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MADVISE_ENTER 1
PPP_CB_TYPEDEF(void, on_madvise_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len, int32_t behav);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MADVISE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MADVISE_RETURN 1
PPP_CB_TYPEDEF(void, on_madvise_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len, int32_t behav);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MINCORE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MINCORE_ENTER 1
PPP_CB_TYPEDEF(void, on_mincore_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len, uint64_t vec);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MINCORE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MINCORE_RETURN 1
PPP_CB_TYPEDEF(void, on_mincore_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len, uint64_t vec);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MINHERIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MINHERIT_ENTER 1
PPP_CB_TYPEDEF(void, on_minherit_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len, int32_t inherit);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MINHERIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MINHERIT_RETURN 1
PPP_CB_TYPEDEF(void, on_minherit_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len, int32_t inherit);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MKDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_mkdir_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MKDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_mkdir_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKDIRAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MKDIRAT_ENTER 1
PPP_CB_TYPEDEF(void, on_mkdirat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKDIRAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MKDIRAT_RETURN 1
PPP_CB_TYPEDEF(void, on_mkdirat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKFIFO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MKFIFO_ENTER 1
PPP_CB_TYPEDEF(void, on_mkfifo_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKFIFO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MKFIFO_RETURN 1
PPP_CB_TYPEDEF(void, on_mkfifo_return, CPUState* cpu, target_ulong pc, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKFIFOAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MKFIFOAT_ENTER 1
PPP_CB_TYPEDEF(void, on_mkfifoat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKFIFOAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MKFIFOAT_RETURN 1
PPP_CB_TYPEDEF(void, on_mkfifoat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKNOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MKNOD_ENTER 1
PPP_CB_TYPEDEF(void, on_mknod_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t mode, int32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKNOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MKNOD_RETURN 1
PPP_CB_TYPEDEF(void, on_mknod_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t mode, int32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKNODAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MKNODAT_ENTER 1
PPP_CB_TYPEDEF(void, on_mknodat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t mode, uint32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MKNODAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MKNODAT_RETURN 1
PPP_CB_TYPEDEF(void, on_mknodat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint32_t mode, uint32_t dev);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_mlock_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_mlock_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MLOCKALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MLOCKALL_ENTER 1
PPP_CB_TYPEDEF(void, on_mlockall_enter, CPUState* cpu, target_ulong pc, int32_t how);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MLOCKALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MLOCKALL_RETURN 1
PPP_CB_TYPEDEF(void, on_mlockall_return, CPUState* cpu, target_ulong pc, int32_t how);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MODFIND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MODFIND_ENTER 1
PPP_CB_TYPEDEF(void, on_modfind_enter, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MODFIND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MODFIND_RETURN 1
PPP_CB_TYPEDEF(void, on_modfind_return, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MODFNEXT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MODFNEXT_ENTER 1
PPP_CB_TYPEDEF(void, on_modfnext_enter, CPUState* cpu, target_ulong pc, int32_t modid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MODFNEXT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MODFNEXT_RETURN 1
PPP_CB_TYPEDEF(void, on_modfnext_return, CPUState* cpu, target_ulong pc, int32_t modid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MODNEXT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MODNEXT_ENTER 1
PPP_CB_TYPEDEF(void, on_modnext_enter, CPUState* cpu, target_ulong pc, int32_t modid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MODNEXT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MODNEXT_RETURN 1
PPP_CB_TYPEDEF(void, on_modnext_return, CPUState* cpu, target_ulong pc, int32_t modid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MODSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MODSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_modstat_enter, CPUState* cpu, target_ulong pc, int32_t modid, uint64_t stat);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MODSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MODSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_modstat_return, CPUState* cpu, target_ulong pc, int32_t modid, uint64_t stat);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MOUNT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MOUNT_ENTER 1
PPP_CB_TYPEDEF(void, on_mount_enter, CPUState* cpu, target_ulong pc, uint64_t type, uint64_t path, int32_t flags, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_mount_return, CPUState* cpu, target_ulong pc, uint64_t type, uint64_t path, int32_t flags, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MPROTECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MPROTECT_ENTER 1
PPP_CB_TYPEDEF(void, on_mprotect_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len, int32_t prot);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MPROTECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MPROTECT_RETURN 1
PPP_CB_TYPEDEF(void, on_mprotect_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len, int32_t prot);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MSGCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MSGCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_msgctl_enter, CPUState* cpu, target_ulong pc, int32_t msqid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MSGCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MSGCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_msgctl_return, CPUState* cpu, target_ulong pc, int32_t msqid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MSGGET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MSGGET_ENTER 1
PPP_CB_TYPEDEF(void, on_msgget_enter, CPUState* cpu, target_ulong pc, uint32_t key, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MSGGET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MSGGET_RETURN 1
PPP_CB_TYPEDEF(void, on_msgget_return, CPUState* cpu, target_ulong pc, uint32_t key, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MSGRCV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MSGRCV_ENTER 1
PPP_CB_TYPEDEF(void, on_msgrcv_enter, CPUState* cpu, target_ulong pc, int32_t msqid, uint64_t msgp, uint32_t msgsz, int64_t msgtyp, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MSGRCV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MSGRCV_RETURN 1
PPP_CB_TYPEDEF(void, on_msgrcv_return, CPUState* cpu, target_ulong pc, int32_t msqid, uint64_t msgp, uint32_t msgsz, int64_t msgtyp, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MSGSND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MSGSND_ENTER 1
PPP_CB_TYPEDEF(void, on_msgsnd_enter, CPUState* cpu, target_ulong pc, int32_t msqid, uint64_t msgp, uint32_t msgsz, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MSGSND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MSGSND_RETURN 1
PPP_CB_TYPEDEF(void, on_msgsnd_return, CPUState* cpu, target_ulong pc, int32_t msqid, uint64_t msgp, uint32_t msgsz, int32_t msgflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MSYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MSYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_msync_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MSYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MSYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_msync_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MUNLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MUNLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_munlock_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MUNLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MUNLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_munlock_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MUNMAP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_MUNMAP_ENTER 1
PPP_CB_TYPEDEF(void, on_munmap_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_MUNMAP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_MUNMAP_RETURN 1
PPP_CB_TYPEDEF(void, on_munmap_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NANOSLEEP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NANOSLEEP_ENTER 1
PPP_CB_TYPEDEF(void, on_nanosleep_enter, CPUState* cpu, target_ulong pc, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NANOSLEEP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NANOSLEEP_RETURN 1
PPP_CB_TYPEDEF(void, on_nanosleep_return, CPUState* cpu, target_ulong pc, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NFSSVC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NFSSVC_ENTER 1
PPP_CB_TYPEDEF(void, on_nfssvc_enter, CPUState* cpu, target_ulong pc, int32_t flag, uint64_t argp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NFSSVC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NFSSVC_RETURN 1
PPP_CB_TYPEDEF(void, on_nfssvc_return, CPUState* cpu, target_ulong pc, int32_t flag, uint64_t argp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NFSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NFSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_nfstat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t sb);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NFSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NFSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_nfstat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t sb);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NLM_SYSCALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NLM_SYSCALL_ENTER 1
PPP_CB_TYPEDEF(void, on_nlm_syscall_enter, CPUState* cpu, target_ulong pc, int32_t debug_level, int32_t grace_period, int32_t addr_count, uint64_t addrs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NLM_SYSCALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NLM_SYSCALL_RETURN 1
PPP_CB_TYPEDEF(void, on_nlm_syscall_return, CPUState* cpu, target_ulong pc, int32_t debug_level, int32_t grace_period, int32_t addr_count, uint64_t addrs);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NLSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NLSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_nlstat_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t ub);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NLSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NLSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_nlstat_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t ub);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NMOUNT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NMOUNT_ENTER 1
PPP_CB_TYPEDEF(void, on_nmount_enter, CPUState* cpu, target_ulong pc, uint64_t iovp, uint32_t iovcnt, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NMOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NMOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_nmount_return, CPUState* cpu, target_ulong pc, uint64_t iovp, uint32_t iovcnt, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NNPFS_SYSCALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NNPFS_SYSCALL_ENTER 1
PPP_CB_TYPEDEF(void, on_nnpfs_syscall_enter, CPUState* cpu, target_ulong pc, int32_t operation, uint64_t a_pathP, int32_t a_opcode, uint64_t a_paramsP, int32_t a_followSymlinks);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NNPFS_SYSCALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NNPFS_SYSCALL_RETURN 1
PPP_CB_TYPEDEF(void, on_nnpfs_syscall_return, CPUState* cpu, target_ulong pc, int32_t operation, uint64_t a_pathP, int32_t a_opcode, uint64_t a_paramsP, int32_t a_followSymlinks);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NOSYS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NOSYS_ENTER 1
PPP_CB_TYPEDEF(void, on_nosys_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NOSYS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NOSYS_RETURN 1
PPP_CB_TYPEDEF(void, on_nosys_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NSTAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NSTAT_ENTER 1
PPP_CB_TYPEDEF(void, on_nstat_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t ub);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NSTAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NSTAT_RETURN 1
PPP_CB_TYPEDEF(void, on_nstat_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t ub);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCEPTCONNECTPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCEPTCONNECTPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAcceptConnectPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortContext, uint64_t ConnectionRequest, uint32_t AcceptConnection, uint64_t ServerView, uint64_t ClientView);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCEPTCONNECTPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCEPTCONNECTPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAcceptConnectPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortContext, uint64_t ConnectionRequest, uint32_t AcceptConnection, uint64_t ServerView, uint64_t ClientView);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECK_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAccessCheck_enter, CPUState* cpu, target_ulong pc, uint64_t SecurityDescriptor, uint64_t ClientToken, uint32_t DesiredAccess, uint64_t GenericMapping, uint64_t PrivilegeSet, uint64_t PrivilegeSetLength, uint64_t GrantedAccess, uint64_t AccessStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECK_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAccessCheck_return, CPUState* cpu, target_ulong pc, uint64_t SecurityDescriptor, uint64_t ClientToken, uint32_t DesiredAccess, uint64_t GenericMapping, uint64_t PrivilegeSet, uint64_t PrivilegeSetLength, uint64_t GrantedAccess, uint64_t AccessStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKANDAUDITALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKANDAUDITALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckAndAuditAlarm_enter, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ObjectTypeName, uint64_t ObjectName, uint64_t SecurityDescriptor, uint32_t DesiredAccess, uint64_t GenericMapping, uint32_t ObjectCreation, uint64_t GrantedAccess, uint64_t AccessStatus, uint64_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKANDAUDITALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKANDAUDITALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckAndAuditAlarm_return, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ObjectTypeName, uint64_t ObjectName, uint64_t SecurityDescriptor, uint32_t DesiredAccess, uint64_t GenericMapping, uint32_t ObjectCreation, uint64_t GrantedAccess, uint64_t AccessStatus, uint64_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckByType_enter, CPUState* cpu, target_ulong pc, uint64_t SecurityDescriptor, uint64_t PrincipalSelfSid, uint64_t ClientToken, uint32_t DesiredAccess, uint64_t ObjectTypeList, uint32_t ObjectTypeListLength, uint64_t GenericMapping, uint64_t PrivilegeSet, uint64_t PrivilegeSetLength, uint64_t GrantedAccess, uint64_t AccessStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckByType_return, CPUState* cpu, target_ulong pc, uint64_t SecurityDescriptor, uint64_t PrincipalSelfSid, uint64_t ClientToken, uint32_t DesiredAccess, uint64_t ObjectTypeList, uint32_t ObjectTypeListLength, uint64_t GenericMapping, uint64_t PrivilegeSet, uint64_t PrivilegeSetLength, uint64_t GrantedAccess, uint64_t AccessStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPEANDAUDITALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPEANDAUDITALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckByTypeAndAuditAlarm_enter, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ObjectTypeName, uint64_t ObjectName, uint64_t SecurityDescriptor, uint64_t PrincipalSelfSid, uint32_t DesiredAccess, uint32_t AuditType, uint32_t Flags, uint64_t ObjectTypeList, uint32_t ObjectTypeListLength, uint64_t GenericMapping, uint32_t ObjectCreation, uint64_t GrantedAccess, uint64_t AccessStatus, uint64_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPEANDAUDITALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPEANDAUDITALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckByTypeAndAuditAlarm_return, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ObjectTypeName, uint64_t ObjectName, uint64_t SecurityDescriptor, uint64_t PrincipalSelfSid, uint32_t DesiredAccess, uint32_t AuditType, uint32_t Flags, uint64_t ObjectTypeList, uint32_t ObjectTypeListLength, uint64_t GenericMapping, uint32_t ObjectCreation, uint64_t GrantedAccess, uint64_t AccessStatus, uint64_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLIST_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLIST_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckByTypeResultList_enter, CPUState* cpu, target_ulong pc, uint64_t SecurityDescriptor, uint64_t PrincipalSelfSid, uint64_t ClientToken, uint32_t DesiredAccess, uint64_t ObjectTypeList, uint32_t ObjectTypeListLength, uint64_t GenericMapping, uint64_t PrivilegeSet, uint64_t PrivilegeSetLength, uint64_t GrantedAccess, uint64_t AccessStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLIST_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLIST_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckByTypeResultList_return, CPUState* cpu, target_ulong pc, uint64_t SecurityDescriptor, uint64_t PrincipalSelfSid, uint64_t ClientToken, uint32_t DesiredAccess, uint64_t ObjectTypeList, uint32_t ObjectTypeListLength, uint64_t GenericMapping, uint64_t PrivilegeSet, uint64_t PrivilegeSetLength, uint64_t GrantedAccess, uint64_t AccessStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckByTypeResultListAndAuditAlarm_enter, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ObjectTypeName, uint64_t ObjectName, uint64_t SecurityDescriptor, uint64_t PrincipalSelfSid, uint32_t DesiredAccess, uint32_t AuditType, uint32_t Flags, uint64_t ObjectTypeList, uint32_t ObjectTypeListLength, uint64_t GenericMapping, uint32_t ObjectCreation, uint64_t GrantedAccess, uint64_t AccessStatus, uint64_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckByTypeResultListAndAuditAlarm_return, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ObjectTypeName, uint64_t ObjectName, uint64_t SecurityDescriptor, uint64_t PrincipalSelfSid, uint32_t DesiredAccess, uint32_t AuditType, uint32_t Flags, uint64_t ObjectTypeList, uint32_t ObjectTypeListLength, uint64_t GenericMapping, uint32_t ObjectCreation, uint64_t GrantedAccess, uint64_t AccessStatus, uint64_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARMBYHANDLE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARMBYHANDLE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckByTypeResultListAndAuditAlarmByHandle_enter, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ClientToken, uint64_t ObjectTypeName, uint64_t ObjectName, uint64_t SecurityDescriptor, uint64_t PrincipalSelfSid, uint32_t DesiredAccess, uint32_t AuditType, uint32_t Flags, uint64_t ObjectTypeList, uint32_t ObjectTypeListLength, uint64_t GenericMapping, uint32_t ObjectCreation, uint64_t GrantedAccess, uint64_t AccessStatus, uint64_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARMBYHANDLE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARMBYHANDLE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAccessCheckByTypeResultListAndAuditAlarmByHandle_return, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ClientToken, uint64_t ObjectTypeName, uint64_t ObjectName, uint64_t SecurityDescriptor, uint64_t PrincipalSelfSid, uint32_t DesiredAccess, uint32_t AuditType, uint32_t Flags, uint64_t ObjectTypeList, uint32_t ObjectTypeListLength, uint64_t GenericMapping, uint32_t ObjectCreation, uint64_t GrantedAccess, uint64_t AccessStatus, uint64_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTADDATOM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTADDATOM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAddAtom_enter, CPUState* cpu, target_ulong pc, uint64_t AtomName, uint32_t Length, uint64_t Atom);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTADDATOM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTADDATOM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAddAtom_return, CPUState* cpu, target_ulong pc, uint64_t AtomName, uint32_t Length, uint64_t Atom);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTADDBOOTENTRY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTADDBOOTENTRY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAddBootEntry_enter, CPUState* cpu, target_ulong pc, uint64_t BootEntry, uint64_t Id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTADDBOOTENTRY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTADDBOOTENTRY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAddBootEntry_return, CPUState* cpu, target_ulong pc, uint64_t BootEntry, uint64_t Id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTADDDRIVERENTRY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTADDDRIVERENTRY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAddDriverEntry_enter, CPUState* cpu, target_ulong pc, uint64_t DriverEntry, uint64_t Id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTADDDRIVERENTRY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTADDDRIVERENTRY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAddDriverEntry_return, CPUState* cpu, target_ulong pc, uint64_t DriverEntry, uint64_t Id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTADJUSTGROUPSTOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTADJUSTGROUPSTOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAdjustGroupsToken_enter, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint32_t ResetToDefault, uint64_t NewState, uint32_t BufferLength, uint64_t PreviousState, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTADJUSTGROUPSTOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTADJUSTGROUPSTOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAdjustGroupsToken_return, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint32_t ResetToDefault, uint64_t NewState, uint32_t BufferLength, uint64_t PreviousState, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTADJUSTPRIVILEGESTOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTADJUSTPRIVILEGESTOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAdjustPrivilegesToken_enter, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint32_t DisableAllPrivileges, uint64_t NewState, uint32_t BufferLength, uint64_t PreviousState, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTADJUSTPRIVILEGESTOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTADJUSTPRIVILEGESTOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAdjustPrivilegesToken_return, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint32_t DisableAllPrivileges, uint64_t NewState, uint32_t BufferLength, uint64_t PreviousState, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALERTRESUMETHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALERTRESUMETHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlertResumeThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t PreviousSuspendCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALERTRESUMETHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALERTRESUMETHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlertResumeThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t PreviousSuspendCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALERTTHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALERTTHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlertThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALERTTHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALERTTHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlertThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATELOCALLYUNIQUEID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATELOCALLYUNIQUEID_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAllocateLocallyUniqueId_enter, CPUState* cpu, target_ulong pc, uint64_t Luid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATELOCALLYUNIQUEID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATELOCALLYUNIQUEID_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAllocateLocallyUniqueId_return, CPUState* cpu, target_ulong pc, uint64_t Luid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATERESERVEOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATERESERVEOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAllocateReserveObject_enter, CPUState* cpu, target_ulong pc, uint64_t MemoryReserveHandle, uint64_t ObjectAttributes, uint32_t Type);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATERESERVEOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATERESERVEOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAllocateReserveObject_return, CPUState* cpu, target_ulong pc, uint64_t MemoryReserveHandle, uint64_t ObjectAttributes, uint32_t Type);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEUSERPHYSICALPAGES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEUSERPHYSICALPAGES_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAllocateUserPhysicalPages_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t NumberOfPages, uint64_t UserPfnArray);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEUSERPHYSICALPAGES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEUSERPHYSICALPAGES_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAllocateUserPhysicalPages_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t NumberOfPages, uint64_t UserPfnArray);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEUUIDS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEUUIDS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAllocateUuids_enter, CPUState* cpu, target_ulong pc, uint64_t Time, uint64_t Range, uint64_t Sequence, uint64_t Seed);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEUUIDS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEUUIDS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAllocateUuids_return, CPUState* cpu, target_ulong pc, uint64_t Time, uint64_t Range, uint64_t Sequence, uint64_t Seed);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEVIRTUALMEMORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEVIRTUALMEMORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAllocateVirtualMemory_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t ZeroBits, uint64_t RegionSize, uint32_t AllocationType, uint32_t Protect);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEVIRTUALMEMORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALLOCATEVIRTUALMEMORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAllocateVirtualMemory_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t ZeroBits, uint64_t RegionSize, uint32_t AllocationType, uint32_t Protect);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCACCEPTCONNECTPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCACCEPTCONNECTPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcAcceptConnectPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ConnectionPortHandle, uint32_t Flags, uint64_t ObjectAttributes, uint64_t PortAttributes, uint64_t PortContext, uint64_t ConnectionRequest, uint64_t ConnectionMessageAttributes, uint32_t AcceptConnection);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCACCEPTCONNECTPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCACCEPTCONNECTPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcAcceptConnectPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ConnectionPortHandle, uint32_t Flags, uint64_t ObjectAttributes, uint64_t PortAttributes, uint64_t PortContext, uint64_t ConnectionRequest, uint64_t ConnectionMessageAttributes, uint32_t AcceptConnection);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCANCELMESSAGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCANCELMESSAGE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcCancelMessage_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t MessageContext);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCANCELMESSAGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCANCELMESSAGE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcCancelMessage_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t MessageContext);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCONNECTPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCONNECTPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcConnectPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortName, uint64_t ObjectAttributes, uint64_t PortAttributes, uint32_t Flags, uint64_t RequiredServerSid, uint64_t ConnectionMessage, uint64_t BufferLength, uint64_t OutMessageAttributes, uint64_t InMessageAttributes, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCONNECTPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCONNECTPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcConnectPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortName, uint64_t ObjectAttributes, uint64_t PortAttributes, uint32_t Flags, uint64_t RequiredServerSid, uint64_t ConnectionMessage, uint64_t BufferLength, uint64_t OutMessageAttributes, uint64_t InMessageAttributes, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATEPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATEPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcCreatePort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ObjectAttributes, uint64_t PortAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATEPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATEPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcCreatePort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ObjectAttributes, uint64_t PortAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATEPORTSECTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATEPORTSECTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcCreatePortSection_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t SectionHandle, uint64_t SectionSize, uint64_t AlpcSectionHandle, uint64_t ActualSectionSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATEPORTSECTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATEPORTSECTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcCreatePortSection_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t SectionHandle, uint64_t SectionSize, uint64_t AlpcSectionHandle, uint64_t ActualSectionSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATERESOURCERESERVE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATERESOURCERESERVE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcCreateResourceReserve_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t MessageSize, uint64_t ResourceId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATERESOURCERESERVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATERESOURCERESERVE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcCreateResourceReserve_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t MessageSize, uint64_t ResourceId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATESECTIONVIEW_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATESECTIONVIEW_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcCreateSectionView_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t ViewAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATESECTIONVIEW_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATESECTIONVIEW_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcCreateSectionView_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t ViewAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATESECURITYCONTEXT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATESECURITYCONTEXT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcCreateSecurityContext_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t SecurityAttribute);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATESECURITYCONTEXT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCCREATESECURITYCONTEXT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcCreateSecurityContext_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t SecurityAttribute);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETEPORTSECTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETEPORTSECTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcDeletePortSection_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t SectionHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETEPORTSECTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETEPORTSECTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcDeletePortSection_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t SectionHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETERESOURCERESERVE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETERESOURCERESERVE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcDeleteResourceReserve_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t ResourceId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETERESOURCERESERVE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETERESOURCERESERVE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcDeleteResourceReserve_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t ResourceId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETESECTIONVIEW_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETESECTIONVIEW_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcDeleteSectionView_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t ViewBase);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETESECTIONVIEW_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETESECTIONVIEW_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcDeleteSectionView_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t ViewBase);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETESECURITYCONTEXT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETESECURITYCONTEXT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcDeleteSecurityContext_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t ContextHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETESECURITYCONTEXT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCDELETESECURITYCONTEXT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcDeleteSecurityContext_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t ContextHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCDISCONNECTPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCDISCONNECTPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcDisconnectPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCDISCONNECTPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCDISCONNECTPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcDisconnectPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCIMPERSONATECLIENTOFPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCIMPERSONATECLIENTOFPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcImpersonateClientOfPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortMessage, uint64_t Reserved);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCIMPERSONATECLIENTOFPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCIMPERSONATECLIENTOFPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcImpersonateClientOfPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortMessage, uint64_t Reserved);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCOPENSENDERPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCOPENSENDERPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcOpenSenderProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t PortHandle, uint64_t PortMessage, uint32_t Flags, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCOPENSENDERPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCOPENSENDERPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcOpenSenderProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t PortHandle, uint64_t PortMessage, uint32_t Flags, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCOPENSENDERTHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCOPENSENDERTHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcOpenSenderThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t PortHandle, uint64_t PortMessage, uint32_t Flags, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCOPENSENDERTHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCOPENSENDERTHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcOpenSenderThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t PortHandle, uint64_t PortMessage, uint32_t Flags, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCQUERYINFORMATION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCQUERYINFORMATION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcQueryInformation_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t PortInformationClass, uint64_t PortInformation, uint32_t Length, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCQUERYINFORMATION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCQUERYINFORMATION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcQueryInformation_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t PortInformationClass, uint64_t PortInformation, uint32_t Length, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCQUERYINFORMATIONMESSAGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCQUERYINFORMATIONMESSAGE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcQueryInformationMessage_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortMessage, uint32_t MessageInformationClass, uint64_t MessageInformation, uint32_t Length, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCQUERYINFORMATIONMESSAGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCQUERYINFORMATIONMESSAGE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcQueryInformationMessage_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortMessage, uint32_t MessageInformationClass, uint64_t MessageInformation, uint32_t Length, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCREVOKESECURITYCONTEXT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCREVOKESECURITYCONTEXT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcRevokeSecurityContext_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t ContextHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCREVOKESECURITYCONTEXT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCREVOKESECURITYCONTEXT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcRevokeSecurityContext_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t ContextHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCSENDWAITRECEIVEPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCSENDWAITRECEIVEPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcSendWaitReceivePort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t SendMessage, uint64_t SendMessageAttributes, uint64_t ReceiveMessage, uint64_t BufferLength, uint64_t ReceiveMessageAttributes, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCSENDWAITRECEIVEPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCSENDWAITRECEIVEPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcSendWaitReceivePort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t Flags, uint64_t SendMessage, uint64_t SendMessageAttributes, uint64_t ReceiveMessage, uint64_t BufferLength, uint64_t ReceiveMessageAttributes, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCSETINFORMATION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCSETINFORMATION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAlpcSetInformation_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t PortInformationClass, uint64_t PortInformation, uint32_t Length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTALPCSETINFORMATION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTALPCSETINFORMATION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAlpcSetInformation_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t PortInformationClass, uint64_t PortInformation, uint32_t Length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTAPPHELPCACHECONTROL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTAPPHELPCACHECONTROL_ENTER 1
PPP_CB_TYPEDEF(void, on_NtApphelpCacheControl_enter, CPUState* cpu, target_ulong pc, uint32_t type, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTAPPHELPCACHECONTROL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTAPPHELPCACHECONTROL_RETURN 1
PPP_CB_TYPEDEF(void, on_NtApphelpCacheControl_return, CPUState* cpu, target_ulong pc, uint32_t type, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTAREMAPPEDFILESTHESAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTAREMAPPEDFILESTHESAME_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAreMappedFilesTheSame_enter, CPUState* cpu, target_ulong pc, uint64_t File1MappedAsAnImage, uint64_t File2MappedAsFile);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTAREMAPPEDFILESTHESAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTAREMAPPEDFILESTHESAME_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAreMappedFilesTheSame_return, CPUState* cpu, target_ulong pc, uint64_t File1MappedAsAnImage, uint64_t File2MappedAsFile);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTASSIGNPROCESSTOJOBOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTASSIGNPROCESSTOJOBOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtAssignProcessToJobObject_enter, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint64_t ProcessHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTASSIGNPROCESSTOJOBOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTASSIGNPROCESSTOJOBOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtAssignProcessToJobObject_return, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint64_t ProcessHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCALLBACKRETURN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCALLBACKRETURN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCallbackReturn_enter, CPUState* cpu, target_ulong pc, uint64_t OutputBuffer, uint32_t OutputLength, uint32_t Status);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCALLBACKRETURN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCALLBACKRETURN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCallbackReturn_return, CPUState* cpu, target_ulong pc, uint64_t OutputBuffer, uint32_t OutputLength, uint32_t Status);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCANCELIOFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCANCELIOFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCancelIoFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCANCELIOFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCANCELIOFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCancelIoFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCANCELIOFILEEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCANCELIOFILEEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCancelIoFileEx_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoRequestToCancel, uint64_t IoStatusBlock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCANCELIOFILEEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCANCELIOFILEEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCancelIoFileEx_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoRequestToCancel, uint64_t IoStatusBlock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCANCELSYNCHRONOUSIOFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCANCELSYNCHRONOUSIOFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCancelSynchronousIoFile_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t IoRequestToCancel, uint64_t IoStatusBlock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCANCELSYNCHRONOUSIOFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCANCELSYNCHRONOUSIOFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCancelSynchronousIoFile_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t IoRequestToCancel, uint64_t IoStatusBlock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCANCELTIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCANCELTIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCancelTimer_enter, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint64_t CurrentState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCANCELTIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCANCELTIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCancelTimer_return, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint64_t CurrentState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCLEAREVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCLEAREVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtClearEvent_enter, CPUState* cpu, target_ulong pc, uint64_t EventHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCLEAREVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCLEAREVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtClearEvent_return, CPUState* cpu, target_ulong pc, uint64_t EventHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCLOSE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCLOSE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtClose_enter, CPUState* cpu, target_ulong pc, uint64_t Handle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCLOSE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCLOSE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtClose_return, CPUState* cpu, target_ulong pc, uint64_t Handle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCLOSEOBJECTAUDITALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCLOSEOBJECTAUDITALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCloseObjectAuditAlarm_enter, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint32_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCLOSEOBJECTAUDITALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCLOSEOBJECTAUDITALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCloseObjectAuditAlarm_return, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint32_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITCOMPLETE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITCOMPLETE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCommitComplete_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITCOMPLETE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITCOMPLETE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCommitComplete_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITENLISTMENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITENLISTMENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCommitEnlistment_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITENLISTMENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITENLISTMENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCommitEnlistment_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITTRANSACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITTRANSACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCommitTransaction_enter, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t Wait);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITTRANSACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMMITTRANSACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCommitTransaction_return, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t Wait);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMPACTKEYS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMPACTKEYS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCompactKeys_enter, CPUState* cpu, target_ulong pc, uint32_t Count, uint64_t KeyArray);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMPACTKEYS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMPACTKEYS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCompactKeys_return, CPUState* cpu, target_ulong pc, uint32_t Count, uint64_t KeyArray);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMPARETOKENS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMPARETOKENS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCompareTokens_enter, CPUState* cpu, target_ulong pc, uint64_t FirstTokenHandle, uint64_t SecondTokenHandle, uint64_t Equal);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMPARETOKENS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMPARETOKENS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCompareTokens_return, CPUState* cpu, target_ulong pc, uint64_t FirstTokenHandle, uint64_t SecondTokenHandle, uint64_t Equal);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMPLETECONNECTPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMPLETECONNECTPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCompleteConnectPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMPLETECONNECTPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMPLETECONNECTPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCompleteConnectPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMPRESSKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMPRESSKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCompressKey_enter, CPUState* cpu, target_ulong pc, uint64_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCOMPRESSKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCOMPRESSKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCompressKey_return, CPUState* cpu, target_ulong pc, uint64_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCONNECTPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCONNECTPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtConnectPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortName, uint64_t SecurityQos, uint64_t ClientView, uint64_t ServerView, uint64_t MaxMessageLength, uint64_t ConnectionInformation, uint64_t ConnectionInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCONNECTPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCONNECTPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtConnectPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortName, uint64_t SecurityQos, uint64_t ClientView, uint64_t ServerView, uint64_t MaxMessageLength, uint64_t ConnectionInformation, uint64_t ConnectionInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCONTINUE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCONTINUE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtContinue_enter, CPUState* cpu, target_ulong pc, uint64_t ContextRecord, uint32_t TestAlert);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCONTINUE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCONTINUE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtContinue_return, CPUState* cpu, target_ulong pc, uint64_t ContextRecord, uint32_t TestAlert);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEDEBUGOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEDEBUGOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateDebugObject_enter, CPUState* cpu, target_ulong pc, uint64_t DebugObjectHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEDEBUGOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEDEBUGOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateDebugObject_return, CPUState* cpu, target_ulong pc, uint64_t DebugObjectHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEDIRECTORYOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEDIRECTORYOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateDirectoryObject_enter, CPUState* cpu, target_ulong pc, uint64_t DirectoryHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEDIRECTORYOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEDIRECTORYOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateDirectoryObject_return, CPUState* cpu, target_ulong pc, uint64_t DirectoryHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEENLISTMENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEENLISTMENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateEnlistment_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint32_t DesiredAccess, uint64_t ResourceManagerHandle, uint64_t TransactionHandle, uint64_t ObjectAttributes, uint32_t CreateOptions, uint32_t NotificationMask, uint64_t EnlistmentKey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEENLISTMENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEENLISTMENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateEnlistment_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint32_t DesiredAccess, uint64_t ResourceManagerHandle, uint64_t TransactionHandle, uint64_t ObjectAttributes, uint32_t CreateOptions, uint32_t NotificationMask, uint64_t EnlistmentKey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateEvent_enter, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t EventType, uint32_t InitialState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateEvent_return, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t EventType, uint32_t InitialState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEEVENTPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEEVENTPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateEventPair_enter, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEEVENTPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEEVENTPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateEventPair_return, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t IoStatusBlock, uint64_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint64_t EaBuffer, uint32_t EaLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t IoStatusBlock, uint64_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint64_t EaBuffer, uint32_t EaLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEIOCOMPLETION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEIOCOMPLETION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateIoCompletion_enter, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t Count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEIOCOMPLETION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEIOCOMPLETION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateIoCompletion_return, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t Count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEJOBOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEJOBOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateJobObject_enter, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEJOBOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEJOBOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateJobObject_return, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEJOBSET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEJOBSET_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateJobSet_enter, CPUState* cpu, target_ulong pc, uint32_t NumJob, uint64_t UserJobSet, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEJOBSET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEJOBSET_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateJobSet_return, CPUState* cpu, target_ulong pc, uint32_t NumJob, uint64_t UserJobSet, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t TitleIndex, uint64_t Class, uint32_t CreateOptions, uint64_t Disposition);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t TitleIndex, uint64_t Class, uint32_t CreateOptions, uint64_t Disposition);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEYEDEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEYEDEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateKeyedEvent_enter, CPUState* cpu, target_ulong pc, uint64_t KeyedEventHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEYEDEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEYEDEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateKeyedEvent_return, CPUState* cpu, target_ulong pc, uint64_t KeyedEventHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEYTRANSACTED_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEYTRANSACTED_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateKeyTransacted_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t TitleIndex, uint64_t Class, uint32_t CreateOptions, uint64_t TransactionHandle, uint64_t Disposition);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEYTRANSACTED_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEKEYTRANSACTED_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateKeyTransacted_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t TitleIndex, uint64_t Class, uint32_t CreateOptions, uint64_t TransactionHandle, uint64_t Disposition);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEMAILSLOTFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEMAILSLOTFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateMailslotFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t IoStatusBlock, uint32_t CreateOptions, uint32_t MailslotQuota, uint32_t MaximumMessageSize, uint64_t ReadTimeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEMAILSLOTFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEMAILSLOTFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateMailslotFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t IoStatusBlock, uint32_t CreateOptions, uint32_t MailslotQuota, uint32_t MaximumMessageSize, uint64_t ReadTimeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEMUTANT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEMUTANT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateMutant_enter, CPUState* cpu, target_ulong pc, uint64_t MutantHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t InitialOwner);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEMUTANT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEMUTANT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateMutant_return, CPUState* cpu, target_ulong pc, uint64_t MutantHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t InitialOwner);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATENAMEDPIPEFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATENAMEDPIPEFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateNamedPipeFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t IoStatusBlock, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t NamedPipeType, uint32_t ReadMode, uint32_t CompletionMode, uint32_t MaximumInstances, uint32_t InboundQuota, uint32_t OutboundQuota, uint64_t DefaultTimeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATENAMEDPIPEFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATENAMEDPIPEFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateNamedPipeFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t IoStatusBlock, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t NamedPipeType, uint32_t ReadMode, uint32_t CompletionMode, uint32_t MaximumInstances, uint32_t InboundQuota, uint32_t OutboundQuota, uint64_t DefaultTimeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPAGINGFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPAGINGFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreatePagingFile_enter, CPUState* cpu, target_ulong pc, uint64_t PageFileName, uint64_t MinimumSize, uint64_t MaximumSize, uint32_t Priority);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPAGINGFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPAGINGFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreatePagingFile_return, CPUState* cpu, target_ulong pc, uint64_t PageFileName, uint64_t MinimumSize, uint64_t MaximumSize, uint32_t Priority);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreatePort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ObjectAttributes, uint32_t MaxConnectionInfoLength, uint32_t MaxMessageLength, uint32_t MaxPoolUsage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreatePort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ObjectAttributes, uint32_t MaxConnectionInfoLength, uint32_t MaxMessageLength, uint32_t MaxPoolUsage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPRIVATENAMESPACE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPRIVATENAMESPACE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreatePrivateNamespace_enter, CPUState* cpu, target_ulong pc, uint64_t NamespaceHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t BoundaryDescriptor);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPRIVATENAMESPACE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPRIVATENAMESPACE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreatePrivateNamespace_return, CPUState* cpu, target_ulong pc, uint64_t NamespaceHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t BoundaryDescriptor);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ParentProcess, uint32_t InheritObjectTable, uint64_t SectionHandle, uint64_t DebugPort, uint64_t ExceptionPort);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ParentProcess, uint32_t InheritObjectTable, uint64_t SectionHandle, uint64_t DebugPort, uint64_t ExceptionPort);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROCESSEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROCESSEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateProcessEx_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ParentProcess, uint32_t Flags, uint64_t SectionHandle, uint64_t DebugPort, uint64_t ExceptionPort, uint32_t JobMemberLevel);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROCESSEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROCESSEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateProcessEx_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ParentProcess, uint32_t Flags, uint64_t SectionHandle, uint64_t DebugPort, uint64_t ExceptionPort, uint32_t JobMemberLevel);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateProfile_enter, CPUState* cpu, target_ulong pc, uint64_t ProfileHandle, uint64_t Process, uint64_t RangeBase, uint64_t RangeSize, uint32_t BucketSize, uint64_t Buffer, uint32_t BufferSize, uint32_t ProfileSource, uint64_t Affinity);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateProfile_return, CPUState* cpu, target_ulong pc, uint64_t ProfileHandle, uint64_t Process, uint64_t RangeBase, uint64_t RangeSize, uint32_t BucketSize, uint64_t Buffer, uint32_t BufferSize, uint32_t ProfileSource, uint64_t Affinity);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROFILEEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROFILEEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateProfileEx_enter, CPUState* cpu, target_ulong pc, uint64_t ProfileHandle, uint64_t Process, uint64_t ProfileBase, uint64_t ProfileSize, uint32_t BucketSize, uint64_t Buffer, uint32_t BufferSize, uint32_t ProfileSource, uint32_t GroupAffinityCount, uint64_t GroupAffinity);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROFILEEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEPROFILEEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateProfileEx_return, CPUState* cpu, target_ulong pc, uint64_t ProfileHandle, uint64_t Process, uint64_t ProfileBase, uint64_t ProfileSize, uint32_t BucketSize, uint64_t Buffer, uint32_t BufferSize, uint32_t ProfileSource, uint32_t GroupAffinityCount, uint64_t GroupAffinity);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATERESOURCEMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATERESOURCEMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateResourceManager_enter, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t DesiredAccess, uint64_t TmHandle, uint64_t RmGuid, uint64_t ObjectAttributes, uint32_t CreateOptions, uint64_t Description);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATERESOURCEMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATERESOURCEMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateResourceManager_return, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t DesiredAccess, uint64_t TmHandle, uint64_t RmGuid, uint64_t ObjectAttributes, uint32_t CreateOptions, uint64_t Description);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATESECTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATESECTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateSection_enter, CPUState* cpu, target_ulong pc, uint64_t SectionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t MaximumSize, uint32_t SectionPageProtection, uint32_t AllocationAttributes, uint64_t FileHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATESECTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATESECTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateSection_return, CPUState* cpu, target_ulong pc, uint64_t SectionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t MaximumSize, uint32_t SectionPageProtection, uint32_t AllocationAttributes, uint64_t FileHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATESEMAPHORE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATESEMAPHORE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateSemaphore_enter, CPUState* cpu, target_ulong pc, uint64_t SemaphoreHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, int32_t InitialCount, int32_t MaximumCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATESEMAPHORE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATESEMAPHORE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateSemaphore_return, CPUState* cpu, target_ulong pc, uint64_t SemaphoreHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, int32_t InitialCount, int32_t MaximumCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATESYMBOLICLINKOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATESYMBOLICLINKOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateSymbolicLinkObject_enter, CPUState* cpu, target_ulong pc, uint64_t LinkHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t LinkTarget);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATESYMBOLICLINKOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATESYMBOLICLINKOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateSymbolicLinkObject_return, CPUState* cpu, target_ulong pc, uint64_t LinkHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t LinkTarget);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ProcessHandle, uint64_t ClientId, uint64_t ThreadContext, uint64_t InitialTeb, uint32_t CreateSuspended);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ProcessHandle, uint64_t ClientId, uint64_t ThreadContext, uint64_t InitialTeb, uint32_t CreateSuspended);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETHREADEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETHREADEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateThreadEx_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ProcessHandle, uint64_t StartRoutine, uint64_t Argument, uint32_t CreateFlags, uint64_t ZeroBits, uint64_t StackSize, uint64_t MaximumStackSize, uint64_t AttributeList);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETHREADEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETHREADEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateThreadEx_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ProcessHandle, uint64_t StartRoutine, uint64_t Argument, uint32_t CreateFlags, uint64_t ZeroBits, uint64_t StackSize, uint64_t MaximumStackSize, uint64_t AttributeList);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateTimer_enter, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t TimerType);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateTimer_return, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t TimerType);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateToken_enter, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t TokenType, uint64_t AuthenticationId, uint64_t ExpirationTime, uint64_t User, uint64_t Groups, uint64_t Privileges, uint64_t Owner, uint64_t PrimaryGroup, uint64_t DefaultDacl, uint64_t TokenSource);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateToken_return, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t TokenType, uint64_t AuthenticationId, uint64_t ExpirationTime, uint64_t User, uint64_t Groups, uint64_t Privileges, uint64_t Owner, uint64_t PrimaryGroup, uint64_t DefaultDacl, uint64_t TokenSource);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETRANSACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETRANSACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateTransaction_enter, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t Uow, uint64_t TmHandle, uint32_t CreateOptions, uint32_t IsolationLevel, uint32_t IsolationFlags, uint64_t Timeout, uint64_t Description);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETRANSACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETRANSACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateTransaction_return, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t Uow, uint64_t TmHandle, uint32_t CreateOptions, uint32_t IsolationLevel, uint32_t IsolationFlags, uint64_t Timeout, uint64_t Description);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETRANSACTIONMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETRANSACTIONMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateTransactionManager_enter, CPUState* cpu, target_ulong pc, uint64_t TmHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t LogFileName, uint32_t CreateOptions, uint32_t CommitStrength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATETRANSACTIONMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATETRANSACTIONMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateTransactionManager_return, CPUState* cpu, target_ulong pc, uint64_t TmHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t LogFileName, uint32_t CreateOptions, uint32_t CommitStrength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEUSERPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEUSERPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateUserProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t ThreadHandle, uint32_t ProcessDesiredAccess, uint32_t ThreadDesiredAccess, uint64_t ProcessObjectAttributes, uint64_t ThreadObjectAttributes, uint32_t ProcessFlags, uint32_t ThreadFlags, uint64_t ProcessParameters, uint64_t CreateInfo, uint64_t AttributeList);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEUSERPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEUSERPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateUserProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t ThreadHandle, uint32_t ProcessDesiredAccess, uint32_t ThreadDesiredAccess, uint64_t ProcessObjectAttributes, uint64_t ThreadObjectAttributes, uint32_t ProcessFlags, uint32_t ThreadFlags, uint64_t ProcessParameters, uint64_t CreateInfo, uint64_t AttributeList);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEWAITABLEPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEWAITABLEPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateWaitablePort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ObjectAttributes, uint32_t MaxConnectionInfoLength, uint32_t MaxMessageLength, uint32_t MaxPoolUsage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEWAITABLEPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEWAITABLEPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateWaitablePort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ObjectAttributes, uint32_t MaxConnectionInfoLength, uint32_t MaxMessageLength, uint32_t MaxPoolUsage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEWORKERFACTORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEWORKERFACTORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtCreateWorkerFactory_enter, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandleReturn, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t CompletionPortHandle, uint64_t WorkerProcessHandle, uint64_t StartRoutine, uint64_t StartParameter, uint32_t MaxThreadCount, uint64_t StackReserve, uint64_t StackCommit);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTCREATEWORKERFACTORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTCREATEWORKERFACTORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtCreateWorkerFactory_return, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandleReturn, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t CompletionPortHandle, uint64_t WorkerProcessHandle, uint64_t StartRoutine, uint64_t StartParameter, uint32_t MaxThreadCount, uint64_t StackReserve, uint64_t StackCommit);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDEBUGACTIVEPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDEBUGACTIVEPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDebugActiveProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t DebugObjectHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDEBUGACTIVEPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDEBUGACTIVEPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDebugActiveProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t DebugObjectHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDEBUGCONTINUE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDEBUGCONTINUE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDebugContinue_enter, CPUState* cpu, target_ulong pc, uint64_t DebugObjectHandle, uint64_t ClientId, uint32_t ContinueStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDEBUGCONTINUE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDEBUGCONTINUE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDebugContinue_return, CPUState* cpu, target_ulong pc, uint64_t DebugObjectHandle, uint64_t ClientId, uint32_t ContinueStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELAYEXECUTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELAYEXECUTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDelayExecution_enter, CPUState* cpu, target_ulong pc, uint32_t Alertable, uint64_t DelayInterval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELAYEXECUTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELAYEXECUTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDelayExecution_return, CPUState* cpu, target_ulong pc, uint32_t Alertable, uint64_t DelayInterval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEATOM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEATOM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDeleteAtom_enter, CPUState* cpu, target_ulong pc, uint32_t Atom);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEATOM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEATOM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDeleteAtom_return, CPUState* cpu, target_ulong pc, uint32_t Atom);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEBOOTENTRY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEBOOTENTRY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDeleteBootEntry_enter, CPUState* cpu, target_ulong pc, uint32_t Id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEBOOTENTRY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEBOOTENTRY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDeleteBootEntry_return, CPUState* cpu, target_ulong pc, uint32_t Id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEDRIVERENTRY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEDRIVERENTRY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDeleteDriverEntry_enter, CPUState* cpu, target_ulong pc, uint32_t Id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEDRIVERENTRY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEDRIVERENTRY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDeleteDriverEntry_return, CPUState* cpu, target_ulong pc, uint32_t Id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDeleteFile_enter, CPUState* cpu, target_ulong pc, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDeleteFile_return, CPUState* cpu, target_ulong pc, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDeleteKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDeleteKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEOBJECTAUDITALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEOBJECTAUDITALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDeleteObjectAuditAlarm_enter, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint32_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEOBJECTAUDITALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEOBJECTAUDITALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDeleteObjectAuditAlarm_return, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint32_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEPRIVATENAMESPACE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEPRIVATENAMESPACE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDeletePrivateNamespace_enter, CPUState* cpu, target_ulong pc, uint64_t NamespaceHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEPRIVATENAMESPACE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEPRIVATENAMESPACE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDeletePrivateNamespace_return, CPUState* cpu, target_ulong pc, uint64_t NamespaceHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEVALUEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEVALUEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDeleteValueKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t ValueName);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDELETEVALUEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDELETEVALUEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDeleteValueKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t ValueName);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDEVICEIOCONTROLFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDEVICEIOCONTROLFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDeviceIoControlFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint32_t IoControlCode, uint64_t InputBuffer, uint32_t InputBufferLength, uint64_t OutputBuffer, uint32_t OutputBufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDEVICEIOCONTROLFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDEVICEIOCONTROLFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDeviceIoControlFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint32_t IoControlCode, uint64_t InputBuffer, uint32_t InputBufferLength, uint64_t OutputBuffer, uint32_t OutputBufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDISABLELASTKNOWNGOOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDISABLELASTKNOWNGOOD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDisableLastKnownGood_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDISABLELASTKNOWNGOOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDISABLELASTKNOWNGOOD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDisableLastKnownGood_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDISPLAYSTRING_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDISPLAYSTRING_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDisplayString_enter, CPUState* cpu, target_ulong pc, uint64_t String);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDISPLAYSTRING_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDISPLAYSTRING_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDisplayString_return, CPUState* cpu, target_ulong pc, uint64_t String);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDRAWTEXT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDRAWTEXT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDrawText_enter, CPUState* cpu, target_ulong pc, uint64_t Text);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDRAWTEXT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDRAWTEXT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDrawText_return, CPUState* cpu, target_ulong pc, uint64_t Text);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDUPLICATEOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDUPLICATEOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDuplicateObject_enter, CPUState* cpu, target_ulong pc, uint64_t SourceProcessHandle, uint64_t SourceHandle, uint64_t TargetProcessHandle, uint64_t TargetHandle, uint32_t DesiredAccess, uint32_t HandleAttributes, uint32_t Options);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDUPLICATEOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDUPLICATEOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDuplicateObject_return, CPUState* cpu, target_ulong pc, uint64_t SourceProcessHandle, uint64_t SourceHandle, uint64_t TargetProcessHandle, uint64_t TargetHandle, uint32_t DesiredAccess, uint32_t HandleAttributes, uint32_t Options);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDUPLICATETOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTDUPLICATETOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtDuplicateToken_enter, CPUState* cpu, target_ulong pc, uint64_t ExistingTokenHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t EffectiveOnly, uint32_t TokenType, uint64_t NewTokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTDUPLICATETOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTDUPLICATETOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtDuplicateToken_return, CPUState* cpu, target_ulong pc, uint64_t ExistingTokenHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t EffectiveOnly, uint32_t TokenType, uint64_t NewTokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENABLELASTKNOWNGOOD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTENABLELASTKNOWNGOOD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtEnableLastKnownGood_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENABLELASTKNOWNGOOD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTENABLELASTKNOWNGOOD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtEnableLastKnownGood_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEBOOTENTRIES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEBOOTENTRIES_ENTER 1
PPP_CB_TYPEDEF(void, on_NtEnumerateBootEntries_enter, CPUState* cpu, target_ulong pc, uint64_t Buffer, uint64_t BufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEBOOTENTRIES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEBOOTENTRIES_RETURN 1
PPP_CB_TYPEDEF(void, on_NtEnumerateBootEntries_return, CPUState* cpu, target_ulong pc, uint64_t Buffer, uint64_t BufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEDRIVERENTRIES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEDRIVERENTRIES_ENTER 1
PPP_CB_TYPEDEF(void, on_NtEnumerateDriverEntries_enter, CPUState* cpu, target_ulong pc, uint64_t Buffer, uint64_t BufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEDRIVERENTRIES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEDRIVERENTRIES_RETURN 1
PPP_CB_TYPEDEF(void, on_NtEnumerateDriverEntries_return, CPUState* cpu, target_ulong pc, uint64_t Buffer, uint64_t BufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtEnumerateKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t Index, uint32_t KeyInformationClass, uint64_t KeyInformation, uint32_t Length, uint64_t ResultLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtEnumerateKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t Index, uint32_t KeyInformationClass, uint64_t KeyInformation, uint32_t Length, uint64_t ResultLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATESYSTEMENVIRONMENTVALUESEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATESYSTEMENVIRONMENTVALUESEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtEnumerateSystemEnvironmentValuesEx_enter, CPUState* cpu, target_ulong pc, uint32_t InformationClass, uint64_t Buffer, uint64_t BufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATESYSTEMENVIRONMENTVALUESEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATESYSTEMENVIRONMENTVALUESEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtEnumerateSystemEnvironmentValuesEx_return, CPUState* cpu, target_ulong pc, uint32_t InformationClass, uint64_t Buffer, uint64_t BufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATETRANSACTIONOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATETRANSACTIONOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtEnumerateTransactionObject_enter, CPUState* cpu, target_ulong pc, uint64_t RootObjectHandle, uint32_t QueryType, uint64_t ObjectCursor, uint32_t ObjectCursorLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATETRANSACTIONOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATETRANSACTIONOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtEnumerateTransactionObject_return, CPUState* cpu, target_ulong pc, uint64_t RootObjectHandle, uint32_t QueryType, uint64_t ObjectCursor, uint32_t ObjectCursorLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEVALUEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEVALUEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtEnumerateValueKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t Index, uint32_t KeyValueInformationClass, uint64_t KeyValueInformation, uint32_t Length, uint64_t ResultLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEVALUEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTENUMERATEVALUEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtEnumerateValueKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t Index, uint32_t KeyValueInformationClass, uint64_t KeyValueInformation, uint32_t Length, uint64_t ResultLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTEXTENDSECTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTEXTENDSECTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtExtendSection_enter, CPUState* cpu, target_ulong pc, uint64_t SectionHandle, uint64_t NewSectionSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTEXTENDSECTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTEXTENDSECTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtExtendSection_return, CPUState* cpu, target_ulong pc, uint64_t SectionHandle, uint64_t NewSectionSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFILTERTOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFILTERTOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFilterToken_enter, CPUState* cpu, target_ulong pc, uint64_t ExistingTokenHandle, uint32_t Flags, uint64_t SidsToDisable, uint64_t PrivilegesToDelete, uint64_t RestrictedSids, uint64_t NewTokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFILTERTOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFILTERTOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFilterToken_return, CPUState* cpu, target_ulong pc, uint64_t ExistingTokenHandle, uint32_t Flags, uint64_t SidsToDisable, uint64_t PrivilegesToDelete, uint64_t RestrictedSids, uint64_t NewTokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFINDATOM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFINDATOM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFindAtom_enter, CPUState* cpu, target_ulong pc, uint64_t AtomName, uint32_t Length, uint64_t Atom);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFINDATOM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFINDATOM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFindAtom_return, CPUState* cpu, target_ulong pc, uint64_t AtomName, uint32_t Length, uint64_t Atom);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHBUFFERSFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHBUFFERSFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFlushBuffersFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHBUFFERSFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHBUFFERSFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFlushBuffersFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHINSTALLUILANGUAGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHINSTALLUILANGUAGE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFlushInstallUILanguage_enter, CPUState* cpu, target_ulong pc, uint32_t InstallUILanguage, uint32_t SetComittedFlag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHINSTALLUILANGUAGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHINSTALLUILANGUAGE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFlushInstallUILanguage_return, CPUState* cpu, target_ulong pc, uint32_t InstallUILanguage, uint32_t SetComittedFlag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHINSTRUCTIONCACHE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHINSTRUCTIONCACHE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFlushInstructionCache_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t Length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHINSTRUCTIONCACHE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHINSTRUCTIONCACHE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFlushInstructionCache_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t Length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFlushKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFlushKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHPROCESSWRITEBUFFERS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHPROCESSWRITEBUFFERS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFlushProcessWriteBuffers_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHPROCESSWRITEBUFFERS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHPROCESSWRITEBUFFERS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFlushProcessWriteBuffers_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHVIRTUALMEMORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHVIRTUALMEMORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFlushVirtualMemory_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize, uint64_t IoStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHVIRTUALMEMORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHVIRTUALMEMORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFlushVirtualMemory_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize, uint64_t IoStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHWRITEBUFFER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHWRITEBUFFER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFlushWriteBuffer_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHWRITEBUFFER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFLUSHWRITEBUFFER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFlushWriteBuffer_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFREEUSERPHYSICALPAGES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFREEUSERPHYSICALPAGES_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFreeUserPhysicalPages_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t NumberOfPages, uint64_t UserPfnArray);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFREEUSERPHYSICALPAGES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFREEUSERPHYSICALPAGES_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFreeUserPhysicalPages_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t NumberOfPages, uint64_t UserPfnArray);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFREEVIRTUALMEMORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFREEVIRTUALMEMORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFreeVirtualMemory_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize, uint32_t FreeType);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFREEVIRTUALMEMORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFREEVIRTUALMEMORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFreeVirtualMemory_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize, uint32_t FreeType);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFREEZEREGISTRY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFREEZEREGISTRY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFreezeRegistry_enter, CPUState* cpu, target_ulong pc, uint32_t TimeOutInSeconds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFREEZEREGISTRY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFREEZEREGISTRY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFreezeRegistry_return, CPUState* cpu, target_ulong pc, uint32_t TimeOutInSeconds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFREEZETRANSACTIONS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFREEZETRANSACTIONS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFreezeTransactions_enter, CPUState* cpu, target_ulong pc, uint64_t FreezeTimeout, uint64_t ThawTimeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFREEZETRANSACTIONS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFREEZETRANSACTIONS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFreezeTransactions_return, CPUState* cpu, target_ulong pc, uint64_t FreezeTimeout, uint64_t ThawTimeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFSCONTROLFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTFSCONTROLFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtFsControlFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint32_t IoControlCode, uint64_t InputBuffer, uint32_t InputBufferLength, uint64_t OutputBuffer, uint32_t OutputBufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTFSCONTROLFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTFSCONTROLFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtFsControlFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint32_t IoControlCode, uint64_t InputBuffer, uint32_t InputBufferLength, uint64_t OutputBuffer, uint32_t OutputBufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETCONTEXTTHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETCONTEXTTHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtGetContextThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t ThreadContext);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETCONTEXTTHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETCONTEXTTHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtGetContextThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t ThreadContext);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETCURRENTPROCESSORNUMBER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETCURRENTPROCESSORNUMBER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtGetCurrentProcessorNumber_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETCURRENTPROCESSORNUMBER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETCURRENTPROCESSORNUMBER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtGetCurrentProcessorNumber_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETDEVICEPOWERSTATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETDEVICEPOWERSTATE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtGetDevicePowerState_enter, CPUState* cpu, target_ulong pc, uint64_t Device, uint64_t State);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETDEVICEPOWERSTATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETDEVICEPOWERSTATE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtGetDevicePowerState_return, CPUState* cpu, target_ulong pc, uint64_t Device, uint64_t State);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETMUIREGISTRYINFO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETMUIREGISTRYINFO_ENTER 1
PPP_CB_TYPEDEF(void, on_NtGetMUIRegistryInfo_enter, CPUState* cpu, target_ulong pc, uint32_t Flags, uint64_t DataSize, uint64_t Data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETMUIREGISTRYINFO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETMUIREGISTRYINFO_RETURN 1
PPP_CB_TYPEDEF(void, on_NtGetMUIRegistryInfo_return, CPUState* cpu, target_ulong pc, uint32_t Flags, uint64_t DataSize, uint64_t Data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETNEXTPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETNEXTPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtGetNextProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint32_t HandleAttributes, uint32_t Flags, uint64_t NewProcessHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETNEXTPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETNEXTPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtGetNextProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint32_t HandleAttributes, uint32_t Flags, uint64_t NewProcessHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETNEXTTHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETNEXTTHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtGetNextThread_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t ThreadHandle, uint32_t DesiredAccess, uint32_t HandleAttributes, uint32_t Flags, uint64_t NewThreadHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETNEXTTHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETNEXTTHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtGetNextThread_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t ThreadHandle, uint32_t DesiredAccess, uint32_t HandleAttributes, uint32_t Flags, uint64_t NewThreadHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETNLSSECTIONPTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETNLSSECTIONPTR_ENTER 1
PPP_CB_TYPEDEF(void, on_NtGetNlsSectionPtr_enter, CPUState* cpu, target_ulong pc, uint32_t SectionType, uint32_t SectionData, uint64_t ContextData, uint64_t SectionPointer, uint64_t SectionSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETNLSSECTIONPTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETNLSSECTIONPTR_RETURN 1
PPP_CB_TYPEDEF(void, on_NtGetNlsSectionPtr_return, CPUState* cpu, target_ulong pc, uint32_t SectionType, uint32_t SectionData, uint64_t ContextData, uint64_t SectionPointer, uint64_t SectionSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETNOTIFICATIONRESOURCEMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETNOTIFICATIONRESOURCEMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtGetNotificationResourceManager_enter, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint64_t TransactionNotification, uint32_t NotificationLength, uint64_t Timeout, uint64_t ReturnLength, uint32_t Asynchronous, uint64_t AsynchronousContext);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETNOTIFICATIONRESOURCEMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETNOTIFICATIONRESOURCEMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtGetNotificationResourceManager_return, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint64_t TransactionNotification, uint32_t NotificationLength, uint64_t Timeout, uint64_t ReturnLength, uint32_t Asynchronous, uint64_t AsynchronousContext);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETPLUGPLAYEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETPLUGPLAYEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtGetPlugPlayEvent_enter, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint64_t Context, uint64_t EventBlock, uint32_t EventBufferSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETPLUGPLAYEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETPLUGPLAYEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtGetPlugPlayEvent_return, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint64_t Context, uint64_t EventBlock, uint32_t EventBufferSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETWRITEWATCH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETWRITEWATCH_ENTER 1
PPP_CB_TYPEDEF(void, on_NtGetWriteWatch_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t Flags, uint64_t BaseAddress, uint64_t RegionSize, uint64_t UserAddressArray, uint64_t EntriesInUserAddressArray, uint64_t Granularity);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTGETWRITEWATCH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTGETWRITEWATCH_RETURN 1
PPP_CB_TYPEDEF(void, on_NtGetWriteWatch_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t Flags, uint64_t BaseAddress, uint64_t RegionSize, uint64_t UserAddressArray, uint64_t EntriesInUserAddressArray, uint64_t Granularity);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATEANONYMOUSTOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATEANONYMOUSTOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtImpersonateAnonymousToken_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATEANONYMOUSTOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATEANONYMOUSTOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtImpersonateAnonymousToken_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATECLIENTOFPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATECLIENTOFPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtImpersonateClientOfPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t Message);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATECLIENTOFPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATECLIENTOFPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtImpersonateClientOfPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t Message);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATETHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATETHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtImpersonateThread_enter, CPUState* cpu, target_ulong pc, uint64_t ServerThreadHandle, uint64_t ClientThreadHandle, uint64_t SecurityQos);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATETHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTIMPERSONATETHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtImpersonateThread_return, CPUState* cpu, target_ulong pc, uint64_t ServerThreadHandle, uint64_t ClientThreadHandle, uint64_t SecurityQos);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTINITIALIZENLSFILES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTINITIALIZENLSFILES_ENTER 1
PPP_CB_TYPEDEF(void, on_NtInitializeNlsFiles_enter, CPUState* cpu, target_ulong pc, uint64_t BaseAddress, uint64_t DefaultLocaleId, uint64_t DefaultCasingTableSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTINITIALIZENLSFILES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTINITIALIZENLSFILES_RETURN 1
PPP_CB_TYPEDEF(void, on_NtInitializeNlsFiles_return, CPUState* cpu, target_ulong pc, uint64_t BaseAddress, uint64_t DefaultLocaleId, uint64_t DefaultCasingTableSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTINITIALIZEREGISTRY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTINITIALIZEREGISTRY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtInitializeRegistry_enter, CPUState* cpu, target_ulong pc, uint32_t BootCondition);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTINITIALIZEREGISTRY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTINITIALIZEREGISTRY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtInitializeRegistry_return, CPUState* cpu, target_ulong pc, uint32_t BootCondition);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTINITIATEPOWERACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTINITIATEPOWERACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtInitiatePowerAction_enter, CPUState* cpu, target_ulong pc, uint32_t SystemAction, uint32_t MinSystemState, uint32_t Flags, uint32_t Asynchronous);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTINITIATEPOWERACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTINITIATEPOWERACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtInitiatePowerAction_return, CPUState* cpu, target_ulong pc, uint32_t SystemAction, uint32_t MinSystemState, uint32_t Flags, uint32_t Asynchronous);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTISPROCESSINJOB_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTISPROCESSINJOB_ENTER 1
PPP_CB_TYPEDEF(void, on_NtIsProcessInJob_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t JobHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTISPROCESSINJOB_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTISPROCESSINJOB_RETURN 1
PPP_CB_TYPEDEF(void, on_NtIsProcessInJob_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t JobHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTISSYSTEMRESUMEAUTOMATIC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTISSYSTEMRESUMEAUTOMATIC_ENTER 1
PPP_CB_TYPEDEF(void, on_NtIsSystemResumeAutomatic_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTISSYSTEMRESUMEAUTOMATIC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTISSYSTEMRESUMEAUTOMATIC_RETURN 1
PPP_CB_TYPEDEF(void, on_NtIsSystemResumeAutomatic_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTISUILANGUAGECOMITTED_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTISUILANGUAGECOMITTED_ENTER 1
PPP_CB_TYPEDEF(void, on_NtIsUILanguageComitted_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTISUILANGUAGECOMITTED_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTISUILANGUAGECOMITTED_RETURN 1
PPP_CB_TYPEDEF(void, on_NtIsUILanguageComitted_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLISTENPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTLISTENPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtListenPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ConnectionRequest);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLISTENPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTLISTENPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtListenPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ConnectionRequest);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOADDRIVER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOADDRIVER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtLoadDriver_enter, CPUState* cpu, target_ulong pc, uint64_t DriverServiceName);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOADDRIVER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOADDRIVER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtLoadDriver_return, CPUState* cpu, target_ulong pc, uint64_t DriverServiceName);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtLoadKey_enter, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint64_t SourceFile);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtLoadKey_return, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint64_t SourceFile);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEY2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEY2_ENTER 1
PPP_CB_TYPEDEF(void, on_NtLoadKey2_enter, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint64_t SourceFile, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEY2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEY2_RETURN 1
PPP_CB_TYPEDEF(void, on_NtLoadKey2_return, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint64_t SourceFile, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEYEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEYEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtLoadKeyEx_enter, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint64_t SourceFile, uint32_t Flags, uint64_t TrustClassKey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEYEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOADKEYEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtLoadKeyEx_return, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint64_t SourceFile, uint32_t Flags, uint64_t TrustClassKey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOCKFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOCKFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtLockFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t ByteOffset, uint64_t Length, uint32_t Key, uint32_t FailImmediately, uint32_t ExclusiveLock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOCKFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOCKFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtLockFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t ByteOffset, uint64_t Length, uint32_t Key, uint32_t FailImmediately, uint32_t ExclusiveLock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOCKPRODUCTACTIVATIONKEYS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOCKPRODUCTACTIVATIONKEYS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtLockProductActivationKeys_enter, CPUState* cpu, target_ulong pc, uint64_t pPrivateVer, uint64_t pSafeMode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOCKPRODUCTACTIVATIONKEYS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOCKPRODUCTACTIVATIONKEYS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtLockProductActivationKeys_return, CPUState* cpu, target_ulong pc, uint64_t pPrivateVer, uint64_t pSafeMode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOCKREGISTRYKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOCKREGISTRYKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtLockRegistryKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOCKREGISTRYKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOCKREGISTRYKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtLockRegistryKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOCKVIRTUALMEMORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOCKVIRTUALMEMORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtLockVirtualMemory_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize, uint32_t MapType);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTLOCKVIRTUALMEMORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTLOCKVIRTUALMEMORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtLockVirtualMemory_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize, uint32_t MapType);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAKEPERMANENTOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAKEPERMANENTOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtMakePermanentObject_enter, CPUState* cpu, target_ulong pc, uint64_t Handle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAKEPERMANENTOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAKEPERMANENTOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtMakePermanentObject_return, CPUState* cpu, target_ulong pc, uint64_t Handle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAKETEMPORARYOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAKETEMPORARYOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtMakeTemporaryObject_enter, CPUState* cpu, target_ulong pc, uint64_t Handle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAKETEMPORARYOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAKETEMPORARYOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtMakeTemporaryObject_return, CPUState* cpu, target_ulong pc, uint64_t Handle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAPCMFMODULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAPCMFMODULE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtMapCMFModule_enter, CPUState* cpu, target_ulong pc, uint32_t What, uint32_t Index, uint64_t CacheIndexOut, uint64_t CacheFlagsOut, uint64_t ViewSizeOut, uint64_t BaseAddress);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAPCMFMODULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAPCMFMODULE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtMapCMFModule_return, CPUState* cpu, target_ulong pc, uint32_t What, uint32_t Index, uint64_t CacheIndexOut, uint64_t CacheFlagsOut, uint64_t ViewSizeOut, uint64_t BaseAddress);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAPUSERPHYSICALPAGES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAPUSERPHYSICALPAGES_ENTER 1
PPP_CB_TYPEDEF(void, on_NtMapUserPhysicalPages_enter, CPUState* cpu, target_ulong pc, uint64_t VirtualAddress, uint64_t NumberOfPages, uint64_t UserPfnArray);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAPUSERPHYSICALPAGES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAPUSERPHYSICALPAGES_RETURN 1
PPP_CB_TYPEDEF(void, on_NtMapUserPhysicalPages_return, CPUState* cpu, target_ulong pc, uint64_t VirtualAddress, uint64_t NumberOfPages, uint64_t UserPfnArray);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAPUSERPHYSICALPAGESSCATTER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAPUSERPHYSICALPAGESSCATTER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtMapUserPhysicalPagesScatter_enter, CPUState* cpu, target_ulong pc, uint64_t VirtualAddresses, uint64_t NumberOfPages, uint64_t UserPfnArray);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAPUSERPHYSICALPAGESSCATTER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAPUSERPHYSICALPAGESSCATTER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtMapUserPhysicalPagesScatter_return, CPUState* cpu, target_ulong pc, uint64_t VirtualAddresses, uint64_t NumberOfPages, uint64_t UserPfnArray);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAPVIEWOFSECTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAPVIEWOFSECTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtMapViewOfSection_enter, CPUState* cpu, target_ulong pc, uint64_t SectionHandle, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t ZeroBits, uint64_t CommitSize, uint64_t SectionOffset, uint64_t ViewSize, uint32_t InheritDisposition, uint32_t AllocationType, uint32_t Win32Protect);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMAPVIEWOFSECTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTMAPVIEWOFSECTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtMapViewOfSection_return, CPUState* cpu, target_ulong pc, uint64_t SectionHandle, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t ZeroBits, uint64_t CommitSize, uint64_t SectionOffset, uint64_t ViewSize, uint32_t InheritDisposition, uint32_t AllocationType, uint32_t Win32Protect);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMODIFYBOOTENTRY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTMODIFYBOOTENTRY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtModifyBootEntry_enter, CPUState* cpu, target_ulong pc, uint64_t BootEntry);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMODIFYBOOTENTRY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTMODIFYBOOTENTRY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtModifyBootEntry_return, CPUState* cpu, target_ulong pc, uint64_t BootEntry);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMODIFYDRIVERENTRY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTMODIFYDRIVERENTRY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtModifyDriverEntry_enter, CPUState* cpu, target_ulong pc, uint64_t DriverEntry);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTMODIFYDRIVERENTRY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTMODIFYDRIVERENTRY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtModifyDriverEntry_return, CPUState* cpu, target_ulong pc, uint64_t DriverEntry);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEDIRECTORYFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEDIRECTORYFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtNotifyChangeDirectoryFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length, uint32_t CompletionFilter, uint32_t WatchTree);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEDIRECTORYFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEDIRECTORYFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtNotifyChangeDirectoryFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length, uint32_t CompletionFilter, uint32_t WatchTree);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtNotifyChangeKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint32_t CompletionFilter, uint32_t WatchTree, uint64_t Buffer, uint32_t BufferSize, uint32_t Asynchronous);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtNotifyChangeKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint32_t CompletionFilter, uint32_t WatchTree, uint64_t Buffer, uint32_t BufferSize, uint32_t Asynchronous);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEMULTIPLEKEYS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEMULTIPLEKEYS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtNotifyChangeMultipleKeys_enter, CPUState* cpu, target_ulong pc, uint64_t MasterKeyHandle, uint32_t Count, uint64_t SlaveObjects, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint32_t CompletionFilter, uint32_t WatchTree, uint64_t Buffer, uint32_t BufferSize, uint32_t Asynchronous);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEMULTIPLEKEYS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGEMULTIPLEKEYS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtNotifyChangeMultipleKeys_return, CPUState* cpu, target_ulong pc, uint64_t MasterKeyHandle, uint32_t Count, uint64_t SlaveObjects, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint32_t CompletionFilter, uint32_t WatchTree, uint64_t Buffer, uint32_t BufferSize, uint32_t Asynchronous);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGESESSION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGESESSION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtNotifyChangeSession_enter, CPUState* cpu, target_ulong pc, uint64_t Session, uint32_t IoStateSequence, uint64_t Reserved, uint32_t Action, uint32_t IoState, uint32_t IoState2, uint64_t Buffer, uint32_t BufferSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGESESSION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTNOTIFYCHANGESESSION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtNotifyChangeSession_return, CPUState* cpu, target_ulong pc, uint64_t Session, uint32_t IoStateSequence, uint64_t Reserved, uint32_t Action, uint32_t IoState, uint32_t IoState2, uint64_t Buffer, uint32_t BufferSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENDIRECTORYOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENDIRECTORYOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenDirectoryObject_enter, CPUState* cpu, target_ulong pc, uint64_t DirectoryHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENDIRECTORYOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENDIRECTORYOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenDirectoryObject_return, CPUState* cpu, target_ulong pc, uint64_t DirectoryHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENENLISTMENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENENLISTMENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenEnlistment_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint32_t DesiredAccess, uint64_t ResourceManagerHandle, uint64_t EnlistmentGuid, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENENLISTMENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENENLISTMENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenEnlistment_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint32_t DesiredAccess, uint64_t ResourceManagerHandle, uint64_t EnlistmentGuid, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenEvent_enter, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenEvent_return, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENEVENTPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENEVENTPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenEventPair_enter, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENEVENTPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENEVENTPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenEventPair_return, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENIOCOMPLETION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENIOCOMPLETION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenIoCompletion_enter, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENIOCOMPLETION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENIOCOMPLETION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenIoCompletion_return, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENJOBOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENJOBOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenJobObject_enter, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENJOBOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENJOBOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenJobObject_return, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYEDEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYEDEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenKeyedEvent_enter, CPUState* cpu, target_ulong pc, uint64_t KeyedEventHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYEDEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYEDEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenKeyedEvent_return, CPUState* cpu, target_ulong pc, uint64_t KeyedEventHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenKeyEx_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t OpenOptions);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenKeyEx_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t OpenOptions);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYTRANSACTED_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYTRANSACTED_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenKeyTransacted_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t TransactionHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYTRANSACTED_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYTRANSACTED_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenKeyTransacted_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t TransactionHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYTRANSACTEDEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYTRANSACTEDEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenKeyTransactedEx_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t OpenOptions, uint64_t TransactionHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYTRANSACTEDEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENKEYTRANSACTEDEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenKeyTransactedEx_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint32_t OpenOptions, uint64_t TransactionHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENMUTANT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENMUTANT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenMutant_enter, CPUState* cpu, target_ulong pc, uint64_t MutantHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENMUTANT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENMUTANT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenMutant_return, CPUState* cpu, target_ulong pc, uint64_t MutantHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENOBJECTAUDITALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENOBJECTAUDITALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenObjectAuditAlarm_enter, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ObjectTypeName, uint64_t ObjectName, uint64_t SecurityDescriptor, uint64_t ClientToken, uint32_t DesiredAccess, uint32_t GrantedAccess, uint64_t Privileges, uint32_t ObjectCreation, uint32_t AccessGranted, uint64_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENOBJECTAUDITALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENOBJECTAUDITALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenObjectAuditAlarm_return, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ObjectTypeName, uint64_t ObjectName, uint64_t SecurityDescriptor, uint64_t ClientToken, uint32_t DesiredAccess, uint32_t GrantedAccess, uint64_t Privileges, uint32_t ObjectCreation, uint32_t AccessGranted, uint64_t GenerateOnClose);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENPRIVATENAMESPACE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENPRIVATENAMESPACE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenPrivateNamespace_enter, CPUState* cpu, target_ulong pc, uint64_t NamespaceHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t BoundaryDescriptor);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENPRIVATENAMESPACE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENPRIVATENAMESPACE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenPrivateNamespace_return, CPUState* cpu, target_ulong pc, uint64_t NamespaceHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t BoundaryDescriptor);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ClientId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ClientId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESSTOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESSTOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenProcessToken_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint64_t TokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESSTOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESSTOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenProcessToken_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint64_t TokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESSTOKENEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESSTOKENEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenProcessTokenEx_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint32_t HandleAttributes, uint64_t TokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESSTOKENEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENPROCESSTOKENEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenProcessTokenEx_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t DesiredAccess, uint32_t HandleAttributes, uint64_t TokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENRESOURCEMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENRESOURCEMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenResourceManager_enter, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t DesiredAccess, uint64_t TmHandle, uint64_t ResourceManagerGuid, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENRESOURCEMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENRESOURCEMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenResourceManager_return, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t DesiredAccess, uint64_t TmHandle, uint64_t ResourceManagerGuid, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENSECTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENSECTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenSection_enter, CPUState* cpu, target_ulong pc, uint64_t SectionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENSECTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENSECTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenSection_return, CPUState* cpu, target_ulong pc, uint64_t SectionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENSEMAPHORE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENSEMAPHORE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenSemaphore_enter, CPUState* cpu, target_ulong pc, uint64_t SemaphoreHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENSEMAPHORE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENSEMAPHORE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenSemaphore_return, CPUState* cpu, target_ulong pc, uint64_t SemaphoreHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENSESSION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENSESSION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenSession_enter, CPUState* cpu, target_ulong pc, uint64_t SessionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENSESSION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENSESSION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenSession_return, CPUState* cpu, target_ulong pc, uint64_t SessionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENSYMBOLICLINKOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENSYMBOLICLINKOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenSymbolicLinkObject_enter, CPUState* cpu, target_ulong pc, uint64_t LinkHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENSYMBOLICLINKOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENSYMBOLICLINKOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenSymbolicLinkObject_return, CPUState* cpu, target_ulong pc, uint64_t LinkHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ClientId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t ClientId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREADTOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREADTOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenThreadToken_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t DesiredAccess, uint32_t OpenAsSelf, uint64_t TokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREADTOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREADTOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenThreadToken_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t DesiredAccess, uint32_t OpenAsSelf, uint64_t TokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREADTOKENEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREADTOKENEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenThreadTokenEx_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t DesiredAccess, uint32_t OpenAsSelf, uint32_t HandleAttributes, uint64_t TokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREADTOKENEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTHREADTOKENEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenThreadTokenEx_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t DesiredAccess, uint32_t OpenAsSelf, uint32_t HandleAttributes, uint64_t TokenHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenTimer_enter, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenTimer_return, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTRANSACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTRANSACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenTransaction_enter, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t Uow, uint64_t TmHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTRANSACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTRANSACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenTransaction_return, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t Uow, uint64_t TmHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTRANSACTIONMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTRANSACTIONMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtOpenTransactionManager_enter, CPUState* cpu, target_ulong pc, uint64_t TmHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t LogFileName, uint64_t TmIdentity, uint32_t OpenOptions);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTOPENTRANSACTIONMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTOPENTRANSACTIONMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtOpenTransactionManager_return, CPUState* cpu, target_ulong pc, uint64_t TmHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t LogFileName, uint64_t TmIdentity, uint32_t OpenOptions);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTP_ADJTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTP_ADJTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_ntp_adjtime_enter, CPUState* cpu, target_ulong pc, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTP_ADJTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTP_ADJTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_ntp_adjtime_return, CPUState* cpu, target_ulong pc, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTP_GETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTP_GETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_ntp_gettime_enter, CPUState* cpu, target_ulong pc, uint64_t ntvp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTP_GETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTP_GETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_ntp_gettime_return, CPUState* cpu, target_ulong pc, uint64_t ntvp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPLUGPLAYCONTROL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPLUGPLAYCONTROL_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPlugPlayControl_enter, CPUState* cpu, target_ulong pc, uint32_t PnPControlClass, uint64_t PnPControlData, uint32_t PnPControlDataLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPLUGPLAYCONTROL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPLUGPLAYCONTROL_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPlugPlayControl_return, CPUState* cpu, target_ulong pc, uint32_t PnPControlClass, uint64_t PnPControlData, uint32_t PnPControlDataLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPOWERINFORMATION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPOWERINFORMATION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPowerInformation_enter, CPUState* cpu, target_ulong pc, uint32_t InformationLevel, uint64_t InputBuffer, uint32_t InputBufferLength, uint64_t OutputBuffer, uint32_t OutputBufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPOWERINFORMATION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPOWERINFORMATION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPowerInformation_return, CPUState* cpu, target_ulong pc, uint32_t InformationLevel, uint64_t InputBuffer, uint32_t InputBufferLength, uint64_t OutputBuffer, uint32_t OutputBufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPREPARECOMPLETE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPREPARECOMPLETE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPrepareComplete_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPREPARECOMPLETE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPREPARECOMPLETE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPrepareComplete_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPREPAREENLISTMENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPREPAREENLISTMENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPrepareEnlistment_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPREPAREENLISTMENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPREPAREENLISTMENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPrepareEnlistment_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPREPREPARECOMPLETE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPREPREPARECOMPLETE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPrePrepareComplete_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPREPREPARECOMPLETE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPREPREPARECOMPLETE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPrePrepareComplete_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPREPREPAREENLISTMENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPREPREPAREENLISTMENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPrePrepareEnlistment_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPREPREPAREENLISTMENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPREPREPAREENLISTMENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPrePrepareEnlistment_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGECHECK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGECHECK_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPrivilegeCheck_enter, CPUState* cpu, target_ulong pc, uint64_t ClientToken, uint64_t RequiredPrivileges, uint64_t Result);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGECHECK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGECHECK_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPrivilegeCheck_return, CPUState* cpu, target_ulong pc, uint64_t ClientToken, uint64_t RequiredPrivileges, uint64_t Result);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGEDSERVICEAUDITALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGEDSERVICEAUDITALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPrivilegedServiceAuditAlarm_enter, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t ServiceName, uint64_t ClientToken, uint64_t Privileges, uint32_t AccessGranted);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGEDSERVICEAUDITALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGEDSERVICEAUDITALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPrivilegedServiceAuditAlarm_return, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t ServiceName, uint64_t ClientToken, uint64_t Privileges, uint32_t AccessGranted);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGEOBJECTAUDITALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGEOBJECTAUDITALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPrivilegeObjectAuditAlarm_enter, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ClientToken, uint32_t DesiredAccess, uint64_t Privileges, uint32_t AccessGranted);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGEOBJECTAUDITALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPRIVILEGEOBJECTAUDITALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPrivilegeObjectAuditAlarm_return, CPUState* cpu, target_ulong pc, uint64_t SubsystemName, uint64_t HandleId, uint64_t ClientToken, uint32_t DesiredAccess, uint64_t Privileges, uint32_t AccessGranted);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPROPAGATIONCOMPLETE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPROPAGATIONCOMPLETE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPropagationComplete_enter, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t RequestCookie, uint32_t BufferLength, uint64_t Buffer);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPROPAGATIONCOMPLETE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPROPAGATIONCOMPLETE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPropagationComplete_return, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t RequestCookie, uint32_t BufferLength, uint64_t Buffer);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPROPAGATIONFAILED_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPROPAGATIONFAILED_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPropagationFailed_enter, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t RequestCookie, uint32_t PropStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPROPAGATIONFAILED_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPROPAGATIONFAILED_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPropagationFailed_return, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t RequestCookie, uint32_t PropStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPROTECTVIRTUALMEMORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPROTECTVIRTUALMEMORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtProtectVirtualMemory_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize, uint32_t NewProtectWin32, uint64_t OldProtect);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPROTECTVIRTUALMEMORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPROTECTVIRTUALMEMORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtProtectVirtualMemory_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize, uint32_t NewProtectWin32, uint64_t OldProtect);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPULSEEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTPULSEEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtPulseEvent_enter, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint64_t PreviousState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTPULSEEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTPULSEEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtPulseEvent_return, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint64_t PreviousState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYATTRIBUTESFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYATTRIBUTESFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryAttributesFile_enter, CPUState* cpu, target_ulong pc, uint64_t ObjectAttributes, uint64_t FileInformation);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYATTRIBUTESFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYATTRIBUTESFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryAttributesFile_return, CPUState* cpu, target_ulong pc, uint64_t ObjectAttributes, uint64_t FileInformation);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYBOOTENTRYORDER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYBOOTENTRYORDER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryBootEntryOrder_enter, CPUState* cpu, target_ulong pc, uint64_t Ids, uint64_t Count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYBOOTENTRYORDER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYBOOTENTRYORDER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryBootEntryOrder_return, CPUState* cpu, target_ulong pc, uint64_t Ids, uint64_t Count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYBOOTOPTIONS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYBOOTOPTIONS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryBootOptions_enter, CPUState* cpu, target_ulong pc, uint64_t BootOptions, uint64_t BootOptionsLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYBOOTOPTIONS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYBOOTOPTIONS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryBootOptions_return, CPUState* cpu, target_ulong pc, uint64_t BootOptions, uint64_t BootOptionsLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEBUGFILTERSTATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEBUGFILTERSTATE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryDebugFilterState_enter, CPUState* cpu, target_ulong pc, uint32_t ComponentId, uint32_t Level);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEBUGFILTERSTATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEBUGFILTERSTATE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryDebugFilterState_return, CPUState* cpu, target_ulong pc, uint32_t ComponentId, uint32_t Level);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEFAULTLOCALE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEFAULTLOCALE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryDefaultLocale_enter, CPUState* cpu, target_ulong pc, uint32_t UserProfile, uint64_t DefaultLocaleId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEFAULTLOCALE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEFAULTLOCALE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryDefaultLocale_return, CPUState* cpu, target_ulong pc, uint32_t UserProfile, uint64_t DefaultLocaleId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEFAULTUILANGUAGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEFAULTUILANGUAGE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryDefaultUILanguage_enter, CPUState* cpu, target_ulong pc, uint64_t DefaultUILanguageId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEFAULTUILANGUAGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDEFAULTUILANGUAGE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryDefaultUILanguage_return, CPUState* cpu, target_ulong pc, uint64_t DefaultUILanguageId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDIRECTORYFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDIRECTORYFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryDirectoryFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t FileInformation, uint32_t Length, uint32_t FileInformationClass, uint32_t ReturnSingleEntry, uint64_t FileName, uint32_t RestartScan);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDIRECTORYFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDIRECTORYFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryDirectoryFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t FileInformation, uint32_t Length, uint32_t FileInformationClass, uint32_t ReturnSingleEntry, uint64_t FileName, uint32_t RestartScan);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDIRECTORYOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDIRECTORYOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryDirectoryObject_enter, CPUState* cpu, target_ulong pc, uint64_t DirectoryHandle, uint64_t Buffer, uint32_t Length, uint32_t ReturnSingleEntry, uint32_t RestartScan, uint64_t Context, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDIRECTORYOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDIRECTORYOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryDirectoryObject_return, CPUState* cpu, target_ulong pc, uint64_t DirectoryHandle, uint64_t Buffer, uint32_t Length, uint32_t ReturnSingleEntry, uint32_t RestartScan, uint64_t Context, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDRIVERENTRYORDER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDRIVERENTRYORDER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryDriverEntryOrder_enter, CPUState* cpu, target_ulong pc, uint64_t Ids, uint64_t Count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDRIVERENTRYORDER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYDRIVERENTRYORDER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryDriverEntryOrder_return, CPUState* cpu, target_ulong pc, uint64_t Ids, uint64_t Count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYEAFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYEAFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryEaFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length, uint32_t ReturnSingleEntry, uint64_t EaList, uint32_t EaListLength, uint64_t EaIndex, uint32_t RestartScan);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYEAFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYEAFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryEaFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length, uint32_t ReturnSingleEntry, uint64_t EaList, uint32_t EaListLength, uint64_t EaIndex, uint32_t RestartScan);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryEvent_enter, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint32_t EventInformationClass, uint64_t EventInformation, uint32_t EventInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryEvent_return, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint32_t EventInformationClass, uint64_t EventInformation, uint32_t EventInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYFULLATTRIBUTESFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYFULLATTRIBUTESFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryFullAttributesFile_enter, CPUState* cpu, target_ulong pc, uint64_t ObjectAttributes, uint64_t FileInformation);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYFULLATTRIBUTESFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYFULLATTRIBUTESFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryFullAttributesFile_return, CPUState* cpu, target_ulong pc, uint64_t ObjectAttributes, uint64_t FileInformation);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONATOM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONATOM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationAtom_enter, CPUState* cpu, target_ulong pc, uint32_t Atom, uint32_t InformationClass, uint64_t AtomInformation, uint32_t AtomInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONATOM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONATOM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationAtom_return, CPUState* cpu, target_ulong pc, uint32_t Atom, uint32_t InformationClass, uint64_t AtomInformation, uint32_t AtomInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONENLISTMENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONENLISTMENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationEnlistment_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint32_t EnlistmentInformationClass, uint64_t EnlistmentInformation, uint32_t EnlistmentInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONENLISTMENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONENLISTMENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationEnlistment_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint32_t EnlistmentInformationClass, uint64_t EnlistmentInformation, uint32_t EnlistmentInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t FileInformation, uint32_t Length, uint32_t FileInformationClass);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t FileInformation, uint32_t Length, uint32_t FileInformationClass);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONJOBOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONJOBOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationJobObject_enter, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint32_t JobObjectInformationClass, uint64_t JobObjectInformation, uint32_t JobObjectInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONJOBOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONJOBOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationJobObject_return, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint32_t JobObjectInformationClass, uint64_t JobObjectInformation, uint32_t JobObjectInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t PortInformationClass, uint64_t PortInformation, uint32_t Length, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint32_t PortInformationClass, uint64_t PortInformation, uint32_t Length, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t ProcessInformationClass, uint64_t ProcessInformation, uint32_t ProcessInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t ProcessInformationClass, uint64_t ProcessInformation, uint32_t ProcessInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONRESOURCEMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONRESOURCEMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationResourceManager_enter, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t ResourceManagerInformationClass, uint64_t ResourceManagerInformation, uint32_t ResourceManagerInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONRESOURCEMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONRESOURCEMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationResourceManager_return, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t ResourceManagerInformationClass, uint64_t ResourceManagerInformation, uint32_t ResourceManagerInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t ThreadInformationClass, uint64_t ThreadInformation, uint32_t ThreadInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t ThreadInformationClass, uint64_t ThreadInformation, uint32_t ThreadInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationToken_enter, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint32_t TokenInformationClass, uint64_t TokenInformation, uint32_t TokenInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationToken_return, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint32_t TokenInformationClass, uint64_t TokenInformation, uint32_t TokenInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTRANSACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTRANSACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationTransaction_enter, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t TransactionInformationClass, uint64_t TransactionInformation, uint32_t TransactionInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTRANSACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTRANSACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationTransaction_return, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t TransactionInformationClass, uint64_t TransactionInformation, uint32_t TransactionInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTRANSACTIONMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTRANSACTIONMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationTransactionManager_enter, CPUState* cpu, target_ulong pc, uint64_t TransactionManagerHandle, uint32_t TransactionManagerInformationClass, uint64_t TransactionManagerInformation, uint32_t TransactionManagerInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTRANSACTIONMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONTRANSACTIONMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationTransactionManager_return, CPUState* cpu, target_ulong pc, uint64_t TransactionManagerHandle, uint32_t TransactionManagerInformationClass, uint64_t TransactionManagerInformation, uint32_t TransactionManagerInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONWORKERFACTORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONWORKERFACTORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationWorkerFactory_enter, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle, uint32_t WorkerFactoryInformationClass, uint64_t WorkerFactoryInformation, uint32_t WorkerFactoryInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONWORKERFACTORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINFORMATIONWORKERFACTORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInformationWorkerFactory_return, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle, uint32_t WorkerFactoryInformationClass, uint64_t WorkerFactoryInformation, uint32_t WorkerFactoryInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINSTALLUILANGUAGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINSTALLUILANGUAGE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryInstallUILanguage_enter, CPUState* cpu, target_ulong pc, uint64_t InstallUILanguageId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINSTALLUILANGUAGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINSTALLUILANGUAGE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryInstallUILanguage_return, CPUState* cpu, target_ulong pc, uint64_t InstallUILanguageId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINTERVALPROFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINTERVALPROFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryIntervalProfile_enter, CPUState* cpu, target_ulong pc, uint32_t ProfileSource, uint64_t Interval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINTERVALPROFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYINTERVALPROFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryIntervalProfile_return, CPUState* cpu, target_ulong pc, uint32_t ProfileSource, uint64_t Interval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYIOCOMPLETION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYIOCOMPLETION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryIoCompletion_enter, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint32_t IoCompletionInformationClass, uint64_t IoCompletionInformation, uint32_t IoCompletionInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYIOCOMPLETION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYIOCOMPLETION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryIoCompletion_return, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint32_t IoCompletionInformationClass, uint64_t IoCompletionInformation, uint32_t IoCompletionInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t KeyInformationClass, uint64_t KeyInformation, uint32_t Length, uint64_t ResultLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t KeyInformationClass, uint64_t KeyInformation, uint32_t Length, uint64_t ResultLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYLICENSEVALUE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYLICENSEVALUE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryLicenseValue_enter, CPUState* cpu, target_ulong pc, uint64_t Name, uint64_t Type, uint64_t Buffer, uint32_t Length, uint64_t ReturnedLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYLICENSEVALUE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYLICENSEVALUE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryLicenseValue_return, CPUState* cpu, target_ulong pc, uint64_t Name, uint64_t Type, uint64_t Buffer, uint32_t Length, uint64_t ReturnedLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYMULTIPLEVALUEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYMULTIPLEVALUEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryMultipleValueKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t ValueEntries, uint32_t EntryCount, uint64_t ValueBuffer, uint64_t BufferLength, uint64_t RequiredBufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYMULTIPLEVALUEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYMULTIPLEVALUEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryMultipleValueKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t ValueEntries, uint32_t EntryCount, uint64_t ValueBuffer, uint64_t BufferLength, uint64_t RequiredBufferLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYMUTANT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYMUTANT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryMutant_enter, CPUState* cpu, target_ulong pc, uint64_t MutantHandle, uint32_t MutantInformationClass, uint64_t MutantInformation, uint32_t MutantInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYMUTANT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYMUTANT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryMutant_return, CPUState* cpu, target_ulong pc, uint64_t MutantHandle, uint32_t MutantInformationClass, uint64_t MutantInformation, uint32_t MutantInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryObject_enter, CPUState* cpu, target_ulong pc, uint64_t Handle, uint32_t ObjectInformationClass, uint64_t ObjectInformation, uint32_t ObjectInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryObject_return, CPUState* cpu, target_ulong pc, uint64_t Handle, uint32_t ObjectInformationClass, uint64_t ObjectInformation, uint32_t ObjectInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOPENSUBKEYS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOPENSUBKEYS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryOpenSubKeys_enter, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint64_t HandleCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOPENSUBKEYS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOPENSUBKEYS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryOpenSubKeys_return, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint64_t HandleCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOPENSUBKEYSEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOPENSUBKEYSEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryOpenSubKeysEx_enter, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint32_t BufferLength, uint64_t Buffer, uint64_t RequiredSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOPENSUBKEYSEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYOPENSUBKEYSEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryOpenSubKeysEx_return, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint32_t BufferLength, uint64_t Buffer, uint64_t RequiredSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYPERFORMANCECOUNTER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYPERFORMANCECOUNTER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryPerformanceCounter_enter, CPUState* cpu, target_ulong pc, uint64_t PerformanceCounter, uint64_t PerformanceFrequency);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYPERFORMANCECOUNTER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYPERFORMANCECOUNTER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryPerformanceCounter_return, CPUState* cpu, target_ulong pc, uint64_t PerformanceCounter, uint64_t PerformanceFrequency);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYPORTINFORMATIONPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYPORTINFORMATIONPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryPortInformationProcess_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYPORTINFORMATIONPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYPORTINFORMATIONPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryPortInformationProcess_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYQUOTAINFORMATIONFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYQUOTAINFORMATIONFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryQuotaInformationFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length, uint32_t ReturnSingleEntry, uint64_t SidList, uint32_t SidListLength, uint64_t StartSid, uint32_t RestartScan);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYQUOTAINFORMATIONFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYQUOTAINFORMATIONFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryQuotaInformationFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length, uint32_t ReturnSingleEntry, uint64_t SidList, uint32_t SidListLength, uint64_t StartSid, uint32_t RestartScan);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQuerySection_enter, CPUState* cpu, target_ulong pc, uint64_t SectionHandle, uint32_t SectionInformationClass, uint64_t SectionInformation, uint64_t SectionInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQuerySection_return, CPUState* cpu, target_ulong pc, uint64_t SectionHandle, uint32_t SectionInformationClass, uint64_t SectionInformation, uint64_t SectionInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECURITYATTRIBUTESTOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECURITYATTRIBUTESTOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQuerySecurityAttributesToken_enter, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint64_t Attributes, uint32_t NumberOfAttributes, uint64_t Buffer, uint32_t Length, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECURITYATTRIBUTESTOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECURITYATTRIBUTESTOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQuerySecurityAttributesToken_return, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint64_t Attributes, uint32_t NumberOfAttributes, uint64_t Buffer, uint32_t Length, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECURITYOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECURITYOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQuerySecurityObject_enter, CPUState* cpu, target_ulong pc, uint64_t Handle, uint32_t SecurityInformation, uint64_t SecurityDescriptor, uint32_t Length, uint64_t LengthNeeded);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECURITYOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSECURITYOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQuerySecurityObject_return, CPUState* cpu, target_ulong pc, uint64_t Handle, uint32_t SecurityInformation, uint64_t SecurityDescriptor, uint32_t Length, uint64_t LengthNeeded);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSEMAPHORE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSEMAPHORE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQuerySemaphore_enter, CPUState* cpu, target_ulong pc, uint64_t SemaphoreHandle, uint32_t SemaphoreInformationClass, uint64_t SemaphoreInformation, uint32_t SemaphoreInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSEMAPHORE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSEMAPHORE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQuerySemaphore_return, CPUState* cpu, target_ulong pc, uint64_t SemaphoreHandle, uint32_t SemaphoreInformationClass, uint64_t SemaphoreInformation, uint32_t SemaphoreInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYMBOLICLINKOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYMBOLICLINKOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQuerySymbolicLinkObject_enter, CPUState* cpu, target_ulong pc, uint64_t LinkHandle, uint64_t LinkTarget, uint64_t ReturnedLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYMBOLICLINKOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYMBOLICLINKOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQuerySymbolicLinkObject_return, CPUState* cpu, target_ulong pc, uint64_t LinkHandle, uint64_t LinkTarget, uint64_t ReturnedLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMENVIRONMENTVALUE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMENVIRONMENTVALUE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQuerySystemEnvironmentValue_enter, CPUState* cpu, target_ulong pc, uint64_t VariableName, uint64_t VariableValue, uint32_t ValueLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMENVIRONMENTVALUE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMENVIRONMENTVALUE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQuerySystemEnvironmentValue_return, CPUState* cpu, target_ulong pc, uint64_t VariableName, uint64_t VariableValue, uint32_t ValueLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMENVIRONMENTVALUEEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMENVIRONMENTVALUEEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQuerySystemEnvironmentValueEx_enter, CPUState* cpu, target_ulong pc, uint64_t VariableName, uint64_t VendorGuid, uint64_t Value, uint64_t ValueLength, uint64_t Attributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMENVIRONMENTVALUEEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMENVIRONMENTVALUEEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQuerySystemEnvironmentValueEx_return, CPUState* cpu, target_ulong pc, uint64_t VariableName, uint64_t VendorGuid, uint64_t Value, uint64_t ValueLength, uint64_t Attributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMINFORMATION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMINFORMATION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQuerySystemInformation_enter, CPUState* cpu, target_ulong pc, uint32_t SystemInformationClass, uint64_t SystemInformation, uint32_t SystemInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMINFORMATION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMINFORMATION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQuerySystemInformation_return, CPUState* cpu, target_ulong pc, uint32_t SystemInformationClass, uint64_t SystemInformation, uint32_t SystemInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMINFORMATIONEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMINFORMATIONEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQuerySystemInformationEx_enter, CPUState* cpu, target_ulong pc, uint32_t SystemInformationClass, uint64_t QueryInformation, uint32_t QueryInformationLength, uint64_t SystemInformation, uint32_t SystemInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMINFORMATIONEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMINFORMATIONEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQuerySystemInformationEx_return, CPUState* cpu, target_ulong pc, uint32_t SystemInformationClass, uint64_t QueryInformation, uint32_t QueryInformationLength, uint64_t SystemInformation, uint32_t SystemInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQuerySystemTime_enter, CPUState* cpu, target_ulong pc, uint64_t SystemTime);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYSYSTEMTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQuerySystemTime_return, CPUState* cpu, target_ulong pc, uint64_t SystemTime);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYTIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYTIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryTimer_enter, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint32_t TimerInformationClass, uint64_t TimerInformation, uint32_t TimerInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYTIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYTIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryTimer_return, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint32_t TimerInformationClass, uint64_t TimerInformation, uint32_t TimerInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYTIMERRESOLUTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYTIMERRESOLUTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryTimerResolution_enter, CPUState* cpu, target_ulong pc, uint64_t MaximumTime, uint64_t MinimumTime, uint64_t CurrentTime);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYTIMERRESOLUTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYTIMERRESOLUTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryTimerResolution_return, CPUState* cpu, target_ulong pc, uint64_t MaximumTime, uint64_t MinimumTime, uint64_t CurrentTime);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVALUEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVALUEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryValueKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t ValueName, uint32_t KeyValueInformationClass, uint64_t KeyValueInformation, uint32_t Length, uint64_t ResultLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVALUEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVALUEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryValueKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t ValueName, uint32_t KeyValueInformationClass, uint64_t KeyValueInformation, uint32_t Length, uint64_t ResultLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVIRTUALMEMORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVIRTUALMEMORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryVirtualMemory_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint32_t MemoryInformationClass, uint64_t MemoryInformation, uint64_t MemoryInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVIRTUALMEMORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVIRTUALMEMORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryVirtualMemory_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint32_t MemoryInformationClass, uint64_t MemoryInformation, uint64_t MemoryInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVOLUMEINFORMATIONFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVOLUMEINFORMATIONFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueryVolumeInformationFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t FsInformation, uint32_t Length, uint32_t FsInformationClass);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVOLUMEINFORMATIONFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUERYVOLUMEINFORMATIONFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueryVolumeInformationFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t FsInformation, uint32_t Length, uint32_t FsInformationClass);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUEUEAPCTHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUEUEAPCTHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueueApcThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t ApcRoutine, uint64_t ApcArgument1, uint64_t ApcArgument2, uint64_t ApcArgument3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUEUEAPCTHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUEUEAPCTHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueueApcThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t ApcRoutine, uint64_t ApcArgument1, uint64_t ApcArgument2, uint64_t ApcArgument3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUEUEAPCTHREADEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUEUEAPCTHREADEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtQueueApcThreadEx_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t UserApcReserveHandle, uint64_t ApcRoutine, uint64_t ApcArgument1, uint64_t ApcArgument2, uint64_t ApcArgument3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTQUEUEAPCTHREADEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTQUEUEAPCTHREADEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtQueueApcThreadEx_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t UserApcReserveHandle, uint64_t ApcRoutine, uint64_t ApcArgument1, uint64_t ApcArgument2, uint64_t ApcArgument3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRAISEEXCEPTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRAISEEXCEPTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRaiseException_enter, CPUState* cpu, target_ulong pc, uint64_t ExceptionRecord, uint64_t ContextRecord, uint32_t FirstChance);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRAISEEXCEPTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRAISEEXCEPTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRaiseException_return, CPUState* cpu, target_ulong pc, uint64_t ExceptionRecord, uint64_t ContextRecord, uint32_t FirstChance);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRAISEHARDERROR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRAISEHARDERROR_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRaiseHardError_enter, CPUState* cpu, target_ulong pc, uint32_t ErrorStatus, uint32_t NumberOfParameters, uint32_t UnicodeStringParameterMask, uint64_t Parameters, uint32_t ValidResponseOptions, uint64_t Response);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRAISEHARDERROR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRAISEHARDERROR_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRaiseHardError_return, CPUState* cpu, target_ulong pc, uint32_t ErrorStatus, uint32_t NumberOfParameters, uint32_t UnicodeStringParameterMask, uint64_t Parameters, uint32_t ValidResponseOptions, uint64_t Response);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREADFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREADFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReadFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length, uint64_t ByteOffset, uint64_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREADFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREADFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReadFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length, uint64_t ByteOffset, uint64_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREADFILESCATTER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREADFILESCATTER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReadFileScatter_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t SegmentArray, uint32_t Length, uint64_t ByteOffset, uint64_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREADFILESCATTER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREADFILESCATTER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReadFileScatter_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t SegmentArray, uint32_t Length, uint64_t ByteOffset, uint64_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREADONLYENLISTMENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREADONLYENLISTMENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReadOnlyEnlistment_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREADONLYENLISTMENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREADONLYENLISTMENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReadOnlyEnlistment_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREADREQUESTDATA_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREADREQUESTDATA_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReadRequestData_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t Message, uint32_t DataEntryIndex, uint64_t Buffer, uint64_t BufferSize, uint64_t NumberOfBytesRead);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREADREQUESTDATA_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREADREQUESTDATA_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReadRequestData_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t Message, uint32_t DataEntryIndex, uint64_t Buffer, uint64_t BufferSize, uint64_t NumberOfBytesRead);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREADVIRTUALMEMORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREADVIRTUALMEMORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReadVirtualMemory_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t Buffer, uint64_t BufferSize, uint64_t NumberOfBytesRead);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREADVIRTUALMEMORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREADVIRTUALMEMORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReadVirtualMemory_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t Buffer, uint64_t BufferSize, uint64_t NumberOfBytesRead);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERENLISTMENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERENLISTMENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRecoverEnlistment_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t EnlistmentKey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERENLISTMENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERENLISTMENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRecoverEnlistment_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t EnlistmentKey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERRESOURCEMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERRESOURCEMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRecoverResourceManager_enter, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERRESOURCEMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERRESOURCEMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRecoverResourceManager_return, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERTRANSACTIONMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERTRANSACTIONMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRecoverTransactionManager_enter, CPUState* cpu, target_ulong pc, uint64_t TransactionManagerHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERTRANSACTIONMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRECOVERTRANSACTIONMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRecoverTransactionManager_return, CPUState* cpu, target_ulong pc, uint64_t TransactionManagerHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREGISTERPROTOCOLADDRESSINFORMATION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREGISTERPROTOCOLADDRESSINFORMATION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRegisterProtocolAddressInformation_enter, CPUState* cpu, target_ulong pc, uint64_t ResourceManager, uint64_t ProtocolId, uint32_t ProtocolInformationSize, uint64_t ProtocolInformation, uint32_t CreateOptions);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREGISTERPROTOCOLADDRESSINFORMATION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREGISTERPROTOCOLADDRESSINFORMATION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRegisterProtocolAddressInformation_return, CPUState* cpu, target_ulong pc, uint64_t ResourceManager, uint64_t ProtocolId, uint32_t ProtocolInformationSize, uint64_t ProtocolInformation, uint32_t CreateOptions);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREGISTERTHREADTERMINATEPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREGISTERTHREADTERMINATEPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRegisterThreadTerminatePort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREGISTERTHREADTERMINATEPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREGISTERTHREADTERMINATEPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRegisterThreadTerminatePort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEKEYEDEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEKEYEDEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReleaseKeyedEvent_enter, CPUState* cpu, target_ulong pc, uint64_t KeyedEventHandle, uint64_t KeyValue, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEKEYEDEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEKEYEDEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReleaseKeyedEvent_return, CPUState* cpu, target_ulong pc, uint64_t KeyedEventHandle, uint64_t KeyValue, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEMUTANT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEMUTANT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReleaseMutant_enter, CPUState* cpu, target_ulong pc, uint64_t MutantHandle, uint64_t PreviousCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEMUTANT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEMUTANT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReleaseMutant_return, CPUState* cpu, target_ulong pc, uint64_t MutantHandle, uint64_t PreviousCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRELEASESEMAPHORE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRELEASESEMAPHORE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReleaseSemaphore_enter, CPUState* cpu, target_ulong pc, uint64_t SemaphoreHandle, int32_t ReleaseCount, uint64_t PreviousCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRELEASESEMAPHORE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRELEASESEMAPHORE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReleaseSemaphore_return, CPUState* cpu, target_ulong pc, uint64_t SemaphoreHandle, int32_t ReleaseCount, uint64_t PreviousCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEWORKERFACTORYWORKER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEWORKERFACTORYWORKER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReleaseWorkerFactoryWorker_enter, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEWORKERFACTORYWORKER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRELEASEWORKERFACTORYWORKER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReleaseWorkerFactoryWorker_return, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEIOCOMPLETION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEIOCOMPLETION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRemoveIoCompletion_enter, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint64_t KeyContext, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEIOCOMPLETION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEIOCOMPLETION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRemoveIoCompletion_return, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint64_t KeyContext, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEIOCOMPLETIONEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEIOCOMPLETIONEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRemoveIoCompletionEx_enter, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint64_t IoCompletionInformation, uint32_t Count, uint64_t NumEntriesRemoved, uint64_t Timeout, uint32_t Alertable);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEIOCOMPLETIONEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEIOCOMPLETIONEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRemoveIoCompletionEx_return, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint64_t IoCompletionInformation, uint32_t Count, uint64_t NumEntriesRemoved, uint64_t Timeout, uint32_t Alertable);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEPROCESSDEBUG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEPROCESSDEBUG_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRemoveProcessDebug_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t DebugObjectHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEPROCESSDEBUG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREMOVEPROCESSDEBUG_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRemoveProcessDebug_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t DebugObjectHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRENAMEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRENAMEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRenameKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t NewName);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRENAMEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRENAMEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRenameKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t NewName);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRENAMETRANSACTIONMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRENAMETRANSACTIONMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRenameTransactionManager_enter, CPUState* cpu, target_ulong pc, uint64_t LogFileName, uint64_t ExistingTransactionManagerGuid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRENAMETRANSACTIONMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRENAMETRANSACTIONMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRenameTransactionManager_return, CPUState* cpu, target_ulong pc, uint64_t LogFileName, uint64_t ExistingTransactionManagerGuid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLACEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLACEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReplaceKey_enter, CPUState* cpu, target_ulong pc, uint64_t NewFile, uint64_t TargetHandle, uint64_t OldFile);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLACEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLACEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReplaceKey_return, CPUState* cpu, target_ulong pc, uint64_t NewFile, uint64_t TargetHandle, uint64_t OldFile);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLACEPARTITIONUNIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLACEPARTITIONUNIT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReplacePartitionUnit_enter, CPUState* cpu, target_ulong pc, uint64_t TargetInstancePath, uint64_t SpareInstancePath, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLACEPARTITIONUNIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLACEPARTITIONUNIT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReplacePartitionUnit_return, CPUState* cpu, target_ulong pc, uint64_t TargetInstancePath, uint64_t SpareInstancePath, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLYPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLYPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReplyPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ReplyMessage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLYPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLYPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReplyPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ReplyMessage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITRECEIVEPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITRECEIVEPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReplyWaitReceivePort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortContext, uint64_t ReplyMessage, uint64_t ReceiveMessage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITRECEIVEPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITRECEIVEPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReplyWaitReceivePort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortContext, uint64_t ReplyMessage, uint64_t ReceiveMessage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITRECEIVEPORTEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITRECEIVEPORTEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReplyWaitReceivePortEx_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortContext, uint64_t ReplyMessage, uint64_t ReceiveMessage, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITRECEIVEPORTEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITRECEIVEPORTEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReplyWaitReceivePortEx_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortContext, uint64_t ReplyMessage, uint64_t ReceiveMessage, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITREPLYPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITREPLYPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtReplyWaitReplyPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ReplyMessage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITREPLYPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREPLYWAITREPLYPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtReplyWaitReplyPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t ReplyMessage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREQUESTPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREQUESTPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRequestPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t RequestMessage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREQUESTPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREQUESTPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRequestPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t RequestMessage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREQUESTWAITREPLYPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTREQUESTWAITREPLYPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRequestWaitReplyPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t RequestMessage, uint64_t ReplyMessage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTREQUESTWAITREPLYPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTREQUESTWAITREPLYPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRequestWaitReplyPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t RequestMessage, uint64_t ReplyMessage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRESETEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRESETEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtResetEvent_enter, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint64_t PreviousState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRESETEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRESETEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtResetEvent_return, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint64_t PreviousState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRESETWRITEWATCH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRESETWRITEWATCH_ENTER 1
PPP_CB_TYPEDEF(void, on_NtResetWriteWatch_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRESETWRITEWATCH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRESETWRITEWATCH_RETURN 1
PPP_CB_TYPEDEF(void, on_NtResetWriteWatch_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRESTOREKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRESTOREKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRestoreKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t FileHandle, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRESTOREKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRESTOREKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRestoreKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t FileHandle, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRESUMEPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRESUMEPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtResumeProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRESUMEPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRESUMEPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtResumeProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRESUMETHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTRESUMETHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtResumeThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t PreviousSuspendCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTRESUMETHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTRESUMETHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtResumeThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t PreviousSuspendCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKCOMPLETE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKCOMPLETE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRollbackComplete_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKCOMPLETE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKCOMPLETE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRollbackComplete_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKENLISTMENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKENLISTMENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRollbackEnlistment_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKENLISTMENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKENLISTMENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRollbackEnlistment_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKTRANSACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKTRANSACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRollbackTransaction_enter, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t Wait);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKTRANSACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTROLLBACKTRANSACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRollbackTransaction_return, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t Wait);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTROLLFORWARDTRANSACTIONMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTROLLFORWARDTRANSACTIONMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtRollforwardTransactionManager_enter, CPUState* cpu, target_ulong pc, uint64_t TransactionManagerHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTROLLFORWARDTRANSACTIONMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTROLLFORWARDTRANSACTIONMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtRollforwardTransactionManager_return, CPUState* cpu, target_ulong pc, uint64_t TransactionManagerHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSAVEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSAVEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSaveKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t FileHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSAVEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSAVEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSaveKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t FileHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSAVEKEYEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSAVEKEYEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSaveKeyEx_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t FileHandle, uint32_t Format);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSAVEKEYEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSAVEKEYEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSaveKeyEx_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t FileHandle, uint32_t Format);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSAVEMERGEDKEYS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSAVEMERGEDKEYS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSaveMergedKeys_enter, CPUState* cpu, target_ulong pc, uint64_t HighPrecedenceKeyHandle, uint64_t LowPrecedenceKeyHandle, uint64_t FileHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSAVEMERGEDKEYS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSAVEMERGEDKEYS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSaveMergedKeys_return, CPUState* cpu, target_ulong pc, uint64_t HighPrecedenceKeyHandle, uint64_t LowPrecedenceKeyHandle, uint64_t FileHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSECURECONNECTPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSECURECONNECTPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSecureConnectPort_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortName, uint64_t SecurityQos, uint64_t ClientView, uint64_t RequiredServerSid, uint64_t ServerView, uint64_t MaxMessageLength, uint64_t ConnectionInformation, uint64_t ConnectionInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSECURECONNECTPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSECURECONNECTPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSecureConnectPort_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t PortName, uint64_t SecurityQos, uint64_t ClientView, uint64_t RequiredServerSid, uint64_t ServerView, uint64_t MaxMessageLength, uint64_t ConnectionInformation, uint64_t ConnectionInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSERIALIZEBOOT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSERIALIZEBOOT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSerializeBoot_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSERIALIZEBOOT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSERIALIZEBOOT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSerializeBoot_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETBOOTENTRYORDER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETBOOTENTRYORDER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetBootEntryOrder_enter, CPUState* cpu, target_ulong pc, uint64_t Ids, uint32_t Count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETBOOTENTRYORDER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETBOOTENTRYORDER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetBootEntryOrder_return, CPUState* cpu, target_ulong pc, uint64_t Ids, uint32_t Count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETBOOTOPTIONS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETBOOTOPTIONS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetBootOptions_enter, CPUState* cpu, target_ulong pc, uint64_t BootOptions, uint32_t FieldsToChange);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETBOOTOPTIONS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETBOOTOPTIONS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetBootOptions_return, CPUState* cpu, target_ulong pc, uint64_t BootOptions, uint32_t FieldsToChange);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETCONTEXTTHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETCONTEXTTHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetContextThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t ThreadContext);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETCONTEXTTHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETCONTEXTTHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetContextThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t ThreadContext);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETDEBUGFILTERSTATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETDEBUGFILTERSTATE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetDebugFilterState_enter, CPUState* cpu, target_ulong pc, uint32_t ComponentId, uint32_t Level, uint32_t State);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETDEBUGFILTERSTATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETDEBUGFILTERSTATE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetDebugFilterState_return, CPUState* cpu, target_ulong pc, uint32_t ComponentId, uint32_t Level, uint32_t State);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTHARDERRORPORT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTHARDERRORPORT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetDefaultHardErrorPort_enter, CPUState* cpu, target_ulong pc, uint64_t DefaultHardErrorPort);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTHARDERRORPORT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTHARDERRORPORT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetDefaultHardErrorPort_return, CPUState* cpu, target_ulong pc, uint64_t DefaultHardErrorPort);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTLOCALE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTLOCALE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetDefaultLocale_enter, CPUState* cpu, target_ulong pc, uint32_t UserProfile, uint32_t DefaultLocaleId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTLOCALE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTLOCALE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetDefaultLocale_return, CPUState* cpu, target_ulong pc, uint32_t UserProfile, uint32_t DefaultLocaleId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTUILANGUAGE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTUILANGUAGE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetDefaultUILanguage_enter, CPUState* cpu, target_ulong pc, uint32_t DefaultUILanguageId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTUILANGUAGE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETDEFAULTUILANGUAGE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetDefaultUILanguage_return, CPUState* cpu, target_ulong pc, uint32_t DefaultUILanguageId);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETDRIVERENTRYORDER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETDRIVERENTRYORDER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetDriverEntryOrder_enter, CPUState* cpu, target_ulong pc, uint64_t Ids, uint32_t Count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETDRIVERENTRYORDER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETDRIVERENTRYORDER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetDriverEntryOrder_return, CPUState* cpu, target_ulong pc, uint64_t Ids, uint32_t Count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETEAFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETEAFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetEaFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETEAFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETEAFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetEaFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetEvent_enter, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint64_t PreviousState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetEvent_return, CPUState* cpu, target_ulong pc, uint64_t EventHandle, uint64_t PreviousState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETEVENTBOOSTPRIORITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETEVENTBOOSTPRIORITY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetEventBoostPriority_enter, CPUState* cpu, target_ulong pc, uint64_t EventHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETEVENTBOOSTPRIORITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETEVENTBOOSTPRIORITY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetEventBoostPriority_return, CPUState* cpu, target_ulong pc, uint64_t EventHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETHIGHEVENTPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETHIGHEVENTPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetHighEventPair_enter, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETHIGHEVENTPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETHIGHEVENTPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetHighEventPair_return, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETHIGHWAITLOWEVENTPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETHIGHWAITLOWEVENTPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetHighWaitLowEventPair_enter, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETHIGHWAITLOWEVENTPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETHIGHWAITLOWEVENTPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetHighWaitLowEventPair_return, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONDEBUGOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONDEBUGOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationDebugObject_enter, CPUState* cpu, target_ulong pc, uint64_t DebugObjectHandle, uint32_t DebugObjectInformationClass, uint64_t DebugInformation, uint32_t DebugInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONDEBUGOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONDEBUGOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationDebugObject_return, CPUState* cpu, target_ulong pc, uint64_t DebugObjectHandle, uint32_t DebugObjectInformationClass, uint64_t DebugInformation, uint32_t DebugInformationLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONENLISTMENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONENLISTMENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationEnlistment_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint32_t EnlistmentInformationClass, uint64_t EnlistmentInformation, uint32_t EnlistmentInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONENLISTMENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONENLISTMENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationEnlistment_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint32_t EnlistmentInformationClass, uint64_t EnlistmentInformation, uint32_t EnlistmentInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t FileInformation, uint32_t Length, uint32_t FileInformationClass);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t FileInformation, uint32_t Length, uint32_t FileInformationClass);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONJOBOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONJOBOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationJobObject_enter, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint32_t JobObjectInformationClass, uint64_t JobObjectInformation, uint32_t JobObjectInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONJOBOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONJOBOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationJobObject_return, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint32_t JobObjectInformationClass, uint64_t JobObjectInformation, uint32_t JobObjectInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t KeySetInformationClass, uint64_t KeySetInformation, uint32_t KeySetInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint32_t KeySetInformationClass, uint64_t KeySetInformation, uint32_t KeySetInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationObject_enter, CPUState* cpu, target_ulong pc, uint64_t Handle, uint32_t ObjectInformationClass, uint64_t ObjectInformation, uint32_t ObjectInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationObject_return, CPUState* cpu, target_ulong pc, uint64_t Handle, uint32_t ObjectInformationClass, uint64_t ObjectInformation, uint32_t ObjectInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t ProcessInformationClass, uint64_t ProcessInformation, uint32_t ProcessInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t ProcessInformationClass, uint64_t ProcessInformation, uint32_t ProcessInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONRESOURCEMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONRESOURCEMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationResourceManager_enter, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t ResourceManagerInformationClass, uint64_t ResourceManagerInformation, uint32_t ResourceManagerInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONRESOURCEMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONRESOURCEMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationResourceManager_return, CPUState* cpu, target_ulong pc, uint64_t ResourceManagerHandle, uint32_t ResourceManagerInformationClass, uint64_t ResourceManagerInformation, uint32_t ResourceManagerInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t ThreadInformationClass, uint64_t ThreadInformation, uint32_t ThreadInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t ThreadInformationClass, uint64_t ThreadInformation, uint32_t ThreadInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTOKEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTOKEN_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationToken_enter, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint32_t TokenInformationClass, uint64_t TokenInformation, uint32_t TokenInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTOKEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTOKEN_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationToken_return, CPUState* cpu, target_ulong pc, uint64_t TokenHandle, uint32_t TokenInformationClass, uint64_t TokenInformation, uint32_t TokenInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTRANSACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTRANSACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationTransaction_enter, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t TransactionInformationClass, uint64_t TransactionInformation, uint32_t TransactionInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTRANSACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTRANSACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationTransaction_return, CPUState* cpu, target_ulong pc, uint64_t TransactionHandle, uint32_t TransactionInformationClass, uint64_t TransactionInformation, uint32_t TransactionInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTRANSACTIONMANAGER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTRANSACTIONMANAGER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationTransactionManager_enter, CPUState* cpu, target_ulong pc, uint64_t TmHandle, uint32_t TransactionManagerInformationClass, uint64_t TransactionManagerInformation, uint32_t TransactionManagerInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTRANSACTIONMANAGER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONTRANSACTIONMANAGER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationTransactionManager_return, CPUState* cpu, target_ulong pc, uint64_t TmHandle, uint32_t TransactionManagerInformationClass, uint64_t TransactionManagerInformation, uint32_t TransactionManagerInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONWORKERFACTORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONWORKERFACTORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetInformationWorkerFactory_enter, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle, uint32_t WorkerFactoryInformationClass, uint64_t WorkerFactoryInformation, uint32_t WorkerFactoryInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONWORKERFACTORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINFORMATIONWORKERFACTORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetInformationWorkerFactory_return, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle, uint32_t WorkerFactoryInformationClass, uint64_t WorkerFactoryInformation, uint32_t WorkerFactoryInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINTERVALPROFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINTERVALPROFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetIntervalProfile_enter, CPUState* cpu, target_ulong pc, uint32_t Interval, uint32_t Source);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETINTERVALPROFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETINTERVALPROFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetIntervalProfile_return, CPUState* cpu, target_ulong pc, uint32_t Interval, uint32_t Source);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETIOCOMPLETION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETIOCOMPLETION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetIoCompletion_enter, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint64_t KeyContext, uint64_t ApcContext, uint32_t IoStatus, uint64_t IoStatusInformation);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETIOCOMPLETION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETIOCOMPLETION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetIoCompletion_return, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint64_t KeyContext, uint64_t ApcContext, uint32_t IoStatus, uint64_t IoStatusInformation);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETIOCOMPLETIONEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETIOCOMPLETIONEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetIoCompletionEx_enter, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint64_t IoCompletionReserveHandle, uint64_t KeyContext, uint64_t ApcContext, uint32_t IoStatus, uint64_t IoStatusInformation);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETIOCOMPLETIONEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETIOCOMPLETIONEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetIoCompletionEx_return, CPUState* cpu, target_ulong pc, uint64_t IoCompletionHandle, uint64_t IoCompletionReserveHandle, uint64_t KeyContext, uint64_t ApcContext, uint32_t IoStatus, uint64_t IoStatusInformation);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETLDTENTRIES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETLDTENTRIES_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetLdtEntries_enter, CPUState* cpu, target_ulong pc, uint32_t Selector0, uint32_t Entry0Low, uint32_t Entry0Hi, uint32_t Selector1, uint32_t Entry1Low, uint32_t Entry1Hi);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETLDTENTRIES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETLDTENTRIES_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetLdtEntries_return, CPUState* cpu, target_ulong pc, uint32_t Selector0, uint32_t Entry0Low, uint32_t Entry0Hi, uint32_t Selector1, uint32_t Entry1Low, uint32_t Entry1Hi);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETLOWEVENTPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETLOWEVENTPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetLowEventPair_enter, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETLOWEVENTPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETLOWEVENTPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetLowEventPair_return, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETLOWWAITHIGHEVENTPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETLOWWAITHIGHEVENTPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetLowWaitHighEventPair_enter, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETLOWWAITHIGHEVENTPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETLOWWAITHIGHEVENTPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetLowWaitHighEventPair_return, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETQUOTAINFORMATIONFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETQUOTAINFORMATIONFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetQuotaInformationFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETQUOTAINFORMATIONFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETQUOTAINFORMATIONFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetQuotaInformationFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSECURITYOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSECURITYOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetSecurityObject_enter, CPUState* cpu, target_ulong pc, uint64_t Handle, uint32_t SecurityInformation, uint64_t SecurityDescriptor);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSECURITYOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSECURITYOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetSecurityObject_return, CPUState* cpu, target_ulong pc, uint64_t Handle, uint32_t SecurityInformation, uint64_t SecurityDescriptor);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMENVIRONMENTVALUE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMENVIRONMENTVALUE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetSystemEnvironmentValue_enter, CPUState* cpu, target_ulong pc, uint64_t VariableName, uint64_t VariableValue);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMENVIRONMENTVALUE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMENVIRONMENTVALUE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetSystemEnvironmentValue_return, CPUState* cpu, target_ulong pc, uint64_t VariableName, uint64_t VariableValue);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMENVIRONMENTVALUEEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMENVIRONMENTVALUEEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetSystemEnvironmentValueEx_enter, CPUState* cpu, target_ulong pc, uint64_t VariableName, uint64_t VendorGuid, uint64_t Value, uint32_t ValueLength, uint32_t Attributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMENVIRONMENTVALUEEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMENVIRONMENTVALUEEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetSystemEnvironmentValueEx_return, CPUState* cpu, target_ulong pc, uint64_t VariableName, uint64_t VendorGuid, uint64_t Value, uint32_t ValueLength, uint32_t Attributes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMINFORMATION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMINFORMATION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetSystemInformation_enter, CPUState* cpu, target_ulong pc, uint32_t SystemInformationClass, uint64_t SystemInformation, uint32_t SystemInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMINFORMATION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMINFORMATION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetSystemInformation_return, CPUState* cpu, target_ulong pc, uint32_t SystemInformationClass, uint64_t SystemInformation, uint32_t SystemInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMPOWERSTATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMPOWERSTATE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetSystemPowerState_enter, CPUState* cpu, target_ulong pc, uint32_t SystemAction, uint32_t MinSystemState, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMPOWERSTATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMPOWERSTATE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetSystemPowerState_return, CPUState* cpu, target_ulong pc, uint32_t SystemAction, uint32_t MinSystemState, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetSystemTime_enter, CPUState* cpu, target_ulong pc, uint64_t SystemTime, uint64_t PreviousTime);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETSYSTEMTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetSystemTime_return, CPUState* cpu, target_ulong pc, uint64_t SystemTime, uint64_t PreviousTime);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETTHREADEXECUTIONSTATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETTHREADEXECUTIONSTATE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetThreadExecutionState_enter, CPUState* cpu, target_ulong pc, uint32_t esFlags, uint64_t PreviousFlags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETTHREADEXECUTIONSTATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETTHREADEXECUTIONSTATE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetThreadExecutionState_return, CPUState* cpu, target_ulong pc, uint32_t esFlags, uint64_t PreviousFlags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetTimer_enter, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint64_t DueTime, uint64_t TimerApcRoutine, uint64_t TimerContext, uint32_t WakeTimer, int32_t Period, uint64_t PreviousState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetTimer_return, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint64_t DueTime, uint64_t TimerApcRoutine, uint64_t TimerContext, uint32_t WakeTimer, int32_t Period, uint64_t PreviousState);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMEREX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMEREX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetTimerEx_enter, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint32_t TimerSetInformationClass, uint64_t TimerSetInformation, uint32_t TimerSetInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMEREX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMEREX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetTimerEx_return, CPUState* cpu, target_ulong pc, uint64_t TimerHandle, uint32_t TimerSetInformationClass, uint64_t TimerSetInformation, uint32_t TimerSetInformationLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMERRESOLUTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMERRESOLUTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetTimerResolution_enter, CPUState* cpu, target_ulong pc, uint32_t DesiredTime, uint32_t SetResolution, uint64_t ActualTime);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMERRESOLUTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETTIMERRESOLUTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetTimerResolution_return, CPUState* cpu, target_ulong pc, uint32_t DesiredTime, uint32_t SetResolution, uint64_t ActualTime);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETUUIDSEED_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETUUIDSEED_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetUuidSeed_enter, CPUState* cpu, target_ulong pc, uint64_t Seed);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETUUIDSEED_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETUUIDSEED_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetUuidSeed_return, CPUState* cpu, target_ulong pc, uint64_t Seed);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETVALUEKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETVALUEKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetValueKey_enter, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t ValueName, uint32_t TitleIndex, uint32_t Type, uint64_t Data, uint32_t DataSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETVALUEKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETVALUEKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetValueKey_return, CPUState* cpu, target_ulong pc, uint64_t KeyHandle, uint64_t ValueName, uint32_t TitleIndex, uint32_t Type, uint64_t Data, uint32_t DataSize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETVOLUMEINFORMATIONFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETVOLUMEINFORMATIONFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSetVolumeInformationFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t FsInformation, uint32_t Length, uint32_t FsInformationClass);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSETVOLUMEINFORMATIONFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSETVOLUMEINFORMATIONFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSetVolumeInformationFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t FsInformation, uint32_t Length, uint32_t FsInformationClass);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSHUTDOWNSYSTEM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSHUTDOWNSYSTEM_ENTER 1
PPP_CB_TYPEDEF(void, on_NtShutdownSystem_enter, CPUState* cpu, target_ulong pc, uint32_t Action);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSHUTDOWNSYSTEM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSHUTDOWNSYSTEM_RETURN 1
PPP_CB_TYPEDEF(void, on_NtShutdownSystem_return, CPUState* cpu, target_ulong pc, uint32_t Action);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSHUTDOWNWORKERFACTORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSHUTDOWNWORKERFACTORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtShutdownWorkerFactory_enter, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle, uint64_t PendingWorkerCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSHUTDOWNWORKERFACTORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSHUTDOWNWORKERFACTORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtShutdownWorkerFactory_return, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle, uint64_t PendingWorkerCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSIGNALANDWAITFORSINGLEOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSIGNALANDWAITFORSINGLEOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSignalAndWaitForSingleObject_enter, CPUState* cpu, target_ulong pc, uint64_t SignalHandle, uint64_t WaitHandle, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSIGNALANDWAITFORSINGLEOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSIGNALANDWAITFORSINGLEOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSignalAndWaitForSingleObject_return, CPUState* cpu, target_ulong pc, uint64_t SignalHandle, uint64_t WaitHandle, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSINGLEPHASEREJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSINGLEPHASEREJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSinglePhaseReject_enter, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSINGLEPHASEREJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSINGLEPHASEREJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSinglePhaseReject_return, CPUState* cpu, target_ulong pc, uint64_t EnlistmentHandle, uint64_t TmVirtualClock);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSTARTPROFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSTARTPROFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtStartProfile_enter, CPUState* cpu, target_ulong pc, uint64_t ProfileHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSTARTPROFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSTARTPROFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtStartProfile_return, CPUState* cpu, target_ulong pc, uint64_t ProfileHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSTOPPROFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSTOPPROFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtStopProfile_enter, CPUState* cpu, target_ulong pc, uint64_t ProfileHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSTOPPROFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSTOPPROFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtStopProfile_return, CPUState* cpu, target_ulong pc, uint64_t ProfileHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSUSPENDPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSUSPENDPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSuspendProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSUSPENDPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSUSPENDPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSuspendProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSUSPENDTHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSUSPENDTHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSuspendThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t PreviousSuspendCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSUSPENDTHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSUSPENDTHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSuspendThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint64_t PreviousSuspendCount);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSYSTEMDEBUGCONTROL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTSYSTEMDEBUGCONTROL_ENTER 1
PPP_CB_TYPEDEF(void, on_NtSystemDebugControl_enter, CPUState* cpu, target_ulong pc, uint32_t Command, uint64_t InputBuffer, uint32_t InputBufferLength, uint64_t OutputBuffer, uint32_t OutputBufferLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTSYSTEMDEBUGCONTROL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTSYSTEMDEBUGCONTROL_RETURN 1
PPP_CB_TYPEDEF(void, on_NtSystemDebugControl_return, CPUState* cpu, target_ulong pc, uint32_t Command, uint64_t InputBuffer, uint32_t InputBufferLength, uint64_t OutputBuffer, uint32_t OutputBufferLength, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATEJOBOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATEJOBOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtTerminateJobObject_enter, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint32_t ExitStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATEJOBOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATEJOBOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtTerminateJobObject_return, CPUState* cpu, target_ulong pc, uint64_t JobHandle, uint32_t ExitStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATEPROCESS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATEPROCESS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtTerminateProcess_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t ExitStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATEPROCESS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATEPROCESS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtTerminateProcess_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint32_t ExitStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATETHREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATETHREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtTerminateThread_enter, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t ExitStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATETHREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTTERMINATETHREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtTerminateThread_return, CPUState* cpu, target_ulong pc, uint64_t ThreadHandle, uint32_t ExitStatus);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTESTALERT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTTESTALERT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtTestAlert_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTESTALERT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTTESTALERT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtTestAlert_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTHAWREGISTRY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTTHAWREGISTRY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtThawRegistry_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTHAWREGISTRY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTTHAWREGISTRY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtThawRegistry_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTHAWTRANSACTIONS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTTHAWTRANSACTIONS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtThawTransactions_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTHAWTRANSACTIONS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTTHAWTRANSACTIONS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtThawTransactions_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTRACECONTROL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTTRACECONTROL_ENTER 1
PPP_CB_TYPEDEF(void, on_NtTraceControl_enter, CPUState* cpu, target_ulong pc, uint32_t FunctionCode, uint64_t InBuffer, uint32_t InBufferLen, uint64_t OutBuffer, uint32_t OutBufferLen, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTRACECONTROL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTTRACECONTROL_RETURN 1
PPP_CB_TYPEDEF(void, on_NtTraceControl_return, CPUState* cpu, target_ulong pc, uint32_t FunctionCode, uint64_t InBuffer, uint32_t InBufferLen, uint64_t OutBuffer, uint32_t OutBufferLen, uint64_t ReturnLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTRACEEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTTRACEEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtTraceEvent_enter, CPUState* cpu, target_ulong pc, uint64_t TraceHandle, uint32_t Flags, uint32_t FieldSize, uint64_t Fields);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTRACEEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTTRACEEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtTraceEvent_return, CPUState* cpu, target_ulong pc, uint64_t TraceHandle, uint32_t Flags, uint32_t FieldSize, uint64_t Fields);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTRANSLATEFILEPATH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTTRANSLATEFILEPATH_ENTER 1
PPP_CB_TYPEDEF(void, on_NtTranslateFilePath_enter, CPUState* cpu, target_ulong pc, uint64_t InputFilePath, uint32_t OutputType, uint64_t OutputFilePath, uint64_t OutputFilePathLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTTRANSLATEFILEPATH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTTRANSLATEFILEPATH_RETURN 1
PPP_CB_TYPEDEF(void, on_NtTranslateFilePath_return, CPUState* cpu, target_ulong pc, uint64_t InputFilePath, uint32_t OutputType, uint64_t OutputFilePath, uint64_t OutputFilePathLength);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUMSTHREADYIELD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTUMSTHREADYIELD_ENTER 1
PPP_CB_TYPEDEF(void, on_NtUmsThreadYield_enter, CPUState* cpu, target_ulong pc, uint64_t SchedulerParam);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUMSTHREADYIELD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTUMSTHREADYIELD_RETURN 1
PPP_CB_TYPEDEF(void, on_NtUmsThreadYield_return, CPUState* cpu, target_ulong pc, uint64_t SchedulerParam);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADDRIVER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADDRIVER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtUnloadDriver_enter, CPUState* cpu, target_ulong pc, uint64_t DriverServiceName);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADDRIVER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADDRIVER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtUnloadDriver_return, CPUState* cpu, target_ulong pc, uint64_t DriverServiceName);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtUnloadKey_enter, CPUState* cpu, target_ulong pc, uint64_t TargetKey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtUnloadKey_return, CPUState* cpu, target_ulong pc, uint64_t TargetKey);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEY2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEY2_ENTER 1
PPP_CB_TYPEDEF(void, on_NtUnloadKey2_enter, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEY2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEY2_RETURN 1
PPP_CB_TYPEDEF(void, on_NtUnloadKey2_return, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint32_t Flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEYEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEYEX_ENTER 1
PPP_CB_TYPEDEF(void, on_NtUnloadKeyEx_enter, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint64_t Event);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEYEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOADKEYEX_RETURN 1
PPP_CB_TYPEDEF(void, on_NtUnloadKeyEx_return, CPUState* cpu, target_ulong pc, uint64_t TargetKey, uint64_t Event);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOCKFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOCKFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtUnlockFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t ByteOffset, uint64_t Length, uint32_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOCKFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOCKFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtUnlockFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t IoStatusBlock, uint64_t ByteOffset, uint64_t Length, uint32_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOCKVIRTUALMEMORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOCKVIRTUALMEMORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtUnlockVirtualMemory_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize, uint32_t MapType);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNLOCKVIRTUALMEMORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNLOCKVIRTUALMEMORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtUnlockVirtualMemory_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t RegionSize, uint32_t MapType);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNMAPVIEWOFSECTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNMAPVIEWOFSECTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtUnmapViewOfSection_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTUNMAPVIEWOFSECTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTUNMAPVIEWOFSECTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtUnmapViewOfSection_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTVDMCONTROL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTVDMCONTROL_ENTER 1
PPP_CB_TYPEDEF(void, on_NtVdmControl_enter, CPUState* cpu, target_ulong pc, uint32_t Service, uint64_t ServiceData);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTVDMCONTROL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTVDMCONTROL_RETURN 1
PPP_CB_TYPEDEF(void, on_NtVdmControl_return, CPUState* cpu, target_ulong pc, uint32_t Service, uint64_t ServiceData);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORDEBUGEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORDEBUGEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWaitForDebugEvent_enter, CPUState* cpu, target_ulong pc, uint64_t DebugObjectHandle, uint32_t Alertable, uint64_t Timeout, uint64_t WaitStateChange);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORDEBUGEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORDEBUGEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWaitForDebugEvent_return, CPUState* cpu, target_ulong pc, uint64_t DebugObjectHandle, uint32_t Alertable, uint64_t Timeout, uint64_t WaitStateChange);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORKEYEDEVENT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORKEYEDEVENT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWaitForKeyedEvent_enter, CPUState* cpu, target_ulong pc, uint64_t KeyedEventHandle, uint64_t KeyValue, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORKEYEDEVENT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORKEYEDEVENT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWaitForKeyedEvent_return, CPUState* cpu, target_ulong pc, uint64_t KeyedEventHandle, uint64_t KeyValue, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORMULTIPLEOBJECTS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORMULTIPLEOBJECTS_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWaitForMultipleObjects_enter, CPUState* cpu, target_ulong pc, uint32_t Count, uint64_t Handles, uint32_t WaitType, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORMULTIPLEOBJECTS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORMULTIPLEOBJECTS_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWaitForMultipleObjects_return, CPUState* cpu, target_ulong pc, uint32_t Count, uint64_t Handles, uint32_t WaitType, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORMULTIPLEOBJECTS32_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORMULTIPLEOBJECTS32_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWaitForMultipleObjects32_enter, CPUState* cpu, target_ulong pc, uint32_t Count, uint64_t Handles, uint32_t WaitType, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORMULTIPLEOBJECTS32_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORMULTIPLEOBJECTS32_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWaitForMultipleObjects32_return, CPUState* cpu, target_ulong pc, uint32_t Count, uint64_t Handles, uint32_t WaitType, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORSINGLEOBJECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORSINGLEOBJECT_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWaitForSingleObject_enter, CPUState* cpu, target_ulong pc, uint64_t Handle, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORSINGLEOBJECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORSINGLEOBJECT_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWaitForSingleObject_return, CPUState* cpu, target_ulong pc, uint64_t Handle, uint32_t Alertable, uint64_t Timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORWORKVIAWORKERFACTORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORWORKVIAWORKERFACTORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWaitForWorkViaWorkerFactory_enter, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle, uint64_t MiniPacket);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORWORKVIAWORKERFACTORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITFORWORKVIAWORKERFACTORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWaitForWorkViaWorkerFactory_return, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle, uint64_t MiniPacket);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITHIGHEVENTPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITHIGHEVENTPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWaitHighEventPair_enter, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITHIGHEVENTPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITHIGHEVENTPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWaitHighEventPair_return, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITLOWEVENTPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITLOWEVENTPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWaitLowEventPair_enter, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWAITLOWEVENTPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWAITLOWEVENTPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWaitLowEventPair_return, CPUState* cpu, target_ulong pc, uint64_t EventPairHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWORKERFACTORYWORKERREADY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWORKERFACTORYWORKERREADY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWorkerFactoryWorkerReady_enter, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWORKERFACTORYWORKERREADY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWORKERFACTORYWORKERREADY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWorkerFactoryWorkerReady_return, CPUState* cpu, target_ulong pc, uint64_t WorkerFactoryHandle);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWRITEFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWRITEFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWriteFile_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length, uint64_t ByteOffset, uint64_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWRITEFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWRITEFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWriteFile_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t Length, uint64_t ByteOffset, uint64_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWRITEFILEGATHER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWRITEFILEGATHER_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWriteFileGather_enter, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t SegmentArray, uint32_t Length, uint64_t ByteOffset, uint64_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWRITEFILEGATHER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWRITEFILEGATHER_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWriteFileGather_return, CPUState* cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t SegmentArray, uint32_t Length, uint64_t ByteOffset, uint64_t Key);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWRITEREQUESTDATA_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWRITEREQUESTDATA_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWriteRequestData_enter, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t Message, uint32_t DataEntryIndex, uint64_t Buffer, uint64_t BufferSize, uint64_t NumberOfBytesWritten);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWRITEREQUESTDATA_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWRITEREQUESTDATA_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWriteRequestData_return, CPUState* cpu, target_ulong pc, uint64_t PortHandle, uint64_t Message, uint32_t DataEntryIndex, uint64_t Buffer, uint64_t BufferSize, uint64_t NumberOfBytesWritten);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWRITEVIRTUALMEMORY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTWRITEVIRTUALMEMORY_ENTER 1
PPP_CB_TYPEDEF(void, on_NtWriteVirtualMemory_enter, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t Buffer, uint64_t BufferSize, uint64_t NumberOfBytesWritten);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTWRITEVIRTUALMEMORY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTWRITEVIRTUALMEMORY_RETURN 1
PPP_CB_TYPEDEF(void, on_NtWriteVirtualMemory_return, CPUState* cpu, target_ulong pc, uint64_t ProcessHandle, uint64_t BaseAddress, uint64_t Buffer, uint64_t BufferSize, uint64_t NumberOfBytesWritten);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTYIELDEXECUTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_NTYIELDEXECUTION_ENTER 1
PPP_CB_TYPEDEF(void, on_NtYieldExecution_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_NTYIELDEXECUTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_NTYIELDEXECUTION_RETURN 1
PPP_CB_TYPEDEF(void, on_NtYieldExecution_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_open_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_open_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_OPENAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_OPENAT_ENTER 1
PPP_CB_TYPEDEF(void, on_openat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, int32_t flag, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_OPENAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_OPENAT_RETURN 1
PPP_CB_TYPEDEF(void, on_openat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, int32_t flag, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PATHCONF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PATHCONF_ENTER 1
PPP_CB_TYPEDEF(void, on_pathconf_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PATHCONF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PATHCONF_RETURN 1
PPP_CB_TYPEDEF(void, on_pathconf_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PDFORK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PDFORK_ENTER 1
PPP_CB_TYPEDEF(void, on_pdfork_enter, CPUState* cpu, target_ulong pc, uint64_t fdp, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PDFORK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PDFORK_RETURN 1
PPP_CB_TYPEDEF(void, on_pdfork_return, CPUState* cpu, target_ulong pc, uint64_t fdp, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PDGETPID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PDGETPID_ENTER 1
PPP_CB_TYPEDEF(void, on_pdgetpid_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t pidp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PDGETPID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PDGETPID_RETURN 1
PPP_CB_TYPEDEF(void, on_pdgetpid_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t pidp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PDKILL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PDKILL_ENTER 1
PPP_CB_TYPEDEF(void, on_pdkill_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t signum);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PDKILL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PDKILL_RETURN 1
PPP_CB_TYPEDEF(void, on_pdkill_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t signum);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PIPE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PIPE_ENTER 1
PPP_CB_TYPEDEF(void, on_pipe_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PIPE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PIPE_RETURN 1
PPP_CB_TYPEDEF(void, on_pipe_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PIPE2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PIPE2_ENTER 1
PPP_CB_TYPEDEF(void, on_pipe2_enter, CPUState* cpu, target_ulong pc, uint64_t fildes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PIPE2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PIPE2_RETURN 1
PPP_CB_TYPEDEF(void, on_pipe2_return, CPUState* cpu, target_ulong pc, uint64_t fildes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_POLL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_POLL_ENTER 1
PPP_CB_TYPEDEF(void, on_poll_enter, CPUState* cpu, target_ulong pc, uint64_t fds, uint32_t nfds, int32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_POLL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_POLL_RETURN 1
PPP_CB_TYPEDEF(void, on_poll_return, CPUState* cpu, target_ulong pc, uint64_t fds, uint32_t nfds, int32_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_POSIX_FADVISE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_POSIX_FADVISE_ENTER 1
PPP_CB_TYPEDEF(void, on_posix_fadvise_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint64_t len, int32_t advice);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_POSIX_FADVISE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_POSIX_FADVISE_RETURN 1
PPP_CB_TYPEDEF(void, on_posix_fadvise_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint64_t len, int32_t advice);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_POSIX_FALLOCATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_POSIX_FALLOCATE_ENTER 1
PPP_CB_TYPEDEF(void, on_posix_fallocate_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint64_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_POSIX_FALLOCATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_POSIX_FALLOCATE_RETURN 1
PPP_CB_TYPEDEF(void, on_posix_fallocate_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint64_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_POSIX_OPENPT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_POSIX_OPENPT_ENTER 1
PPP_CB_TYPEDEF(void, on_posix_openpt_enter, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_POSIX_OPENPT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_POSIX_OPENPT_RETURN 1
PPP_CB_TYPEDEF(void, on_posix_openpt_return, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PPOLL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PPOLL_ENTER 1
PPP_CB_TYPEDEF(void, on_ppoll_enter, CPUState* cpu, target_ulong pc, uint64_t fds, uint32_t nfds, uint64_t ts, uint64_t set);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PPOLL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PPOLL_RETURN 1
PPP_CB_TYPEDEF(void, on_ppoll_return, CPUState* cpu, target_ulong pc, uint64_t fds, uint32_t nfds, uint64_t ts, uint64_t set);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_pread_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t nbyte, uint64_t offset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_pread_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t nbyte, uint64_t offset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PREADV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PREADV_ENTER 1
PPP_CB_TYPEDEF(void, on_preadv_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t iovp, uint32_t iovcnt, uint64_t offset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PREADV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PREADV_RETURN 1
PPP_CB_TYPEDEF(void, on_preadv_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t iovp, uint32_t iovcnt, uint64_t offset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PROCCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PROCCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_procctl_enter, CPUState* cpu, target_ulong pc, uint32_t idtype, uint32_t id, int32_t com, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PROCCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PROCCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_procctl_return, CPUState* cpu, target_ulong pc, uint32_t idtype, uint32_t id, int32_t com, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PROFIL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PROFIL_ENTER 1
PPP_CB_TYPEDEF(void, on_profil_enter, CPUState* cpu, target_ulong pc, uint64_t samples, uint32_t size, uint32_t offset, uint32_t scale);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PROFIL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PROFIL_RETURN 1
PPP_CB_TYPEDEF(void, on_profil_return, CPUState* cpu, target_ulong pc, uint64_t samples, uint32_t size, uint32_t offset, uint32_t scale);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PSELECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PSELECT_ENTER 1
PPP_CB_TYPEDEF(void, on_pselect_enter, CPUState* cpu, target_ulong pc, int32_t nd, uint64_t in, uint64_t ou, uint64_t ex, uint64_t ts, uint64_t sm);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PSELECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PSELECT_RETURN 1
PPP_CB_TYPEDEF(void, on_pselect_return, CPUState* cpu, target_ulong pc, int32_t nd, uint64_t in, uint64_t ou, uint64_t ex, uint64_t ts, uint64_t sm);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PTRACE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PTRACE_ENTER 1
PPP_CB_TYPEDEF(void, on_ptrace_enter, CPUState* cpu, target_ulong pc, int32_t req, int32_t pid, uint32_t addr, int32_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PTRACE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PTRACE_RETURN 1
PPP_CB_TYPEDEF(void, on_ptrace_return, CPUState* cpu, target_ulong pc, int32_t req, int32_t pid, uint32_t addr, int32_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PWRITE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PWRITE_ENTER 1
PPP_CB_TYPEDEF(void, on_pwrite_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t nbyte, uint64_t offset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PWRITE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PWRITE_RETURN 1
PPP_CB_TYPEDEF(void, on_pwrite_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t nbyte, uint64_t offset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PWRITEV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_PWRITEV_ENTER 1
PPP_CB_TYPEDEF(void, on_pwritev_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t iovp, uint32_t iovcnt, uint64_t offset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_PWRITEV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_PWRITEV_RETURN 1
PPP_CB_TYPEDEF(void, on_pwritev_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t iovp, uint32_t iovcnt, uint64_t offset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_QUOTA_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_QUOTA_ENTER 1
PPP_CB_TYPEDEF(void, on_quota_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_QUOTA_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_QUOTA_RETURN 1
PPP_CB_TYPEDEF(void, on_quota_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_QUOTACTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_QUOTACTL_ENTER 1
PPP_CB_TYPEDEF(void, on_quotactl_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t cmd, int32_t uid, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_QUOTACTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_QUOTACTL_RETURN 1
PPP_CB_TYPEDEF(void, on_quotactl_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t cmd, int32_t uid, uint64_t arg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RCTL_ADD_RULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RCTL_ADD_RULE_ENTER 1
PPP_CB_TYPEDEF(void, on_rctl_add_rule_enter, CPUState* cpu, target_ulong pc, uint64_t inbufp, uint32_t inbuflen, uint64_t outbufp, uint32_t outbuflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RCTL_ADD_RULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RCTL_ADD_RULE_RETURN 1
PPP_CB_TYPEDEF(void, on_rctl_add_rule_return, CPUState* cpu, target_ulong pc, uint64_t inbufp, uint32_t inbuflen, uint64_t outbufp, uint32_t outbuflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_LIMITS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_LIMITS_ENTER 1
PPP_CB_TYPEDEF(void, on_rctl_get_limits_enter, CPUState* cpu, target_ulong pc, uint64_t inbufp, uint32_t inbuflen, uint64_t outbufp, uint32_t outbuflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_LIMITS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_LIMITS_RETURN 1
PPP_CB_TYPEDEF(void, on_rctl_get_limits_return, CPUState* cpu, target_ulong pc, uint64_t inbufp, uint32_t inbuflen, uint64_t outbufp, uint32_t outbuflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_RACCT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_RACCT_ENTER 1
PPP_CB_TYPEDEF(void, on_rctl_get_racct_enter, CPUState* cpu, target_ulong pc, uint64_t inbufp, uint32_t inbuflen, uint64_t outbufp, uint32_t outbuflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_RACCT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_RACCT_RETURN 1
PPP_CB_TYPEDEF(void, on_rctl_get_racct_return, CPUState* cpu, target_ulong pc, uint64_t inbufp, uint32_t inbuflen, uint64_t outbufp, uint32_t outbuflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_RULES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_RULES_ENTER 1
PPP_CB_TYPEDEF(void, on_rctl_get_rules_enter, CPUState* cpu, target_ulong pc, uint64_t inbufp, uint32_t inbuflen, uint64_t outbufp, uint32_t outbuflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_RULES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RCTL_GET_RULES_RETURN 1
PPP_CB_TYPEDEF(void, on_rctl_get_rules_return, CPUState* cpu, target_ulong pc, uint64_t inbufp, uint32_t inbuflen, uint64_t outbufp, uint32_t outbuflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RCTL_REMOVE_RULE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RCTL_REMOVE_RULE_ENTER 1
PPP_CB_TYPEDEF(void, on_rctl_remove_rule_enter, CPUState* cpu, target_ulong pc, uint64_t inbufp, uint32_t inbuflen, uint64_t outbufp, uint32_t outbuflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RCTL_REMOVE_RULE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RCTL_REMOVE_RULE_RETURN 1
PPP_CB_TYPEDEF(void, on_rctl_remove_rule_return, CPUState* cpu, target_ulong pc, uint64_t inbufp, uint32_t inbuflen, uint64_t outbufp, uint32_t outbuflen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_READ_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_READ_ENTER 1
PPP_CB_TYPEDEF(void, on_read_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t nbyte);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_READ_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_READ_RETURN 1
PPP_CB_TYPEDEF(void, on_read_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t nbyte);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_READLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_READLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_readlink_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_READLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_READLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_readlink_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t buf, uint32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_READLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_READLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_readlinkat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t buf, uint32_t bufsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_READLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_READLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_readlinkat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t buf, uint32_t bufsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_READV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_READV_ENTER 1
PPP_CB_TYPEDEF(void, on_readv_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t iovp, uint32_t iovcnt);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_READV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_READV_RETURN 1
PPP_CB_TYPEDEF(void, on_readv_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t iovp, uint32_t iovcnt);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_REBOOT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_REBOOT_ENTER 1
PPP_CB_TYPEDEF(void, on_reboot_enter, CPUState* cpu, target_ulong pc, int32_t opt);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_REBOOT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_REBOOT_RETURN 1
PPP_CB_TYPEDEF(void, on_reboot_return, CPUState* cpu, target_ulong pc, int32_t opt);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RECV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RECV_ENTER 1
PPP_CB_TYPEDEF(void, on_recv_enter, CPUState* cpu, target_ulong pc, int32_t s, uint64_t buf, int32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RECV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RECV_RETURN 1
PPP_CB_TYPEDEF(void, on_recv_return, CPUState* cpu, target_ulong pc, int32_t s, uint64_t buf, int32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RECVFROM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RECVFROM_ENTER 1
PPP_CB_TYPEDEF(void, on_recvfrom_enter, CPUState* cpu, target_ulong pc, int32_t s, uint64_t buf, uint32_t len, int32_t flags, uint64_t from, uint64_t fromlenaddr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RECVFROM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RECVFROM_RETURN 1
PPP_CB_TYPEDEF(void, on_recvfrom_return, CPUState* cpu, target_ulong pc, int32_t s, uint64_t buf, uint32_t len, int32_t flags, uint64_t from, uint64_t fromlenaddr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RECVMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RECVMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_recvmsg_enter, CPUState* cpu, target_ulong pc, int32_t s, uint64_t msg, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RECVMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RECVMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_recvmsg_return, CPUState* cpu, target_ulong pc, int32_t s, uint64_t msg, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RENAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RENAME_ENTER 1
PPP_CB_TYPEDEF(void, on_rename_enter, CPUState* cpu, target_ulong pc, uint64_t from, uint64_t to);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RENAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RENAME_RETURN 1
PPP_CB_TYPEDEF(void, on_rename_return, CPUState* cpu, target_ulong pc, uint64_t from, uint64_t to);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RENAMEAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RENAMEAT_ENTER 1
PPP_CB_TYPEDEF(void, on_renameat_enter, CPUState* cpu, target_ulong pc, int32_t oldfd, uint64_t old, int32_t newfd, uint64_t _new);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RENAMEAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RENAMEAT_RETURN 1
PPP_CB_TYPEDEF(void, on_renameat_return, CPUState* cpu, target_ulong pc, int32_t oldfd, uint64_t old, int32_t newfd, uint64_t _new);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_REVOKE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_REVOKE_ENTER 1
PPP_CB_TYPEDEF(void, on_revoke_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_REVOKE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_REVOKE_RETURN 1
PPP_CB_TYPEDEF(void, on_revoke_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RFORK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RFORK_ENTER 1
PPP_CB_TYPEDEF(void, on_rfork_enter, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RFORK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RFORK_RETURN 1
PPP_CB_TYPEDEF(void, on_rfork_return, CPUState* cpu, target_ulong pc, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RMDIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RMDIR_ENTER 1
PPP_CB_TYPEDEF(void, on_rmdir_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RMDIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RMDIR_RETURN 1
PPP_CB_TYPEDEF(void, on_rmdir_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RPCTLS_SYSCALL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RPCTLS_SYSCALL_ENTER 1
PPP_CB_TYPEDEF(void, on_rpctls_syscall_enter, CPUState* cpu, target_ulong pc, int32_t op, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RPCTLS_SYSCALL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RPCTLS_SYSCALL_RETURN 1
PPP_CB_TYPEDEF(void, on_rpctls_syscall_return, CPUState* cpu, target_ulong pc, int32_t op, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RTPRIO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RTPRIO_ENTER 1
PPP_CB_TYPEDEF(void, on_rtprio_enter, CPUState* cpu, target_ulong pc, int32_t function, int32_t pid, uint64_t rtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RTPRIO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RTPRIO_RETURN 1
PPP_CB_TYPEDEF(void, on_rtprio_return, CPUState* cpu, target_ulong pc, int32_t function, int32_t pid, uint64_t rtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RTPRIO_THREAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_RTPRIO_THREAD_ENTER 1
PPP_CB_TYPEDEF(void, on_rtprio_thread_enter, CPUState* cpu, target_ulong pc, int32_t function, int32_t lwpid, uint64_t rtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_RTPRIO_THREAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_RTPRIO_THREAD_RETURN 1
PPP_CB_TYPEDEF(void, on_rtprio_thread_return, CPUState* cpu, target_ulong pc, int32_t function, int32_t lwpid, uint64_t rtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SBRK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SBRK_ENTER 1
PPP_CB_TYPEDEF(void, on_sbrk_enter, CPUState* cpu, target_ulong pc, int32_t incr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SBRK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SBRK_RETURN 1
PPP_CB_TYPEDEF(void, on_sbrk_return, CPUState* cpu, target_ulong pc, int32_t incr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_GET_PRIORITY_MAX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_GET_PRIORITY_MAX_ENTER 1
PPP_CB_TYPEDEF(void, on_sched_get_priority_max_enter, CPUState* cpu, target_ulong pc, int32_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_GET_PRIORITY_MAX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_GET_PRIORITY_MAX_RETURN 1
PPP_CB_TYPEDEF(void, on_sched_get_priority_max_return, CPUState* cpu, target_ulong pc, int32_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_GET_PRIORITY_MIN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_GET_PRIORITY_MIN_ENTER 1
PPP_CB_TYPEDEF(void, on_sched_get_priority_min_enter, CPUState* cpu, target_ulong pc, int32_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_GET_PRIORITY_MIN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_GET_PRIORITY_MIN_RETURN 1
PPP_CB_TYPEDEF(void, on_sched_get_priority_min_return, CPUState* cpu, target_ulong pc, int32_t policy);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_GETPARAM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_GETPARAM_ENTER 1
PPP_CB_TYPEDEF(void, on_sched_getparam_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_GETPARAM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_GETPARAM_RETURN 1
PPP_CB_TYPEDEF(void, on_sched_getparam_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_GETSCHEDULER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_GETSCHEDULER_ENTER 1
PPP_CB_TYPEDEF(void, on_sched_getscheduler_enter, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_GETSCHEDULER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_GETSCHEDULER_RETURN 1
PPP_CB_TYPEDEF(void, on_sched_getscheduler_return, CPUState* cpu, target_ulong pc, int32_t pid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_RR_GET_INTERVAL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_RR_GET_INTERVAL_ENTER 1
PPP_CB_TYPEDEF(void, on_sched_rr_get_interval_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t interval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_RR_GET_INTERVAL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_RR_GET_INTERVAL_RETURN 1
PPP_CB_TYPEDEF(void, on_sched_rr_get_interval_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t interval);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_SETPARAM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_SETPARAM_ENTER 1
PPP_CB_TYPEDEF(void, on_sched_setparam_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_SETPARAM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_SETPARAM_RETURN 1
PPP_CB_TYPEDEF(void, on_sched_setparam_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_SETSCHEDULER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_SETSCHEDULER_ENTER 1
PPP_CB_TYPEDEF(void, on_sched_setscheduler_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t policy, uint64_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_SETSCHEDULER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_SETSCHEDULER_RETURN 1
PPP_CB_TYPEDEF(void, on_sched_setscheduler_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t policy, uint64_t param);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_YIELD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_YIELD_ENTER 1
PPP_CB_TYPEDEF(void, on_sched_yield_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCHED_YIELD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCHED_YIELD_RETURN 1
PPP_CB_TYPEDEF(void, on_sched_yield_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_RECVMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_RECVMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sctp_generic_recvmsg_enter, CPUState* cpu, target_ulong pc, int32_t sd, uint64_t iov, int32_t iovlen, uint64_t from, uint64_t fromlenaddr, uint64_t sinfo, uint64_t msg_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_RECVMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_RECVMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sctp_generic_recvmsg_return, CPUState* cpu, target_ulong pc, int32_t sd, uint64_t iov, int32_t iovlen, uint64_t from, uint64_t fromlenaddr, uint64_t sinfo, uint64_t msg_flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_SENDMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_SENDMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sctp_generic_sendmsg_enter, CPUState* cpu, target_ulong pc, int32_t sd, uint64_t msg, int32_t mlen, uint64_t to, uint32_t tolen, uint64_t sinfo, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_SENDMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_SENDMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sctp_generic_sendmsg_return, CPUState* cpu, target_ulong pc, int32_t sd, uint64_t msg, int32_t mlen, uint64_t to, uint32_t tolen, uint64_t sinfo, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_SENDMSG_IOV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_SENDMSG_IOV_ENTER 1
PPP_CB_TYPEDEF(void, on_sctp_generic_sendmsg_iov_enter, CPUState* cpu, target_ulong pc, int32_t sd, uint64_t iov, int32_t iovlen, uint64_t to, uint32_t tolen, uint64_t sinfo, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_SENDMSG_IOV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCTP_GENERIC_SENDMSG_IOV_RETURN 1
PPP_CB_TYPEDEF(void, on_sctp_generic_sendmsg_iov_return, CPUState* cpu, target_ulong pc, int32_t sd, uint64_t iov, int32_t iovlen, uint64_t to, uint32_t tolen, uint64_t sinfo, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCTP_PEELOFF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SCTP_PEELOFF_ENTER 1
PPP_CB_TYPEDEF(void, on_sctp_peeloff_enter, CPUState* cpu, target_ulong pc, int32_t sd, int32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SCTP_PEELOFF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SCTP_PEELOFF_RETURN 1
PPP_CB_TYPEDEF(void, on_sctp_peeloff_return, CPUState* cpu, target_ulong pc, int32_t sd, int32_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SELECT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SELECT_ENTER 1
PPP_CB_TYPEDEF(void, on_select_enter, CPUState* cpu, target_ulong pc, int32_t nd, uint64_t in, uint64_t ou, uint64_t ex, uint64_t tv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SELECT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SELECT_RETURN 1
PPP_CB_TYPEDEF(void, on_select_return, CPUState* cpu, target_ulong pc, int32_t nd, uint64_t in, uint64_t ou, uint64_t ex, uint64_t tv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SEMGET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SEMGET_ENTER 1
PPP_CB_TYPEDEF(void, on_semget_enter, CPUState* cpu, target_ulong pc, uint32_t key, int32_t nsems, int32_t semflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SEMGET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SEMGET_RETURN 1
PPP_CB_TYPEDEF(void, on_semget_return, CPUState* cpu, target_ulong pc, uint32_t key, int32_t nsems, int32_t semflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SEMOP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SEMOP_ENTER 1
PPP_CB_TYPEDEF(void, on_semop_enter, CPUState* cpu, target_ulong pc, int32_t semid, uint64_t sops, uint32_t nsops);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SEMOP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SEMOP_RETURN 1
PPP_CB_TYPEDEF(void, on_semop_return, CPUState* cpu, target_ulong pc, int32_t semid, uint64_t sops, uint32_t nsops);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SEMSYS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SEMSYS_ENTER 1
PPP_CB_TYPEDEF(void, on_semsys_enter, CPUState* cpu, target_ulong pc, int32_t which, int32_t a2, int32_t a3, int32_t a4, int32_t a5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SEMSYS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SEMSYS_RETURN 1
PPP_CB_TYPEDEF(void, on_semsys_return, CPUState* cpu, target_ulong pc, int32_t which, int32_t a2, int32_t a3, int32_t a4, int32_t a5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SEND_ENTER 1
PPP_CB_TYPEDEF(void, on_send_enter, CPUState* cpu, target_ulong pc, int32_t s, uint64_t buf, int32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SEND_RETURN 1
PPP_CB_TYPEDEF(void, on_send_return, CPUState* cpu, target_ulong pc, int32_t s, uint64_t buf, int32_t len, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SENDFILE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SENDFILE_ENTER 1
PPP_CB_TYPEDEF(void, on_sendfile_enter, CPUState* cpu, target_ulong pc, int32_t fd, int32_t s, uint64_t offset, uint32_t nbytes, uint64_t hdtr, uint64_t sbytes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SENDFILE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SENDFILE_RETURN 1
PPP_CB_TYPEDEF(void, on_sendfile_return, CPUState* cpu, target_ulong pc, int32_t fd, int32_t s, uint64_t offset, uint32_t nbytes, uint64_t hdtr, uint64_t sbytes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SENDMSG_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SENDMSG_ENTER 1
PPP_CB_TYPEDEF(void, on_sendmsg_enter, CPUState* cpu, target_ulong pc, int32_t s, uint64_t msg, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SENDMSG_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SENDMSG_RETURN 1
PPP_CB_TYPEDEF(void, on_sendmsg_return, CPUState* cpu, target_ulong pc, int32_t s, uint64_t msg, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SENDTO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SENDTO_ENTER 1
PPP_CB_TYPEDEF(void, on_sendto_enter, CPUState* cpu, target_ulong pc, int32_t s, uint64_t buf, uint32_t len, int32_t flags, uint64_t to, int32_t tolen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SENDTO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SENDTO_RETURN 1
PPP_CB_TYPEDEF(void, on_sendto_return, CPUState* cpu, target_ulong pc, int32_t s, uint64_t buf, uint32_t len, int32_t flags, uint64_t to, int32_t tolen);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETAUDIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETAUDIT_ENTER 1
PPP_CB_TYPEDEF(void, on_setaudit_enter, CPUState* cpu, target_ulong pc, uint64_t auditinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETAUDIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETAUDIT_RETURN 1
PPP_CB_TYPEDEF(void, on_setaudit_return, CPUState* cpu, target_ulong pc, uint64_t auditinfo);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETAUDIT_ADDR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETAUDIT_ADDR_ENTER 1
PPP_CB_TYPEDEF(void, on_setaudit_addr_enter, CPUState* cpu, target_ulong pc, uint64_t auditinfo_addr, uint32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETAUDIT_ADDR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETAUDIT_ADDR_RETURN 1
PPP_CB_TYPEDEF(void, on_setaudit_addr_return, CPUState* cpu, target_ulong pc, uint64_t auditinfo_addr, uint32_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETAUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETAUID_ENTER 1
PPP_CB_TYPEDEF(void, on_setauid_enter, CPUState* cpu, target_ulong pc, uint64_t auid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETAUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETAUID_RETURN 1
PPP_CB_TYPEDEF(void, on_setauid_return, CPUState* cpu, target_ulong pc, uint64_t auid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETCONTEXT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETCONTEXT_ENTER 1
PPP_CB_TYPEDEF(void, on_setcontext_enter, CPUState* cpu, target_ulong pc, uint64_t ucp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETCONTEXT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETCONTEXT_RETURN 1
PPP_CB_TYPEDEF(void, on_setcontext_return, CPUState* cpu, target_ulong pc, uint64_t ucp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETDOMAINNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETDOMAINNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_setdomainname_enter, CPUState* cpu, target_ulong pc, uint64_t domainname, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETDOMAINNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETDOMAINNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_setdomainname_return, CPUState* cpu, target_ulong pc, uint64_t domainname, int32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETEGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETEGID_ENTER 1
PPP_CB_TYPEDEF(void, on_setegid_enter, CPUState* cpu, target_ulong pc, uint32_t egid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETEGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETEGID_RETURN 1
PPP_CB_TYPEDEF(void, on_setegid_return, CPUState* cpu, target_ulong pc, uint32_t egid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETEUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETEUID_ENTER 1
PPP_CB_TYPEDEF(void, on_seteuid_enter, CPUState* cpu, target_ulong pc, uint32_t euid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETEUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETEUID_RETURN 1
PPP_CB_TYPEDEF(void, on_seteuid_return, CPUState* cpu, target_ulong pc, uint32_t euid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETFIB_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETFIB_ENTER 1
PPP_CB_TYPEDEF(void, on_setfib_enter, CPUState* cpu, target_ulong pc, int32_t fibnum);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETFIB_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETFIB_RETURN 1
PPP_CB_TYPEDEF(void, on_setfib_return, CPUState* cpu, target_ulong pc, int32_t fibnum);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETGID_ENTER 1
PPP_CB_TYPEDEF(void, on_setgid_enter, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETGID_RETURN 1
PPP_CB_TYPEDEF(void, on_setgid_return, CPUState* cpu, target_ulong pc, uint32_t gid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETGROUPS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETGROUPS_ENTER 1
PPP_CB_TYPEDEF(void, on_setgroups_enter, CPUState* cpu, target_ulong pc, uint32_t gidsetsize, uint64_t gidset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETGROUPS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETGROUPS_RETURN 1
PPP_CB_TYPEDEF(void, on_setgroups_return, CPUState* cpu, target_ulong pc, uint32_t gidsetsize, uint64_t gidset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETHOSTID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETHOSTID_ENTER 1
PPP_CB_TYPEDEF(void, on_sethostid_enter, CPUState* cpu, target_ulong pc, int64_t hostid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETHOSTID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETHOSTID_RETURN 1
PPP_CB_TYPEDEF(void, on_sethostid_return, CPUState* cpu, target_ulong pc, int64_t hostid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETHOSTNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETHOSTNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_sethostname_enter, CPUState* cpu, target_ulong pc, uint64_t hostname, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETHOSTNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETHOSTNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_sethostname_return, CPUState* cpu, target_ulong pc, uint64_t hostname, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETITIMER_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETITIMER_ENTER 1
PPP_CB_TYPEDEF(void, on_setitimer_enter, CPUState* cpu, target_ulong pc, uint32_t which, uint64_t itv, uint64_t oitv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETITIMER_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETITIMER_RETURN 1
PPP_CB_TYPEDEF(void, on_setitimer_return, CPUState* cpu, target_ulong pc, uint32_t which, uint64_t itv, uint64_t oitv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETLOGIN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETLOGIN_ENTER 1
PPP_CB_TYPEDEF(void, on_setlogin_enter, CPUState* cpu, target_ulong pc, uint64_t namebuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETLOGIN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETLOGIN_RETURN 1
PPP_CB_TYPEDEF(void, on_setlogin_return, CPUState* cpu, target_ulong pc, uint64_t namebuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETLOGINCLASS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETLOGINCLASS_ENTER 1
PPP_CB_TYPEDEF(void, on_setloginclass_enter, CPUState* cpu, target_ulong pc, uint64_t namebuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETLOGINCLASS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETLOGINCLASS_RETURN 1
PPP_CB_TYPEDEF(void, on_setloginclass_return, CPUState* cpu, target_ulong pc, uint64_t namebuf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETPGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETPGID_ENTER 1
PPP_CB_TYPEDEF(void, on_setpgid_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t pgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETPGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETPGID_RETURN 1
PPP_CB_TYPEDEF(void, on_setpgid_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t pgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETPRIORITY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETPRIORITY_ENTER 1
PPP_CB_TYPEDEF(void, on_setpriority_enter, CPUState* cpu, target_ulong pc, int32_t which, int32_t who, int32_t prio);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETPRIORITY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETPRIORITY_RETURN 1
PPP_CB_TYPEDEF(void, on_setpriority_return, CPUState* cpu, target_ulong pc, int32_t which, int32_t who, int32_t prio);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETREGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETREGID_ENTER 1
PPP_CB_TYPEDEF(void, on_setregid_enter, CPUState* cpu, target_ulong pc, int32_t rgid, int32_t egid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETREGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETREGID_RETURN 1
PPP_CB_TYPEDEF(void, on_setregid_return, CPUState* cpu, target_ulong pc, int32_t rgid, int32_t egid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETRESGID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETRESGID_ENTER 1
PPP_CB_TYPEDEF(void, on_setresgid_enter, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETRESGID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETRESGID_RETURN 1
PPP_CB_TYPEDEF(void, on_setresgid_return, CPUState* cpu, target_ulong pc, uint32_t rgid, uint32_t egid, uint32_t sgid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETRESUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETRESUID_ENTER 1
PPP_CB_TYPEDEF(void, on_setresuid_enter, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETRESUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETRESUID_RETURN 1
PPP_CB_TYPEDEF(void, on_setresuid_return, CPUState* cpu, target_ulong pc, uint32_t ruid, uint32_t euid, uint32_t suid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETREUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETREUID_ENTER 1
PPP_CB_TYPEDEF(void, on_setreuid_enter, CPUState* cpu, target_ulong pc, int32_t ruid, int32_t euid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETREUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETREUID_RETURN 1
PPP_CB_TYPEDEF(void, on_setreuid_return, CPUState* cpu, target_ulong pc, int32_t ruid, int32_t euid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETRLIMIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETRLIMIT_ENTER 1
PPP_CB_TYPEDEF(void, on_setrlimit_enter, CPUState* cpu, target_ulong pc, uint32_t which, uint64_t rlp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETRLIMIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETRLIMIT_RETURN 1
PPP_CB_TYPEDEF(void, on_setrlimit_return, CPUState* cpu, target_ulong pc, uint32_t which, uint64_t rlp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETSID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETSID_ENTER 1
PPP_CB_TYPEDEF(void, on_setsid_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETSID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETSID_RETURN 1
PPP_CB_TYPEDEF(void, on_setsid_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETSOCKOPT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETSOCKOPT_ENTER 1
PPP_CB_TYPEDEF(void, on_setsockopt_enter, CPUState* cpu, target_ulong pc, int32_t s, int32_t level, int32_t name, uint64_t val, int32_t valsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETSOCKOPT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETSOCKOPT_RETURN 1
PPP_CB_TYPEDEF(void, on_setsockopt_return, CPUState* cpu, target_ulong pc, int32_t s, int32_t level, int32_t name, uint64_t val, int32_t valsize);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETTIMEOFDAY_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETTIMEOFDAY_ENTER 1
PPP_CB_TYPEDEF(void, on_settimeofday_enter, CPUState* cpu, target_ulong pc, uint64_t tv, uint64_t tzp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETTIMEOFDAY_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETTIMEOFDAY_RETURN 1
PPP_CB_TYPEDEF(void, on_settimeofday_return, CPUState* cpu, target_ulong pc, uint64_t tv, uint64_t tzp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETUID_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SETUID_ENTER 1
PPP_CB_TYPEDEF(void, on_setuid_enter, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SETUID_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SETUID_RETURN 1
PPP_CB_TYPEDEF(void, on_setuid_return, CPUState* cpu, target_ulong pc, uint32_t uid);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHM_OPEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SHM_OPEN_ENTER 1
PPP_CB_TYPEDEF(void, on_shm_open_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHM_OPEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SHM_OPEN_RETURN 1
PPP_CB_TYPEDEF(void, on_shm_open_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHM_OPEN2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SHM_OPEN2_ENTER 1
PPP_CB_TYPEDEF(void, on_shm_open2_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t flags, uint32_t mode, int32_t shmflags, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHM_OPEN2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SHM_OPEN2_RETURN 1
PPP_CB_TYPEDEF(void, on_shm_open2_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t flags, uint32_t mode, int32_t shmflags, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHM_RENAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SHM_RENAME_ENTER 1
PPP_CB_TYPEDEF(void, on_shm_rename_enter, CPUState* cpu, target_ulong pc, uint64_t path_from, uint64_t path_to, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHM_RENAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SHM_RENAME_RETURN 1
PPP_CB_TYPEDEF(void, on_shm_rename_return, CPUState* cpu, target_ulong pc, uint64_t path_from, uint64_t path_to, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHM_UNLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SHM_UNLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_shm_unlink_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHM_UNLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SHM_UNLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_shm_unlink_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHMCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SHMCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_shmctl_enter, CPUState* cpu, target_ulong pc, int32_t shmid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHMCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SHMCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_shmctl_return, CPUState* cpu, target_ulong pc, int32_t shmid, int32_t cmd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHMDT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SHMDT_ENTER 1
PPP_CB_TYPEDEF(void, on_shmdt_enter, CPUState* cpu, target_ulong pc, uint64_t shmaddr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHMDT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SHMDT_RETURN 1
PPP_CB_TYPEDEF(void, on_shmdt_return, CPUState* cpu, target_ulong pc, uint64_t shmaddr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHMGET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SHMGET_ENTER 1
PPP_CB_TYPEDEF(void, on_shmget_enter, CPUState* cpu, target_ulong pc, uint32_t key, uint32_t size, int32_t shmflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHMGET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SHMGET_RETURN 1
PPP_CB_TYPEDEF(void, on_shmget_return, CPUState* cpu, target_ulong pc, uint32_t key, uint32_t size, int32_t shmflg);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHUTDOWN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SHUTDOWN_ENTER 1
PPP_CB_TYPEDEF(void, on_shutdown_enter, CPUState* cpu, target_ulong pc, int32_t s, int32_t how);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SHUTDOWN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SHUTDOWN_RETURN 1
PPP_CB_TYPEDEF(void, on_shutdown_return, CPUState* cpu, target_ulong pc, int32_t s, int32_t how);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGACTION_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGACTION_ENTER 1
PPP_CB_TYPEDEF(void, on_sigaction_enter, CPUState* cpu, target_ulong pc, int32_t sig, uint64_t act, uint64_t oact);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGACTION_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGACTION_RETURN 1
PPP_CB_TYPEDEF(void, on_sigaction_return, CPUState* cpu, target_ulong pc, int32_t sig, uint64_t act, uint64_t oact);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGALTSTACK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGALTSTACK_ENTER 1
PPP_CB_TYPEDEF(void, on_sigaltstack_enter, CPUState* cpu, target_ulong pc, uint64_t ss, uint64_t oss);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGALTSTACK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGALTSTACK_RETURN 1
PPP_CB_TYPEDEF(void, on_sigaltstack_return, CPUState* cpu, target_ulong pc, uint64_t ss, uint64_t oss);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGBLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGBLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_sigblock_enter, CPUState* cpu, target_ulong pc, int32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGBLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGBLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_sigblock_return, CPUState* cpu, target_ulong pc, int32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGFASTBLOCK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGFASTBLOCK_ENTER 1
PPP_CB_TYPEDEF(void, on_sigfastblock_enter, CPUState* cpu, target_ulong pc, int32_t cmd, uint64_t ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGFASTBLOCK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGFASTBLOCK_RETURN 1
PPP_CB_TYPEDEF(void, on_sigfastblock_return, CPUState* cpu, target_ulong pc, int32_t cmd, uint64_t ptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGPENDING_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGPENDING_ENTER 1
PPP_CB_TYPEDEF(void, on_sigpending_enter, CPUState* cpu, target_ulong pc, uint64_t set);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGPENDING_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGPENDING_RETURN 1
PPP_CB_TYPEDEF(void, on_sigpending_return, CPUState* cpu, target_ulong pc, uint64_t set);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGPROCMASK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGPROCMASK_ENTER 1
PPP_CB_TYPEDEF(void, on_sigprocmask_enter, CPUState* cpu, target_ulong pc, int32_t how, uint64_t set, uint64_t oset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGPROCMASK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGPROCMASK_RETURN 1
PPP_CB_TYPEDEF(void, on_sigprocmask_return, CPUState* cpu, target_ulong pc, int32_t how, uint64_t set, uint64_t oset);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGQUEUE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGQUEUE_ENTER 1
PPP_CB_TYPEDEF(void, on_sigqueue_enter, CPUState* cpu, target_ulong pc, int32_t pid, int32_t signum, uint64_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGQUEUE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGQUEUE_RETURN 1
PPP_CB_TYPEDEF(void, on_sigqueue_return, CPUState* cpu, target_ulong pc, int32_t pid, int32_t signum, uint64_t value);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGRETURN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGRETURN_ENTER 1
PPP_CB_TYPEDEF(void, on_sigreturn_enter, CPUState* cpu, target_ulong pc, uint64_t sigcntxp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGRETURN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGRETURN_RETURN 1
PPP_CB_TYPEDEF(void, on_sigreturn_return, CPUState* cpu, target_ulong pc, uint64_t sigcntxp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGSETMASK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGSETMASK_ENTER 1
PPP_CB_TYPEDEF(void, on_sigsetmask_enter, CPUState* cpu, target_ulong pc, int32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGSETMASK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGSETMASK_RETURN 1
PPP_CB_TYPEDEF(void, on_sigsetmask_return, CPUState* cpu, target_ulong pc, int32_t mask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGSTACK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGSTACK_ENTER 1
PPP_CB_TYPEDEF(void, on_sigstack_enter, CPUState* cpu, target_ulong pc, uint64_t nss, uint64_t oss);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGSTACK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGSTACK_RETURN 1
PPP_CB_TYPEDEF(void, on_sigstack_return, CPUState* cpu, target_ulong pc, uint64_t nss, uint64_t oss);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGSUSPEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGSUSPEND_ENTER 1
PPP_CB_TYPEDEF(void, on_sigsuspend_enter, CPUState* cpu, target_ulong pc, uint64_t sigmask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGSUSPEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGSUSPEND_RETURN 1
PPP_CB_TYPEDEF(void, on_sigsuspend_return, CPUState* cpu, target_ulong pc, uint64_t sigmask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGTIMEDWAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGTIMEDWAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sigtimedwait_enter, CPUState* cpu, target_ulong pc, uint64_t set, uint64_t info, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGTIMEDWAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGTIMEDWAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sigtimedwait_return, CPUState* cpu, target_ulong pc, uint64_t set, uint64_t info, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGVEC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGVEC_ENTER 1
PPP_CB_TYPEDEF(void, on_sigvec_enter, CPUState* cpu, target_ulong pc, int32_t signum, uint64_t nsv, uint64_t osv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGVEC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGVEC_RETURN 1
PPP_CB_TYPEDEF(void, on_sigvec_return, CPUState* cpu, target_ulong pc, int32_t signum, uint64_t nsv, uint64_t osv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGWAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGWAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_sigwait_enter, CPUState* cpu, target_ulong pc, uint64_t set, uint64_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGWAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGWAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_sigwait_return, CPUState* cpu, target_ulong pc, uint64_t set, uint64_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGWAITINFO_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SIGWAITINFO_ENTER 1
PPP_CB_TYPEDEF(void, on_sigwaitinfo_enter, CPUState* cpu, target_ulong pc, uint64_t set, uint64_t info);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SIGWAITINFO_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SIGWAITINFO_RETURN 1
PPP_CB_TYPEDEF(void, on_sigwaitinfo_return, CPUState* cpu, target_ulong pc, uint64_t set, uint64_t info);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SOCKET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SOCKET_ENTER 1
PPP_CB_TYPEDEF(void, on_socket_enter, CPUState* cpu, target_ulong pc, int32_t domain, int32_t type, int32_t protocol);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SOCKET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SOCKET_RETURN 1
PPP_CB_TYPEDEF(void, on_socket_return, CPUState* cpu, target_ulong pc, int32_t domain, int32_t type, int32_t protocol);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SOCKETPAIR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SOCKETPAIR_ENTER 1
PPP_CB_TYPEDEF(void, on_socketpair_enter, CPUState* cpu, target_ulong pc, int32_t domain, int32_t type, int32_t protocol, uint64_t rsv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SOCKETPAIR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SOCKETPAIR_RETURN 1
PPP_CB_TYPEDEF(void, on_socketpair_return, CPUState* cpu, target_ulong pc, int32_t domain, int32_t type, int32_t protocol, uint64_t rsv);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SSTK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SSTK_ENTER 1
PPP_CB_TYPEDEF(void, on_sstk_enter, CPUState* cpu, target_ulong pc, int32_t incr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SSTK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SSTK_RETURN 1
PPP_CB_TYPEDEF(void, on_sstk_return, CPUState* cpu, target_ulong pc, int32_t incr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_STAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_STAT_ENTER 1
PPP_CB_TYPEDEF(void, on_stat_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t ub);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_STAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_STAT_RETURN 1
PPP_CB_TYPEDEF(void, on_stat_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t ub);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_STATFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_STATFS_ENTER 1
PPP_CB_TYPEDEF(void, on_statfs_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_STATFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_STATFS_RETURN 1
PPP_CB_TYPEDEF(void, on_statfs_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SWAPCONTEXT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SWAPCONTEXT_ENTER 1
PPP_CB_TYPEDEF(void, on_swapcontext_enter, CPUState* cpu, target_ulong pc, uint64_t oucp, uint64_t ucp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SWAPCONTEXT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SWAPCONTEXT_RETURN 1
PPP_CB_TYPEDEF(void, on_swapcontext_return, CPUState* cpu, target_ulong pc, uint64_t oucp, uint64_t ucp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SWAPOFF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SWAPOFF_ENTER 1
PPP_CB_TYPEDEF(void, on_swapoff_enter, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SWAPOFF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SWAPOFF_RETURN 1
PPP_CB_TYPEDEF(void, on_swapoff_return, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SWAPON_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SWAPON_ENTER 1
PPP_CB_TYPEDEF(void, on_swapon_enter, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SWAPON_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SWAPON_RETURN 1
PPP_CB_TYPEDEF(void, on_swapon_return, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYMLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYMLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_symlink_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t link);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYMLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYMLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_symlink_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t link);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYMLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYMLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_symlinkat_enter, CPUState* cpu, target_ulong pc, uint64_t path1, int32_t fd, uint64_t path2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYMLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYMLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_symlinkat_return, CPUState* cpu, target_ulong pc, uint64_t path1, int32_t fd, uint64_t path2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYNC_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYNC_ENTER 1
PPP_CB_TYPEDEF(void, on_sync_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYNC_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYNC_RETURN 1
PPP_CB_TYPEDEF(void, on_sync_return, CPUState* cpu, target_ulong pc);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_alarm_enter, CPUState* cpu, target_ulong pc, uint32_t seconds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ALARM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_alarm_return, CPUState* cpu, target_ulong pc, uint32_t seconds);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ARCH_PRCTL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ARCH_PRCTL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_arch_prctl_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_ARCH_PRCTL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_ARCH_PRCTL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_arch_prctl_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_getres_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETRES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_getres_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_gettime_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_GETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_gettime_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_nanosleep_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, int32_t flags, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_NANOSLEEP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_nanosleep_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, int32_t flags, uint64_t rqtp, uint64_t rmtp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clock_settime_enter, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLOCK_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clock_settime_return, CPUState* cpu, target_ulong pc, uint32_t which_clock, uint64_t tp);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_clone_enter, CPUState* cpu, target_ulong pc, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_CLONE_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_clone_return, CPUState* cpu, target_ulong pc, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FADVISE64_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FADVISE64_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fadvise64_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint32_t len, int32_t advice);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FADVISE64_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FADVISE64_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fadvise64_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t offset, uint32_t len, int32_t advice);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fsetxattr_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t name, uint64_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fsetxattr_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t name, uint64_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_fstatfs_enter, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FSTATFS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_fstatfs_return, CPUState* cpu, target_ulong pc, uint32_t fd, uint64_t buf);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_futex_enter, CPUState* cpu, target_ulong pc, uint64_t uaddr, int32_t op, uint32_t val, uint64_t utime, uint64_t uaddr2, uint32_t val3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTEX_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_futex_return, CPUState* cpu, target_ulong pc, uint64_t uaddr, int32_t op, uint32_t val, uint64_t utime, uint64_t uaddr2, uint32_t val3);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_futimesat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t utimes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_FUTIMESAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_futimesat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t utimes);
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
PPP_CB_TYPEDEF(void, on_sys_ioperm_enter, CPUState* cpu, target_ulong pc, uint64_t arg0, uint64_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPERM_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPERM_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_ioperm_return, CPUState* cpu, target_ulong pc, uint64_t arg0, uint64_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPL_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_iopl_enter, CPUState* cpu, target_ulong pc, uint32_t arg0);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_IOPL_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_iopl_return, CPUState* cpu, target_ulong pc, uint32_t arg0);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_kcmp_enter, CPUState* cpu, target_ulong pc, int32_t pid1, int32_t pid2, int32_t type, uint64_t idx1, uint64_t idx2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KCMP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_kcmp_return, CPUState* cpu, target_ulong pc, int32_t pid1, int32_t pid2, int32_t type, uint64_t idx1, uint64_t idx2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_FILE_LOAD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_FILE_LOAD_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_kexec_file_load_enter, CPUState* cpu, target_ulong pc, int32_t kernel_fd, int32_t initrd_fd, uint64_t cmdline_len, uint64_t cmdline_ptr, uint64_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_FILE_LOAD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_KEXEC_FILE_LOAD_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_kexec_file_load_return, CPUState* cpu, target_ulong pc, int32_t kernel_fd, int32_t initrd_fd, uint64_t cmdline_len, uint64_t cmdline_ptr, uint64_t flags);
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
PPP_CB_TYPEDEF(void, on_sys_mmap_enter, CPUState* cpu, target_ulong pc, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MMAP_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MMAP_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mmap_return, CPUState* cpu, target_ulong pc, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MODIFY_LDT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MODIFY_LDT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_modify_ldt_enter, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MODIFY_LDT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MODIFY_LDT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_modify_ldt_return, CPUState* cpu, target_ulong pc, int32_t arg0, uint64_t arg1, uint64_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mount_enter, CPUState* cpu, target_ulong pc, uint64_t dev_name, uint64_t dir_name, uint64_t type, uint64_t flags, uint64_t _data);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mount_return, CPUState* cpu, target_ulong pc, uint64_t dev_name, uint64_t dir_name, uint64_t type, uint64_t flags, uint64_t _data);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedsend_enter, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint64_t abs_timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_MQ_TIMEDSEND_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_mq_timedsend_return, CPUState* cpu, target_ulong pc, uint32_t mqdes, uint64_t msg_ptr, uint32_t msg_len, uint32_t msg_prio, uint64_t abs_timeout);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_openat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, int32_t flags, uint32_t mode);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_OPENAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_openat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, int32_t flags, uint32_t mode);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_setxattr_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name, uint64_t value, uint32_t size, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SETXATTR_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_setxattr_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t name, uint64_t value, uint32_t size, int32_t flags);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_sigaltstack_enter, CPUState* cpu, target_ulong pc, uint64_t uss, uint64_t uoss);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SIGALTSTACK_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_sigaltstack_return, CPUState* cpu, target_ulong pc, uint64_t uss, uint64_t uoss);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKET_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKET_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_socket_enter, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1, int32_t arg2);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKET_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_SOCKET_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_socket_return, CPUState* cpu, target_ulong pc, int32_t arg0, int32_t arg1, int32_t arg2);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_statfs_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATFS_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_statfs_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t buf);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_statx_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, uint32_t flags, uint32_t mask, uint64_t buffer);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_STATX_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_statx_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t path, uint32_t flags, uint32_t mask, uint64_t buffer);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_time_enter, CPUState* cpu, target_ulong pc, uint64_t tloc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_time_return, CPUState* cpu, target_ulong pc, uint64_t tloc);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timer_settime_enter, CPUState* cpu, target_ulong pc, uint32_t timer_id, int32_t flags, uint64_t new_setting, uint64_t old_setting);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMER_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timer_settime_return, CPUState* cpu, target_ulong pc, uint32_t timer_id, int32_t flags, uint64_t new_setting, uint64_t old_setting);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_settime_enter, CPUState* cpu, target_ulong pc, int32_t ufd, int32_t flags, uint64_t utmr, uint64_t otmr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_TIMERFD_SETTIME_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_timerfd_settime_return, CPUState* cpu, target_ulong pc, int32_t ufd, int32_t flags, uint64_t utmr, uint64_t otmr);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utimensat_enter, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t utimes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMENSAT_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utimensat_return, CPUState* cpu, target_ulong pc, int32_t dfd, uint64_t filename, uint64_t utimes, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_ENTER 1
PPP_CB_TYPEDEF(void, on_sys_utimes_enter, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t utimes);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYS_UTIMES_RETURN 1
PPP_CB_TYPEDEF(void, on_sys_utimes_return, CPUState* cpu, target_ulong pc, uint64_t filename, uint64_t utimes);
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
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYSARCH_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_SYSARCH_ENTER 1
PPP_CB_TYPEDEF(void, on_sysarch_enter, CPUState* cpu, target_ulong pc, int32_t op, uint64_t parms);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_SYSARCH_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_SYSARCH_RETURN 1
PPP_CB_TYPEDEF(void, on_sysarch_return, CPUState* cpu, target_ulong pc, int32_t op, uint64_t parms);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_CREATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_THR_CREATE_ENTER 1
PPP_CB_TYPEDEF(void, on_thr_create_enter, CPUState* cpu, target_ulong pc, uint64_t ctx, uint64_t id, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_CREATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_THR_CREATE_RETURN 1
PPP_CB_TYPEDEF(void, on_thr_create_return, CPUState* cpu, target_ulong pc, uint64_t ctx, uint64_t id, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_EXIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_THR_EXIT_ENTER 1
PPP_CB_TYPEDEF(void, on_thr_exit_enter, CPUState* cpu, target_ulong pc, uint64_t state);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_EXIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_THR_EXIT_RETURN 1
PPP_CB_TYPEDEF(void, on_thr_exit_return, CPUState* cpu, target_ulong pc, uint64_t state);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_KILL_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_THR_KILL_ENTER 1
PPP_CB_TYPEDEF(void, on_thr_kill_enter, CPUState* cpu, target_ulong pc, int64_t id, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_KILL_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_THR_KILL_RETURN 1
PPP_CB_TYPEDEF(void, on_thr_kill_return, CPUState* cpu, target_ulong pc, int64_t id, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_KILL2_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_THR_KILL2_ENTER 1
PPP_CB_TYPEDEF(void, on_thr_kill2_enter, CPUState* cpu, target_ulong pc, int32_t pid, int64_t id, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_KILL2_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_THR_KILL2_RETURN 1
PPP_CB_TYPEDEF(void, on_thr_kill2_return, CPUState* cpu, target_ulong pc, int32_t pid, int64_t id, int32_t sig);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_NEW_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_THR_NEW_ENTER 1
PPP_CB_TYPEDEF(void, on_thr_new_enter, CPUState* cpu, target_ulong pc, uint64_t param, int32_t param_size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_NEW_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_THR_NEW_RETURN 1
PPP_CB_TYPEDEF(void, on_thr_new_return, CPUState* cpu, target_ulong pc, uint64_t param, int32_t param_size);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_SELF_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_THR_SELF_ENTER 1
PPP_CB_TYPEDEF(void, on_thr_self_enter, CPUState* cpu, target_ulong pc, uint64_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_SELF_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_THR_SELF_RETURN 1
PPP_CB_TYPEDEF(void, on_thr_self_return, CPUState* cpu, target_ulong pc, uint64_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_SET_NAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_THR_SET_NAME_ENTER 1
PPP_CB_TYPEDEF(void, on_thr_set_name_enter, CPUState* cpu, target_ulong pc, int64_t id, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_SET_NAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_THR_SET_NAME_RETURN 1
PPP_CB_TYPEDEF(void, on_thr_set_name_return, CPUState* cpu, target_ulong pc, int64_t id, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_SUSPEND_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_THR_SUSPEND_ENTER 1
PPP_CB_TYPEDEF(void, on_thr_suspend_enter, CPUState* cpu, target_ulong pc, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_SUSPEND_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_THR_SUSPEND_RETURN 1
PPP_CB_TYPEDEF(void, on_thr_suspend_return, CPUState* cpu, target_ulong pc, uint64_t timeout);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_WAKE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_THR_WAKE_ENTER 1
PPP_CB_TYPEDEF(void, on_thr_wake_enter, CPUState* cpu, target_ulong pc, int64_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_THR_WAKE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_THR_WAKE_RETURN 1
PPP_CB_TYPEDEF(void, on_thr_wake_return, CPUState* cpu, target_ulong pc, int64_t id);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_TRUNCATE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_TRUNCATE_ENTER 1
PPP_CB_TYPEDEF(void, on_truncate_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_TRUNCATE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_TRUNCATE_RETURN 1
PPP_CB_TYPEDEF(void, on_truncate_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t length);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UMASK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_UMASK_ENTER 1
PPP_CB_TYPEDEF(void, on_umask_enter, CPUState* cpu, target_ulong pc, uint32_t newmask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UMASK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_UMASK_RETURN 1
PPP_CB_TYPEDEF(void, on_umask_return, CPUState* cpu, target_ulong pc, uint32_t newmask);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UNAME_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_UNAME_ENTER 1
PPP_CB_TYPEDEF(void, on_uname_enter, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UNAME_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_UNAME_RETURN 1
PPP_CB_TYPEDEF(void, on_uname_return, CPUState* cpu, target_ulong pc, uint64_t name);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UNDELETE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_UNDELETE_ENTER 1
PPP_CB_TYPEDEF(void, on_undelete_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UNDELETE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_UNDELETE_RETURN 1
PPP_CB_TYPEDEF(void, on_undelete_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UNLINK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_UNLINK_ENTER 1
PPP_CB_TYPEDEF(void, on_unlink_enter, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UNLINK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_UNLINK_RETURN 1
PPP_CB_TYPEDEF(void, on_unlink_return, CPUState* cpu, target_ulong pc, uint64_t path);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UNLINKAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_UNLINKAT_ENTER 1
PPP_CB_TYPEDEF(void, on_unlinkat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UNLINKAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_UNLINKAT_RETURN 1
PPP_CB_TYPEDEF(void, on_unlinkat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UNMOUNT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_UNMOUNT_ENTER 1
PPP_CB_TYPEDEF(void, on_unmount_enter, CPUState* cpu, target_ulong pc, uint64_t path, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UNMOUNT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_UNMOUNT_RETURN 1
PPP_CB_TYPEDEF(void, on_unmount_return, CPUState* cpu, target_ulong pc, uint64_t path, int32_t flags);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UTIMENSAT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_UTIMENSAT_ENTER 1
PPP_CB_TYPEDEF(void, on_utimensat_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t times, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UTIMENSAT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_UTIMENSAT_RETURN 1
PPP_CB_TYPEDEF(void, on_utimensat_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t path, uint64_t times, int32_t flag);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UTIMES_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_UTIMES_ENTER 1
PPP_CB_TYPEDEF(void, on_utimes_enter, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t tptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UTIMES_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_UTIMES_RETURN 1
PPP_CB_TYPEDEF(void, on_utimes_return, CPUState* cpu, target_ulong pc, uint64_t path, uint64_t tptr);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UTRACE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_UTRACE_ENTER 1
PPP_CB_TYPEDEF(void, on_utrace_enter, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UTRACE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_UTRACE_RETURN 1
PPP_CB_TYPEDEF(void, on_utrace_return, CPUState* cpu, target_ulong pc, uint64_t addr, uint32_t len);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UUIDGEN_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_UUIDGEN_ENTER 1
PPP_CB_TYPEDEF(void, on_uuidgen_enter, CPUState* cpu, target_ulong pc, uint64_t store, int32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_UUIDGEN_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_UUIDGEN_RETURN 1
PPP_CB_TYPEDEF(void, on_uuidgen_return, CPUState* cpu, target_ulong pc, uint64_t store, int32_t count);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_VADVISE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_VADVISE_ENTER 1
PPP_CB_TYPEDEF(void, on_vadvise_enter, CPUState* cpu, target_ulong pc, int32_t anom);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_VADVISE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_VADVISE_RETURN 1
PPP_CB_TYPEDEF(void, on_vadvise_return, CPUState* cpu, target_ulong pc, int32_t anom);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_VFORK_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_VFORK_ENTER 1
PPP_CB_TYPEDEF(void, on_vfork_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_VFORK_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_VFORK_RETURN 1
PPP_CB_TYPEDEF(void, on_vfork_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_WAIT_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_WAIT_ENTER 1
PPP_CB_TYPEDEF(void, on_wait_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_WAIT_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_WAIT_RETURN 1
PPP_CB_TYPEDEF(void, on_wait_return, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_WAIT4_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_WAIT4_ENTER 1
PPP_CB_TYPEDEF(void, on_wait4_enter, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t status, int32_t options, uint64_t rusage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_WAIT4_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_WAIT4_RETURN 1
PPP_CB_TYPEDEF(void, on_wait4_return, CPUState* cpu, target_ulong pc, int32_t pid, uint64_t status, int32_t options, uint64_t rusage);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_WAIT6_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_WAIT6_ENTER 1
PPP_CB_TYPEDEF(void, on_wait6_enter, CPUState* cpu, target_ulong pc, uint32_t idtype, uint32_t id, uint64_t status, int32_t options, uint64_t wrusage, uint64_t info);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_WAIT6_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_WAIT6_RETURN 1
PPP_CB_TYPEDEF(void, on_wait6_return, CPUState* cpu, target_ulong pc, uint32_t idtype, uint32_t id, uint64_t status, int32_t options, uint64_t wrusage, uint64_t info);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_WRITE_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_WRITE_ENTER 1
PPP_CB_TYPEDEF(void, on_write_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t nbyte);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_WRITE_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_WRITE_RETURN 1
PPP_CB_TYPEDEF(void, on_write_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t buf, uint32_t nbyte);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_WRITEV_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_WRITEV_ENTER 1
PPP_CB_TYPEDEF(void, on_writev_enter, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t iovp, uint32_t iovcnt);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_WRITEV_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_WRITEV_RETURN 1
PPP_CB_TYPEDEF(void, on_writev_return, CPUState* cpu, target_ulong pc, int32_t fd, uint64_t iovp, uint32_t iovcnt);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_YIELD_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_YIELD_ENTER 1
PPP_CB_TYPEDEF(void, on_yield_enter, CPUState* cpu, target_ulong pc);
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_YIELD_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_YIELD_RETURN 1
PPP_CB_TYPEDEF(void, on_yield_return, CPUState* cpu, target_ulong pc);
#endif

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
