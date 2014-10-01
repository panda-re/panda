/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 *
 * This library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SYSCALLTABLE_LINUX_2_6_H
#define SYSCALLTABLE_LINUX_2_6_H

#define SYSCALLTABLE_LINUX_2_6_LEN 338

#define SYS_RESTART_SYSCALL     0
#define SYS_EXIT        1
#define SYS_FORK        2
#define SYS_READ        3
#define SYS_WRITE       4
#define SYS_OPEN        5
#define SYS_CLOSE       6
#define SYS_WAITPID     7
#define SYS_CREAT       8
#define SYS_LINK        9
#define SYS_UNLINK      10
#define SYS_EXECVE      11
#define SYS_CHDIR       12
#define SYS_TIME        13
#define SYS_MKNOD       14
#define SYS_CHMOD       15
#define SYS_LCHOWN16    16
//#define SYS_NI_SYSCALL  17
#define SYS_STAT        18
#define SYS_LSEEK       19
#define SYS_GETPID      20
#define SYS_MOUNT       21
#define SYS_OLDUMOUNT   22
#define SYS_SETUID16    23
#define SYS_GETUID16    24
#define SYS_STIME       25
#define SYS_PTRACE      26
#define SYS_ALARM       27
#define SYS_FSTAT       28
#define SYS_PAUSE       29
#define SYS_UTIME       30
//#define SYS_NI_SYSCALL  31
//#define SYS_NI_SYSCALL  32
#define SYS_ACCESS      33
#define SYS_NICE        34
//#define SYS_NI_SYSCALL  35
#define SYS_SYNC        36
#define SYS_KILL        37
#define SYS_RENAME      38
#define SYS_MKDIR       39
#define SYS_RMDIR       40
#define SYS_DUP 41
#define SYS_PIPE        42
#define SYS_TIMES       43
//#define SYS_NI_SYSCALL  44
#define SYS_BRK 45
#define SYS_SETGID16    46
#define SYS_GETGID16    47
#define SYS_SIGNAL      48
#define SYS_GETEUID16   49
#define SYS_GETEGID16   50
#define SYS_ACCT        51
#define SYS_UMOUNT      52
//#define SYS_NI_SYSCALL  53
#define SYS_IOCTL       54
#define SYS_FCNTL       55
//#define SYS_NI_SYSCALL  56
#define SYS_SETPGID     57
//#define SYS_NI_SYSCALL  58
#define SYS_OLDUNAME    59
#define SYS_UMASK       60
#define SYS_CHROOT      61
#define SYS_USTAT       62
#define SYS_DUP2        63
#define SYS_GETPPID     64
#define SYS_GETPGRP     65
#define SYS_SETSID      66
#define SYS_SIGACTION   67
#define SYS_SGETMASK    68
#define SYS_SSETMASK    69
#define SYS_SETREUID16  70
#define SYS_SETREGID16  71
#define SYS_SIGSUSPEND  72
#define SYS_SIGPENDING  73
#define SYS_SETHOSTNAME 74
#define SYS_SETRLIMIT   75
#define SYS_OLD_GETRLIMIT       76
#define SYS_GETRUSAGE   77
#define SYS_GETTIMEOFDAY        78
#define SYS_SETTIMEOFDAY        79
#define SYS_GETGROUPS16 80
#define SYS_SETGROUPS16 81
#define OLD_SELECT      82
#define SYS_SYMLINK     83
#define SYS_LSTAT       84
#define SYS_READLINK    85
#define SYS_USELIB      86
#define SYS_SWAPON      87
#define SYS_REBOOT      88
#define SYS_OLD_READDIR 89
#define OLD_MMAP        90
#define SYS_MUNMAP      91
#define SYS_TRUNCATE    92
#define SYS_FTRUNCATE   93
#define SYS_FCHMOD      94
#define SYS_FCHOWN16    95
#define SYS_GETPRIORITY 96
#define SYS_SETPRIORITY 97
//#define SYS_NI_SYSCALL  98
#define SYS_STATFS      99
#define SYS_FSTATFS     100
#define SYS_IOPERM      101
#define SYS_SOCKETCALL  102
#define SYS_SYSLOG      103
#define SYS_SETITIMER   104
#define SYS_GETITIMER   105
#define SYS_NEWSTAT     106
#define SYS_NEWLSTAT    107
#define SYS_NEWFSTAT    108
#define SYS_UNAME       109
#define PTREGS_IOPL     110
#define SYS_VHANGUP     111
//#define SYS_NI_SYSCALL  112
#define PTREGS_VM86OLD  113
#define SYS_WAIT4       114
#define SYS_SWAPOFF     115
#define SYS_SYSINFO     116
#define SYS_IPC 117
#define SYS_FSYNC       118
#define PTREGS_SIGRETURN        119
#define PTREGS_CLONE    120
#define SYS_SETDOMAINNAME       121
#define SYS_NEWUNAME    122
#define SYS_MODIFY_LDT  123
#define SYS_ADJTIMEX    124
#define SYS_MPROTECT    125
#define SYS_SIGPROCMASK 126
//#define SYS_NI_SYSCALL  127
#define SYS_INIT_MODULE 128
#define SYS_DELETE_MODULE       129
//#define SYS_NI_SYSCALL  130
#define SYS_QUOTACTL    131
#define SYS_GETPGID     132
#define SYS_FCHDIR      133
#define SYS_BDFLUSH     134
#define SYS_SYSFS       135
#define SYS_PERSONALITY 136
//#define SYS_NI_SYSCALL  137
#define SYS_SETFSUID16  138
#define SYS_SETFSGID16  139
#define SYS_LLSEEK      140
#define SYS_GETDENTS    141
#define SYS_SELECT      142
#define SYS_FLOCK       143
#define SYS_MSYNC       144
#define SYS_READV       145
#define SYS_WRITEV      146
#define SYS_GETSID      147
#define SYS_FDATASYNC   148
#define SYS_SYSCTL      149
#define SYS_MLOCK       150
#define SYS_MUNLOCK     151
#define SYS_MLOCKALL    152
#define SYS_MUNLOCKALL  153
#define SYS_SCHED_SETPARAM      154
#define SYS_SCHED_GETPARAM      155
#define SYS_SCHED_SETSCHEDULER  156
#define SYS_SCHED_GETSCHEDULER  157
#define SYS_SCHED_YIELD 158
#define SYS_SCHED_GET_PRIORITY_MAX      159
#define SYS_SCHED_GET_PRIORITY_MIN      160
#define SYS_SCHED_RR_GET_INTERVAL       161
#define SYS_NANOSLEEP   162
#define SYS_MREMAP      163
#define SYS_SETRESUID16 164
#define SYS_GETRESUID16 165
#define PTREGS_VM86     166
//#define SYS_NI_SYSCALL  167
#define SYS_POLL        168
#define SYS_NFSSERVCTL  169
#define SYS_SETRESGID16 170
#define SYS_GETRESGID16 171
#define SYS_PRCTL       172
#define PTREGS_RT_SIGRETURN     173
#define SYS_RT_SIGACTION        174
#define SYS_RT_SIGPROCMASK      175
#define SYS_RT_SIGPENDING       176
#define SYS_RT_SIGTIMEDWAIT     177
#define SYS_RT_SIGQUEUEINFO     178
#define SYS_RT_SIGSUSPEND       179
#define SYS_PREAD64     180
#define SYS_PWRITE64    181
#define SYS_CHOWN16     182
#define SYS_GETCWD      183
#define SYS_CAPGET      184
#define SYS_CAPSET      185
#define PTREGS_SIGALTSTACK      186
#define SYS_SENDFILE    187
//#define SYS_NI_SYSCALL  188
//#define SYS_NI_SYSCALL  189
#define PTREGS_VFORK    190
#define SYS_GETRLIMIT   191
#define SYS_MMAP2       192
#define SYS_TRUNCATE64  193
#define SYS_FTRUNCATE64 194
#define SYS_STAT64      195
#define SYS_LSTAT64     196
#define SYS_FSTAT64     197
#define SYS_LCHOWN      198
#define SYS_GETUID      199
#define SYS_GETGID      200
#define SYS_GETEUID     201
#define SYS_GETEGID     202
#define SYS_SETREUID    203
#define SYS_SETREGID    204
#define SYS_GETGROUPS   205
#define SYS_SETGROUPS   206
#define SYS_FCHOWN      207
#define SYS_SETRESUID   208
#define SYS_GETRESUID   209
#define SYS_SETRESGID   210
#define SYS_GETRESGID   211
#define SYS_CHOWN       212
#define SYS_SETUID      213
#define SYS_SETGID      214
#define SYS_SETFSUID    215
#define SYS_SETFSGID    216
#define SYS_PIVOT_ROOT  217
#define SYS_MINCORE     218
#define SYS_MADVISE     219
#define SYS_GETDENTS64  220
#define SYS_FCNTL64     221
//#define SYS_NI_SYSCALL  222
//#define SYS_NI_SYSCALL  223
#define SYS_GETTID      224
#define SYS_READAHEAD   225
#define SYS_SETXATTR    226
#define SYS_LSETXATTR   227
#define SYS_FSETXATTR   228
#define SYS_GETXATTR    229
#define SYS_LGETXATTR   230
#define SYS_FGETXATTR   231
#define SYS_LISTXATTR   232
#define SYS_LLISTXATTR  233
#define SYS_FLISTXATTR  234
#define SYS_REMOVEXATTR 235
#define SYS_LREMOVEXATTR        236
#define SYS_FREMOVEXATTR        237
#define SYS_TKILL       238
#define SYS_SENDFILE64  239
#define SYS_FUTEX       240
#define SYS_SCHED_SETAFFINITY   241
#define SYS_SCHED_GETAFFINITY   242
#define SYS_SET_THREAD_AREA     243
#define SYS_GET_THREAD_AREA     244
#define SYS_IO_SETUP    245
#define SYS_IO_DESTROY  246
#define SYS_IO_GETEVENTS        247
#define SYS_IO_SUBMIT   248
#define SYS_IO_CANCEL   249
#define SYS_FADVISE64   250
//#define SYS_NI_SYSCALL  251
#define SYS_EXIT_GROUP  252
#define SYS_LOOKUP_DCOOKIE      253
#define SYS_EPOLL_CREATE        254
#define SYS_EPOLL_CTL   255
#define SYS_EPOLL_WAIT  256
#define SYS_REMAP_FILE_PAGES    257
#define SYS_SET_TID_ADDRESS     258
#define SYS_TIMER_CREATE        259
#define SYS_TIMER_SETTIME       260
#define SYS_TIMER_GETTIME       261
#define SYS_TIMER_GETOVERRUN    262
#define SYS_TIMER_DELETE        263
#define SYS_CLOCK_SETTIME       264
#define SYS_CLOCK_GETTIME       265
#define SYS_CLOCK_GETRES        266
#define SYS_CLOCK_NANOSLEEP     267
#define SYS_STATFS64    268
#define SYS_FSTATFS64   269
#define SYS_TGKILL      270
#define SYS_UTIMES      271
#define SYS_FADVISE64_64        272
//#define SYS_NI_SYSCALL  273
#define SYS_MBIND       274
#define SYS_GET_MEMPOLICY       275
#define SYS_SET_MEMPOLICY       276
#define SYS_MQ_OPEN     277
#define SYS_MQ_UNLINK   278
#define SYS_MQ_TIMEDSEND        279
#define SYS_MQ_TIMEDRECEIVE     280
#define SYS_MQ_NOTIFY   281
#define SYS_MQ_GETSETATTR       282
#define SYS_KEXEC_LOAD  283
#define SYS_WAITID      284
//#define SYS_NI_SYSCALL  285
#define SYS_ADD_KEY     286
#define SYS_REQUEST_KEY 287
#define SYS_KEYCTL      288
#define SYS_IOPRIO_SET  289
#define SYS_IOPRIO_GET  290
#define SYS_INOTIFY_INIT        291
#define SYS_INOTIFY_ADD_WATCH   292
#define SYS_INOTIFY_RM_WATCH    293
#define SYS_MIGRATE_PAGES       294
#define SYS_OPENAT      295
#define SYS_MKDIRAT     296
#define SYS_MKNODAT     297
#define SYS_FCHOWNAT    298
#define SYS_FUTIMESAT   299
#define SYS_FSTATAT64   300
#define SYS_UNLINKAT    301
#define SYS_RENAMEAT    302
#define SYS_LINKAT      303
#define SYS_SYMLINKAT   304
#define SYS_READLINKAT  305
#define SYS_FCHMODAT    306
#define SYS_FACCESSAT   307
#define SYS_PSELECT6    308
#define SYS_PPOLL       309
#define SYS_UNSHARE     310
#define SYS_SET_ROBUST_LIST     311
#define SYS_GET_ROBUST_LIST     312
#define SYS_SPLICE      313
#define SYS_SYNC_FILE_RANGE     314
#define SYS_TEE 315
#define SYS_VMSPLICE    316
#define SYS_MOVE_PAGES  317
#define SYS_GETCPU      318
#define SYS_EPOLL_PWAIT 319
#define SYS_UTIMENSAT   320
#define SYS_SIGNALFD    321
#define SYS_TIMERFD_CREATE      322
#define SYS_EVENTFD     323
#define SYS_FALLOCATE   324
#define SYS_TIMERFD_SETTIME     325
#define SYS_TIMERFD_GETTIME     326
#define SYS_SIGNALFD4   327
#define SYS_EVENTFD2    328
#define SYS_EPOLL_CREATE1       329
#define SYS_DUP3        330
#define SYS_PIPE2       331
#define SYS_INOTIFY_INIT1       332
#define SYS_PREADV      333
#define SYS_PWRITEV     334
#define SYS_RT_TGSIGQUEUEINFO   335
#define SYS_PERF_COUNTER_OPEN   336
#define SYS_RECVMMSG    337

static const char* sysCallTable[SYSCALLTABLE_LINUX_2_6_LEN] = {
  "sys_restart_syscall",
      /* 0 - old "setup()" system call, used for restarting */
  "sys_exit",
  "sys_fork",
  "sys_read",
  "sys_write",
  "sys_open",
         /* 5 */
  "sys_close",
  "sys_waitpid",
  "sys_creat",
  "sys_link",
  "sys_unlink",
       /* 10 */
  "sys_execve",
  "sys_chdir",
  "sys_time",
  "sys_mknod",
  "sys_chmod",
        /* 15 */
  "sys_lchown16",
  "sys_ni_syscall",
   /* old break syscall holder */
  "sys_stat",
  "sys_lseek",
  "sys_getpid",
       /* 20 */
  "sys_mount",
  "sys_oldumount",
  "sys_setuid16",
  "sys_getuid16",
  "sys_stime",
        /* 25 */
  "sys_ptrace",
  "sys_alarm",
  "sys_fstat",
  "sys_pause",
  "sys_utime",
        /* 30 */
  "sys_ni_syscall",
   /* old stty syscall holder */
  "sys_ni_syscall",
   /* old gtty syscall holder */
  "sys_access",
  "sys_nice",
  "sys_ni_syscall",
   /* 35 - old ftime syscall holder */
  "sys_sync",
  "sys_kill",
  "sys_rename",
  "sys_mkdir",
  "sys_rmdir",
        /* 40 */
  "sys_dup",
  "sys_pipe",
  "sys_times",
  "sys_ni_syscall",
   /* old prof syscall holder */
  "sys_brk",
          /* 45 */
  "sys_setgid16",
  "sys_getgid16",
  "sys_signal",
  "sys_geteuid16",
  "sys_getegid16",
    /* 50 */
  "sys_acct",
  "sys_umount",
       /* recycled never used phys() */
  "sys_ni_syscall",
   /* old lock syscall holder */
  "sys_ioctl",
  "sys_fcntl",
        /* 55 */
  "sys_ni_syscall",
   /* old mpx syscall holder */
  "sys_setpgid",
  "sys_ni_syscall",
   /* old ulimit syscall holder */
  "sys_olduname",
  "sys_umask",
        /* 60 */
  "sys_chroot",
  "sys_ustat",
  "sys_dup2",
  "sys_getppid",
  "sys_getpgrp",
      /* 65 */
  "sys_setsid",
  "sys_sigaction",
  "sys_sgetmask",
  "sys_ssetmask",
  "sys_setreuid16",
   /* 70 */
  "sys_setregid16",
  "sys_sigsuspend",
  "sys_sigpending",
  "sys_sethostname",
  "sys_setrlimit",
    /* 75 */
  "sys_old_getrlimit",
  "sys_getrusage",
  "sys_gettimeofday",
  "sys_settimeofday",
  "sys_getgroups16",
  /* 80 */
  "sys_setgroups16",
  "old_select",
  "sys_symlink",
  "sys_lstat",
  "sys_readlink",
     /* 85 */
  "sys_uselib",
  "sys_swapon",
  "sys_reboot",
  "sys_old_readdir",
  "old_mmap",
         /* 90 */
  "sys_munmap",
  "sys_truncate",
  "sys_ftruncate",
  "sys_fchmod",
  "sys_fchown16",
     /* 95 */
  "sys_getpriority",
  "sys_setpriority",
  "sys_ni_syscall",
   /* old profil syscall holder */
  "sys_statfs",
  "sys_fstatfs",
      /* 100 */
  "sys_ioperm",
  "sys_socketcall",
  "sys_syslog",
  "sys_setitimer",
  "sys_getitimer",
    /* 105 */
  "sys_newstat",
  "sys_newlstat",
  "sys_newfstat",
  "sys_uname",
  "ptregs_iopl",
      /* 110 */
  "sys_vhangup",
  "sys_ni_syscall",
   /* old "idle" system call */
  "ptregs_vm86old",
  "sys_wait4",
  "sys_swapoff",
      /* 115 */
  "sys_sysinfo",
  "sys_ipc",
  "sys_fsync",
  "ptregs_sigreturn",
  "ptregs_clone",
     /* 120 */
  "sys_setdomainname",
  "sys_newuname",
  "sys_modify_ldt",
  "sys_adjtimex",
  "sys_mprotect",
     /* 125 */
  "sys_sigprocmask",
  "sys_ni_syscall",
   /* old "create_module" */
  "sys_init_module",
  "sys_delete_module",
  "sys_ni_syscall",
   /* 130: old "get_kernel_syms" */
  "sys_quotactl",
  "sys_getpgid",
  "sys_fchdir",
  "sys_bdflush",
  "sys_sysfs",
        /* 135 */
  "sys_personality",
  "sys_ni_syscall",
   /* reserved for afs_syscall */
  "sys_setfsuid16",
  "sys_setfsgid16",
  "sys_llseek",
       /* 140 */
  "sys_getdents",
  "sys_select",
  "sys_flock",
  "sys_msync",
  "sys_readv",
        /* 145 */
  "sys_writev",
  "sys_getsid",
  "sys_fdatasync",
  "sys_sysctl",
  "sys_mlock",
        /* 150 */
  "sys_munlock",
  "sys_mlockall",
  "sys_munlockall",
  "sys_sched_setparam",
  "sys_sched_getparam",
  /* 155 */
  "sys_sched_setscheduler",
  "sys_sched_getscheduler",
  "sys_sched_yield",
  "sys_sched_get_priority_max",
  "sys_sched_get_priority_min",
 /* 160 */
  "sys_sched_rr_get_interval",
  "sys_nanosleep",
  "sys_mremap",
  "sys_setresuid16",
  "sys_getresuid16",
  /* 165 */
  "ptregs_vm86",
  "sys_ni_syscall",
   /* Old sys_query_module */
  "sys_poll",
  "sys_nfsservctl",
  "sys_setresgid16",
  /* 170 */
  "sys_getresgid16",
  "sys_prctl",
  "ptregs_rt_sigreturn",
  "sys_rt_sigaction",
  "sys_rt_sigprocmask",
       /* 175 */
  "sys_rt_sigpending",
  "sys_rt_sigtimedwait",
  "sys_rt_sigqueueinfo",
  "sys_rt_sigsuspend",
  "sys_pread64",
      /* 180 */
  "sys_pwrite64",
  "sys_chown16",
  "sys_getcwd",
  "sys_capget",
  "sys_capset",
       /* 185 */
  "ptregs_sigaltstack",
  "sys_sendfile",
  "sys_ni_syscall",
   /* reserved for streams1 */
  "sys_ni_syscall",
   /* reserved for streams2 */
  "ptregs_vfork",
     /* 190 */
  "sys_getrlimit",
  "sys_mmap2",
  "sys_truncate64",
  "sys_ftruncate64",
  "sys_stat64",
       /* 195 */
  "sys_lstat64",
  "sys_fstat64",
  "sys_lchown",
  "sys_getuid",
  "sys_getgid",
       /* 200 */
  "sys_geteuid",
  "sys_getegid",
  "sys_setreuid",
  "sys_setregid",
  "sys_getgroups",
    /* 205 */
  "sys_setgroups",
  "sys_fchown",
  "sys_setresuid",
  "sys_getresuid",
  "sys_setresgid",
    /* 210 */
  "sys_getresgid",
  "sys_chown",
  "sys_setuid",
  "sys_setgid",
  "sys_setfsuid",
     /* 215 */
  "sys_setfsgid",
  "sys_pivot_root",
  "sys_mincore",
  "sys_madvise",
  "sys_getdents64",
   /* 220 */
  "sys_fcntl64",
  "sys_ni_syscall",
   /* reserved for TUX */
  "sys_ni_syscall",
  "sys_gettid",
  "sys_readahead",
    /* 225 */
  "sys_setxattr",
  "sys_lsetxattr",
  "sys_fsetxattr",
  "sys_getxattr",
  "sys_lgetxattr",
    /* 230 */
  "sys_fgetxattr",
  "sys_listxattr",
  "sys_llistxattr",
  "sys_flistxattr",
  "sys_removexattr",
  /* 235 */
  "sys_lremovexattr",
  "sys_fremovexattr",
  "sys_tkill",
  "sys_sendfile64",
  "sys_futex",
        /* 240 */
  "sys_sched_setaffinity",
  "sys_sched_getaffinity",
  "sys_set_thread_area",
  "sys_get_thread_area",
  "sys_io_setup",
     /* 245 */
  "sys_io_destroy",
  "sys_io_getevents",
  "sys_io_submit",
  "sys_io_cancel",
  "sys_fadvise64",
    /* 250 */
  "sys_ni_syscall",
  "sys_exit_group",
  "sys_lookup_dcookie",
  "sys_epoll_create",
  "sys_epoll_ctl",
    /* 255 */
  "sys_epoll_wait",
  "sys_remap_file_pages",
  "sys_set_tid_address",
  "sys_timer_create",
  "sys_timer_settime",
        /* 260 */
  "sys_timer_gettime",
  "sys_timer_getoverrun",
  "sys_timer_delete",
  "sys_clock_settime",
  "sys_clock_gettime",
        /* 265 */
  "sys_clock_getres",
  "sys_clock_nanosleep",
  "sys_statfs64",
  "sys_fstatfs64",
  "sys_tgkill",
       /* 270 */
  "sys_utimes",
  "sys_fadvise64_64",
  "sys_ni_syscall",
   /* sys_vserver */
  "sys_mbind",
  "sys_get_mempolicy",
  "sys_set_mempolicy",
  "sys_mq_open",
  "sys_mq_unlink",
  "sys_mq_timedsend",
  "sys_mq_timedreceive",
      /* 280 */
  "sys_mq_notify",
  "sys_mq_getsetattr",
  "sys_kexec_load",
  "sys_waitid",
  "sys_ni_syscall",
           /* 285 */ /* available */
  "sys_add_key",
  "sys_request_key",
  "sys_keyctl",
  "sys_ioprio_set",
  "sys_ioprio_get",
           /* 290 */
  "sys_inotify_init",
  "sys_inotify_add_watch",
  "sys_inotify_rm_watch",
  "sys_migrate_pages",
  "sys_openat",
               /* 295 */
  "sys_mkdirat",
  "sys_mknodat",
  "sys_fchownat",
  "sys_futimesat",
  "sys_fstatat64",
            /* 300 */
  "sys_unlinkat",
  "sys_renameat",
  "sys_linkat",
  "sys_symlinkat",
  "sys_readlinkat",
           /* 305 */
  "sys_fchmodat",
  "sys_faccessat",
  "sys_pselect6",
  "sys_ppoll",
  "sys_unshare",
              /* 310 */
  "sys_set_robust_list",
  "sys_get_robust_list",
  "sys_splice",
  "sys_sync_file_range",
  "sys_tee",
                  /* 315 */
  "sys_vmsplice",
  "sys_move_pages",
  "sys_getcpu",
  "sys_epoll_pwait",
  "sys_utimensat",
            /* 320 */
  "sys_signalfd",
  "sys_timerfd_create",
  "sys_eventfd",
  "sys_fallocate",
  "sys_timerfd_settime",
      /* 325 */
  "sys_timerfd_gettime",
  "sys_signalfd4",
  "sys_eventfd2",
  "sys_epoll_create1",
  "sys_dup3",
                 /* 330 */
  "sys_pipe2",
  "sys_inotify_init1",
  "sys_preadv",
  "sys_pwritev",
  "sys_rt_tgsigqueueinfo",
    /* 335 */
  "sys_perf_counter_open",
  "sys_recvmmsg"
};

const char* syscallToString(int syscallnum)
{
  if ( (syscallnum < 0) || (syscallnum >= SYSCALLTABLE_LINUX_2_6_LEN) )
  {
    return (NULL);
  }

  return (sysCallTable[syscallnum]);
}

#endif//SYSCALLTABLE_LINUX_2_6_H
