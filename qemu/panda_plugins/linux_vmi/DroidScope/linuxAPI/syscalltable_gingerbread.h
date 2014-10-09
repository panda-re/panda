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

#define SYSCALLTABLE_LINUX_2_6_LEN 361

/** Got this from arch/arm/include/asm/unistd.h in the kernel source! **/

#define SYS_RESTART                                     0
#define SYS_EXIT                                                1
#define SYS_FORK                                                2
#define SYS_READ                                                3
#define SYS_WRITE                                               4
#define SYS_OPEN                                                5
#define SYS_CLOSE                                               6
                                        /*      7       was     sys_waitpid     */
#define SYS_CREAT                                               8
#define SYS_LINK                                                9
#define SYS_UNLINK                                      10
#define SYS_EXECVE                                      11
#define SYS_CHDIR                                       12
#define SYS_TIME                                        13
#define SYS_MKNOD                                       14
#define SYS_CHMOD                                       15
#define SYS_LCHOWN                                      16
                                        /*      17      was     sys_break       */
                                        /*      18      was     sys_stat        */
#define SYS_LSEEK                                       19
#define SYS_GETPID                                      20
#define SYS_MOUNT                                       21
#define SYS_UMOUNT                                      22
#define SYS_SETUID                                      23
#define SYS_GETUID                                      24
#define SYS_STIME                                       25
#define SYS_PTRACE                                      26
#define SYS_ALARM                                       27
                                        /*      28      was     sys_fstat       */
#define SYS_PAUSE                                       29
#define SYS_UTIME                                       30
                                        /*      31      was     sys_stty        */
                                        /*      32      was     sys_gtty        */
#define SYS_ACCESS                                      33
#define SYS_NICE                                        34
                                        /*      35      was     sys_ftime       */
#define SYS_SYNC                                        36
#define SYS_KILL                                        37
#define SYS_RENAME                                      38
#define SYS_MKDIR                                       39
#define SYS_RMDIR                                       40
#define SYS_DUP                                 41
#define SYS_PIPE                                        42
#define SYS_TIMES                                       43
                                        /*      44      was     sys_prof        */
#define SYS_BRK                                 45
#define SYS_SETGID                                      46
#define SYS_GETGID                                      47
                                        /*      48      was     sys_signal      */
#define SYS_GETEUID                                     49
#define SYS_GETEGID                                     50
#define SYS_ACCT                                        51
#define SYS_UMOUNT2                                     52
                                        /*      53      was     sys_lock        */
#define SYS_IOCTL                                       54
#define SYS_FCNTL                                       55
                                        /*      56      was     sys_mpx */
#define SYS_SETPGID                                     57
                                        /*      58      was     sys_ulimit      */
                                        /*      59      was     sys_olduname    */
#define SYS_UMASK                                       60
#define SYS_CHROOT                                      61
#define SYS_USTAT                                       62
#define SYS_DUP2                                        63
#define SYS_GETPPID                                     64
#define SYS_GETPGRP                                     65
#define SYS_SETSID                                      66
#define SYS_SIGACTION                                   67
                                        /*      68      was     sys_sgetmask    */
                                        /*      69      was     sys_ssetmask    */
#define SYS_SETREUID                                    70
#define SYS_SETREGID                                    71
#define SYS_SIGSUSPEND                                  72
#define SYS_SIGPENDING                                  73
#define SYS_SETHOSTNAME                         74
#define SYS_SETRLIMIT                                   75
#define SYS_GETRLIMIT                                   76              /*      Back    compat  2GB     limited rlimit  */
#define SYS_GETRUSAGE                                   77
#define SYS_GETTIMEOFDAY                                78
#define SYS_SETTIMEOFDAY                                79
#define SYS_GETGROUPS                                   80
#define SYS_SETGROUPS                                   81
#define SYS_SELECT                                      82
#define SYS_SYMLINK                                     83
                                        /*      84      was     sys_lstat       */
#define SYS_READLINK                                    85
#define SYS_USELIB                                      86
#define SYS_SWAPON                                      87
#define SYS_REBOOT                                      88
#define SYS_READDIR                                     89
#define SYS_MMAP                                        90
#define SYS_MUNMAP                                      91
#define SYS_TRUNCATE                                    92
#define SYS_FTRUNCATE                                   93
#define SYS_FCHMOD                                      94
#define SYS_FCHOWN                                      95
#define SYS_GETPRIORITY                         96
#define SYS_SETPRIORITY                         97
                                        /*      98      was     sys_profil      */
#define SYS_STATFS                                      99
#define SYS_FSTATFS                             100
                                        /*      101     was     sys_ioperm      */
#define SYS_SOCKETCALL                          102
#define SYS_SYSLOG                              103
#define SYS_SETITIMER                           104
#define SYS_GETITIMER                           105
#define SYS_STAT                                106
#define SYS_LSTAT                               107
#define SYS_FSTAT                               108
                                        /*      109     was     sys_uname       */
                                        /*      110     was     sys_iopl        */
#define SYS_VHANGUP                             111
                                        /*      112     was     sys_idle        */
#define SYS_SYSCALL                             113             /*      syscall to      call    a       syscall!        */
#define SYS_WAIT4                               114
#define SYS_SWAPOFF                             115
#define SYS_SYSINFO                             116
#define SYS_IPC                         117
#define SYS_FSYNC                               118
#define SYS_SIGRETURN                           119
#define SYS_CLONE                               120
#define SYS_SETDOMAINNAME                       121
#define SYS_UNAME                               122
                                        /*      123     was     sys_modify_ldt  */
#define SYS_ADJTIMEX                            124
#define SYS_MPROTECT                            125
#define SYS_SIGPROCMASK                 126
                                        /*      127     was     sys_create_module       */
#define SYS_INIT_MODULE                 128
#define SYS_DELETE_MODULE                       129
                                        /*      130     was     sys_get_kernel_syms     */
#define SYS_QUOTACTL                            131
#define SYS_GETPGID                             132
#define SYS_FCHDIR                              133
#define SYS_BDFLUSH                             134
#define SYS_SYSFS                               135
#define SYS_PERSONALITY                 136
                                        /*      137     was     sys_afs_syscall */
#define SYS_SETFSUID                            138
#define SYS_SETFSGID                            139
#define SYS__LLSEEK                             140
#define SYS_GETDENTS                            141
#define SYS__NEWSELECT                          142
#define SYS_FLOCK                               143
#define SYS_MSYNC                               144
#define SYS_READV                               145
#define SYS_WRITEV                              146
#define SYS_GETSID                              147
#define SYS_FDATASYNC                           148
#define SYS__SYSCTL                             149
#define SYS_MLOCK                               150
#define SYS_MUNLOCK                             151
#define SYS_MLOCKALL                            152
#define SYS_MUNLOCKALL                          153
#define SYS_SCHED_SETPARAM                      154
#define SYS_SCHED_GETPARAM                      155
#define SYS_SCHED_SETSCHEDULER                  156
#define SYS_SCHED_GETSCHEDULER                  157
#define SYS_SCHED_YIELD                 158
#define SYS_SCHED_GET_PRIORITY_MAX              159
#define SYS_SCHED_GET_PRIORITY_MIN              160
#define SYS_SCHED_RR_GET_INTERVAL               161
#define SYS_NANOSLEEP                           162
#define SYS_MREMAP                              163
#define SYS_SETRESUID                           164
#define SYS_GETRESUID                           165
                                        /*      166     was     sys_vm86        */
                                        /*      167     was     sys_query_module        */
#define SYS_POLL                                168
#define SYS_NFSSERVCTL                          169
#define SYS_SETRESGID                           170
#define SYS_GETRESGID                           171
#define SYS_PRCTL                               172
#define SYS_RT_SIGRETURN                        173
#define SYS_RT_SIGACTION                        174
#define SYS_RT_SIGPROCMASK                      175
#define SYS_RT_SIGPENDING                       176
#define SYS_RT_SIGTIMEDWAIT                     177
#define SYS_RT_SIGQUEUEINFO                     178
#define SYS_RT_SIGSUSPEND                       179
#define SYS_PREAD64                             180
#define SYS_PWRITE64                            181
#define SYS_CHOWN                               182
#define SYS_GETCWD                              183
#define SYS_CAPGET                              184
#define SYS_CAPSET                              185
#define SYS_SIGALTSTACK                 186
#define SYS_SENDFILE                            187
                                        /*      188     reserved        */
                                        /*      189     reserved        */
#define SYS_VFORK                               190
#define SYS_UGETRLIMIT                          191             /*      SuS     compliant       getrlimit       */
#define SYS_MMAP2                               192
#define SYS_TRUNCATE64                          193
#define SYS_FTRUNCATE64                 194
#define SYS_STAT64                              195
#define SYS_LSTAT64                             196
#define SYS_FSTAT64                             197
#define SYS_LCHOWN32                            198
#define SYS_GETUID32                            199
#define SYS_GETGID32                            200
#define SYS_GETEUID32                           201
#define SYS_GETEGID32                           202
#define SYS_SETREUID32                          203
#define SYS_SETREGID32                          204
#define SYS_GETGROUPS32                 205
#define SYS_SETGROUPS32                 206
#define SYS_FCHOWN32                            207
#define SYS_SETRESUID32                 208
#define SYS_GETRESUID32                 209
#define SYS_SETRESGID32                 210
#define SYS_GETRESGID32                 211
#define SYS_CHOWN32                             212
#define SYS_SETUID32                            213
#define SYS_SETGID32                            214
#define SYS_SETFSUID32                          215
#define SYS_SETFSGID32                          216
#define SYS_GETDENTS64                          217
#define SYS_PIVOT_ROOT                          218
#define SYS_MINCORE                             219
#define SYS_MADVISE                             220
#define SYS_FCNTL64                             221
                                        /*      222     for     tux     */
                                        /*      223     is      unused  */
#define SYS_GETTID                              224
#define SYS_READAHEAD                           225
#define SYS_SETXATTR                            226
#define SYS_LSETXATTR                           227
#define SYS_FSETXATTR                           228
#define SYS_GETXATTR                            229
#define SYS_LGETXATTR                           230
#define SYS_FGETXATTR                           231
#define SYS_LISTXATTR                           232
#define SYS_LLISTXATTR                          233
#define SYS_FLISTXATTR                          234
#define SYS_REMOVEXATTR                 235
#define SYS_LREMOVEXATTR                        236
#define SYS_FREMOVEXATTR                        237
#define SYS_TKILL                               238
#define SYS_SENDFILE64                          239
#define SYS_FUTEX                               240
#define SYS_SCHED_SETAFFINITY                   241
#define SYS_SCHED_GETAFFINITY                   242
#define SYS_IO_SETUP                            243
#define SYS_IO_DESTROY                          244
#define SYS_IO_GETEVENTS                        245
#define SYS_IO_SUBMIT                           246
#define SYS_IO_CANCEL                           247
#define SYS_EXIT_GROUP                          248
#define SYS_LOOKUP_DCOOKIE                      249
#define SYS_EPOLL_CREATE                        250
#define SYS_EPOLL_CTL                           251
#define SYS_EPOLL_WAIT                          252
#define SYS_REMAP_FILE_PAGES                    253
                                        /*      254     for     set_thread_area */
                                        /*      255     for     get_thread_area */
#define SYS_SET_TID_ADDRESS                     256
#define SYS_TIMER_CREATE                        257
#define SYS_TIMER_SETTIME                       258
#define SYS_TIMER_GETTIME                       259
#define SYS_TIMER_GETOVERRUN                    260
#define SYS_TIMER_DELETE                        261
#define SYS_CLOCK_SETTIME                       262
#define SYS_CLOCK_GETTIME                       263
#define SYS_CLOCK_GETRES                        264
#define SYS_CLOCK_NANOSLEEP                     265
#define SYS_STATFS64                            266
#define SYS_FSTATFS64                           267
#define SYS_TGKILL                              268
#define SYS_UTIMES                              269
#define SYS_ARM_FADVISE64_64                    270
#define SYS_PCICONFIG_IOBASE                    271
#define SYS_PCICONFIG_READ                      272
#define SYS_PCICONFIG_WRITE                     273
#define SYS_MQ_OPEN                             274
#define SYS_MQ_UNLINK                           275
#define SYS_MQ_TIMEDSEND                        276
#define SYS_MQ_TIMEDRECEIVE                     277
#define SYS_MQ_NOTIFY                           278
#define SYS_MQ_GETSETATTR                       279
#define SYS_WAITID                              280
#define SYS_SOCKET                              281
#define SYS_BIND                                282
#define SYS_CONNECT                             283
#define SYS_LISTEN                              284
#define SYS_ACCEPT                              285
#define SYS_GETSOCKNAME                 286
#define SYS_GETPEERNAME                 287
#define SYS_SOCKETPAIR                          288
#define SYS_SEND                                289
#define SYS_SENDTO                              290
#define SYS_RECV                                291
#define SYS_RECVFROM                            292
#define SYS_SHUTDOWN                            293
#define SYS_SETSOCKOPT                          294
#define SYS_GETSOCKOPT                          295
#define SYS_SENDMSG                             296
#define SYS_RECVMSG                             297
#define SYS_SEMOP                               298
#define SYS_SEMGET                              299
#define SYS_SEMCTL                              300
#define SYS_MSGSND                              301
#define SYS_MSGRCV                              302
#define SYS_MSGGET                              303
#define SYS_MSGCTL                              304
#define SYS_SHMAT                               305
#define SYS_SHMDT                               306
#define SYS_SHMGET                              307
#define SYS_SHMCTL                              308
#define SYS_ADD_KEY                             309
#define SYS_REQUEST_KEY                 310
#define SYS_KEYCTL                              311
#define SYS_SEMTIMEDOP                          312
#define SYS_VSERVER                             313
#define SYS_IOPRIO_SET                          314
#define SYS_IOPRIO_GET                          315
#define SYS_INOTIFY_INIT                        316
#define SYS_INOTIFY_ADD_WATCH                   317
#define SYS_INOTIFY_RM_WATCH                    318
#define SYS_MBIND                               319
#define SYS_GET_MEMPOLICY                       320
#define SYS_SET_MEMPOLICY                       321
#define SYS_OPENAT                              322
#define SYS_MKDIRAT                             323
#define SYS_MKNODAT                             324
#define SYS_FCHOWNAT                            325
#define SYS_FUTIMESAT                           326
#define SYS_FSTATAT64                           327
#define SYS_UNLINKAT                            328
#define SYS_RENAMEAT                            329
#define SYS_LINKAT                              330
#define SYS_SYMLINKAT                           331
#define SYS_READLINKAT                          332
#define SYS_FCHMODAT                            333
#define SYS_FACCESSAT                           334
                                        /*      335     for     pselect6        */
                                        /*      336     for     ppoll   */
#define SYS_UNSHARE                             337
#define SYS_SET_ROBUST_LIST                     338
#define SYS_GET_ROBUST_LIST                     339
#define SYS_SPLICE                              340
#define SYS_ARM_SYNC_FILE_RANGE         341
#define SYS_SYNC_FILE_RANGE2            SYS_ARM_SYNC_FILE_RANGE
#define SYS_TEE                         342
#define SYS_VMSPLICE                            343
#define SYS_MOVE_PAGES                          344
#define SYS_GETCPU                              345
                                        /*      346     for     epoll_pwait     */
#define SYS_KEXEC_LOAD                          347
#define SYS_UTIMENSAT                           348
#define SYS_SIGNALFD                            349
#define SYS_TIMERFD_CREATE                      350
#define SYS_EVENTFD                             351
#define SYS_FALLOCATE                           352
#define SYS_TIMERFD_SETTIME                     353
#define SYS_TIMERFD_GETTIME                     354
#define SYS_SIGNALFD4                           355
#define SYS_EVENTFD2                            356
#define SYS_EPOLL_CREATE1                       357
#define SYS_DUP3                                358
#define SYS_PIPE2                               359
#define SYS_INOTIFY_INIT1                       360



static const char* sysCallTable[SYSCALLTABLE_LINUX_2_6_LEN] = {
    "sys_restart_syscall"        ,
    "sys_exit"     ,
    "sys_fork"     ,
    "sys_read"     ,
    "sys_write"    ,
    "sys_open"     ,
    "sys_close"    ,
    ""/* 7 was sys_waitpid */       ,
    "sys_creat"    ,
    "sys_link"     ,
    "sys_unlink"   ,
    "sys_execve"   ,
    "sys_chdir"    ,
    "sys_time"     ,
    "sys_mknod"    ,
    "sys_chmod"    ,
    "sys_lchown"   ,
    ""/* 17 was sys_break */        ,
    ""/* 18 was sys_stat */ ,
    "sys_lseek"    ,
    "sys_getpid"   ,
    "sys_mount"    ,
    "sys_umount"   ,
    "sys_setuid"   ,
    "sys_getuid"   ,
    "sys_stime"    ,
    "sys_ptrace"   ,
    "sys_alarm"    ,
    ""/* 28 was sys_fstat */        ,
    "sys_pause"    ,
    "sys_utime"    ,
    ""/* 31 was sys_stty */ ,
    ""/* 32 was sys_gtty */ ,
    "sys_access"   ,
    "sys_nice"     ,
    ""/* 35 was sys_ftime */        ,
    "sys_sync"     ,
    "sys_kill"     ,
    "sys_rename"   ,
    "sys_mkdir"    ,
    "sys_rmdir"    ,
    "sys_dup"      ,
    "sys_pipe"     ,
    "sys_times"    ,
    ""/* 44 was sys_prof */ ,
    "sys_brk"      ,
    "sys_setgid"   ,
    "sys_getgid"   ,
    ""/* 48 was sys_signal */       ,
    "sys_geteuid"  ,
    "sys_getegid"  ,
    "sys_acct"     ,
    "sys_umount2"  ,
    ""/* 53 was sys_lock */ ,
    "sys_ioctl"    ,
    "sys_fcntl"    ,
    ""/* 56 was sys_mpx */  ,
    "sys_setpgid"  ,
    ""/* 58 was sys_ulimit */       ,
    ""/* 59 was sys_olduname */     ,
    "sys_umask"    ,
    "sys_chroot"   ,
    "sys_ustat"    ,
    "sys_dup2"     ,
    "sys_getppid"  ,
    "sys_getpgrp"  ,
    "sys_setsid"   ,
    "sys_sigaction"        ,
    ""/* 68 was sys_sgetmask */     ,
    ""/* 69 was sys_ssetmask */     ,
    "sys_setreuid" ,
    "sys_setregid" ,
    "sys_sigsuspend"       ,
    "sys_sigpending"       ,
    "sys_sethostname"      ,
    "sys_setrlimit"        ,
    "sys_getrlimit"        ,
    "sys_getrusage"        ,
    "sys_gettimeofday"     ,
    "sys_settimeofday"     ,
    "sys_getgroups"        ,
    "sys_setgroups"        ,
    "sys_select"   ,
    "sys_symlink"  ,
    ""/* 84 was sys_lstat */        ,
    "sys_readlink" ,
    "sys_uselib"   ,
    "sys_swapon"   ,
    "sys_reboot"   ,
    "sys_readdir"  ,
    "sys_mmap"     ,
    "sys_munmap"   ,
    "sys_truncate" ,
    "sys_ftruncate"        ,
    "sys_fchmod"   ,
    "sys_fchown"   ,
    "sys_getpriority"      ,
    "sys_setpriority"      ,
    ""/* 98 was sys_profil */       ,
    "sys_statfs"   ,
    "sys_fstatfs"  ,
    ""/* 101 was sys_ioperm */      ,
    "sys_socketcall"       ,
    "sys_syslog"   ,
    "sys_setitimer"        ,
    "sys_getitimer"        ,
    "sys_stat"     ,
    "sys_lstat"    ,
    "sys_fstat"    ,
    ""/* 109 was sys_uname */       ,
    ""/* 110 was sys_iopl */        ,
    "sys_vhangup"  ,
    ""/* 112 was sys_idle */        ,
    "sys_syscall"  ,
    "sys_wait4"    ,
    "sys_swapoff"  ,
    "sys_sysinfo"  ,
    "sys_ipc"      ,
    "sys_fsync"    ,
    "sys_sigreturn"        ,
    "sys_clone"    ,
    "sys_setdomainname"    ,
    "sys_uname"    ,
    ""/* 123 was sys_modify_ldt */  ,
    "sys_adjtimex" ,
    "sys_mprotect" ,
    "sys_sigprocmask"      ,
    ""/* 127 was sys_create_module */       ,
    "sys_init_module"      ,
    "sys_delete_module"    ,
    ""/* 130 was sys_get_kernel_syms */     ,
    "sys_quotactl" ,
    "sys_getpgid"  ,
    "sys_fchdir"   ,
    "sys_bdflush"  ,
    "sys_sysfs"    ,
    "sys_personality"      ,
    ""/* 137 was sys_afs_syscall */ ,
    "sys_setfsuid" ,
    "sys_setfsgid" ,
    "sys__llseek"  ,
    "sys_getdents" ,
    "sys__newselect"       ,
    "sys_flock"    ,
    "sys_msync"    ,
    "sys_readv"    ,
    "sys_writev"   ,
    "sys_getsid"   ,
    "sys_fdatasync"        ,
    "sys__sysctl"  ,
    "sys_mlock"    ,
    "sys_munlock"  ,
    "sys_mlockall" ,
    "sys_munlockall"       ,
    "sys_sched_setparam"   ,
    "sys_sched_getparam"   ,
    "sys_sched_setscheduler"       ,
    "sys_sched_getscheduler"       ,
    "sys_sched_yield"      ,
    "sys_sched_get_priority_max"            ,
    "sys_sched_get_priority_min"            ,
    "sys_sched_rr_get_interval"             ,
    "sys_nanosleep"        ,
    "sys_mremap"   ,
    "sys_setresuid"        ,
    "sys_getresuid"        ,
    ""/* 166 was sys_vm86 */        ,
    ""/* 167 was sys_query_module */        ,
    "sys_poll"     ,
    "sys_nfsservctl"       ,
    "sys_setresgid"        ,
    "sys_getresgid"        ,
    "sys_prctl"    ,
    "sys_rt_sigreturn"     ,
    "sys_rt_sigaction"     ,
    "sys_rt_sigprocmask"   ,
    "sys_rt_sigpending"    ,
    "sys_rt_sigtimedwait"  ,
    "sys_rt_sigqueueinfo"  ,
    "sys_rt_sigsuspend"    ,
    "sys_pread64"  ,
    "sys_pwrite64" ,
    "sys_chown"    ,
    "sys_getcwd"   ,
    "sys_capget"   ,
    "sys_capset"   ,
    "sys_sigaltstack"      ,
    "sys_sendfile" ,
    ""/* 188 reserved */    ,
    ""/* 189 reserved */    ,
    "sys_vfork"    ,
    "sys_ugetrlimit"       ,
    "sys_mmap2"    ,
    "sys_truncate64"       ,
    "sys_ftruncate64"      ,
    "sys_stat64"   ,
    "sys_lstat64"  ,
    "sys_fstat64"  ,
    "sys_lchown32" ,
    "sys_getuid32" ,
    "sys_getgid32" ,
    "sys_geteuid32"        ,
    "sys_getegid32"        ,
    "sys_setreuid32"       ,
    "sys_setregid32"       ,
    "sys_getgroups32"      ,
    "sys_setgroups32"      ,
    "sys_fchown32" ,
    "sys_setresuid32"      ,
    "sys_getresuid32"      ,
    "sys_setresgid32"      ,
    "sys_getresgid32"      ,
    "sys_chown32"  ,
    "sys_setuid32" ,
    "sys_setgid32" ,
    "sys_setfsuid32"       ,
    "sys_setfsgid32"       ,
    "sys_getdents64"       ,
    "sys_pivot_root"       ,
    "sys_mincore"  ,
    "sys_madvise"  ,
    "sys_fcntl64"  ,
    ""/* 222 for tux */     ,
    ""/* 223 is unused */   ,
    "sys_gettid"   ,
    "sys_readahead"        ,
    "sys_setxattr" ,
    "sys_lsetxattr"        ,
    "sys_fsetxattr"        ,
    "sys_getxattr" ,
    "sys_lgetxattr"        ,
    "sys_fgetxattr"        ,
    "sys_listxattr"        ,
    "sys_llistxattr"       ,
    "sys_flistxattr"       ,
    "sys_removexattr"      ,
    "sys_lremovexattr"     ,
    "sys_fremovexattr"     ,
    "sys_tkill"    ,
    "sys_sendfile64"       ,
    "sys_futex"    ,
    "sys_sched_setaffinity"        ,
    "sys_sched_getaffinity"        ,
    "sys_io_setup" ,
    "sys_io_destroy"       ,
    "sys_io_getevents"     ,
    "sys_io_submit"        ,
    "sys_io_cancel"        ,
    "sys_exit_group"       ,
    "sys_lookup_dcookie"   ,
    "sys_epoll_create"     ,
    "sys_epoll_ctl"        ,
    "sys_epoll_wait"       ,
    "sys_remap_file_pages" ,
    ""/* 254 for set_thread_area */ ,
    ""/* 255 for get_thread_area */ ,
    "sys_set_tid_address"  ,
    "sys_timer_create"     ,
    "sys_timer_settime"    ,
    "sys_timer_gettime"    ,
    "sys_timer_getoverrun" ,
    "sys_timer_delete"     ,
    "sys_clock_settime"    ,
    "sys_clock_gettime"    ,
    "sys_clock_getres"     ,
    "sys_clock_nanosleep"  ,
    "sys_statfs64" ,
    "sys_fstatfs64"        ,
    "sys_tgkill"   ,
    "sys_utimes"   ,
    "sys_arm_fadvise64_64" ,
    "sys_pciconfig_iobase" ,
    "sys_pciconfig_read"   ,
    "sys_pciconfig_write"  ,
    "sys_mq_open"  ,
    "sys_mq_unlink"        ,
    "sys_mq_timedsend"     ,
    "sys_mq_timedreceive"  ,
    "sys_mq_notify"        ,
    "sys_mq_getsetattr"    ,
    "sys_waitid"   ,
    "sys_socket"   ,
    "sys_bind"     ,
    "sys_connect"  ,
    "sys_listen"   ,
    "sys_accept"   ,
    "sys_getsockname"      ,
    "sys_getpeername"      ,
    "sys_socketpair"       ,
    "sys_send"     ,
    "sys_sendto"   ,
    "sys_recv"     ,
    "sys_recvfrom" ,
    "sys_shutdown" ,
    "sys_setsockopt"       ,
    "sys_getsockopt"       ,
    "sys_sendmsg"  ,
    "sys_recvmsg"  ,
    "sys_semop"    ,
    "sys_semget"   ,
    "sys_semctl"   ,
    "sys_msgsnd"   ,
    "sys_msgrcv"   ,
    "sys_msgget"   ,
    "sys_msgctl"   ,
    "sys_shmat"    ,
    "sys_shmdt"    ,
    "sys_shmget"   ,
    "sys_shmctl"   ,
    "sys_add_key"  ,
    "sys_request_key"      ,
    "sys_keyctl"   ,
    "sys_semtimedop"       ,
    "sys_vserver"  ,
    "sys_ioprio_set"       ,
    "sys_ioprio_get"       ,
    "sys_inotify_init"     ,
    "sys_inotify_add_watch"        ,
    "sys_inotify_rm_watch" ,
    "sys_mbind"    ,
    "sys_get_mempolicy"    ,
    "sys_set_mempolicy"    ,
    "sys_openat"   ,
    "sys_mkdirat"  ,
    "sys_mknodat"  ,
    "sys_fchownat" ,
    "sys_futimesat"        ,
    "sys_fstatat64"        ,
    "sys_unlinkat" ,
    "sys_renameat" ,
    "sys_linkat"   ,
    "sys_symlinkat"        ,
    "sys_readlinkat"       ,
    "sys_fchmodat" ,
    "sys_faccessat"        ,
    ""/* 335 for pselect6 */        ,
    ""/* 336 for ppoll */   ,
    "sys_unshare"  ,
    "sys_set_robust_list"  ,
    "sys_get_robust_list"  ,
    "sys_splice"   ,
    "sys_arm_sync_file_range"              ,
    "sys_tee"      ,
    "sys_vmsplice" ,
    "sys_move_pages"       ,
    "sys_getcpu"   ,
    ""/* 346 for epoll_pwait */     ,
    "sys_kexec_load"       ,
    "sys_utimensat"        ,
    "sys_signalfd" ,
    "sys_timerfd_create"   ,
    "sys_eventfd"  ,
    "sys_fallocate"        ,
    "sys_timerfd_settime"  ,
    "sys_timerfd_gettime"  ,
    "sys_signalfd4"        ,
    "sys_eventfd2" ,
    "sys_epoll_create1"    ,
    "sys_dup3"     ,
    "sys_pipe2"    ,
    "sys_inotify_init1"
};

static const char* syscallToString(int syscallnum)
{
  if ( (syscallnum < 0) || (syscallnum >= SYSCALLTABLE_LINUX_2_6_LEN) )
  {
    return (NULL);
  }

  return (sysCallTable[syscallnum]);
}

#endif//SYSCALLTABLE_LINUX_2_6_H
