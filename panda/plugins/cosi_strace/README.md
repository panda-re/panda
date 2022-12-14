# cosi strace

A plugin for using cosi to provide strace-like functionality or to pull information about the system's syscalls.

### Args

* `dump_prototypes` (optional) - a path to dump syscalls prototypes to, disabling syscall tracing

### Example

```py
from pandare import Panda

panda = Panda(generic="i386")
panda.load_plugin("cosi_strace")

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    panda.run_serial_cmd("ls")
    panda.end_analysis()

panda.run()
```

### Example Output


```
sys_rt_sigaction(sig=15, act={sa_flags=0x0, sa_handler=NULL, sa_mask=(unnamed_6ae8a4e8352b722a*)0xbf825094, sa_restorer=(pointer)0x5410}, oact=(sigaction*)0xbf825114, sigsetsize=0x8) = 0
sys_rt_sigaction(sig=17, act={sa_flags=0x10000000, sa_handler=NULL, sa_mask=(unnamed_6ae8a4e8352b722a*)0xbf825094, sa_restorer=(pointer)0x5410}, oact=(sigaction*)0xbf825114, sigsetsize=0x8) = 0
sys_ioctl(fd=0xff, cmd=0x540f, arg=0xbf82511c) = 0
sys_rt_sigprocmask(how=2, nset=(pointer)0xbf8251fc, oset=(pointer)0x0, sigsetsize=0x8) = 0
sys_rt_sigprocmask(how=0, nset=(pointer)0xbf82527c, oset=(pointer)0xbf8252fc, sigsetsize=0x8) = 0
sys_waitpid(pid=0xffffffff, stat_addr=0, options=10)
sys_execve(filename="/bin/ls", argv="ls", envp="XDG_SESSION_ID=1")
sys_brk(brk=0x0) = 136523776
sys_access(filename="/etc/ld.so.nohwcap", mode=0) = -2 (ENOENT)
sys_mmap_pgoff(addr=0x0, len=0x1000, prot=0x3, flags=0x22, fd=0xffffffff, pgoff=0x0) = -1217208320
sys_access(filename="/etc/ld.so.preload", mode=4) = -2 (ENOENT)
sys_open(filename="/etc/ld.so.cache", flags=524288, mode=0x0) = 3
sys_fstat64(fd=0x3, statbuf=(stat64*)0xbff68430) = 0
sys_mmap_pgoff(addr=0x0, len=0x50a9, prot=0x1, flags=0x2, fd=0x3, pgoff=0x0) = -1217232896
sys_close(fd=0x3) = 0
sys_access(filename="/etc/ld.so.nohwcap", mode=0) = -2 (ENOENT)
sys_open(filename="/lib/i386-linux-gnu/libselinux.so.1", flags=524288, mode=0x0) = 3
sys_read(fd=0x3, buf=(char*)0xbff68550, count=0x200) = 512
sys_fstat64(fd=0x3, statbuf=(stat64*)0xbff68470) = 0
sys_mmap_pgoff(addr=0x0, len=0x25bd4, prot=0x5, flags=0x802, fd=0x3, pgoff=0x0) = -1217388544
sys_mprotect(start=0xb7724000, len=0x1000, prot=0x0) = 0
sys_mmap_pgoff(addr=0xb7725000, len=0x2000, prot=0x3, flags=0x812, fd=0x3, pgoff=0x22) = -1217245184
sys_mmap_pgoff(addr=0xb7727000, len=0xbd4, prot=0x3, flags=0x32, fd=0xffffffff, pgoff=0x0) = -1217236992
sys_close(fd=0x3) = 0
```

### Syscall Prototype Dumping

cosi_strace features the ability to dump syscall prototypes to a file, useful for
generating syscall lists for strace. Enabling this functionality disables outputting
a syscall trace.

```py
panda.load_plugin("cosi_strace", { "dump_prototypes": "prototypes.txt" })
```

#### Output Sample

```c
0 long sys_restart_syscall(void);
1 long sys_exit(int error_code);
2 long sys_fork(void);
3 long sys_read(unsigned int fd, char __user *buf, size_t count);
4 long sys_write(unsigned int fd, const char __user *buf, size_t count);
5 long sys_open(const char __user *filename, int flags, umode_t mode);
6 long sys_close(unsigned int fd);
7 long sys_waitpid(pid_t pid, int __user *stat_addr, int options);
8 long sys_creat(const char __user *pathname, umode_t mode);
9 long sys_link(const char __user *oldname, const char __user *newname);
10 long sys_unlink(const char __user *pathname);
11 long sys_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
12 long sys_chdir(const char __user *filename);
```
