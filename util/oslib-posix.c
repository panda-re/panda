/*
 * os-posix-lib.c
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2010 Red Hat, Inc.
 *
 * QEMU library functions on POSIX which are shared between QEMU and
 * the QEMU tools.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include <termios.h>

#include <glib/gprintf.h>

#include "sysemu/sysemu.h"
#include "trace.h"
#include "qapi/error.h"
#include "qemu/sockets.h"
#include <libgen.h>
#include <sys/signal.h>
#include "qemu/cutils.h"

#ifdef CONFIG_LINUX
#include <sys/syscall.h>
#endif

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libutil.h>
#endif

#include "qemu/mmap-alloc.h"

#ifdef CONFIG_DEBUG_STACK_USAGE
#include "qemu/error-report.h"
#endif

#define MAX_MEM_PREALLOC_THREAD_COUNT 16

struct MemsetThread {
    char *addr;
    uint64_t numpages;
    uint64_t hpagesize;
    QemuThread pgthread;
    sigjmp_buf env;
};
typedef struct MemsetThread MemsetThread;

static MemsetThread *memset_thread;
static int memset_num_threads;
static bool memset_thread_failed;

int qemu_get_thread_id(void)
{
#if defined(__linux__)
    return syscall(SYS_gettid);
#else
    return getpid();
#endif
}

int qemu_daemon(int nochdir, int noclose)
{
    return daemon(nochdir, noclose);
}

void *qemu_oom_check(void *ptr)
{
    if (ptr == NULL) {
        fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
        abort();
    }
    return ptr;
}

void *qemu_try_memalign(size_t alignment, size_t size)
{
    void *ptr;

    if (alignment < sizeof(void*)) {
        alignment = sizeof(void*);
    }

#if defined(_POSIX_C_SOURCE) && !defined(__sun__)
    int ret;
    ret = posix_memalign(&ptr, alignment, size);
    if (ret != 0) {
        errno = ret;
        ptr = NULL;
    }
#elif defined(CONFIG_BSD)
    ptr = valloc(size);
#else
    ptr = memalign(alignment, size);
#endif
    trace_qemu_memalign(alignment, size, ptr);
    return ptr;
}

void *qemu_memalign(size_t alignment, size_t size)
{
    return qemu_oom_check(qemu_try_memalign(alignment, size));
}

/* alloc shared memory pages */
void *qemu_anon_ram_alloc(size_t size, uint64_t *alignment)
{
    size_t align = QEMU_VMALLOC_ALIGN;
    void *ptr = qemu_ram_mmap(-1, size, align, false);

    if (ptr == MAP_FAILED) {
        return NULL;
    }

    if (alignment) {
        *alignment = align;
    }

    trace_qemu_anon_ram_alloc(size, ptr);
    return ptr;
}

void qemu_vfree(void *ptr)
{
    trace_qemu_vfree(ptr);
    free(ptr);
}

void qemu_anon_ram_free(void *ptr, size_t size)
{
    trace_qemu_anon_ram_free(ptr, size);
    qemu_ram_munmap(ptr, size);
}

void qemu_set_block(int fd)
{
    int f;
    f = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, f & ~O_NONBLOCK);
}

void qemu_set_nonblock(int fd)
{
    int f;
    f = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

int socket_set_fast_reuse(int fd)
{
    int val = 1, ret;

    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                     (const char *)&val, sizeof(val));

    assert(ret == 0);

    return ret;
}

void qemu_set_cloexec(int fd)
{
    int f;
    f = fcntl(fd, F_GETFD);
    fcntl(fd, F_SETFD, f | FD_CLOEXEC);
}

/*
 * Creates a pipe with FD_CLOEXEC set on both file descriptors
 */
int qemu_pipe(int pipefd[2])
{
    int ret;

#ifdef CONFIG_PIPE2
    ret = pipe2(pipefd, O_CLOEXEC);
    if (ret != -1 || errno != ENOSYS) {
        return ret;
    }
#endif
    ret = pipe(pipefd);
    if (ret == 0) {
        qemu_set_cloexec(pipefd[0]);
        qemu_set_cloexec(pipefd[1]);
    }

    return ret;
}

int qemu_utimens(const char *path, const struct timespec *times)
{
    struct timeval tv[2], tv_now;
    struct stat st;
    int i;
#ifdef CONFIG_UTIMENSAT
    int ret;

    ret = utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW);
    if (ret != -1 || errno != ENOSYS) {
        return ret;
    }
#endif
    /* Fallback: use utimes() instead of utimensat() */

    /* happy if special cases */
    if (times[0].tv_nsec == UTIME_OMIT && times[1].tv_nsec == UTIME_OMIT) {
        return 0;
    }
    if (times[0].tv_nsec == UTIME_NOW && times[1].tv_nsec == UTIME_NOW) {
        return utimes(path, NULL);
    }

    /* prepare for hard cases */
    if (times[0].tv_nsec == UTIME_NOW || times[1].tv_nsec == UTIME_NOW) {
        gettimeofday(&tv_now, NULL);
    }
    if (times[0].tv_nsec == UTIME_OMIT || times[1].tv_nsec == UTIME_OMIT) {
        stat(path, &st);
    }

    for (i = 0; i < 2; i++) {
        if (times[i].tv_nsec == UTIME_NOW) {
            tv[i].tv_sec = tv_now.tv_sec;
            tv[i].tv_usec = tv_now.tv_usec;
        } else if (times[i].tv_nsec == UTIME_OMIT) {
            tv[i].tv_sec = (i == 0) ? st.st_atime : st.st_mtime;
            tv[i].tv_usec = 0;
        } else {
            tv[i].tv_sec = times[i].tv_sec;
            tv[i].tv_usec = times[i].tv_nsec / 1000;
        }
    }

    return utimes(path, &tv[0]);
}

char *
qemu_get_local_state_pathname(const char *relative_pathname)
{
    return g_strdup_printf("%s/%s", CONFIG_QEMU_LOCALSTATEDIR,
                           relative_pathname);
}

void qemu_set_tty_echo(int fd, bool echo)
{
    struct termios tty;

    tcgetattr(fd, &tty);

    if (echo) {
        tty.c_lflag |= ECHO | ECHONL | ICANON | IEXTEN;
    } else {
        tty.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN);
    }

    tcsetattr(fd, TCSANOW, &tty);
}

static char exec_dir[PATH_MAX];

void qemu_init_exec_dir(const char *argv0)
{
    char *dir;
    char *p = NULL;
    char buf[PATH_MAX];

    assert(!exec_dir[0]);

#if defined(__linux__)
    {
        int len;
        len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = 0;
            p = buf;
        }
    }
#elif defined(__FreeBSD__)
    {
        static int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
        size_t len = sizeof(buf) - 1;

        *buf = '\0';
        if (!sysctl(mib, ARRAY_SIZE(mib), buf, &len, NULL, 0) &&
            *buf) {
            buf[sizeof(buf) - 1] = '\0';
            p = buf;
        }
    }
#endif
    /* If we don't have any way of figuring out the actual executable
       location then try argv[0].  */
    if (!p) {
        if (!argv0) {
            return;
        }
        p = realpath(argv0, buf);
        if (!p) {
            return;
        }
    }
    dir = g_path_get_dirname(p);

    pstrcpy(exec_dir, sizeof(exec_dir), dir);

    g_free(dir);
}

char *qemu_get_exec_dir(void)
{
    return g_strdup(exec_dir);
}

static void sigbus_handler(int signal)
{
    int i;
    if (memset_thread) {
        for (i = 0; i < memset_num_threads; i++) {
            if (qemu_thread_is_self(&memset_thread[i].pgthread)) {
                siglongjmp(memset_thread[i].env, 1);
            }
        }
    }
}

static void *do_touch_pages(void *arg)
{
    MemsetThread *memset_args = (MemsetThread *)arg;
    char *addr = memset_args->addr;
    uint64_t numpages = memset_args->numpages;
    uint64_t hpagesize = memset_args->hpagesize;
    sigset_t set, oldset;
    int i = 0;

    /* unblock SIGBUS */
    sigemptyset(&set);
    sigaddset(&set, SIGBUS);
    pthread_sigmask(SIG_UNBLOCK, &set, &oldset);

    if (sigsetjmp(memset_args->env, 1)) {
        memset_thread_failed = true;
    } else {
        for (i = 0; i < numpages; i++) {
            /*
             * Read & write back the same value, so we don't
             * corrupt existing user/app data that might be
             * stored.
             *
             * 'volatile' to stop compiler optimizing this away
             * to a no-op
             *
             * TODO: get a better solution from kernel so we
             * don't need to write at all so we don't cause
             * wear on the storage backing the region...
             */
            *(volatile char *)addr = *addr;
            addr += hpagesize;
        }
    }
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    return NULL;
}

static inline int get_memset_num_threads(int smp_cpus)
{
    long host_procs = sysconf(_SC_NPROCESSORS_ONLN);
    int ret = 1;

    if (host_procs > 0) {
        ret = MIN(MIN(host_procs, MAX_MEM_PREALLOC_THREAD_COUNT), smp_cpus);
    }
    /* In case sysconf() fails, we fall back to single threaded */
    return ret;
}

static bool touch_all_pages(char *area, size_t hpagesize, size_t numpages,
                            int smp_cpus)
{
    uint64_t numpages_per_thread, size_per_thread;
    char *addr = area;
    int i = 0;

    memset_thread_failed = false;
    memset_num_threads = get_memset_num_threads(smp_cpus);
    memset_thread = g_new0(MemsetThread, memset_num_threads);
    numpages_per_thread = (numpages / memset_num_threads);
    size_per_thread = (hpagesize * numpages_per_thread);
    for (i = 0; i < memset_num_threads; i++) {
        memset_thread[i].addr = addr;
        memset_thread[i].numpages = (i == (memset_num_threads - 1)) ?
                                    numpages : numpages_per_thread;
        memset_thread[i].hpagesize = hpagesize;
        qemu_thread_create(&memset_thread[i].pgthread, "touch_pages",
                           do_touch_pages, &memset_thread[i],
                           QEMU_THREAD_JOINABLE);
        addr += size_per_thread;
        numpages -= numpages_per_thread;
    }
    for (i = 0; i < memset_num_threads; i++) {
        qemu_thread_join(&memset_thread[i].pgthread);
    }
    g_free(memset_thread);
    memset_thread = NULL;

    return memset_thread_failed;
}

void os_mem_prealloc(int fd, char *area, size_t memory, int smp_cpus,
                     Error **errp)
{
    int ret;
    struct sigaction act, oldact;
    size_t hpagesize = qemu_fd_getpagesize(fd);
    size_t numpages = DIV_ROUND_UP(memory, hpagesize);

    memset(&act, 0, sizeof(act));
    act.sa_handler = &sigbus_handler;
    act.sa_flags = 0;

    ret = sigaction(SIGBUS, &act, &oldact);
    if (ret) {
        error_setg_errno(errp, errno,
            "os_mem_prealloc: failed to install signal handler");
        return;
    }

    /* touch pages simultaneously */
    if (touch_all_pages(area, hpagesize, numpages, smp_cpus)) {
        error_setg(errp, "os_mem_prealloc: Insufficient free host memory "
            "pages available to allocate guest RAM\n");
    }

    ret = sigaction(SIGBUS, &oldact, NULL);
    if (ret) {
        /* Terminate QEMU since it can't recover from error */
        perror("os_mem_prealloc: failed to reinstall signal handler");
        exit(1);
    }
}


static struct termios oldtty;

static void term_exit(void)
{
    tcsetattr(0, TCSANOW, &oldtty);
}

static void term_init(void)
{
    struct termios tty;

    tcgetattr(0, &tty);
    oldtty = tty;

    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
                          |INLCR|IGNCR|ICRNL|IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
    tty.c_cflag &= ~(CSIZE|PARENB);
    tty.c_cflag |= CS8;
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;

    tcsetattr(0, TCSANOW, &tty);

    atexit(term_exit);
}

int qemu_read_password(char *buf, int buf_size)
{
    uint8_t ch;
    int i, ret;

    printf("password: ");
    fflush(stdout);
    term_init();
    i = 0;
    for (;;) {
        ret = read(0, &ch, 1);
        if (ret == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            } else {
                break;
            }
        } else if (ret == 0) {
            ret = -1;
            break;
        } else {
            if (ch == '\r' ||
                ch == '\n') {
                ret = 0;
                break;
            }
            if (i < (buf_size - 1)) {
                buf[i++] = ch;
            }
        }
    }
    term_exit();
    buf[i] = '\0';
    printf("\n");
    return ret;
}


char *qemu_get_pid_name(pid_t pid)
{
    char *name = NULL;

#if defined(__FreeBSD__)
    /* BSDs don't have /proc, but they provide a nice substitute */
    struct kinfo_proc *proc = kinfo_getproc(pid);

    if (proc) {
        name = g_strdup(proc->ki_comm);
        free(proc);
    }
#else
    /* Assume a system with reasonable procfs */
    char *pid_path;
    size_t len;

    pid_path = g_strdup_printf("/proc/%d/cmdline", pid);
    g_file_get_contents(pid_path, &name, &len, NULL);
    g_free(pid_path);
#endif

    return name;
}


pid_t qemu_fork(Error **errp)
{
    sigset_t oldmask, newmask;
    struct sigaction sig_action;
    int saved_errno;
    pid_t pid;

    /*
     * Need to block signals now, so that child process can safely
     * kill off caller's signal handlers without a race.
     */
    sigfillset(&newmask);
    if (pthread_sigmask(SIG_SETMASK, &newmask, &oldmask) != 0) {
        error_setg_errno(errp, errno,
                         "cannot block signals");
        return -1;
    }

    pid = fork();
    saved_errno = errno;

    if (pid < 0) {
        /* attempt to restore signal mask, but ignore failure, to
         * avoid obscuring the fork failure */
        (void)pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
        error_setg_errno(errp, saved_errno,
                         "cannot fork child process");
        errno = saved_errno;
        return -1;
    } else if (pid) {
        /* parent process */

        /* Restore our original signal mask now that the child is
         * safely running. Only documented failures are EFAULT (not
         * possible, since we are using just-grabbed mask) or EINVAL
         * (not possible, since we are using correct arguments).  */
        (void)pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
    } else {
        /* child process */
        size_t i;

        /* Clear out all signal handlers from parent so nothing
         * unexpected can happen in our child once we unblock
         * signals */
        sig_action.sa_handler = SIG_DFL;
        sig_action.sa_flags = 0;
        sigemptyset(&sig_action.sa_mask);

        for (i = 1; i < NSIG; i++) {
            /* Only possible errors are EFAULT or EINVAL The former
             * won't happen, the latter we expect, so no need to check
             * return value */
            (void)sigaction(i, &sig_action, NULL);
        }

        /* Unmask all signals in child, since we've no idea what the
         * caller's done with their signal mask and don't want to
         * propagate that to children */
        sigemptyset(&newmask);
        if (pthread_sigmask(SIG_SETMASK, &newmask, NULL) != 0) {
            Error *local_err = NULL;
            error_setg_errno(&local_err, errno,
                             "cannot unblock signals");
            error_report_err(local_err);
            _exit(1);
        }
    }
    return pid;
}

void *qemu_alloc_stack(size_t *sz)
{
    void *ptr, *guardpage;
#ifdef CONFIG_DEBUG_STACK_USAGE
    void *ptr2;
#endif
    size_t pagesz = getpagesize();
#ifdef _SC_THREAD_STACK_MIN
    /* avoid stacks smaller than _SC_THREAD_STACK_MIN */
    long min_stack_sz = sysconf(_SC_THREAD_STACK_MIN);
    *sz = MAX(MAX(min_stack_sz, 0), *sz);
#endif
    /* adjust stack size to a multiple of the page size */
    *sz = ROUND_UP(*sz, pagesz);
    /* allocate one extra page for the guard page */
    *sz += pagesz;

    ptr = mmap(NULL, *sz, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        abort();
    }

#if defined(HOST_IA64)
    /* separate register stack */
    guardpage = ptr + (((*sz - pagesz) / 2) & ~pagesz);
#elif defined(HOST_HPPA)
    /* stack grows up */
    guardpage = ptr + *sz - pagesz;
#else
    /* stack grows down */
    guardpage = ptr;
#endif
    if (mprotect(guardpage, pagesz, PROT_NONE) != 0) {
        abort();
    }

#ifdef CONFIG_DEBUG_STACK_USAGE
    for (ptr2 = ptr + pagesz; ptr2 < ptr + *sz; ptr2 += sizeof(uint32_t)) {
        *(uint32_t *)ptr2 = 0xdeadbeaf;
    }
#endif

    return ptr;
}

#ifdef CONFIG_DEBUG_STACK_USAGE
static __thread unsigned int max_stack_usage;
#endif

void qemu_free_stack(void *stack, size_t sz)
{
#ifdef CONFIG_DEBUG_STACK_USAGE
    unsigned int usage;
    void *ptr;

    for (ptr = stack + getpagesize(); ptr < stack + sz;
         ptr += sizeof(uint32_t)) {
        if (*(uint32_t *)ptr != 0xdeadbeaf) {
            break;
        }
    }
    usage = sz - (uintptr_t) (ptr - stack);
    if (usage > max_stack_usage) {
        error_report("thread %d max stack usage increased from %u to %u",
                     qemu_get_thread_id(), max_stack_usage, usage);
        max_stack_usage = usage;
    }
#endif

    munmap(stack, sz);
}

void sigaction_invoke(struct sigaction *action,
                      struct qemu_signalfd_siginfo *info)
{
    siginfo_t si = { 0 };
    si.si_signo = info->ssi_signo;
    si.si_errno = info->ssi_errno;
    si.si_code = info->ssi_code;

    /* Convert the minimal set of fields defined by POSIX.
     * Positive si_code values are reserved for kernel-generated
     * signals, where the valid siginfo fields are determined by
     * the signal number.  But according to POSIX, it is unspecified
     * whether SI_USER and SI_QUEUE have values less than or equal to
     * zero.
     */
    if (info->ssi_code == SI_USER || info->ssi_code == SI_QUEUE ||
        info->ssi_code <= 0) {
        /* SIGTERM, etc.  */
        si.si_pid = info->ssi_pid;
        si.si_uid = info->ssi_uid;
    } else if (info->ssi_signo == SIGILL || info->ssi_signo == SIGFPE ||
               info->ssi_signo == SIGSEGV || info->ssi_signo == SIGBUS) {
        si.si_addr = (void *)(uintptr_t)info->ssi_addr;
    } else if (info->ssi_signo == SIGCHLD) {
        si.si_pid = info->ssi_pid;
        si.si_status = info->ssi_status;
        si.si_uid = info->ssi_uid;
    }
    action->sa_sigaction(info->ssi_signo, &si, NULL);
}
