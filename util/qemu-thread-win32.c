/*
 * Win32 implementation for mutex/cond/thread functions
 *
 * Copyright Red Hat, Inc. 2010
 *
 * Author:
 *  Paolo Bonzini <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/thread.h"
#include "qemu/notify.h"
#include <process.h>

static bool name_threads;

void qemu_thread_naming(bool enable)
{
    /* But note we don't actually name them on Windows yet */
    name_threads = enable;

    fprintf(stderr, "qemu: thread naming not supported on this host\n");
}

static void error_exit(int err, const char *msg)
{
    char *pstr;

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                  NULL, err, 0, (LPTSTR)&pstr, 2, NULL);
    fprintf(stderr, "qemu: %s: %s\n", msg, pstr);
    LocalFree(pstr);
    abort();
}

void qemu_mutex_init(QemuMutex *mutex)
{
    InitializeSRWLock(&mutex->lock);
}

void qemu_mutex_destroy(QemuMutex *mutex)
{
    InitializeSRWLock(&mutex->lock);
}

void qemu_mutex_lock(QemuMutex *mutex)
{
    AcquireSRWLockExclusive(&mutex->lock);
}

int qemu_mutex_trylock(QemuMutex *mutex)
{
    int owned;

    owned = TryAcquireSRWLockExclusive(&mutex->lock);
    return !owned;
}

void qemu_mutex_unlock(QemuMutex *mutex)
{
    ReleaseSRWLockExclusive(&mutex->lock);
}

void qemu_rec_mutex_init(QemuRecMutex *mutex)
{
    InitializeCriticalSection(&mutex->lock);
}

void qemu_rec_mutex_destroy(QemuRecMutex *mutex)
{
    DeleteCriticalSection(&mutex->lock);
}

void qemu_rec_mutex_lock(QemuRecMutex *mutex)
{
    EnterCriticalSection(&mutex->lock);
}

int qemu_rec_mutex_trylock(QemuRecMutex *mutex)
{
    return !TryEnterCriticalSection(&mutex->lock);
}

void qemu_rec_mutex_unlock(QemuRecMutex *mutex)
{
    LeaveCriticalSection(&mutex->lock);
}

void qemu_cond_init(QemuCond *cond)
{
    memset(cond, 0, sizeof(*cond));
    InitializeConditionVariable(&cond->var);
}

void qemu_cond_destroy(QemuCond *cond)
{
    InitializeConditionVariable(&cond->var);
}

void qemu_cond_signal(QemuCond *cond)
{
    WakeConditionVariable(&cond->var);
}

void qemu_cond_broadcast(QemuCond *cond)
{
    WakeAllConditionVariable(&cond->var);
}

void qemu_cond_wait(QemuCond *cond, QemuMutex *mutex)
{
    SleepConditionVariableSRW(&cond->var, &mutex->lock, INFINITE, 0);
}

void qemu_sem_init(QemuSemaphore *sem, int init)
{
    /* Manual reset.  */
    sem->sema = CreateSemaphore(NULL, init, LONG_MAX, NULL);
}

void qemu_sem_destroy(QemuSemaphore *sem)
{
    CloseHandle(sem->sema);
}

void qemu_sem_post(QemuSemaphore *sem)
{
    ReleaseSemaphore(sem->sema, 1, NULL);
}

int qemu_sem_timedwait(QemuSemaphore *sem, int ms)
{
    int rc = WaitForSingleObject(sem->sema, ms);
    if (rc == WAIT_OBJECT_0) {
        return 0;
    }
    if (rc != WAIT_TIMEOUT) {
        error_exit(GetLastError(), __func__);
    }
    return -1;
}

void qemu_sem_wait(QemuSemaphore *sem)
{
    if (WaitForSingleObject(sem->sema, INFINITE) != WAIT_OBJECT_0) {
        error_exit(GetLastError(), __func__);
    }
}

/* Wrap a Win32 manual-reset event with a fast userspace path.  The idea
 * is to reset the Win32 event lazily, as part of a test-reset-test-wait
 * sequence.  Such a sequence is, indeed, how QemuEvents are used by
 * RCU and other subsystems!
 *
 * Valid transitions:
 * - free->set, when setting the event
 * - busy->set, when setting the event, followed by SetEvent
 * - set->free, when resetting the event
 * - free->busy, when waiting
 *
 * set->busy does not happen (it can be observed from the outside but
 * it really is set->free->busy).
 *
 * busy->free provably cannot happen; to enforce it, the set->free transition
 * is done with an OR, which becomes a no-op if the event has concurrently
 * transitioned to free or busy (and is faster than cmpxchg).
 */

#define EV_SET         0
#define EV_FREE        1
#define EV_BUSY       -1

void qemu_event_init(QemuEvent *ev, bool init)
{
    /* Manual reset.  */
    ev->event = CreateEvent(NULL, TRUE, TRUE, NULL);
    ev->value = (init ? EV_SET : EV_FREE);
}

void qemu_event_destroy(QemuEvent *ev)
{
    CloseHandle(ev->event);
}

void qemu_event_set(QemuEvent *ev)
{
    /* qemu_event_set has release semantics, but because it *loads*
     * ev->value we need a full memory barrier here.
     */
    smp_mb();
    if (atomic_read(&ev->value) != EV_SET) {
        if (atomic_xchg(&ev->value, EV_SET) == EV_BUSY) {
            /* There were waiters, wake them up.  */
            SetEvent(ev->event);
        }
    }
}

void qemu_event_reset(QemuEvent *ev)
{
    unsigned value;

    value = atomic_read(&ev->value);
    smp_mb_acquire();
    if (value == EV_SET) {
        /* If there was a concurrent reset (or even reset+wait),
         * do nothing.  Otherwise change EV_SET->EV_FREE.
         */
        atomic_or(&ev->value, EV_FREE);
    }
}

void qemu_event_wait(QemuEvent *ev)
{
    unsigned value;

    value = atomic_read(&ev->value);
    smp_mb_acquire();
    if (value != EV_SET) {
        if (value == EV_FREE) {
            /* qemu_event_set is not yet going to call SetEvent, but we are
             * going to do another check for EV_SET below when setting EV_BUSY.
             * At that point it is safe to call WaitForSingleObject.
             */
            ResetEvent(ev->event);

            /* Tell qemu_event_set that there are waiters.  No need to retry
             * because there cannot be a concurent busy->free transition.
             * After the CAS, the event will be either set or busy.
             */
            if (atomic_cmpxchg(&ev->value, EV_FREE, EV_BUSY) == EV_SET) {
                value = EV_SET;
            } else {
                value = EV_BUSY;
            }
        }
        if (value == EV_BUSY) {
            WaitForSingleObject(ev->event, INFINITE);
        }
    }
}

struct QemuThreadData {
    /* Passed to win32_start_routine.  */
    void             *(*start_routine)(void *);
    void             *arg;
    short             mode;
    NotifierList      exit;

    /* Only used for joinable threads. */
    bool              exited;
    void             *ret;
    CRITICAL_SECTION  cs;
};

static bool atexit_registered;
static NotifierList main_thread_exit;

static __thread QemuThreadData *qemu_thread_data;

static void run_main_thread_exit(void)
{
    notifier_list_notify(&main_thread_exit, NULL);
}

void qemu_thread_atexit_add(Notifier *notifier)
{
    if (!qemu_thread_data) {
        if (!atexit_registered) {
            atexit_registered = true;
            atexit(run_main_thread_exit);
        }
        notifier_list_add(&main_thread_exit, notifier);
    } else {
        notifier_list_add(&qemu_thread_data->exit, notifier);
    }
}

void qemu_thread_atexit_remove(Notifier *notifier)
{
    notifier_remove(notifier);
}

static unsigned __stdcall win32_start_routine(void *arg)
{
    QemuThreadData *data = (QemuThreadData *) arg;
    void *(*start_routine)(void *) = data->start_routine;
    void *thread_arg = data->arg;

    qemu_thread_data = data;
    qemu_thread_exit(start_routine(thread_arg));
    abort();
}

void qemu_thread_exit(void *arg)
{
    QemuThreadData *data = qemu_thread_data;

    notifier_list_notify(&data->exit, NULL);
    if (data->mode == QEMU_THREAD_JOINABLE) {
        data->ret = arg;
        EnterCriticalSection(&data->cs);
        data->exited = true;
        LeaveCriticalSection(&data->cs);
    } else {
        g_free(data);
    }
    _endthreadex(0);
}

void *qemu_thread_join(QemuThread *thread)
{
    QemuThreadData *data;
    void *ret;
    HANDLE handle;

    data = thread->data;
    if (data->mode == QEMU_THREAD_DETACHED) {
        return NULL;
    }

    /*
     * Because multiple copies of the QemuThread can exist via
     * qemu_thread_get_self, we need to store a value that cannot
     * leak there.  The simplest, non racy way is to store the TID,
     * discard the handle that _beginthreadex gives back, and
     * get another copy of the handle here.
     */
    handle = qemu_thread_get_handle(thread);
    if (handle) {
        WaitForSingleObject(handle, INFINITE);
        CloseHandle(handle);
    }
    ret = data->ret;
    DeleteCriticalSection(&data->cs);
    g_free(data);
    return ret;
}

void qemu_thread_create(QemuThread *thread, const char *name,
                       void *(*start_routine)(void *),
                       void *arg, int mode)
{
    HANDLE hThread;
    struct QemuThreadData *data;

    data = g_malloc(sizeof *data);
    data->start_routine = start_routine;
    data->arg = arg;
    data->mode = mode;
    data->exited = false;
    notifier_list_init(&data->exit);

    if (data->mode != QEMU_THREAD_DETACHED) {
        InitializeCriticalSection(&data->cs);
    }

    hThread = (HANDLE) _beginthreadex(NULL, 0, win32_start_routine,
                                      data, 0, &thread->tid);
    if (!hThread) {
        error_exit(GetLastError(), __func__);
    }
    CloseHandle(hThread);
    thread->data = data;
}

void qemu_thread_get_self(QemuThread *thread)
{
    thread->data = qemu_thread_data;
    thread->tid = GetCurrentThreadId();
}

HANDLE qemu_thread_get_handle(QemuThread *thread)
{
    QemuThreadData *data;
    HANDLE handle;

    data = thread->data;
    if (data->mode == QEMU_THREAD_DETACHED) {
        return NULL;
    }

    EnterCriticalSection(&data->cs);
    if (!data->exited) {
        handle = OpenThread(SYNCHRONIZE | THREAD_SUSPEND_RESUME |
                            THREAD_SET_CONTEXT, FALSE, thread->tid);
    } else {
        handle = NULL;
    }
    LeaveCriticalSection(&data->cs);
    return handle;
}

bool qemu_thread_is_self(QemuThread *thread)
{
    return GetCurrentThreadId() == thread->tid;
}
