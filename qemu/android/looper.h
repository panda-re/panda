/* Copyright (C) 2010 The Android Open Source Project
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/
#ifndef ANDROID_LOOPER_H
#define ANDROID_LOOPER_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <android/utils/system.h>

/**********************************************************************
 **********************************************************************
 *****
 *****  T I M E   R E P R E S E N T A T I O N
 *****
 **********************************************************************
 **********************************************************************/

/* An Duration represents a duration in milliseconds */
typedef int64_t   Duration;

/* A special Duration value used to mean "infinite" */
#define  DURATION_INFINITE       ((Duration)INT64_MAX)

/**********************************************************************
 **********************************************************************
 *****
 *****  E V E N T   L O O P   O B J E C T S
 *****
 **********************************************************************
 **********************************************************************/


/* A Looper is an abstraction for an event loop, which can
 * be implemented in different ways. For example, the UI program may
 * want to implement a custom event loop on top of the SDL event queue,
 * while the QEMU core would implement it on top of QEMU's internal
 * main loop which works differently.
 *
 * Once you have a Looper pointer, you can register "watchers" that
 * will trigger callbacks whenever certain events occur. Supported event
 * types are:
 *
 *   - timer expiration
 *   - i/o file descriptor input/output
 *
 * See the relevant documentation for these below.
 *
 * Once you have registered one or more watchers, you can call looper_run()
 * which will run the event loop until looper_forceQuit() is called from a
 * callback, or no more watchers are registered.
 *
 * You can register/unregister watchers from a callback, or call various
 * Looper methods from them (e.g. looper_now(), looper_forceQuit(), etc..)
 *
 * You can create a new Looper by calling looper_newGeneric(). This provides
 * a default implementation that can be used in all threads.
 *
 * For the QEMU core, you can grab a Looper pointer by calling
 * looper_newCore() instead. Its implementation relies on top of
 * the QEMU event loop instead.
 */
typedef struct Looper    Looper;

/* Create a new generic looper that can be used in any context / thread. */
Looper*  looper_newGeneric(void);

/* Create a new looper which is implemented on top of the QEMU main event
 * loop. You should only use this when implementing the emulator UI and Core
 * features in a single program executable.
 */
Looper*  looper_newCore(void);


typedef struct LoopTimer LoopTimer;
typedef void (*LoopTimerFunc)(void* opaque);

typedef struct LoopIo    LoopIo;
typedef void (*LoopIoFunc)(void* opaque, int fd, unsigned events);

struct Looper {
    Duration (*now)   (Looper* looper);
    void (*timer_init)(Looper* looper, LoopTimer* timer, LoopTimerFunc callback, void* opaque);
    void (*io_init)   (Looper* looper, LoopIo* io, int fd, LoopIoFunc callback, void* opaque);
    int  (*run)       (Looper* looper, Duration deadline_ms);
    void (*forceQuit) (Looper* looper);
    void (*destroy)   (Looper* looper);
};



/**********************************************************************
 **********************************************************************
 *****
 *****  T I M E R S
 *****
 **********************************************************************
 **********************************************************************/


typedef struct LoopTimerClass  LoopTimerClass;

struct LoopTimer {
    LoopTimerClass*  clazz;
    void*            impl;
};

struct LoopTimerClass {
    void (*startRelative)(void* impl, Duration timeout_ms);
    void (*startAbsolute)(void* impl, Duration deadline_ms);
    void (*stop)         (void* impl);
    int  (*isActive)     (void* impl);
    void (*done)         (void* impl);
};

/* Initialize a LoopTimer with a callback and an 'opaque' value.
 * Each timer belongs to only one looper object.
 */
AINLINED void
loopTimer_init(LoopTimer*     timer,
               Looper*        looper,
               LoopTimerFunc  callback,
               void*          opaque)
{
    looper->timer_init(looper, timer, callback, opaque);
}

/* Finalize a LoopTimer */
AINLINED void
loopTimer_done(LoopTimer* timer)
{
    timer->clazz->done(timer->impl);
    timer->clazz = NULL;
    timer->impl  = NULL;
}

/* Start a timer, i.e. arm it to expire in 'timeout_ms' milliseconds,
 * unless loopTimer_stop() is called before that, or the timer is
 * reprogrammed with another loopTimer_startXXX() call.
 */
AINLINED void
loopTimer_startRelative(LoopTimer* timer, Duration timeout_ms)
{
    timer->clazz->startRelative(timer->impl, timeout_ms);
}

/* A variant of loopTimer_startRelative that fires on a given deadline
 * in milliseconds instead. If the deadline already passed, the timer is
 * automatically appended to the list of pending event watchers and will
 * fire as soon as possible. Note that this can cause infinite loops
 * in your code if you're not careful.
 */
AINLINED void
loopTimer_startAbsolute(LoopTimer* timer, Duration deadline_ms)
{
    timer->clazz->startAbsolute(timer->impl, deadline_ms);
}

/* Stop a given timer */
AINLINED void
loopTimer_stop(LoopTimer* timer)
{
    timer->clazz->stop(timer->impl);
}

/* Returns true iff the timer is active / started */
AINLINED int
loopTimer_isActive(LoopTimer* timer)
{
    return timer->clazz->isActive(timer->impl);
}

/**********************************************************************
 **********************************************************************
 *****
 *****  F I L E   D E S C R I P T O R S
 *****
 **********************************************************************
 **********************************************************************/

typedef struct LoopIoClass  LoopIoClass;

struct LoopIo {
    LoopIoClass*  clazz;
    void*         impl;
    int           fd;
};

/* Bitmasks about i/o events. Note that errors (e.g. network disconnections)
 * are mapped to both read and write events. The idea is that a read() or
 * write() will return 0 or even -1 on non-blocking file descriptors in this
 * case.
 *
 * You can receive several events at the same time on a single LoopIo
 *
 * Socket connect()s are mapped to LOOP_IO_WRITE events.
 * Socket accept()s are mapped to LOOP_IO_READ events.
 */
enum {
    LOOP_IO_READ  = (1 << 0),
    LOOP_IO_WRITE = (1 << 1),
};

struct LoopIoClass {
    void (*wantRead)(void* impl);
    void (*wantWrite)(void* impl);
    void (*dontWantRead)(void* impl);
    void (*dontWantWrite)(void* impl);
    unsigned (*poll)(void* impl);
    void (*done)(void* impl);
};

AINLINED void
loopIo_init(LoopIo* io, Looper* looper, int fd, LoopIoFunc callback, void* opaque)
{
    looper->io_init(looper, io, fd, callback, opaque);
    io->fd = fd;
}

/* Note: This does not close the file descriptor! */
AINLINED void
loopIo_done(LoopIo* io)
{
    io->clazz->done(io->impl);
}

/* The following functions are used to indicate whether you want the callback
 * to be fired when there is data to be read or when the file is ready to
 * be written to. */
AINLINED void
loopIo_wantRead(LoopIo* io)
{
    io->clazz->wantRead(io->impl);
}
AINLINED void
loopIo_wantWrite(LoopIo* io)
{
    io->clazz->wantWrite(io->impl);
}
AINLINED void
loopIo_dontWantRead(LoopIo* io)
{
    io->clazz->dontWantRead(io->impl);
}
AINLINED void
loopIo_dontWantWrite(LoopIo* io)
{
    io->clazz->dontWantWrite(io->impl);
}
AINLINED unsigned
loopIo_poll(LoopIo* io)
{
    return io->clazz->poll(io->impl);
}

/**********************************************************************
 **********************************************************************
 *****
 *****  L O O P E R
 *****
 **********************************************************************
 **********************************************************************/

AINLINED Duration
looper_now(Looper* looper)
{
    return looper->now(looper);
}
/* Run the event loop, until looper_forceQuit() is called, or there is no
 * more registered watchers for events/timers in the looper.
 *
 * The value returned indicates the reason:
 *    0           -> normal exit through looper_forceQuit()
 *    EWOULDBLOCK -> there are not more watchers registered (the looper
 *                   would loop infinitely)
 */
AINLINED void
looper_run(Looper* looper)
{
    (void) looper->run(looper, DURATION_INFINITE);
}

/* A variant of looper_run() that allows to run the event loop only
 * until a certain timeout in milliseconds has passed.
 *
 * Returns the reason why the looper stopped:
 *    0           -> normal exit through looper_forceQuit()
 *    EWOULDBLOCK -> there are not more watchers registered (the looper
 *                   would loop infinitely)
 *    ETIMEDOUT   -> timeout reached
 *
 */
AINLINED int
looper_runWithTimeout(Looper* looper, Duration timeout_ms)
{
    if (timeout_ms != DURATION_INFINITE)
        timeout_ms += looper_now(looper);

    return looper->run(looper, timeout_ms);
}

/* Another variant of looper_run() that takes a deadline instead of a
 * timeout. Same return values than looper_runWithTimeout()
 */
AINLINED int
looper_runWithDeadline(Looper* looper, Duration deadline_ms)
{
    return looper->run(looper, deadline_ms);
}

/* Call this function from within the event loop to force it to quit
 * as soon as possible. looper_run() / _runWithTimeout() / _runWithDeadline()
 * will then return 0.
 */
AINLINED void
looper_forceQuit(Looper* looper)
{
    looper->forceQuit(looper);
}

/* Destroy a given looper object. Only works for those created
 * with looper_new(). Cannot be called within looper_run()!!
 *
 * NOTE: This assumes that the user has destroyed all its
 *        timers and ios properly
 */
AINLINED void
looper_free(Looper* looper)
{
    if (looper)
        looper->destroy(looper);
}

/* */

#endif /* ANDROID_LOOPER_H */
