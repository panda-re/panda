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

/* Implement the Looper interface on top of the QEMU main event loop */

#include "android/looper.h"
#include "android/utils/panic.h"
#include "qemu-common.h"
#include "qemu-timer.h"
#include "qemu-char.h"
#include "sockets.h"  /* for socket_set_nonblock() */

/**********************************************************************
 **********************************************************************
 *****
 *****  T I M E R S
 *****
 **********************************************************************
 **********************************************************************/

/* Model a timer simple as a QEMUTimer for the host_clock */

static void
qlooptimer_startRelative(void* impl, Duration timeout_ms)
{
    QEMUTimer* tt = impl;
    if (timeout_ms == DURATION_INFINITE)
        qemu_del_timer(tt);
    else
        qemu_mod_timer(tt, qemu_get_clock_ms(host_clock) + timeout_ms);
}

static void
qlooptimer_startAbsolute(void* impl, Duration deadline_ms)
{
    QEMUTimer* tt = impl;
    if (deadline_ms == DURATION_INFINITE)
        qemu_del_timer(tt);
    else
        qemu_mod_timer(tt, deadline_ms);
}

static void
qlooptimer_stop(void* impl)
{
    QEMUTimer* tt = impl;
    qemu_del_timer(tt);
}

static int
qlooptimer_isActive(void* impl)
{
    QEMUTimer* tt = impl;
    return qemu_timer_pending(tt);
}

static void
qlooptimer_free(void* impl)
{
    QEMUTimer* tt = impl;
    qemu_free_timer(tt);
}

static const LoopTimerClass  qlooptimer_class = {
    qlooptimer_startRelative,
    qlooptimer_startAbsolute,
    qlooptimer_stop,
    qlooptimer_isActive,
    qlooptimer_free
};

static void
qlooper_timer_init(Looper*        looper,
                   LoopTimer*     timer,
                   LoopTimerFunc  callback,
                   void*          opaque)
{
    timer->clazz = (LoopTimerClass*) &qlooptimer_class;
    timer->impl  = qemu_new_timer_ms(host_clock, callback, opaque);
}

/**********************************************************************
 **********************************************************************
 *****
 *****  F I L E   D E S C R I P T O R S
 *****
 **********************************************************************
 **********************************************************************/

/* Modeling the LoopIo is a bit more complex because the main event loop
 * will call different functions for read and write readiness, while our
 * users expect a single call with a mask of ready events.
 *
 * Since the QEMU main event loop looks like the following:
 *
 *    1/ perform select()
 *    2/ for each file descriptor:
 *         if readReady:
 *             call readHandler()
 *         if writeReady:
 *             call writeHandler()
 *    3/ run timers
 *    4/ run bottom-half handlers
 *
 * We're going to provide simple read and write handlers that only mark
 * the file descriptor for readiness, and put it on a "pending list".
 *
 * Then, we're going to schedule a bottom-half handler when such a pending
 * i/o event occurs, in order to call the user callback with the correct
 * flags.
 */

typedef struct QLoopIo QLoopIo;

typedef struct QLooper  QLooper;

struct QLoopIo {
    int         fd;
    LoopIoFunc  user_callback;
    void*       user_opaque;
    unsigned    wanted;
    unsigned    ready;
    QLooper*    looper;
    QLoopIo*    pendingNext;
    QLoopIo*    next;
};

static void qlooper_addIo(QLooper*  looper, QLoopIo* io);
static void qlooper_delIo(QLooper*  looper, QLoopIo* io);

static QLoopIo*
qloopio_new(int fd, LoopIoFunc callback, void* opaque, QLooper* qlooper)
{
    QLoopIo*  io = g_malloc(sizeof(*io));

    io->fd = fd;
    io->user_callback = callback;
    io->user_opaque   = opaque;
    io->wanted        = 0;
    io->ready         = 0;
    io->looper        = qlooper;
    io->pendingNext   = NULL;

    qlooper_addIo(qlooper, io);

    return io;
}

static void qlooper_addPendingIo(QLooper* qlooper, QLoopIo* io);
static void qlooper_delPendingIo(QLooper* qlooper, QLoopIo*  io);

static void
qloopio_removePending(QLoopIo* io)
{
    if (io->ready != 0) {
        qlooper_delPendingIo(io->looper, io);
        io->ready = 0;
    }
}

static void
qloopio_setReady(QLoopIo* io, unsigned flag)
{
    if (io->ready == 0) {
        qlooper_addPendingIo(io->looper, io);
    }
    io->ready |= flag;
}

static void
qloopio_handleRead(void* opaque)
{
    QLoopIo* io = opaque;
    qloopio_setReady(io, LOOP_IO_READ);
}

static void
qloopio_handleWrite(void* opaque)
{
    QLoopIo* io = opaque;
    qloopio_setReady(io, LOOP_IO_WRITE);
}

static void
qloopio_modify(QLoopIo* io, unsigned wanted)
{
    /* no change, don't bother */
    if (wanted == io->wanted)
        return;

    /* if we're pending, but the new mask doesn't care about
     * out state, remove from pending list */
    if (io->ready && (io->ready & wanted) == 0) {
        qloopio_removePending(io);
    }

    /* recompute read/write handlers for QEMU */
    IOHandler* fd_read  = (wanted & LOOP_IO_READ)  ? qloopio_handleRead  : NULL;
    IOHandler* fd_write = (wanted & LOOP_IO_WRITE) ? qloopio_handleWrite : NULL;
    qemu_set_fd_handler(io->fd, fd_read, fd_write, io);
    io->wanted = wanted;
}

static void
qloopio_wantRead(void* impl)
{
    QLoopIo* io = impl;
    qloopio_modify(io, io->wanted | LOOP_IO_READ);
}

static void
qloopio_wantWrite(void* impl)
{
    QLoopIo* io = impl;
    qloopio_modify(io, io->wanted | LOOP_IO_WRITE);
}

static void
qloopio_dontWantRead(void* impl)
{
    QLoopIo* io = impl;
    qloopio_modify(io, io->wanted & ~LOOP_IO_READ);
}

static void
qloopio_dontWantWrite(void* impl)
{
    QLoopIo* io = impl;
    qloopio_modify(io, io->wanted & ~LOOP_IO_WRITE);
}

static void
qloopio_free(void* impl)
{
    QLoopIo* io = impl;
    if (io->ready)
        qloopio_removePending(io);

    /* remove from global list */
    qlooper_delIo(io->looper, io);

    /* make QEMU forget about this fd */
    qemu_set_fd_handler(io->fd, NULL, NULL, NULL);
    io->fd = -1;
    g_free(io);
}

static unsigned
qloopio_poll(void* impl)
{
    QLoopIo* io = impl;
    return io->ready;
}

static const LoopIoClass  qlooper_io_class = {
    qloopio_wantRead,
    qloopio_wantWrite,
    qloopio_dontWantRead,
    qloopio_dontWantWrite,
    qloopio_poll,
    qloopio_free
};

static void
qlooper_io_init(Looper*     looper,
                LoopIo*     loopio,
                int         fd,
                LoopIoFunc  callback,
                void*       opaque)
{
    QLoopIo* io = qloopio_new(fd, callback, opaque, (QLooper*)looper);

    socket_set_nonblock(fd);

    loopio->clazz = (LoopIoClass*) &qlooper_io_class;
    loopio->impl  = io;
}

struct QLooper {
    Looper    looper;
    QLoopIo*  io_list;
    QLoopIo*  io_pending;
    QEMUBH*   io_bh;
};

static void
qlooper_addIo(QLooper* looper, QLoopIo* io)
{
    io->next        = looper->io_list;
    looper->io_list = io;
}

static void
qlooper_delIo(QLooper* looper, QLoopIo* io)
{
    QLoopIo** pnode = &looper->io_list;
    for (;;) {
        if (*pnode == NULL)
            break;
        if (*pnode == io) {
            *pnode = io->next;
            io->next = NULL;
            break;
        }
        pnode = &(*pnode)->next;
    }
}

static void
qlooper_addPendingIo(QLooper* looper, QLoopIo* io)
{
    if (looper->io_pending == NULL) {
        qemu_bh_schedule(looper->io_bh);
    }
    io->pendingNext    = looper->io_pending;
    looper->io_pending = io;
}

static void
qlooper_delPendingIo(QLooper* looper, QLoopIo* io)
{
    QLoopIo** pnode = &looper->io_pending;
    for (;;) {
        if (*pnode == NULL)
            break;
        if (*pnode == io) {
            *pnode = io->pendingNext;
            break;
        }
        pnode = &(*pnode)->pendingNext;
    }
    io->pendingNext = NULL;
}

/* This function is called by the main event loop when pending i/o
 * events were registered with qlooper_addPendingIo(). It will parse
 * the list of pending QLoopIo and call the user callback with the
 * appropriate flags.
 */
static void
qlooper_handle_io_bh(void* opaque)
{
    QLooper*  looper = opaque;
    QLoopIo*  io;

    while ((io = looper->io_pending) != NULL) {
        unsigned ready;
        /* extract from list */
        looper->io_pending = io->pendingNext;
        io->pendingNext    = NULL;
        /* call the user callback, clear io->ready before to
         * indicate that the item is not on the pending list
         * anymore.
         */
        ready     = io->ready;
        io->ready = 0;
        io->user_callback(io->user_opaque, io->fd, ready);
    }
}

static Duration
qlooper_now(Looper* ll)
{
    return qemu_get_clock_ms(host_clock);
}

extern void qemu_system_shutdown_request(void);

static void
qlooper_forceQuit(Looper* ll)
{
    qemu_system_shutdown_request();
}

/* The user cannot call looper_run on the core event loop, because it
 * is started by qemu_main() explicitely instead, so just panic. */
int
qlooper_run(Looper* ll, Duration deadline_ms)
{
    APANIC("Trying to run the QEMU main event loop explicitely!");
    return EINVAL;
}

static void
qlooper_destroy(Looper* ll)
{
    QLooper*  looper = (QLooper*)ll;
    QLoopIo*  io;

    while ((io = looper->io_list) != NULL)
        qloopio_free(io);

    qemu_bh_delete(looper->io_bh);
    g_free(looper);
}

Looper*
looper_newCore(void)
{
    QLooper*  looper = g_malloc0(sizeof(*looper));

    looper->io_list    = NULL;
    looper->io_pending = NULL;
    looper->io_bh      = qemu_bh_new(qlooper_handle_io_bh, looper);

    looper->looper.now        = qlooper_now;
    looper->looper.timer_init = qlooper_timer_init;
    looper->looper.io_init    = qlooper_io_init;
    looper->looper.run        = qlooper_run;
    looper->looper.forceQuit  = qlooper_forceQuit;
    looper->looper.destroy    = qlooper_destroy;

    return &looper->looper;
}
