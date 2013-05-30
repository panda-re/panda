/* Copyright (C) 2007-2008 The Android Open Source Project
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
#include "sockets.h"
#include "sysdeps.h"
#include "qemu-common.h"
#include "qemu-timer.h"
#include "qemu-char.h"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#endif

#define  DEBUG  0

#define  D_ACTIVE  DEBUG

#if DEBUG
#define  D(...)  do { if (D_ACTIVE) fprintf(stderr, __VA_ARGS__); } while (0)
#else
#define  D(...)  ((void)0)
#endif

/** TIME
 **/

SysTime
sys_time_ms( void )
{
    return qemu_get_clock_ms(rt_clock);
}

/** TIMERS
 **/

typedef struct SysTimerRec_ {
    QEMUTimer*    timer;
    QEMUTimerCB*  callback;
    void*         opaque;
    SysTimer      next;
} SysTimerRec;

#define  MAX_TIMERS  32

static SysTimerRec  _s_timers0[ MAX_TIMERS ];
static SysTimer     _s_free_timers;

static void
sys_init_timers( void )
{
    int  nn;
    for (nn = 0; nn < MAX_TIMERS-1; nn++)
        _s_timers0[nn].next = _s_timers0 + (nn+1);

    _s_free_timers = _s_timers0;
}

static SysTimer
sys_timer_alloc( void )
{
    SysTimer  timer = _s_free_timers;

    if (timer != NULL) {
        _s_free_timers = timer->next;
        timer->next    = NULL;
        timer->timer   = NULL;
    }
    return timer;
}


static void
sys_timer_free( SysTimer  timer )
{
    if (timer->timer) {
        qemu_del_timer( timer->timer );
        qemu_free_timer( timer->timer );
        timer->timer = NULL;
    }
    timer->next    = _s_free_timers;
    _s_free_timers = timer;
}


SysTimer   sys_timer_create( void )
{
    SysTimer  timer = sys_timer_alloc();
    return timer;
}

void
sys_timer_set( SysTimer  timer, SysTime  when, SysCallback   _callback, void*  opaque )
{
    QEMUTimerCB*  callback = (QEMUTimerCB*)_callback;

    if (callback == NULL) {  /* unsetting the timer */
        if (timer->timer) {
            qemu_del_timer( timer->timer );
            qemu_free_timer( timer->timer );
            timer->timer = NULL;
        }
        timer->callback = callback;
        timer->opaque   = NULL;
        return;
    }

    if ( timer->timer ) {
         if ( timer->callback == callback && timer->opaque == opaque )
            goto ReuseTimer;

         /* need to replace the timer */
         qemu_free_timer( timer->timer );
    }

    timer->timer    = qemu_new_timer_ms( rt_clock, callback, opaque );
    timer->callback = callback;
    timer->opaque   = opaque;

ReuseTimer:
    qemu_mod_timer( timer->timer, when );
}

void
sys_timer_unset( SysTimer  timer )
{
    if (timer->timer) {
        qemu_del_timer( timer->timer );
    }
}

void
sys_timer_destroy( SysTimer  timer )
{
    sys_timer_free( timer );
}


/** CHANNELS
 **/

typedef struct SysChannelRec_ {
    int                 fd;
    SysChannelCallback  callback;
    void*               opaque;
    SysChannel          next;
} SysChannelRec;

#define  MAX_CHANNELS  16

static SysChannelRec  _s_channels0[ MAX_CHANNELS ];
static SysChannel     _s_free_channels;

static void
sys_init_channels( void )
{
    int  nn;

    for ( nn = 0; nn < MAX_CHANNELS-1; nn++ ) {
        _s_channels0[nn].next = _s_channels0 + (nn+1);
    }
    _s_free_channels = _s_channels0;
}

static SysChannel
sys_channel_alloc( )
{
    SysChannel  channel = _s_free_channels;
    if (channel != NULL) {
        _s_free_channels  = channel->next;
        channel->next     = NULL;
        channel->fd       = -1;
        channel->callback = NULL;
        channel->opaque   = NULL;
    }
    return channel;
}

static void
sys_channel_free( SysChannel  channel )
{
    if (channel->fd >= 0) {
        socket_close( channel->fd );
        channel->fd = -1;
    }
    channel->next    = _s_free_channels;
    _s_free_channels = channel;
}


static void
sys_channel_read_handler( void*  _channel )
{
    SysChannel  channel = _channel;
    D( "%s: read event for channel %p:%d\n", __FUNCTION__,
       channel, channel->fd );
    channel->callback( channel->opaque, SYS_EVENT_READ );
}

static void
sys_channel_write_handler( void*  _channel )
{
    SysChannel  channel = _channel;
    D( "%s: write event for channel %p:%d\n", __FUNCTION__, channel, channel->fd );
    channel->callback( channel->opaque, SYS_EVENT_WRITE );
}

void
sys_channel_on( SysChannel          channel,
                int                 events,
                SysChannelCallback  event_callback,
                void*               event_opaque )
{
    IOHandler*  read_handler  = NULL;
    IOHandler*  write_handler = NULL;

    if (events & SYS_EVENT_READ) {
        read_handler = sys_channel_read_handler;
    }
    if (events & SYS_EVENT_WRITE) {
        write_handler = sys_channel_write_handler;
    }
    channel->callback = event_callback;
    channel->opaque   = event_opaque;
    qemu_set_fd_handler( channel->fd, read_handler, write_handler, channel );
}

int
sys_channel_read( SysChannel  channel, void*  buffer, int  size )
{
    int   len = size;
    char* buf = (char*) buffer;

    while (len > 0) {
        int  ret = socket_recv(channel->fd, buf, len);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                break;
            D( "%s: after reading %d bytes, recv() returned error %d: %s\n",
                __FUNCTION__, size - len, errno, errno_str);
            return -1;
        } else if (ret == 0) {
            break;
        } else {
            buf += ret;
            len -= ret;
        }
    }
    return size - len;
}


int
sys_channel_write( SysChannel  channel, const void*  buffer, int  size )
{
    int         len = size;
    const char* buf = (const char*) buffer;

    while (len > 0) {
        int  ret = socket_send(channel->fd, buf, len);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                break;
            D( "%s: send() returned error %d: %s\n",
                __FUNCTION__, errno, errno_str);
            return -1;
        } else if (ret == 0) {
            break;
        } else {
            buf += ret;
            len -= ret;
        }
    }
    return size - len;
}

void  sys_channel_close( SysChannel  channel )
{
    qemu_set_fd_handler( channel->fd, NULL, NULL, NULL );
    sys_channel_free( channel );
}

void  sys_main_init( void )
{
    sys_init_channels();
    sys_init_timers();
}


int   sys_main_loop( void )
{
    /* no looping, qemu has its own event loop */
    return 0;
}




SysChannel
sys_channel_create_tcp_server( int port )
{
    SysChannel  channel = sys_channel_alloc();

    channel->fd = socket_anyaddr_server( port, SOCKET_STREAM );
    if (channel->fd < 0) {
        D( "%s: failed to created network socket on TCP:%d\n",
            __FUNCTION__, port );
        sys_channel_free( channel );
        return NULL;
    }

    D( "%s: server channel %p:%d now listening on port %d\n",
       __FUNCTION__, channel, channel->fd, port );

    return channel;
}


SysChannel
sys_channel_create_tcp_handler( SysChannel  server_channel )
{
    SysChannel  channel = sys_channel_alloc();

    D( "%s: creating handler from server channel %p:%d\n", __FUNCTION__,
       server_channel, server_channel->fd );

    channel->fd = socket_accept_any( server_channel->fd );
    if (channel->fd < 0) {
        perror( "accept" );
        sys_channel_free( channel );
        return NULL;
    }

    /* disable Nagle algorithm */
    socket_set_nodelay( channel->fd );

    D( "%s: handler %p:%d created from server %p:%d\n", __FUNCTION__,
        server_channel, server_channel->fd, channel, channel->fd );

     return channel;
}


SysChannel
sys_channel_create_tcp_client( const char*  hostname, int  port )
{
    SysChannel  channel = sys_channel_alloc();

    channel->fd = socket_network_client( hostname, port, SOCKET_STREAM );
    if (channel->fd < 0) {
        sys_channel_free(channel);
        return NULL;
    };

    /* set to non-blocking and disable Nagle algorithm */
    socket_set_nonblock( channel->fd );
    socket_set_nodelay( channel->fd );

    return channel;
}

