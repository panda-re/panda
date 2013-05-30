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
#include "sysdeps.h"
#include <assert.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <memory.h>
#include <stdio.h>
#ifndef HAVE_WINSOCK
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#endif

/**  QUEUE
 **/
#define  SYS_MAX_QUEUE  16

typedef struct {
    int    start;
    int    end;
    void*  pending[ SYS_MAX_QUEUE ];
}
SysQueueRec, *SysQueue;

static void
sys_queue_reset( SysQueue  queue )
{
    queue->start = queue->end = 0;
}

static void
sys_queue_add( SysQueue  queue, void*  item )
{
    assert( queue->end - queue->start < SYS_MAX_QUEUE );
    assert( queue->start == 0 );
    assert( item != NULL );
    queue->pending[ queue->end++ ] = item;
}

#if 0
static void
sys_queue_remove( SysQueue  queue, void*  item )
{
    int  nn, count;
    assert( queue->end > queue->start );
    assert( item != NULL );
    count = queue->end - queue->start;
    for ( nn = queue->start; count > 0; ++nn, --count ) {
        if ( queue->pending[nn] == item ) {
            queue->pending[nn] = queue->pending[nn+count-1];
            queue->end -= 1;
            break;
        }
    }
    assert( 0 && "sys_queue_remove: item not found" );
}
#endif

static void*
sys_queue_get( SysQueue  queue )
{
    if (queue->end > queue->start) {
        return queue->pending[ queue->start++ ];
    }
    return NULL;
}

/** CHANNELS
 **/
typedef struct SysChannelRec_ {
    SysChannel          next;
    int                 fd;
    char                active;
    char                pending;
    char                closed;
    int                 wanted;
    int                 ready;
    SysChannelCallback  callback;
    void*               opaque;
} SysChannelRec;


/*** channel allocation ***/
#define  SYS_EVENT_MAX     3
#define  SYS_MAX_CHANNELS  16

static SysChannelRec  _s_channels0[ SYS_MAX_CHANNELS ];
static SysChannel     _s_free_channels;

static SysChannel
sys_channel_alloc( void )
{
    SysChannel  channel = _s_free_channels;
    assert( channel != NULL && "out of free channels" );
    _s_free_channels  = channel->next;
    channel->next     = NULL;
    channel->active   = 0;
    channel->closed   = 0;
    channel->pending  = 0;
    channel->wanted   = 0;
    return channel;
}

static void
sys_channel_free( SysChannel  channel )
{
    if (channel->fd >= 0) {
#ifdef _WIN32
        shutdown( channel->fd, SD_BOTH );
#else
        shutdown( channel->fd, SHUT_RDWR );
#endif
        close(channel->fd);
        channel->fd = -1;
    }
    channel->wanted   = 0;
    channel->ready    = 0;
    channel->callback = NULL;

    channel->next    = _s_free_channels;
    _s_free_channels = channel;
}


/* list of active channels */
static SysChannel     _s_channels;

/* used by select to wait on channel events */
static fd_set         _s_fdsets[SYS_EVENT_MAX];
static int            _s_maxfd;

static void
sys_channel_deactivate( SysChannel  channel )
{
    assert( channel->active != 0 );
    SysChannel  *pnode = &_s_channels;
    for (;;) {
        SysChannel  node = *pnode;
        assert( node != NULL );
        if (node == channel)
            break;
        pnode = &node->next;
    }
    *pnode          = channel->next;
    channel->next   = NULL;
    channel->active = 0;
}

static void
sys_channel_activate( SysChannel  channel )
{
    assert( channel->active == 0 );
    channel->next = _s_channels;
    _s_channels   = channel;
    channel->active = 1;
    if (channel->fd > _s_maxfd)
        _s_maxfd = channel->fd;
}


/* queue of pending channels */
static SysQueueRec    _s_pending_channels[1];


static void
sys_init_channels( void )
{
    int  nn;

    for (nn = 0; nn < SYS_MAX_CHANNELS-1; nn++)
        _s_channels0[nn].next = &_s_channels0[nn+1];
    _s_free_channels = &_s_channels0[0];

    for (nn = 0; nn < SYS_EVENT_MAX; nn++)
        FD_ZERO( &_s_fdsets[nn] );

    _s_maxfd = -1;

    sys_queue_reset( _s_pending_channels );
}


void
sys_channel_on( SysChannel          channel,
                int                 events,
                SysChannelCallback  callback,
                void*               opaque )
{
    int   adds    = events & ~channel->wanted;
    int   removes = channel->wanted & ~events;

    channel->wanted   = events;
    channel->callback = callback;
    channel->opaque   = opaque;

    /* update global fdsets */
    if (adds) {
        int  ee;
        for (ee = 0; ee < SYS_EVENT_MAX; ee++)
            if (adds & (1 << ee))
                FD_SET( channel->fd, &_s_fdsets[ee] );
    }
    if (removes) {
        int  ee;
        for (ee = 0; ee < SYS_EVENT_MAX; ee++)
            if (removes & (1 << ee))
                FD_CLR( channel->fd, &_s_fdsets[ee] );
    }
    if (events && !channel->active) {
        sys_channel_activate( channel );
    }
    else if (!events && channel->active) {
        sys_channel_deactivate( channel );
    }
}

int
sys_channel_read( SysChannel  channel, void*  buffer, int  size )
{
    char*  buff = buffer;
    int    count = 0;

    assert( !channel->closed );

    while (size > 0) {
        int  len = read(channel->fd, buff, size);
        if (len < 0) {
            if (errno == EINTR)
                continue;
            if (count == 0)
                count = -1;
            break;
        }
        buff  += len;
        size  -= len;
        count += len;
    }
    return count;
}


int
sys_channel_write( SysChannel  channel, const void*  buffer, int  size )
{
    const char*  buff = buffer;
    int          count = 0;

    assert( !channel->closed );

    while (size > 0) {
        int  len = write(channel->fd, buff, size);
        if (len < 0) {
            if (errno == EINTR)
                continue;
            if (count == 0)
                count = -1;
            break;
        }
        buff  += len;
        size  -= len;
        count += len;
    }
    return count;
}


void
sys_channel_close( SysChannel  channel )
{
    if (channel->active) {
        sys_channel_on( channel, 0, NULL, NULL );
    }

    if (channel->pending) {
        /* we can't free the channel right now because it */
        /* is in the pending list, set a flag             */
        channel->closed = 1;
        return;
    }

    if (!channel->closed) {
        channel->closed = 1;
    }

    sys_channel_free( channel );
}

/** time measurement
 **/
SysTime  sys_time_ms( void )
{
    struct timeval  tv;
    gettimeofday( &tv, NULL );
    return (SysTime)(tv.tv_usec / 1000) + (SysTime)tv.tv_sec * 1000;
}

/** timers
 **/
typedef struct SysTimerRec_
{
    SysTimer     next;
    SysTime      when;
    SysCallback  callback;
    void*        opaque;
} SysTimerRec;

#define  SYS_MAX_TIMERS  16

static SysTimerRec   _s_timers0[ SYS_MAX_TIMERS ];
static SysTimer      _s_free_timers;
static SysTimer      _s_timers;

static SysQueueRec   _s_pending_timers[1];


static void
sys_init_timers( void )
{
    int  nn;
    for (nn = 0; nn < SYS_MAX_TIMERS-1; nn++) {
        _s_timers0[nn].next = & _s_timers0[nn+1];
    }
    _s_free_timers = &_s_timers0[0];

    sys_queue_reset( _s_pending_timers );
}


SysTimer   sys_timer_create( void )
{
    SysTimer  timer = _s_free_timers;
    assert( timer != NULL && "too many timers allocated" );
    _s_free_timers = timer->next;
    timer->next    = NULL;
    return timer;
}


void  sys_timer_unset( SysTimer  timer )
{
    if (timer->callback != NULL) {
        SysTimer  *pnode, node;
        pnode = &_s_timers;
        for (;;) {
            node = *pnode;
            if (node == NULL)
                break;
            if (node == timer) {
                *pnode = node->next;
                break;
            }
            pnode = &node->next;
        }
        timer->next     = NULL;
        timer->callback = NULL;
        timer->opaque   = NULL;
    }
}


void  sys_timer_set( SysTimer      timer,
                     SysTime       when,
                     SysCallback   callback,
                     void*         opaque )
{
    if (timer->callback != NULL)
        sys_timer_unset(timer);

    if (callback != NULL) {
        SysTime  now = sys_time_ms();

        if (now >= when) {
            callback( opaque );
        } else {
            SysTimer  *pnode, node;
            pnode = &_s_timers;
            for (;;) {
                node = *pnode;
                if (node == NULL || node->when >= when) {
                    break;
                }
                pnode = &node->next;
            }
            timer->next     = *pnode;
            *pnode          = timer;
            timer->when     = when;
            timer->callback = callback;
            timer->opaque   = opaque;
        }
    }
}


void  sys_timer_destroy( SysTimer  timer )
{
    assert( timer != NULL && "sys_timer_destroy: bad argument" );
    if (timer->callback != NULL)
        sys_timer_unset(timer);

    timer->next    = _s_free_timers;
    _s_free_timers = timer;
}


static void
sys_single_loop( void )
{
    fd_set rfd, wfd, efd;
    struct timeval  timeout_tv, *timeout = NULL;
    int    n;

    memcpy(&rfd, &_s_fdsets[0], sizeof(fd_set));
    memcpy(&wfd, &_s_fdsets[1], sizeof(fd_set));
    memcpy(&efd, &_s_fdsets[2], sizeof(fd_set));

    if ( _s_timers != NULL ) {
        SysTime   now   = sys_time_ms();
        SysTimer  first = _s_timers;

        timeout = &timeout_tv;
        if (first->when <= now) {
            timeout->tv_sec  = 0;
            timeout->tv_usec = 0;
        } else {
            SysTime  diff = first->when - now;
            timeout->tv_sec =   diff / 1000;
            timeout->tv_usec = (diff - timeout->tv_sec*1000) * 1000;
        }
    }

    n = select( _s_maxfd+1, &rfd, &wfd, &efd, timeout);
    if(n < 0) {
        if(errno == EINTR) return;
        perror("select");
        return;
    }

    /* enqueue pending channels */
    {
        int  i;

        sys_queue_reset( _s_pending_channels );
        for(i = 0; (i <= _s_maxfd) && (n > 0); i++)
        {
            int  events = 0;

            if(FD_ISSET(i, &rfd)) events |= SYS_EVENT_READ;
            if(FD_ISSET(i, &wfd)) events |= SYS_EVENT_WRITE;
            if(FD_ISSET(i, &efd)) events |= SYS_EVENT_ERROR;

            if (events) {
                SysChannel  channel;

                n--;
                for (channel = _s_channels; channel; channel = channel->next)
                {
                    if (channel->fd != i)
                        continue;

                    channel->ready   = events;
                    channel->pending = 1;
                    sys_queue_add( _s_pending_channels, channel );
                    break;
                }
            }
        }
    }

    /* enqueue pending timers */
    {
        SysTimer  timer = _s_timers;
        SysTime   now   = sys_time_ms();

        sys_queue_reset( _s_pending_timers );
        while (timer != NULL)
        {
            if (timer->when > now)
                break;

            sys_queue_add( _s_pending_timers, timer );
            _s_timers = timer = timer->next;
        }
    }
}

void  sys_main_init( void )
{
    sys_init_channels();
    sys_init_timers();
}


int   sys_main_loop( void )
{
    for (;;) {
        SysTimer    timer;
        SysChannel  channel;

        /* exit if we have nothing to do */
        if (_s_channels == NULL && _s_timers == NULL)
            break;

        sys_single_loop();

        while ((timer = sys_queue_get( _s_pending_timers )) != NULL) {
            timer->callback( timer->opaque );
        }

        while ((channel = sys_queue_get( _s_pending_channels )) != NULL) {
            int  events;

            channel->pending = 0;
            if (channel->closed) {
                /* the channel was closed by a previous callback */
                sys_channel_close(channel);
            }
            events = channel->ready;
            channel->ready = 0;
            channel->callback( channel->opaque, events );
        }
    }
    return 0;
}




SysChannel
sys_channel_create_tcp_server( int port )
{
    SysChannel          channel;
    int                 on = 1;
    const int           BACKLOG = 4;

    channel = sys_channel_alloc();
    if (-1==(channel->fd=socket(AF_INET, SOCK_STREAM, 0))) {
        perror("socket");
        sys_channel_free( channel );
        return NULL;
    }

    /* Enable address re-use for server mode */
    if ( -1==setsockopt( channel->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) )) {
        perror("setsockopt(SO_REUSEADDR)");
    }

    {
        struct sockaddr_in  servname;
        long                in_addr = INADDR_ANY;

        servname.sin_family = AF_INET;
        servname.sin_port   = htons(port);

        servname.sin_addr.s_addr=in_addr;

        if (-1==bind(channel->fd, (struct sockaddr*)&servname, sizeof(servname))) {
            perror("bind");
            sys_channel_close(channel);
            return NULL;
        }

        /* Listen but don't accept */
        if ( listen(channel->fd, BACKLOG) < 0 ) {
            perror("listen");
            sys_channel_close(channel);
            return NULL;
        }
    }
    return channel;
}


SysChannel
sys_channel_create_tcp_handler( SysChannel  server_channel )
{
    int         on      = 1;
    SysChannel  channel = sys_channel_alloc();

    channel->fd = accept( server_channel->fd, NULL, 0 );
    if (channel->fd < 0) {
        perror( "accept" );
        sys_channel_free( channel );
        return NULL;
    }

    /* set to non-blocking and disable TCP Nagle algorithm */
    fcntl(channel->fd, F_SETFL, O_NONBLOCK);
    setsockopt(channel->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    return channel;
}


SysChannel
sys_channel_create_tcp_client( const char*  hostname, int  port )
{
    struct hostent*     hp;
    struct sockaddr_in  addr;
    SysChannel          channel = sys_channel_alloc();
    int                 on = 1;

    hp = gethostbyname(hostname);
    if(hp == 0) {
        fprintf(stderr, "unknown host: %s\n", hostname);
        sys_channel_free(channel);
        return NULL;
    };

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = hp->h_addrtype;
    addr.sin_port   = htons(port);
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);

    channel->fd = socket(hp->h_addrtype, SOCK_STREAM, 0);
    if(channel->fd < 0) {
        sys_channel_free(channel);
        return NULL;
    }

    if(connect( channel->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror( "connect" );
        sys_channel_free(channel);
        return NULL;
    }

    /* set to non-blocking and disable Nagle algorithm */
    fcntl(channel->fd, F_SETFL, O_NONBLOCK);
    setsockopt( channel->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on) );
    return channel;
}

