/* Copyright (C) 2011 The Android Open Source Project
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
#include "android/utils/panic.h"
#include "android/utils/system.h"
#include "hw/goldfish_pipe.h"
#include "hw/goldfish_device.h"
#include "qemu-timer.h"
#ifdef CONFIG_KVM
#include "kvm.h"
#endif

#define  DEBUG 0

/* Set to 1 to debug i/o register reads/writes */
#define DEBUG_REGS  0

#if DEBUG >= 1
#  define D(...)  fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#else
#  define D(...)  (void)0
#endif

#if DEBUG >= 2
#  define DD(...)  fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#else
#  define DD(...)  (void)0
#endif

#if DEBUG_REGS >= 1
#  define DR(...)   D(__VA_ARGS__)
#else
#  define DR(...)   (void)0
#endif

#define E(...)  fprintf(stderr, "ERROR:" __VA_ARGS__), fprintf(stderr, "\n")

/* Set to 1 to enable the 'zero' pipe type, useful for debugging */
#define DEBUG_ZERO_PIPE  1

/* Set to 1 to enable the 'pingpong' pipe type, useful for debugging */
#define DEBUG_PINGPONG_PIPE 1

/* Set to 1 to enable the 'throttle' pipe type, useful for debugging */
#define DEBUG_THROTTLE_PIPE 1

/* Maximum length of pipe service name, in characters (excluding final 0) */
#define MAX_PIPE_SERVICE_NAME_SIZE  255

#define GOLDFISH_PIPE_SAVE_VERSION  2

/***********************************************************************
 ***********************************************************************
 *****
 *****   P I P E   S E R V I C E   R E G I S T R A T I O N
 *****
 *****/

#define MAX_PIPE_SERVICES  8
typedef struct {
    const char*        name;
    void*              opaque;
    GoldfishPipeFuncs  funcs;
} PipeService;

typedef struct {
    int          count;
    PipeService  services[MAX_PIPE_SERVICES];
} PipeServices;

static PipeServices  _pipeServices[1];

void
goldfish_pipe_add_type(const char*               pipeName,
                       void*                     pipeOpaque,
                       const GoldfishPipeFuncs*  pipeFuncs )
{
    PipeServices* list = _pipeServices;
    int           count = list->count;

    if (count >= MAX_PIPE_SERVICES) {
        APANIC("Too many goldfish pipe services (%d)", count);
    }

    if (strlen(pipeName) > MAX_PIPE_SERVICE_NAME_SIZE) {
        APANIC("Pipe service name too long: '%s'", pipeName);
    }

    list->services[count].name   = pipeName;
    list->services[count].opaque = pipeOpaque;
    list->services[count].funcs  = pipeFuncs[0];

    list->count++;
}

static const PipeService*
goldfish_pipe_find_type(const char*  pipeName)
{
    PipeServices* list = _pipeServices;
    int           count = list->count;
    int           nn;

    for (nn = 0; nn < count; nn++) {
        if (!strcmp(list->services[nn].name, pipeName)) {
            return &list->services[nn];
        }
    }
    return NULL;
}


/***********************************************************************
 ***********************************************************************
 *****
 *****    P I P E   C O N N E C T I O N S
 *****
 *****/

typedef struct PipeDevice  PipeDevice;

typedef struct Pipe {
    struct Pipe*              next;
    struct Pipe*              next_waked;
    PipeDevice*                device;
    uint32_t                   channel;
    void*                      opaque;
    const GoldfishPipeFuncs*   funcs;
    const PipeService*         service;
    char*                      args;
    unsigned char              wanted;
    char                       closed;
} Pipe;

/* Forward */
static void*  pipeConnector_new(Pipe*  pipe);

static Pipe*
pipe_new0(PipeDevice* dev)
{
    Pipe*  pipe;
    ANEW0(pipe);
    pipe->device = dev;
    return pipe;
}

static Pipe*
pipe_new(uint32_t channel, PipeDevice* dev)
{
    Pipe*  pipe = pipe_new0(dev);
    pipe->channel = channel;
    pipe->opaque  = pipeConnector_new(pipe);
    return pipe;
}

static Pipe**
pipe_list_findp_channel( Pipe** list, uint32_t channel )
{
    Pipe** pnode = list;
    for (;;) {
        Pipe* node = *pnode;
        if (node == NULL || node->channel == channel) {
            break;
        }
        pnode = &node->next;
    }
    return pnode;
}

#if 0
static Pipe**
pipe_list_findp_opaque( Pipe** list, void* opaque )
{
    Pipe** pnode = list;
    for (;;) {
        Pipe* node = *pnode;
        if (node == NULL || node->opaque == opaque) {
            break;
        }
        pnode = &node->next;
    }
    return pnode;
}
#endif

static Pipe**
pipe_list_findp_waked( Pipe** list, Pipe* pipe )
{
    Pipe** pnode = list;
    for (;;) {
        Pipe* node = *pnode;
        if (node == NULL || node == pipe) {
            break;
        }
        pnode = &node->next_waked;
    }
    return pnode;
}


static void
pipe_list_remove_waked( Pipe** list, Pipe*  pipe )
{
    Pipe** lookup = pipe_list_findp_waked(list, pipe);
    Pipe*  node   = *lookup;

    if (node != NULL) {
        (*lookup) = node->next_waked;
        node->next_waked = NULL;
    }
}

static void
pipe_save( Pipe* pipe, QEMUFile* file )
{
    if (pipe->service == NULL) {
        /* pipe->service == NULL means we're still using a PipeConnector */
        /* Write a zero to indicate this condition */
        qemu_put_byte(file, 0);
    } else {
        /* Otherwise, write a '1' then the service name */
        qemu_put_byte(file, 1);
        qemu_put_string(file, pipe->service->name);
    }

    /* Now save other common data */
    qemu_put_be32(file, (unsigned int)pipe->channel);
    qemu_put_byte(file, (int)pipe->wanted);
    qemu_put_byte(file, (int)pipe->closed);

    /* Write 1 + args, if any, or simply 0 otherwise */
    if (pipe->args != NULL) {
        qemu_put_byte(file, 1);
        qemu_put_string(file, pipe->args);
    } else {
        qemu_put_byte(file, 0);
    }

    if (pipe->funcs->save) {
        pipe->funcs->save(pipe->opaque, file);
    }
}

static Pipe*
pipe_load( PipeDevice* dev, QEMUFile* file )
{
    Pipe*              pipe;
    const PipeService* service = NULL;
    int   state = qemu_get_byte(file);
    uint32_t channel;

    if (state != 0) {
        /* Pipe is associated with a service. */
        char* name = qemu_get_string(file);
        if (name == NULL)
            return NULL;

        service = goldfish_pipe_find_type(name);
        if (service == NULL) {
            D("No QEMU pipe service named '%s'", name);
            AFREE(name);
            return NULL;
        }
    }

    channel = qemu_get_be32(file);
    pipe = pipe_new(channel, dev);
    pipe->wanted  = qemu_get_byte(file);
    pipe->closed  = qemu_get_byte(file);
    if (qemu_get_byte(file) != 0) {
        pipe->args = qemu_get_string(file);
    }

    pipe->service = service;
    if (service != NULL) {
        pipe->funcs = &service->funcs;
    }

    if (pipe->funcs->load) {
        pipe->opaque = pipe->funcs->load(pipe, service ? service->opaque : NULL, pipe->args, file);
        if (pipe->opaque == NULL) {
            AFREE(pipe);
            return NULL;
        }
    } else {
        /* Force-close the pipe on load */
        pipe->closed = 1;
    }
    return pipe;
}

static void
pipe_free( Pipe* pipe )
{
    /* Call close callback */
    if (pipe->funcs->close) {
        pipe->funcs->close(pipe->opaque);
    }
    /* Free stuff */
    AFREE(pipe->args);
    AFREE(pipe);
}

/***********************************************************************
 ***********************************************************************
 *****
 *****    P I P E   C O N N E C T O R S
 *****
 *****/

/* These are used to handle the initial connection attempt, where the
 * client is going to write the name of the pipe service it wants to
 * connect to, followed by a terminating zero.
 */
typedef struct {
    Pipe*  pipe;
    char   buffer[128];
    int    buffpos;
} PipeConnector;

static const GoldfishPipeFuncs  pipeConnector_funcs;  // forward

void*
pipeConnector_new(Pipe*  pipe)
{
    PipeConnector*  pcon;

    ANEW0(pcon);
    pcon->pipe  = pipe;
    pipe->funcs = &pipeConnector_funcs;
    return pcon;
}

static void
pipeConnector_close( void* opaque )
{
    PipeConnector*  pcon = opaque;
    AFREE(pcon);
}

static int
pipeConnector_sendBuffers( void* opaque, const GoldfishPipeBuffer* buffers, int numBuffers )
{
    PipeConnector* pcon = opaque;
    const GoldfishPipeBuffer*  buffers_limit = buffers + numBuffers;
    int ret = 0;

    DD("%s: channel=0x%x numBuffers=%d", __FUNCTION__,
       pcon->pipe->channel,
       numBuffers);

    while (buffers < buffers_limit) {
        int  avail;

        DD("%s: buffer data (%3d bytes): '%.*s'", __FUNCTION__,
           buffers[0].size, buffers[0].size, buffers[0].data);

        if (buffers[0].size == 0) {
            buffers++;
            continue;
        }

        avail = sizeof(pcon->buffer) - pcon->buffpos;
        if (avail > buffers[0].size)
            avail = buffers[0].size;

        if (avail > 0) {
            cpu_memory_rw(cpu_single_env, buffers[0].addr, pcon->buffer + pcon->buffpos, avail, 0);
            pcon->buffpos += avail;
            ret += avail;
        }
        buffers++;
    }

    /* Now check that our buffer contains a zero-terminated string */
    if (memchr(pcon->buffer, '\0', pcon->buffpos) != NULL) {
        /* Acceptable formats for the connection string are:
         *
         *   pipe:<name>
         *   pipe:<name>:<arguments>
         */
        char* pipeName;
        char* pipeArgs;

        D("%s: connector: '%s'", __FUNCTION__, pcon->buffer);

        if (memcmp(pcon->buffer, "pipe:", 5) != 0) {
            /* Nope, we don't handle these for now. */
            D("%s: Unknown pipe connection: '%s'", __FUNCTION__, pcon->buffer);
            return PIPE_ERROR_INVAL;
        }

        pipeName = pcon->buffer + 5;
        pipeArgs = strchr(pipeName, ':');

        if (pipeArgs != NULL) {
            *pipeArgs++ = '\0';
            if (!*pipeArgs)
                pipeArgs = NULL;
        }

        Pipe* pipe = pcon->pipe;
        const PipeService* svc = goldfish_pipe_find_type(pipeName);
        if (svc == NULL) {
            D("%s: Unknown server!", __FUNCTION__);
            return PIPE_ERROR_INVAL;
        }

        void*  peer = svc->funcs.init(pipe, svc->opaque, pipeArgs);
        if (peer == NULL) {
            D("%s: Initialization failed!", __FUNCTION__);
            return PIPE_ERROR_INVAL;
        }

        /* Do the evil switch now */
        pipe->opaque = peer;
        pipe->service = svc;
        pipe->funcs  = &svc->funcs;
        pipe->args   = ASTRDUP(pipeArgs);
        AFREE(pcon);
    }

    return ret;
}

static int
pipeConnector_recvBuffers( void* opaque, GoldfishPipeBuffer* buffers, int numBuffers )
{
    return PIPE_ERROR_IO;
}

static unsigned
pipeConnector_poll( void* opaque )
{
    return PIPE_POLL_OUT;
}

static void
pipeConnector_wakeOn( void* opaque, int flags )
{
    /* nothing, really should never happen */
}

static void
pipeConnector_save( void* pipe, QEMUFile* file )
{
    PipeConnector*  pcon = pipe;
    qemu_put_sbe32(file, pcon->buffpos);
    qemu_put_sbuffer(file, (const int8_t*)pcon->buffer, pcon->buffpos);
}

static void*
pipeConnector_load( void* hwpipe, void* pipeOpaque, const char* args, QEMUFile* file )
{
    PipeConnector*  pcon;

    int len = qemu_get_sbe32(file);
    if (len < 0 || len > sizeof(pcon->buffer)) {
        return NULL;
    }
    pcon = pipeConnector_new(hwpipe);
    pcon->buffpos = len;
    if (qemu_get_buffer(file, (uint8_t*)pcon->buffer, pcon->buffpos) != pcon->buffpos) {
        AFREE(pcon);
        return NULL;
    }
    return pcon;
}

static const GoldfishPipeFuncs  pipeConnector_funcs = {
    NULL,  /* init */
    pipeConnector_close,        /* should rarely happen */
    pipeConnector_sendBuffers,  /* the interesting stuff */
    pipeConnector_recvBuffers,  /* should not happen */
    pipeConnector_poll,         /* should not happen */
    pipeConnector_wakeOn,       /* should not happen */
    pipeConnector_save,
    pipeConnector_load,
};

/***********************************************************************
 ***********************************************************************
 *****
 *****    Z E R O   P I P E S
 *****
 *****/

/* A simple pipe service that mimics /dev/zero, you can write anything to
 * it, and you can always read any number of zeros from it. Useful for debugging
 * the kernel driver.
 */
#if DEBUG_ZERO_PIPE

typedef struct {
    void* hwpipe;
} ZeroPipe;

static void*
zeroPipe_init( void* hwpipe, void* svcOpaque, const char* args )
{
    ZeroPipe*  zpipe;

    D("%s: hwpipe=%p", __FUNCTION__, hwpipe);
    ANEW0(zpipe);
    zpipe->hwpipe = hwpipe;
    return zpipe;
}

static void
zeroPipe_close( void* opaque )
{
    ZeroPipe*  zpipe = opaque;

    D("%s: hwpipe=%p", __FUNCTION__, zpipe->hwpipe);
    AFREE(zpipe);
}

static int
zeroPipe_sendBuffers( void* opaque, const GoldfishPipeBuffer* buffers, int numBuffers )
{
    int  ret = 0;
    while (numBuffers > 0) {
        ret += buffers[0].size;
        buffers++;
        numBuffers--;
    }
    return ret;
}

static int
zeroPipe_recvBuffers( void* opaque, GoldfishPipeBuffer* buffers, int numBuffers )
{
    int  ret = 0;
    while (numBuffers > 0) {
        char zeros[buffers[0].addr];
        memset(zeros, 0, buffers[0].addr);
        ret += buffers[0].size;
        cpu_memory_rw(cpu_single_env,buffers[0].addr, zeros, buffers[0].size, 1);
        buffers++;
        numBuffers--;
    }
    return ret;
}

static unsigned
zeroPipe_poll( void* opaque )
{
    return PIPE_POLL_IN | PIPE_POLL_OUT;
}

static void
zeroPipe_wakeOn( void* opaque, int flags )
{
    /* nothing to do here */
}

static const GoldfishPipeFuncs  zeroPipe_funcs = {
    zeroPipe_init,
    zeroPipe_close,
    zeroPipe_sendBuffers,
    zeroPipe_recvBuffers,
    zeroPipe_poll,
    zeroPipe_wakeOn,
};

#endif /* DEBUG_ZERO */

/***********************************************************************
 ***********************************************************************
 *****
 *****    P I N G   P O N G   P I P E S
 *****
 *****/

/* Similar debug service that sends back anything it receives */
/* All data is kept in a circular dynamic buffer */

#if DEBUG_PINGPONG_PIPE

/* Initial buffer size */
#define PINGPONG_SIZE  1024

typedef struct {
    void*     hwpipe;
    uint8_t*  buffer;
    size_t    size;
    size_t    pos;
    size_t    count;
    unsigned  flags;
} PingPongPipe;

static void
pingPongPipe_init0( PingPongPipe* pipe, void* hwpipe, void* svcOpaque )
{
    pipe->hwpipe = hwpipe;
    pipe->size = PINGPONG_SIZE;
    pipe->buffer = malloc(pipe->size);
    pipe->pos = 0;
    pipe->count = 0;
}

static void*
pingPongPipe_init( void* hwpipe, void* svcOpaque, const char* args )
{
    PingPongPipe*  ppipe;

    D("%s: hwpipe=%p", __FUNCTION__, hwpipe);
    ANEW0(ppipe);
    pingPongPipe_init0(ppipe, hwpipe, svcOpaque);
    return ppipe;
}

static void
pingPongPipe_close( void* opaque )
{
    PingPongPipe*  ppipe = opaque;

    D("%s: hwpipe=%p (pos=%d count=%d size=%d)", __FUNCTION__,
      ppipe->hwpipe, ppipe->pos, ppipe->count, ppipe->size);
    free(ppipe->buffer);
    AFREE(ppipe);
}

static int
pingPongPipe_sendBuffers( void* opaque, const GoldfishPipeBuffer* buffers, int numBuffers )
{
    PingPongPipe*  pipe = opaque;
    int  ret = 0;
    int  count;
    const GoldfishPipeBuffer* buff = buffers;
    const GoldfishPipeBuffer* buffEnd = buff + numBuffers;

    count = 0;
    for ( ; buff < buffEnd; buff++ )
        count += buff->size;

    /* Do we need to grow the pingpong buffer? */
    while (count > pipe->size - pipe->count) {
        size_t    newsize = pipe->size*2;
        uint8_t*  newbuff = realloc(pipe->buffer, newsize);
        int       wpos    = pipe->pos + pipe->count;
        if (newbuff == NULL) {
            break;
        }
        if (wpos > pipe->size) {
            wpos -= pipe->size;
            memcpy(newbuff + pipe->size, newbuff, wpos);
        }
        pipe->buffer = newbuff;
        pipe->size   = newsize;
        D("pingpong buffer is now %d bytes", newsize);
    }

    for ( buff = buffers; buff < buffEnd; buff++ ) {
        int avail = pipe->size - pipe->count;
        if (avail <= 0) {
            if (ret == 0)
                ret = PIPE_ERROR_AGAIN;
            break;
        }
        if (avail > buff->size) {
            avail = buff->size;
        }

        int wpos = pipe->pos + pipe->count;
        if (wpos >= pipe->size) {
            wpos -= pipe->size;
        }
        if (wpos + avail <= pipe->size) {
            cpu_memory_rw(cpu_single_env,buff->addr, pipe->buffer + wpos, avail,0);
        } else {
            int  avail2 = pipe->size - wpos;
            cpu_memory_rw(cpu_single_env,buff->addr, pipe->buffer + wpos, avail2,0);
            cpu_memory_rw(cpu_single_env,buff->addr + avail2, pipe->buffer, avail-avail2,0);
        }
        pipe->count += avail;
        ret += avail;
    }

    /* Wake up any waiting readers if we wrote something */
    if (pipe->count > 0 && (pipe->flags & PIPE_WAKE_READ)) {
        goldfish_pipe_wake(pipe->hwpipe, PIPE_WAKE_READ);
    }

    return ret;
}

static int
pingPongPipe_recvBuffers( void* opaque, GoldfishPipeBuffer* buffers, int numBuffers )
{
    PingPongPipe*  pipe = opaque;
    int  ret = 0;

    while (numBuffers > 0) {
        int avail = pipe->count;
        if (avail <= 0) {
            if (ret == 0)
                ret = PIPE_ERROR_AGAIN;
            break;
        }
        if (avail > buffers[0].size) {
            avail = buffers[0].size;
        }

        int rpos = pipe->pos;

        if (rpos + avail <= pipe->size) {
            cpu_memory_rw(cpu_single_env,buffers[0].addr,pipe->buffer + rpos, avail,1);
        } else {
            int  avail2 = pipe->size - rpos;
            cpu_memory_rw(cpu_single_env,buffers[0].addr, pipe->buffer + rpos, avail2,1);
            cpu_memory_rw(cpu_single_env,buffers[0].addr+ avail2, pipe->buffer, avail - avail2,1);
        }
        pipe->count -= avail;
        pipe->pos   += avail;
        if (pipe->pos >= pipe->size) {
            pipe->pos -= pipe->size;
        }
        ret += avail;
        numBuffers--;
        buffers++;
    }

    /* Wake up any waiting readers if we wrote something */
    if (pipe->count < PINGPONG_SIZE && (pipe->flags & PIPE_WAKE_WRITE)) {
        goldfish_pipe_wake(pipe->hwpipe, PIPE_WAKE_WRITE);
    }

    return ret;
}

static unsigned
pingPongPipe_poll( void* opaque )
{
    PingPongPipe*  pipe = opaque;
    unsigned       ret = 0;

    if (pipe->count < pipe->size)
        ret |= PIPE_POLL_OUT;

    if (pipe->count > 0)
        ret |= PIPE_POLL_IN;

    return ret;
}

static void
pingPongPipe_wakeOn( void* opaque, int flags )
{
    PingPongPipe* pipe = opaque;
    pipe->flags |= (unsigned)flags;
}

static const GoldfishPipeFuncs  pingPongPipe_funcs = {
    pingPongPipe_init,
    pingPongPipe_close,
    pingPongPipe_sendBuffers,
    pingPongPipe_recvBuffers,
    pingPongPipe_poll,
    pingPongPipe_wakeOn,
};

#endif /* DEBUG_PINGPONG_PIPE */

/***********************************************************************
 ***********************************************************************
 *****
 *****    T H R O T T L E   P I P E S
 *****
 *****/

/* Similar to PingPongPipe, but will throttle the bandwidth to test
 * blocking I/O.
 */

#ifdef DEBUG_THROTTLE_PIPE

typedef struct {
    PingPongPipe  pingpong;
    double        sendRate;
    int64_t       sendExpiration;
    double        recvRate;
    int64_t       recvExpiration;
    QEMUTimer*    timer;
} ThrottlePipe;

/* forward declaration */
static void throttlePipe_timerFunc( void* opaque );

static void*
throttlePipe_init( void* hwpipe, void* svcOpaque, const char* args )
{
    ThrottlePipe* pipe;

    ANEW0(pipe);
    pingPongPipe_init0(&pipe->pingpong, hwpipe, svcOpaque);
    pipe->timer = qemu_new_timer_ns(vm_clock, throttlePipe_timerFunc, pipe);
    /* For now, limit to 500 KB/s in both directions */
    pipe->sendRate = 1e9 / (500*1024*8);
    pipe->recvRate = pipe->sendRate;
    return pipe;
}

static void
throttlePipe_close( void* opaque )
{
    ThrottlePipe* pipe = opaque;

    qemu_del_timer(pipe->timer);
    qemu_free_timer(pipe->timer);
    pingPongPipe_close(&pipe->pingpong);
}

static void
throttlePipe_rearm( ThrottlePipe* pipe )
{
    int64_t  minExpiration = 0;

    DD("%s: sendExpiration=%lld recvExpiration=%lld\n", __FUNCTION__, pipe->sendExpiration, pipe->recvExpiration);

    if (pipe->sendExpiration) {
        if (minExpiration == 0 || pipe->sendExpiration < minExpiration)
            minExpiration = pipe->sendExpiration;
    }

    if (pipe->recvExpiration) {
        if (minExpiration == 0 || pipe->recvExpiration < minExpiration)
            minExpiration = pipe->recvExpiration;
    }

    if (minExpiration != 0) {
        DD("%s: Arming for %lld\n", __FUNCTION__, minExpiration);
        qemu_mod_timer(pipe->timer, minExpiration);
    }
}

static void
throttlePipe_timerFunc( void* opaque )
{
    ThrottlePipe* pipe = opaque;
    int64_t  now = qemu_get_clock_ns(vm_clock);

    DD("%s: TICK! now=%lld sendExpiration=%lld recvExpiration=%lld\n",
       __FUNCTION__, now, pipe->sendExpiration, pipe->recvExpiration);

    /* Timer has expired, signal wake up if needed */
    int      flags = 0;

    if (pipe->sendExpiration && now > pipe->sendExpiration) {
        flags |= PIPE_WAKE_WRITE;
        pipe->sendExpiration = 0;
    }
    if (pipe->recvExpiration && now > pipe->recvExpiration) {
        flags |= PIPE_WAKE_READ;
        pipe->recvExpiration = 0;
    }
    flags &= pipe->pingpong.flags;
    if (flags != 0) {
        DD("%s: WAKE %d\n", __FUNCTION__, flags);
        goldfish_pipe_wake(pipe->pingpong.hwpipe, flags);
    }

    throttlePipe_rearm(pipe);
}

static int
throttlePipe_sendBuffers( void* opaque, const GoldfishPipeBuffer* buffers, int numBuffers )
{
    ThrottlePipe*  pipe = opaque;
    int            ret;

    if (pipe->sendExpiration > 0) {
        return PIPE_ERROR_AGAIN;
    }

    ret = pingPongPipe_sendBuffers(&pipe->pingpong, buffers, numBuffers);
    if (ret > 0) {
        /* Compute next send expiration time */
        pipe->sendExpiration = qemu_get_clock_ns(vm_clock) + ret*pipe->sendRate;
        throttlePipe_rearm(pipe);
    }
    return ret;
}

static int
throttlePipe_recvBuffers( void* opaque, GoldfishPipeBuffer* buffers, int numBuffers )
{
    ThrottlePipe* pipe = opaque;
    int           ret;

    if (pipe->recvExpiration > 0) {
        return PIPE_ERROR_AGAIN;
    }

    ret = pingPongPipe_recvBuffers(&pipe->pingpong, buffers, numBuffers);
    if (ret > 0) {
        pipe->recvExpiration = qemu_get_clock_ns(vm_clock) + ret*pipe->recvRate;
        throttlePipe_rearm(pipe);
    }
    return ret;
}

static unsigned
throttlePipe_poll( void* opaque )
{
    ThrottlePipe*  pipe = opaque;
    unsigned       ret  = pingPongPipe_poll(&pipe->pingpong);

    if (pipe->sendExpiration > 0)
        ret &= ~PIPE_POLL_OUT;

    if (pipe->recvExpiration > 0)
        ret &= ~PIPE_POLL_IN;

    return ret;
}

static void
throttlePipe_wakeOn( void* opaque, int flags )
{
    ThrottlePipe* pipe = opaque;
    pingPongPipe_wakeOn(&pipe->pingpong, flags);
}

static const GoldfishPipeFuncs  throttlePipe_funcs = {
    throttlePipe_init,
    throttlePipe_close,
    throttlePipe_sendBuffers,
    throttlePipe_recvBuffers,
    throttlePipe_poll,
    throttlePipe_wakeOn,
};

#endif /* DEBUG_THROTTLE_PIPE */

/***********************************************************************
 ***********************************************************************
 *****
 *****    G O L D F I S H   P I P E   D E V I C E
 *****
 *****/

struct PipeDevice {
    struct GoldfishDevice dev;

    /* the list of all pipes */
    Pipe*  pipes;

    /* the list of signalled pipes */
    Pipe*  signaled_pipes;

    /* i/o registers */
    uint32_t  address;
    uint32_t  size;
    uint32_t  status;
    uint32_t  channel;
    uint32_t  wakes;
    uint64_t  params_addr;
};

static void
pipeDevice_doCommand( PipeDevice* dev, uint32_t command )
{
    Pipe** lookup = pipe_list_findp_channel(&dev->pipes, dev->channel);
    Pipe*  pipe   = *lookup;
    CPUState* env = cpu_single_env;

    /* Check that we're referring a known pipe channel */
    if (command != PIPE_CMD_OPEN && pipe == NULL) {
        dev->status = PIPE_ERROR_INVAL;
        return;
    }

    /* If the pipe is closed by the host, return an error */
    if (pipe != NULL && pipe->closed && command != PIPE_CMD_CLOSE) {
        dev->status = PIPE_ERROR_IO;
        return;
    }

    switch (command) {
    case PIPE_CMD_OPEN:
        DD("%s: CMD_OPEN channel=0x%x", __FUNCTION__, dev->channel);
        if (pipe != NULL) {
            dev->status = PIPE_ERROR_INVAL;
            break;
        }
        pipe = pipe_new(dev->channel, dev);
        pipe->next = dev->pipes;
        dev->pipes = pipe;
        dev->status = 0;
        break;

    case PIPE_CMD_CLOSE:
        DD("%s: CMD_CLOSE channel=0x%x", __FUNCTION__, dev->channel);
        /* Remove from device's lists */
        *lookup = pipe->next;
        pipe->next = NULL;
        pipe_list_remove_waked(&dev->signaled_pipes, pipe);
        pipe_free(pipe);
        break;

    case PIPE_CMD_POLL:
        dev->status = pipe->funcs->poll(pipe->opaque);
        DD("%s: CMD_POLL > status=%d", __FUNCTION__, dev->status);
        break;

    case PIPE_CMD_READ_BUFFER: {
        /* Translate virtual address into physical one, into emulator memory. */
        GoldfishPipeBuffer  buffer;
        uint32_t            address = dev->address;
        //uint32_t            page    = address & TARGET_PAGE_MASK;
        //target_phys_addr_t  phys;
#ifdef CONFIG_KVM
        if(kvm_enabled()) {
            cpu_synchronize_state(env);
        }
#endif
        buffer.addr = address;
        //phys = cpu_get_phys_page_debug(env, page);
        //buffer.data = qemu_get_ram_ptr(phys) + (address - page);
        buffer.size = dev->size;
        dev->status = pipe->funcs->recvBuffers(pipe->opaque, &buffer, 1);
        DD("%s: CMD_READ_BUFFER channel=0x%x address=0x%08x size=%d > status=%d",
           __FUNCTION__, dev->channel, dev->address, dev->size, dev->status);
        break;
    }

    case PIPE_CMD_WRITE_BUFFER: {
        /* Translate virtual address into physical one, into emulator memory. */
        GoldfishPipeBuffer  buffer;
        uint32_t            address = dev->address;
        //uint32_t            page    = address & TARGET_PAGE_MASK;
        //target_phys_addr_t  phys;
#ifdef CONFIG_KVM
        if(kvm_enabled()) {
            cpu_synchronize_state(env);
        }
#endif
        //phys = cpu_get_phys_page_debug(env, page);
        //buffer.data = qemu_get_ram_ptr(phys) + (address - page);
        buffer.addr = address;
        buffer.size = dev->size;
        dev->status = pipe->funcs->sendBuffers(pipe->opaque, &buffer, 1);
        DD("%s: CMD_WRITE_BUFFER channel=0x%x address=0x%08x size=%d > status=%d",
           __FUNCTION__, dev->channel, dev->address, dev->size, dev->status);
        break;
    }

    case PIPE_CMD_WAKE_ON_READ:
        DD("%s: CMD_WAKE_ON_READ channel=0x%x", __FUNCTION__, dev->channel);
        if ((pipe->wanted & PIPE_WAKE_READ) == 0) {
            pipe->wanted |= PIPE_WAKE_READ;
            pipe->funcs->wakeOn(pipe->opaque, pipe->wanted);
        }
        dev->status = 0;
        break;

    case PIPE_CMD_WAKE_ON_WRITE:
        DD("%s: CMD_WAKE_ON_WRITE channel=0x%x", __FUNCTION__, dev->channel);
        if ((pipe->wanted & PIPE_WAKE_WRITE) == 0) {
            pipe->wanted |= PIPE_WAKE_WRITE;
            pipe->funcs->wakeOn(pipe->opaque, pipe->wanted);
        }
        dev->status = 0;
        break;

    default:
        D("%s: command=%d (0x%x)\n", __FUNCTION__, command, command);
    }
}

static void pipe_dev_write(void *opaque, target_phys_addr_t offset, uint32_t value)
{
    PipeDevice *s = (PipeDevice *)opaque;

    switch (offset) {
    case PIPE_REG_COMMAND:
        DR("%s: command=%d (0x%x)", __FUNCTION__, value, value);
        pipeDevice_doCommand(s, value);
        break;

    case PIPE_REG_SIZE:
        DR("%s: size=%d (0x%x)", __FUNCTION__, value, value);
        s->size = value;
        break;

    case PIPE_REG_ADDRESS:
        DR("%s: address=%d (0x%x)", __FUNCTION__, value, value);
        s->address = value;
        break;

    case PIPE_REG_CHANNEL:
        DR("%s: channel=%d (0x%x)", __FUNCTION__, value, value);
        s->channel = value;
        break;

    case PIPE_REG_PARAMS_ADDR_HIGH:
        s->params_addr = (s->params_addr & ~(0xFFFFFFFFULL << 32) ) |
                          ((uint64_t)value << 32);
        break;

    case PIPE_REG_PARAMS_ADDR_LOW:
        s->params_addr = (s->params_addr & ~(0xFFFFFFFFULL) ) | value;
        break;

    case PIPE_REG_ACCESS_PARAMS:
    {
        struct access_params aps;
        uint32_t cmd;

        /* Don't touch aps.result if anything wrong */
        if (s->params_addr == 0)
            break;

        cpu_physical_memory_read(s->params_addr, (void*)&aps,
                        sizeof(struct access_params));

        /* sync pipe device state from batch buffer */
        s->channel = aps.channel;
        s->size = aps.size;
        s->address = aps.address;
        cmd = aps.cmd;
        if ((cmd != PIPE_CMD_READ_BUFFER) && (cmd != PIPE_CMD_WRITE_BUFFER))
            break;

        pipeDevice_doCommand(s, cmd);
        aps.result = s->status;
        cpu_physical_memory_write(s->params_addr, (void*)&aps,
                    sizeof(struct access_params));
    }
    break;

    default:
        D("%s: offset=%d (0x%x) value=%d (0x%x)\n", __FUNCTION__, offset,
            offset, value, value);
        break;
    }
}

/* I/O read */
static uint32_t pipe_dev_read(void *opaque, target_phys_addr_t offset)
{
    PipeDevice *dev = (PipeDevice *)opaque;

    switch (offset) {
    case PIPE_REG_STATUS:
        DR("%s: REG_STATUS status=%d (0x%x)", __FUNCTION__, dev->status, dev->status);
        return dev->status;

    case PIPE_REG_CHANNEL:
        if (dev->signaled_pipes != NULL) {
            Pipe* pipe = dev->signaled_pipes;
            DR("%s: channel=0x%x wanted=%d", __FUNCTION__,
               pipe->channel, pipe->wanted);
            dev->wakes = pipe->wanted;
            pipe->wanted = 0;
            dev->signaled_pipes = pipe->next_waked;
            pipe->next_waked = NULL;
            if (dev->signaled_pipes == NULL) {
                goldfish_device_set_irq(&dev->dev, 0, 0);
                DD("%s: lowering IRQ", __FUNCTION__);
            }
            return pipe->channel;
        }
        DR("%s: no signaled channels", __FUNCTION__);
        return 0;

    case PIPE_REG_WAKES:
        DR("%s: wakes %d", __FUNCTION__, dev->wakes);
        return dev->wakes;

    case PIPE_REG_PARAMS_ADDR_HIGH:
        return dev->params_addr >> 32;

    case PIPE_REG_PARAMS_ADDR_LOW:
        return dev->params_addr & 0xFFFFFFFFUL;

    default:
        D("%s: offset=%d (0x%x)\n", __FUNCTION__, offset, offset);
    }
    return 0;
}

static CPUReadMemoryFunc *pipe_dev_readfn[] = {
   pipe_dev_read,
   pipe_dev_read,
   pipe_dev_read
};

static CPUWriteMemoryFunc *pipe_dev_writefn[] = {
   pipe_dev_write,
   pipe_dev_write,
   pipe_dev_write
};

static void
goldfish_pipe_save( QEMUFile* file, void* opaque )
{
    PipeDevice* dev = opaque;
    Pipe* pipe;

    qemu_put_be32(file, dev->address);
    qemu_put_be32(file, dev->size);
    qemu_put_be32(file, dev->status);
    qemu_put_be32(file, dev->channel);
    qemu_put_be32(file, dev->wakes);
    qemu_put_be64(file, dev->params_addr);

    /* Count the number of pipe connections */
    int count = 0;
    for ( pipe = dev->pipes; pipe; pipe = pipe->next )
        count++;

    qemu_put_sbe32(file, count);

    /* Now save each pipe one after the other */
    for ( pipe = dev->pipes; pipe; pipe = pipe->next ) {
        pipe_save(pipe, file);
    }
}

static int
goldfish_pipe_load( QEMUFile* file, void* opaque, int version_id )
{
    PipeDevice* dev = opaque;
    Pipe*       pipe;

    if (version_id != GOLDFISH_PIPE_SAVE_VERSION)
        return -EINVAL;

    dev->address = qemu_get_be32(file);
    dev->size    = qemu_get_be32(file);
    dev->status  = qemu_get_be32(file);
    dev->channel = qemu_get_be32(file);
    dev->wakes   = qemu_get_be32(file);
    dev->params_addr   = qemu_get_be64(file);

    /* Count the number of pipe connections */
    int count = qemu_get_sbe32(file);

    /* Load all pipe connections */
    for ( ; count > 0; count-- ) {
        pipe = pipe_load(dev, file);
        if (pipe == NULL) {
            return -EIO;
        }
        pipe->next = dev->pipes;
        dev->pipes = pipe;
    }

    /* Now we need to wake/close all relevant pipes */
    for ( pipe = dev->pipes; pipe; pipe = pipe->next ) {
        if (pipe->wanted != 0)
            goldfish_pipe_wake(pipe, pipe->wanted);
        if (pipe->closed != 0)
            goldfish_pipe_close(pipe);
    }
    return 0;
}

static int goldfish_pipe_init(GoldfishDevice *dev){
    register_savevm(&dev->qdev, "goldfish_pipe", 0, GOLDFISH_PIPE_SAVE_VERSION,
                      goldfish_pipe_save, goldfish_pipe_load, dev);
    return 0;
}

DeviceState *goldfish_pipe_create(GoldfishBus* gbus)
{
    DeviceState *dev;
    char *name = (char*)"qemu_pipe";
    dev = qdev_create(&gbus->bus, name);
    qdev_prop_set_string(dev, "name", name);
    qdev_init_nofail(dev);
    

    return dev;
}

static GoldfishDeviceInfo goldfish_pipe_info = {
    .init = goldfish_pipe_init,
    .readfn = pipe_dev_readfn,
    .writefn = pipe_dev_writefn,
    .qdev.name = "qemu_pipe",
    .qdev.size = sizeof(PipeDevice),
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT32("base", GoldfishDevice, base, 0),
        DEFINE_PROP_UINT32("id", GoldfishDevice, id, -1),
        DEFINE_PROP_UINT32("size", GoldfishDevice, size, 0x2000),
        DEFINE_PROP_UINT32("irq", GoldfishDevice, irq, 0),
        DEFINE_PROP_UINT32("irq_count", GoldfishDevice, irq_count, 1),
        DEFINE_PROP_STRING("name", GoldfishDevice, name),
    /*uint32_t  address;
    uint32_t  size;
    uint32_t  status;
    uint32_t  channel;
    uint32_t  wakes;
    uint64_t  params_addr;*/
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void goldfish_pipe_register(void)
{
    goldfish_bus_register_withprop(&goldfish_pipe_info);
    #if DEBUG_ZERO_PIPE
    goldfish_pipe_add_type("zero", NULL, &zeroPipe_funcs);
    #endif
    #if DEBUG_PINGPONG_PIPE
    goldfish_pipe_add_type("pingpong", NULL, &pingPongPipe_funcs);
    #endif
    #if DEBUG_THROTTLE_PIPE
    goldfish_pipe_add_type("throttle", NULL, &throttlePipe_funcs);
    #endif
}
device_init(goldfish_pipe_register);


void
goldfish_pipe_wake( void* hwpipe, unsigned flags )
{
    Pipe*  pipe = hwpipe;
    Pipe** lookup;
    PipeDevice*  dev = pipe->device;

    DD("%s: channel=0x%x flags=%d", __FUNCTION__, pipe->channel, flags);

    /* If not already there, add to the list of signaled pipes */
    lookup = pipe_list_findp_waked(&dev->signaled_pipes, pipe);
    if (!*lookup) {
        pipe->next_waked = dev->signaled_pipes;
        dev->signaled_pipes = pipe;
    }
    pipe->wanted |= (unsigned)flags;

    /* Raise IRQ to indicate there are items on our list ! */
    goldfish_device_set_irq(&dev->dev, 0, 1);
    DD("%s: raising IRQ", __FUNCTION__);
}

void
goldfish_pipe_close( void* hwpipe )
{
    Pipe* pipe = hwpipe;

    D("%s: channel=0x%x (closed=%d)", __FUNCTION__, pipe->channel, pipe->closed);

    if (!pipe->closed) {
        pipe->closed = 1;
        goldfish_pipe_wake( hwpipe, PIPE_WAKE_CLOSED );
    }
}
