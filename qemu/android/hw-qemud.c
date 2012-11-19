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
#include "android/hw-qemud.h"
#include "android/utils/debug.h"
#include "android/utils/misc.h"
#include "android/utils/system.h"
#include "android/utils/bufprint.h"
#include "android/looper.h"
#include "hw/hw.h"
#include "hw/goldfish_pipe.h"
#include "qemu-char.h"
#include "charpipe.h"
#include "cbuffer.h"
#include "utils/panic.h"

#define  D(...)    VERBOSE_PRINT(qemud,__VA_ARGS__)
#define  D_ACTIVE  VERBOSE_CHECK(qemud)

/* the T(...) macro is used to dump traffic */
#define  T_ACTIVE   0

#if T_ACTIVE
#define  T(...)    VERBOSE_PRINT(qemud,__VA_ARGS__)
#else
#define  T(...)    ((void)0)
#endif

/* max serial MTU. Don't change this without modifying
 * development/emulator/qemud/qemud.c as well.
 */
#define  MAX_SERIAL_PAYLOAD        4000

/* max framed data payload. Must be < (1 << 16)
 */
#define  MAX_FRAME_PAYLOAD  65535

/* Version number of snapshots code. Increment whenever the data saved
 * or the layout in which it is saved is changed.
 */
#define QEMUD_SAVE_VERSION 2

#define min(a, b) (((a) < (b)) ? (a) : (b))


/* define SUPPORT_LEGACY_QEMUD to 1 if you want to support
 * talking to a legacy qemud daemon. See docs/ANDROID-QEMUD.TXT
 * for details.
 */
#ifdef TARGET_ARM
#define  SUPPORT_LEGACY_QEMUD  0
#endif
#ifdef TARGET_I386
#define  SUPPORT_LEGACY_QEMUD  0 /* no legacy support */
#endif
#if SUPPORT_LEGACY_QEMUD
#include "telephony/android_modem.h"
#include "telephony/modem_driver.h"
#endif

/*
 *  This implements support for the 'qemud' multiplexing communication
 *  channel between clients running in the emulated system and 'services'
 *  provided by the emulator.
 *
 *  For additional details, please read docs/ANDROID-QEMUD.TXT
 *
 */

/*
 * IMPLEMENTATION DETAILS:
 *
 * We use one charpipe to connect the emulated serial port to the 'QemudSerial'
 * object. This object is used to receive data from the serial port, and
 * unframe messages (i.e. extract payload length + channel id from header,
 * then the payload itself), before sending them to a generic receiver.
 *
 * The QemudSerial object can also be used to send messages to the daemon
 * through the serial port (see qemud_serial_send())
 *
 * The multiplexer is connected to one or more 'service' objects.
 * are themselves connected through a charpipe to an emulated device or
 * control sub-module in the emulator.
 *
 *  tty <==charpipe==> QemudSerial ---> QemudMultiplexer ----> QemudClient
 *                          ^                                      |
 *                          |                                      |
 *                          +--------------------------------------+
 *
 */

/** HANDLING INCOMING DATA FRAMES
 **/

/* A QemudSink is just a handly data structure that is used to
 * read a fixed amount of bytes into a buffer
 */
typedef struct QemudSink {
    int       used;  /* number of bytes already used */
    int       size;  /* total number of bytes in buff */
    uint8_t*  buff;
} QemudSink;

/* save the state of a QemudSink to a snapshot.
 *
 * The buffer pointer is not saved, since it usually points to buffer
 * fields in other structs, which have save functions themselves. It
 * is up to the caller to make sure the buffer is correctly saved and
 * restored.
 */
static void
qemud_sink_save(QEMUFile* f, QemudSink* s)
{
    qemu_put_be32(f, s->used);
    qemu_put_be32(f, s->size);
}

/* load the state of a QemudSink from a snapshot.
 */
static int
qemud_sink_load(QEMUFile* f, QemudSink* s)
{
    s->used = qemu_get_be32(f);
    s->size = qemu_get_be32(f);
    return 0;
}


/* reset a QemudSink, i.e. provide a new destination buffer address
 * and its size in bytes.
 */
static void
qemud_sink_reset( QemudSink*  ss, int  size, uint8_t*  buffer )
{
    ss->used = 0;
    ss->size = size;
    ss->buff = buffer;
}

/* try to fill the sink by reading bytes from the source buffer
 * '*pmsg' which contains '*plen' bytes
 *
 * this functions updates '*pmsg' and '*plen', and returns
 * 1 if the sink's destination buffer is full, or 0 otherwise.
 */
static int
qemud_sink_fill( QemudSink*  ss, const uint8_t* *pmsg, int  *plen)
{
    int  avail = ss->size - ss->used;

    if (avail <= 0)
        return 1;

    if (avail > *plen)
        avail = *plen;

    memcpy(ss->buff + ss->used, *pmsg, avail);
    *pmsg += avail;
    *plen -= avail;
    ss->used += avail;

    return (ss->used == ss->size);
}

/* returns the number of bytes needed to fill a sink's destination
 * buffer.
 */
static int
qemud_sink_needed( QemudSink*  ss )
{
    return ss->size - ss->used;
}

/** HANDLING SERIAL PORT CONNECTION
 **/

/* The QemudSerial object receives data from the serial port charpipe.
 * It parses the header to extract the channel id and payload length,
 * then the message itself.
 *
 * Incoming messages are sent to a generic receiver identified by
 * the 'recv_opaque' and 'recv_func' parameters to qemud_serial_init()
 *
 * It also provides qemud_serial_send() which can be used to send
 * messages back through the serial port.
 */

#define  HEADER_SIZE    6

#define  LENGTH_OFFSET  2
#define  LENGTH_SIZE    4

#define  CHANNEL_OFFSET 0
#define  CHANNEL_SIZE   2

#if SUPPORT_LEGACY_QEMUD
typedef enum {
    QEMUD_VERSION_UNKNOWN,
    QEMUD_VERSION_LEGACY,
    QEMUD_VERSION_NORMAL
} QemudVersion;

#  define  LEGACY_LENGTH_OFFSET   0
#  define  LEGACY_CHANNEL_OFFSET  4
#endif

/* length of the framed header */
#define  FRAME_HEADER_SIZE  4

#define  BUFFER_SIZE    MAX_SERIAL_PAYLOAD

/* out of convenience, the incoming message is zero-terminated
 * and can be modified by the receiver (e.g. for tokenization).
 */
typedef void  (*QemudSerialReceive)( void*  opaque, int  channel, uint8_t*  msg, int  msglen);

typedef struct QemudSerial {
    CharDriverState*  cs;  /* serial charpipe endpoint */

    /* managing incoming packets from the serial port */
    bool         need_header;
    int           overflow;
    int           in_size;
    int           in_channel;
#if SUPPORT_LEGACY_QEMUD
    QemudVersion  version;
#endif
    QemudSink     header[1];
    QemudSink     payload[1];
    uint8_t       data0[MAX_SERIAL_PAYLOAD+1];

    /* receiver */
    QemudSerialReceive  recv_func;    /* receiver callback */
    void*               recv_opaque;  /* receiver user-specific data */
} QemudSerial;


/* Save the state of a QemudSerial to a snapshot file.
 */
static void
qemud_serial_save(QEMUFile* f, QemudSerial* s)
{
    /* cs, recv_func and recv_opaque are not saved, as these are assigned only
     * during emulator init. A load within a session can re-use the values
     * already assigned, a newly launched emulator has freshly assigned values.
     */

    /* state of incoming packets from the serial port */
    qemu_put_be32(f, s->need_header);
    qemu_put_be32(f, s->overflow);
    qemu_put_be32(f, s->in_size);
    qemu_put_be32(f, s->in_channel);
#if SUPPORT_LEGACY_QEMUD
    qemu_put_be32(f, s->version);
#endif
    qemud_sink_save(f, s->header);
    qemud_sink_save(f, s->payload);
    qemu_put_be32(f, MAX_SERIAL_PAYLOAD+1);
    qemu_put_buffer(f, s->data0, MAX_SERIAL_PAYLOAD+1);
}

/* Load the state of a QemudSerial from a snapshot file.
 */
static int
qemud_serial_load(QEMUFile* f, QemudSerial* s)
{
    /* state of incoming packets from the serial port */
    s->need_header = qemu_get_be32(f);
    s->overflow    = qemu_get_be32(f);
    s->in_size     = qemu_get_be32(f);
    s->in_channel  = qemu_get_be32(f);
#if SUPPORT_LEGACY_QEMUD
    s->version = qemu_get_be32(f);
#endif
    qemud_sink_load(f, s->header);
    qemud_sink_load(f, s->payload);

    /* s->header and s->payload are only ever connected to s->data0 */
    s->header->buff = s->payload->buff = s->data0;

    int len = qemu_get_be32(f);
    if (len - 1 > MAX_SERIAL_PAYLOAD) {
        D("%s: load failed: size of saved payload buffer (%d) exceeds "
          "current maximum (%d)\n",
          __FUNCTION__, len - 1, MAX_SERIAL_PAYLOAD);
        return -EIO;
    }
    int ret;
    if ((ret = qemu_get_buffer(f, s->data0, len)) != len) {
        D("%s: failed to load serial buffer contents (tried reading %d bytes, got %d)\n",
          __FUNCTION__, len, ret);
        return -EIO;
    }

    return 0;
}

/* called by the charpipe to see how much bytes can be
 * read from the serial port.
 */
static int
qemud_serial_can_read( void*  opaque )
{
    QemudSerial*  s = opaque;

    if (s->overflow > 0) {
        return s->overflow;
    }

    /* if in_size is 0, we're reading the header */
    if (s->need_header)
        return qemud_sink_needed(s->header);

    /* otherwise, we're reading the payload */
    return qemud_sink_needed(s->payload);
}

/* called by the charpipe to read data from the serial
 * port. 'len' cannot be more than the value returned
 * by 'qemud_serial_can_read'.
 */
static void
qemud_serial_read( void*  opaque, const uint8_t*  from, int  len )
{
    QemudSerial*  s = opaque;

    T("%s: received %3d bytes: '%s'", __FUNCTION__, len, quote_bytes((const void*)from, len));

    while (len > 0) {
        int  avail;

        /* skip overflow bytes */
        if (s->overflow > 0) {
            avail = s->overflow;
            if (avail > len)
                avail = len;

            from += avail;
            len  -= avail;
            continue;
        }

        /* read header if needed */
        if (s->need_header) {
            if (!qemud_sink_fill(s->header, (const uint8_t**)&from, &len))
                break;

#if SUPPORT_LEGACY_QEMUD
            if (s->version == QEMUD_VERSION_UNKNOWN) {
                /* if we receive "001200" as the first header, then we
                 * detected a legacy qemud daemon. See the comments
                 * in qemud_serial_send_legacy_probe() for details.
                 */
                if ( !memcmp(s->data0, "001200", 6) ) {
                    D("%s: legacy qemud detected.", __FUNCTION__);
                    s->version = QEMUD_VERSION_LEGACY;
                    /* tell the modem to use legacy emulation mode */
                    amodem_set_legacy(android_modem);
                } else {
                    D("%s: normal qemud detected.", __FUNCTION__);
                    s->version = QEMUD_VERSION_NORMAL;
                }
            }

            if (s->version == QEMUD_VERSION_LEGACY) {
                s->in_size     = hex2int( s->data0 + LEGACY_LENGTH_OFFSET,  LENGTH_SIZE );
                s->in_channel  = hex2int( s->data0 + LEGACY_CHANNEL_OFFSET, CHANNEL_SIZE );
            } else {
                s->in_size     = hex2int( s->data0 + LENGTH_OFFSET,  LENGTH_SIZE );
                s->in_channel  = hex2int( s->data0 + CHANNEL_OFFSET, CHANNEL_SIZE );
            }
#else
            /* extract payload length + channel id */
            s->in_size     = hex2int( s->data0 + LENGTH_OFFSET,  LENGTH_SIZE );
            s->in_channel  = hex2int( s->data0 + CHANNEL_OFFSET, CHANNEL_SIZE );
#endif
            s->header->used = 0;

            if (s->in_size <= 0 || s->in_channel < 0) {
                D("%s: bad header: '%.*s'", __FUNCTION__, HEADER_SIZE, s->data0);
                continue;
            }

            if (s->in_size > MAX_SERIAL_PAYLOAD) {
                D("%s: ignoring huge serial packet: length=%d channel=%1",
                  __FUNCTION__, s->in_size, s->in_channel);
                s->overflow = s->in_size;
                continue;
            }

            /* prepare 'in_data' for payload */
            s->need_header = 0;
            qemud_sink_reset(s->payload, s->in_size, s->data0);
        }

        /* read payload bytes */
        if (!qemud_sink_fill(s->payload, &from, &len))
            break;

        /* zero-terminate payload, then send it to receiver */
        s->payload->buff[s->payload->size] = 0;
        D("%s: channel=%2d len=%3d '%s'", __FUNCTION__,
          s->in_channel, s->payload->size,
          quote_bytes((const void*)s->payload->buff, s->payload->size));

        s->recv_func( s->recv_opaque, s->in_channel, s->payload->buff, s->payload->size );

        /* prepare for new header */
        s->need_header = 1;
    }
}


#if SUPPORT_LEGACY_QEMUD
static void
qemud_serial_send_legacy_probe( QemudSerial*  s )
{
    /* we're going to send a specially crafted packet to the qemud
     * daemon, this will help us determine whether we're talking
     * to a legacy or a normal daemon.
     *
     * the trick is to known that a legacy daemon uses the following
     * header:
     *
     *    <length><channel><payload>
     *
     * while the normal one uses:
     *
     *    <channel><length><payload>
     *
     * where <channel> is a 2-hexchar string, and <length> a 4-hexchar
     * string.
     *
     * if we send a header of "000100", it is interpreted:
     *
     * - as the header of a 1-byte payload by the legacy daemon
     * - as the header of a 256-byte payload by the normal one.
     *
     * we're going to send something that looks like:
     *
     *   "000100" + "X" +
     *   "000b00" + "connect:gsm" +
     *   "000b00" + "connect:gps" +
     *   "000f00" + "connect:control" +
     *   "00c210" + "0"*194
     *
     * the normal daemon will interpret this as a 256-byte payload
     * for channel 0, with garbage content ("X000b00conn...") which
     * will be silently ignored.
     *
     * on the other hand, the legacy daemon will see it as a
     * series of packets:
     *
     *   one message "X" on channel 0, which will force the daemon
     *   to send back "001200ko:unknown command" as its first answer.
     *
     *   three "connect:<xxx>" messages used to receive the channel
     *   numbers of the three legacy services implemented by the daemon.
     *
     *   a garbage packet of 194 zeroes for channel 16, which will be
     *   silently ignored.
     */
    uint8_t  tab[194];

    memset(tab, 0, sizeof(tab));
    qemu_chr_fe_write(s->cs, (uint8_t*)"000100X", 7);
    qemu_chr_fe_write(s->cs, (uint8_t*)"000b00connect:gsm", 17);
    qemu_chr_fe_write(s->cs, (uint8_t*)"000b00connect:gps", 17);
    qemu_chr_fe_write(s->cs, (uint8_t*)"000f00connect:control", 21);
    qemu_chr_fe_write(s->cs, (uint8_t*)"00c210", 6);
    qemu_chr_fe_write(s->cs, tab, sizeof(tab));
}
#endif /* SUPPORT_LEGACY_QEMUD */

/* intialize a QemudSerial object with a charpipe endpoint
 * and a receiver.
 */
static void
qemud_serial_init( QemudSerial*        s,
                   CharDriverState*    cs,
                   QemudSerialReceive  recv_func,
                   void*               recv_opaque )
{
    s->cs           = cs;
    s->recv_func    = recv_func;
    s->recv_opaque  = recv_opaque;
    s->need_header  = 1;
    s->overflow     = 0;

    qemud_sink_reset( s->header, HEADER_SIZE, s->data0 );
    s->in_size      = 0;
    s->in_channel   = -1;

#if SUPPORT_LEGACY_QEMUD
    s->version = QEMUD_VERSION_UNKNOWN;
    qemud_serial_send_legacy_probe(s);
#endif

    qemu_chr_add_handlers( cs,
                           qemud_serial_can_read,
                           qemud_serial_read,
                           NULL,
                           s );
}

/* send a message to the serial port. This will add the necessary
 * header.
 */
static void
qemud_serial_send( QemudSerial*    s,
                   int             channel,
                   bool            framing,
                   const uint8_t*  msg,
                   int             msglen )
{
    uint8_t   header[HEADER_SIZE];
    uint8_t   frame[FRAME_HEADER_SIZE];
    int       avail, len = msglen;

    if (msglen <= 0 || channel < 0)
        return;

    D("%s: channel=%2d len=%3d '%s'",
      __FUNCTION__, channel, msglen,
      quote_bytes((const void*)msg, msglen));

    if (framing) {
        len += FRAME_HEADER_SIZE;
    }

    /* packetize the payload for the serial MTU */
    while (len > 0)
    {
        avail = len;
        if (avail > MAX_SERIAL_PAYLOAD)
            avail = MAX_SERIAL_PAYLOAD;

        /* write this packet's header */
#if SUPPORT_LEGACY_QEMUD
        if (s->version == QEMUD_VERSION_LEGACY) {
            int2hex(header + LEGACY_LENGTH_OFFSET,  LENGTH_SIZE,  avail);
            int2hex(header + LEGACY_CHANNEL_OFFSET, CHANNEL_SIZE, channel);
        } else {
            int2hex(header + LENGTH_OFFSET,  LENGTH_SIZE,  avail);
            int2hex(header + CHANNEL_OFFSET, CHANNEL_SIZE, channel);
        }
#else
        int2hex(header + LENGTH_OFFSET,  LENGTH_SIZE,  avail);
        int2hex(header + CHANNEL_OFFSET, CHANNEL_SIZE, channel);
#endif
        T("%s: '%.*s'", __FUNCTION__, HEADER_SIZE, header);
        qemu_chr_fe_write(s->cs, header, HEADER_SIZE);

        /* insert frame header when needed */
        if (framing) {
            int2hex(frame, FRAME_HEADER_SIZE, msglen);
            T("%s: '%.*s'", __FUNCTION__, FRAME_HEADER_SIZE, frame);
            qemu_chr_fe_write(s->cs, frame, FRAME_HEADER_SIZE);
            avail  -= FRAME_HEADER_SIZE;
            len    -= FRAME_HEADER_SIZE;
            framing = 0;
        }

        /* write message content */
        T("%s: '%.*s'", __FUNCTION__, avail, msg);
        qemu_chr_fe_write(s->cs, msg, avail);
        msg += avail;
        len -= avail;
    }
}

/** CLIENTS
 **/

/* Descriptor for a data buffer pending to be sent to a qemud pipe client.
 *
 * When a service decides to send data to the client, there could be cases when
 * client is not ready to read them. In this case there is no GoldfishPipeBuffer
 * available to write service's data to, So, we need to cache that data into the
 * client descriptor, and "send" them over to the client in _qemudPipe_recvBuffers
 * callback. Pending service data is stored in the client descriptor as a list
 * of QemudPipeMessage instances.
 */
typedef struct QemudPipeMessage QemudPipeMessage;
struct QemudPipeMessage {
    /* Message to send. */
    uint8_t*            message;
    /* Message size. */
    size_t              size;
    /* Offset in the message buffer of the chunk, that has not been sent
     * to the pipe yet. */
    size_t              offset;
    /* Links next message in the client. */
    QemudPipeMessage*   next;
};


/* A QemudClient models a single client as seen by the emulator.
 * Each client has its own channel id (for the serial qemud), or pipe descriptor
 * (for the pipe based qemud), and belongs to a given QemudService (see below).
 *
 * There is a global list of serial clients used to multiplex incoming
 * messages from the channel id (see qemud_multiplexer_serial_recv()). Pipe
 * clients don't need multiplexing, because they are communicated via qemud pipes
 * that are unique for each client.
 *
 */

/* Defines type of the client: pipe, or serial.
 */
typedef enum QemudProtocol {
    /* Client is communicating via pipe. */
    QEMUD_PROTOCOL_PIPE,
    /* Client is communicating via serial port. */
    QEMUD_PROTOCOL_SERIAL
} QemudProtocol;

/* Descriptor for a QEMUD pipe connection.
 *
 * Every time a client connects to the QEMUD via pipe, an instance of this
 * structure is created to represent a connection used by new pipe client.
 */
typedef struct QemudPipe {
    /* Pipe descriptor. */
    void*           hwpipe;
    /* Looper used for I/O */
    void*           looper;
    /* Service for this pipe. */
    QemudService*   service;
    /* Client for this pipe. */
    QemudClient*    client;
} QemudPipe;

struct QemudClient {
    /* Defines protocol, used by the client. */
    QemudProtocol     protocol;

    /* Fields that are common for all protocols. */
    char*             param;
    void*             clie_opaque;
    QemudClientRecv   clie_recv;
    QemudClientClose  clie_close;
    QemudClientSave   clie_save;
    QemudClientLoad   clie_load;
    QemudService*     service;
    QemudClient*      next_serv; /* next in same service */
    QemudClient*      next;
    QemudClient**     pref;

    /* framing support */
    int               framing;
    bool             need_header;
    bool             closing;
    QemudSink         header[1];
    uint8_t           header0[FRAME_HEADER_SIZE];
    QemudSink         payload[1];

    /* Fields that are protocol-specific. */
    union {
        /* Serial-specific fields. */
        struct {
            int                 channel;
            QemudSerial*        serial;
        } Serial;
        /* Pipe-specific fields. */
        struct {
            QemudPipe*          qemud_pipe;
            QemudPipeMessage*   messages;
        } Pipe;
    } ProtocolSelector;
};

static bool
_is_pipe_client(QemudClient* client)
{
    return (client-> protocol == QEMUD_PROTOCOL_PIPE) ? true : false;
}

static void  qemud_service_remove_client( QemudService*  service,
                                          QemudClient*   client );

/* remove a QemudClient from global list */
static void
qemud_client_remove( QemudClient*  c )
{
    c->pref[0] = c->next;
    if (c->next)
        c->next->pref = c->pref;

    c->next = NULL;
    c->pref = &c->next;
}

/* add a QemudClient to global list */
static void
qemud_client_prepend( QemudClient*  c, QemudClient** plist )
{
    c->next = *plist;
    c->pref = plist;
    *plist  = c;
    if (c->next)
        c->next->pref = &c->next;
}

/* receive a new message from a client, and dispatch it to
 * the real service implementation.
 */
static void
qemud_client_recv( void*  opaque, uint8_t*  msg, int  msglen )
{
    QemudClient*  c = opaque;

    /* no framing, things are simple */
    if (!c->framing) {
        if (c->clie_recv)
            c->clie_recv( c->clie_opaque, msg, msglen, c );
        return;
    }

    /* framing */

#if 1
    /* special case, in 99% of cases, everything is in
     * the incoming message, and we can do all we need
     * directly without dynamic allocation.
     */
    if (msglen > FRAME_HEADER_SIZE   &&
        c->need_header == 1          &&
        qemud_sink_needed(c->header) == 0)
    {
        int  len = hex2int( msg, FRAME_HEADER_SIZE );

        if (len >= 0 && msglen == len + FRAME_HEADER_SIZE) {
            if (c->clie_recv)
                c->clie_recv( c->clie_opaque,
                              msg+FRAME_HEADER_SIZE,
                              msglen-FRAME_HEADER_SIZE, c );
            return;
        }
    }
#endif

    while (msglen > 0) {
        uint8_t *data;

        /* read the header */
        if (c->need_header) {
            int       frame_size;
            uint8_t*  data;

            if (!qemud_sink_fill(c->header, (const uint8_t**)&msg, &msglen))
                break;

            frame_size = hex2int(c->header0, 4);
            if (frame_size == 0) {
                D("%s: ignoring empty frame", __FUNCTION__);
                continue;
            }
            if (frame_size < 0) {
                D("%s: ignoring corrupted frame header '.*s'",
                  __FUNCTION__, FRAME_HEADER_SIZE, c->header0 );
                continue;
            }

            AARRAY_NEW(data, frame_size+1);  /* +1 for terminating zero */
            qemud_sink_reset(c->payload, frame_size, data);
            c->need_header = 0;
            c->header->used = 0;
        }

        /* read the payload */
        if (!qemud_sink_fill(c->payload, (const uint8_t**)&msg, &msglen))
            break;

        c->payload->buff[c->payload->size] = 0;
        c->need_header = 1;
        data = c->payload->buff;

        /* Technically, calling 'clie_recv' can destroy client object 'c'
         * if it decides to close the connection, so ensure we don't
         * use/dereference it after the call. */
        if (c->clie_recv)
            c->clie_recv( c->clie_opaque, c->payload->buff, c->payload->size, c );

        AFREE(data);
    }
}

/* Sends data to a pipe-based client.
 */
static void
_qemud_pipe_send(QemudClient*  client, const uint8_t*  msg, int  msglen);

/* Frees memory allocated for the qemud client.
 */
static void
_qemud_client_free(QemudClient* c)
{
    if ( c != NULL) {
        if (_is_pipe_client(c)) {
            /* Free outstanding messages. */
            QemudPipeMessage** msg_list = &c->ProtocolSelector.Pipe.messages;
            while (*msg_list != NULL) {
                QemudPipeMessage* to_free = *msg_list;
                *msg_list = to_free->next;
                free(to_free);
            }
        }
        if (c->param != NULL) {
            free(c->param);
        }
        AFREE(c);
    }
}

/* disconnect a client. this automatically frees the QemudClient.
 * note that this also removes the client from the global list
 * and from its service's list, if any.
 * Param:
 *  opaque - QemuClient instance
 *  guest_close - For pipe clients control whether or not the disconnect is
 *      caused by guest closing the pipe handle (in which case 1 is passed in
 *      this parameter). For serial clients this parameter is ignored.
 */
static void
qemud_client_disconnect( void*  opaque, int guest_close )
{
    QemudClient*  c = opaque;

    if (c->closing) {  /* recursive call, exit immediately */
        return;
    }

    if (_is_pipe_client(c) && !guest_close) {
        /* This is emulator component (rather than the guest) closing a pipe
         * client. Since pipe clients are controlled strictly by the guest, we
         * don't actually close the client here, but notify the guest about the
         * client being disconnected. Then we will do the real client close when
         * the guest explicitly closes the pipe, in which case this routine will
         * be called from the _qemudPipe_closeFromGuest callback with guest_close
         * set to 1. */
        char  tmp[128], *p=tmp, *end=p+sizeof(tmp);
        p = bufprint(tmp, end, "disconnect:00");
        _qemud_pipe_send(c, (uint8_t*)tmp, p-tmp);
        return;
    }

    c->closing = 1;

    /* remove from current list */
    qemud_client_remove(c);

    if (_is_pipe_client(c)) {
        /* We must NULL the client reference in the QemuPipe for this connection,
         * so if a sudden receive request comes after client has been closed, we
         * don't blow up. */
        c->ProtocolSelector.Pipe.qemud_pipe->client = NULL;
    } else if (c->ProtocolSelector.Serial.channel > 0) {
        /* send a disconnect command to the daemon */
        char  tmp[128], *p=tmp, *end=p+sizeof(tmp);
        p = bufprint(tmp, end, "disconnect:%02x",
                     c->ProtocolSelector.Serial.channel);
        qemud_serial_send(c->ProtocolSelector.Serial.serial, 0, 0, (uint8_t*)tmp, p-tmp);
    }

    /* call the client close callback */
    if (c->clie_close) {
        c->clie_close(c->clie_opaque);
        c->clie_close = NULL;
    }
    c->clie_recv = NULL;

    /* remove from service list, if any */
    if (c->service) {
        qemud_service_remove_client(c->service, c);
        c->service = NULL;
    }

    _qemud_client_free(c);
}

/* allocate a new QemudClient object
 * NOTE: channel_id valie is used as a selector between serial and pipe clients.
 * Since channel_id < 0 is an invalid value for a serial client, it would
 * indicate that creating client is a pipe client. */
static QemudClient*
qemud_client_alloc( int               channel_id,
                    const char*       client_param,
                    void*             clie_opaque,
                    QemudClientRecv   clie_recv,
                    QemudClientClose  clie_close,
                    QemudClientSave   clie_save,
                    QemudClientLoad   clie_load,
                    QemudSerial*      serial,
                    QemudClient**     pclients )
{
    QemudClient*  c;

    ANEW0(c);

    if (channel_id < 0) {
        /* Allocating a pipe client. */
        c->protocol = QEMUD_PROTOCOL_PIPE;
        c->ProtocolSelector.Pipe.messages   = NULL;
        c->ProtocolSelector.Pipe.qemud_pipe = NULL;
    } else {
        /* Allocating a serial client. */
        c->protocol = QEMUD_PROTOCOL_SERIAL;
        c->ProtocolSelector.Serial.serial   = serial;
        c->ProtocolSelector.Serial.channel  = channel_id;
    }
    c->param       = client_param ? ASTRDUP(client_param) : NULL;
    c->clie_opaque = clie_opaque;
    c->clie_recv   = clie_recv;
    c->clie_close  = clie_close;
    c->clie_save   = clie_save;
    c->clie_load   = clie_load;
    c->service     = NULL;
    c->next_serv   = NULL;
    c->next        = NULL;
    c->framing     = 0;
    c->need_header = 1;
    qemud_sink_reset(c->header, FRAME_HEADER_SIZE, c->header0);

    qemud_client_prepend(c, pclients);

    return c;
}

/* forward */
static void  qemud_service_save_name( QEMUFile* f, QemudService* s );
static char* qemud_service_load_name( QEMUFile* f );
static QemudService* qemud_service_find(  QemudService*  service_list,
                                          const char*    service_name );
static QemudClient*  qemud_service_connect_client(  QemudService  *sv,
                                                    int           channel_id,
                                                    const char* client_param);

/* Saves the client state needed to re-establish connections on load.
 * Note that we save only serial clients here. The pipe clients will be
 * saved along with the pipe to which they are attached.
 */
static void
qemud_serial_client_save(QEMUFile* f, QemudClient* c)
{
    /* save generic information */
    qemud_service_save_name(f, c->service);
    //qemu_put_string(f, c->param);
    qemu_put_be32(f, c->ProtocolSelector.Serial.channel);

    /* save client-specific state */
    if (c->clie_save)
        c->clie_save(f, c, c->clie_opaque);

    /* save framing configuration */
    qemu_put_be32(f, c->framing);
    if (c->framing) {
        qemu_put_be32(f, c->need_header);
        /* header sink always connected to c->header0, no need to save */
        qemu_put_be32(f, FRAME_HEADER_SIZE);
        qemu_put_buffer(f, c->header0, FRAME_HEADER_SIZE);
        /* payload sink */
        qemud_sink_save(f, c->payload);
        qemu_put_buffer(f, c->payload->buff, c->payload->size);
    }
}

/* Loads client state from file, then starts a new client connected to the
 * corresponding service.
 * Note that we load only serial clients here. The pipe clients will be
 * loaded along with the pipe to which they were attached.
 */
static int
qemud_serial_client_load(QEMUFile* f, QemudService* current_services, int version )
{
    char *service_name = qemud_service_load_name(f);
    if (service_name == NULL)
        return -EIO;
    const char* param = "";//qemu_get_string(f);
    /* get current service instance */
    QemudService *sv = qemud_service_find(current_services, service_name);
    if (sv == NULL) {
        D("%s: load failed: unknown service \"%s\"\n",
          __FUNCTION__, service_name);
        return -EIO;
    }

    int channel = qemu_get_be32(f);

    if (channel == 0) {
        D("%s: illegal snapshot: client for control channel must no be saved\n",
          __FUNCTION__);
        return -EIO;
    }

    /* re-connect client */
    QemudClient* c = qemud_service_connect_client(sv, channel, param);
    if(c == NULL)
        return -EIO;

    /* load client-specific state */
    int ret;
    if (c->clie_load)
        if ((ret = c->clie_load(f, c, c->clie_opaque)))
            return ret;  /* load failure */

    /* load framing configuration */
    c->framing = qemu_get_be32(f);
    if (c->framing) {

        /* header buffer */
        c->need_header = qemu_get_be32(f);
        int header_size = qemu_get_be32(f);
        if (header_size > FRAME_HEADER_SIZE) {
            D("%s: load failed: payload buffer requires %d bytes, %d available\n",
              __FUNCTION__, header_size, FRAME_HEADER_SIZE);
            return -EIO;
        }
        int ret;
        if ((ret = qemu_get_buffer(f, c->header0, header_size)) != header_size) {
            D("%s: frame header buffer load failed: expected %d bytes, got %d\n",
              __FUNCTION__, header_size, ret);
            return -EIO;
        }

        /* payload sink */
        if ((ret = qemud_sink_load(f, c->payload)))
            return ret;

        /* replace payload buffer by saved data */
        if (c->payload->buff) {
            AFREE(c->payload->buff);
        }
        AARRAY_NEW(c->payload->buff, c->payload->size+1);  /* +1 for terminating zero */
        if ((ret = qemu_get_buffer(f, c->payload->buff, c->payload->size)) != c->payload->size) {
            D("%s: frame payload buffer load failed: expected %d bytes, got %d\n",
              __FUNCTION__, c->payload->size, ret);
            AFREE(c->payload->buff);
            return -EIO;
        }
    }

    return 0;
}


/** SERVICES
 **/

/* A QemudService models a _named_ service facility implemented
 * by the emulator, that clients in the emulated system can connect
 * to.
 *
 * Each service can have a limit on the number of clients they
 * accept (this number if unlimited if 'max_clients' is 0).
 *
 * Each service maintains a list of active QemudClients and
 * can also be used to create new QemudClient objects through
 * its 'serv_opaque' and 'serv_connect' fields.
 */
struct QemudService {
    const char*          name;
    int                  max_clients;
    int                  num_clients;
    QemudClient*         clients;
    QemudServiceConnect  serv_connect;
    QemudServiceSave     serv_save;
    QemudServiceLoad     serv_load;
    void*                serv_opaque;
    QemudService*        next;
};

/* Create a new QemudService object */
static QemudService*
qemud_service_new( const char*          name,
                   int                  max_clients,
                   void*                serv_opaque,
                   QemudServiceConnect  serv_connect,
                   QemudServiceSave     serv_save,
                   QemudServiceLoad     serv_load,
                   QemudService**       pservices )
{
    QemudService*  s;

    ANEW0(s);
    s->name        = ASTRDUP(name);
    s->max_clients = max_clients;
    s->num_clients = 0;
    s->clients     = NULL;

    s->serv_opaque  = serv_opaque;
    s->serv_connect = serv_connect;
    s->serv_save = serv_save;
    s->serv_load = serv_load;

    s->next    = *pservices;
    *pservices = s;

    return s;
}

/* used internally to populate a QemudService object with a
 * new QemudClient */
static void
qemud_service_add_client( QemudService*  s, QemudClient*  c )
{
    c->service      = s;
    c->next_serv    = s->clients;
    s->clients      = c;
    s->num_clients += 1;
}

/* used internally to remove a QemudClient from a QemudService */
static void
qemud_service_remove_client( QemudService*  s, QemudClient*  c )
{
    QemudClient**  pnode = &s->clients;
    QemudClient*   node;

    /* remove from clients linked-list */
    for (;;) {
        node = *pnode;
        if (node == NULL) {
            D("%s: could not find client for service '%s'",
              __FUNCTION__, s->name);
            return;
        }
        if (node == c)
            break;
        pnode = &node->next_serv;
    }

    *pnode          = node->next_serv;
    s->num_clients -= 1;
}

/* ask the service to create a new QemudClient. Note that we
 * assume that this calls qemud_client_new() which will add
 * the client to the service's list automatically.
 *
 * returns the client or NULL if an error occurred
 */
static QemudClient*
qemud_service_connect_client(QemudService *sv,
                             int channel_id,
                             const char* client_param)
{
    QemudClient* client =
        sv->serv_connect( sv->serv_opaque, sv, channel_id, client_param );
    if (client == NULL) {
        D("%s: registration failed for '%s' service",
          __FUNCTION__, sv->name);
        return NULL;
    }
    D("%s: registered client channel %d for '%s' service",
      __FUNCTION__, channel_id, sv->name);
    return client;
}

/* find a registered service by name.
 */
static QemudService*
qemud_service_find( QemudService*  service_list, const char*  service_name)
{
    QemudService*  sv = NULL;
    for (sv = service_list; sv != NULL; sv = sv->next) {
        if (!strcmp(sv->name, service_name)) {
            break;
        }
    }
    return sv;
}

/* Save the name of the given service.
 */
static void
qemud_service_save_name(QEMUFile* f, QemudService* s)
{
    int len = strlen(s->name) + 1;  // include '\0' terminator
    qemu_put_be32(f, len);
    qemu_put_buffer(f, (const uint8_t *) s->name, len);
}

/* Load the name of a service. Returns a pointer to the loaded name, or NULL
 * on failure.
 */
static char*
qemud_service_load_name( QEMUFile*  f )
{
    int ret;
    int name_len = qemu_get_be32(f);
    char *service_name = android_alloc(name_len);
    if ((ret = qemu_get_buffer(f, (uint8_t*)service_name, name_len) != name_len)) {
        D("%s: service name load failed: expected %d bytes, got %d\n",
          __FUNCTION__, name_len, ret);
        AFREE(service_name);
        return NULL;
    }
    if (service_name[name_len - 1] != '\0') {
        char last = service_name[name_len - 1];
        service_name[name_len - 1] = '\0';  /* make buffer contents printable */
        D("%s: service name load failed: expecting NULL-terminated string, but "
          "last char is '%c' (buffer contents: '%s%c')\n",
          __FUNCTION__, name_len, last, service_name, last);
        AFREE(service_name);
        return NULL;
    }

    return service_name;
}

/* Saves state of a service.
 */
static void
qemud_service_save(QEMUFile* f, QemudService* s)
{
    qemud_service_save_name(f, s);
    qemu_put_be32(f, s->max_clients);
    qemu_put_be32(f, s->num_clients);

    if (s->serv_save)
        s->serv_save(f, s, s->serv_opaque);
}

/* Loads service state from file, then updates the currently running instance
 * of that service to mirror the loaded state. If the service is not running,
 * the load process is aborted.
 *
 * Parameter 'current_services' should be the list of active services.
 */
static int
qemud_service_load(  QEMUFile*  f, QemudService*  current_services  )
{
    char* service_name = qemud_service_load_name(f);
    if (service_name == NULL)
        return -EIO;

    /* get current service instance */
    QemudService *sv = qemud_service_find(current_services, service_name);
    if (sv == NULL) {
        D("%s: loading failed: service \"%s\" not available\n",
          __FUNCTION__, service_name);
        return -EIO;
    }

    /* reconfigure service as required */
    sv->max_clients = qemu_get_be32(f);
    sv->num_clients = qemu_get_be32(f);

    /* load service specific data */
    int ret;
    if (sv->serv_load)
        if ((ret = sv->serv_load(f, sv, sv->serv_opaque)))
            return ret;  /* load failure */

    return 0;
}


/** MULTIPLEXER
 **/

/* A QemudMultiplexer object maintains the global state of the
 * qemud service facility. It holds a QemudSerial object to
 * maintain the state of the serial port connection.
 *
 * The QemudMultiplexer receives all incoming messages from
 * the serial port, and dispatches them to the appropriate
 * QemudClient.
 *
 * It also has a global list of clients, and a global list of
 * services.
 *
 * Finally, the QemudMultiplexer has a special QemudClient used
 * to handle channel 0, i.e. the control channel used to handle
 * connections and disconnections of clients.
 */
typedef struct QemudMultiplexer  QemudMultiplexer;

struct QemudMultiplexer {
    QemudSerial    serial[1];
    QemudClient*   clients;
    QemudService*  services;
};

/* this is the serial_recv callback that is called
 * whenever an incoming message arrives through the serial port
 */
static void
qemud_multiplexer_serial_recv( void*     opaque,
                               int       channel,
                               uint8_t*  msg,
                               int       msglen )
{
    QemudMultiplexer*  m = opaque;
    QemudClient*       c = m->clients;

    /* dispatch to an existing client if possible
     * note that channel 0 is handled by a special
     * QemudClient that is setup in qemud_multiplexer_init()
     */
    for ( ; c != NULL; c = c->next ) {
        if (!_is_pipe_client(c) && c->ProtocolSelector.Serial.channel == channel) {
            qemud_client_recv(c, msg, msglen);
            return;
        }
    }

    D("%s: ignoring %d bytes for unknown channel %d",
      __FUNCTION__, msglen, channel);
}

/* handle a new connection attempt. This returns 0 on
 * success, -1 if the service name is unknown, or -2
 * if the service's maximum number of clients has been
 * reached.
 */
static int
qemud_multiplexer_connect( QemudMultiplexer*  m,
                           const char*        service_name,
                           int                channel_id )
{
    /* find the corresponding registered service by name */
    QemudService*  sv = qemud_service_find(m->services, service_name);
    if (sv == NULL) {
        D("%s: no registered '%s' service", __FUNCTION__, service_name);
        return -1;
    }

    /* check service's client count */
    if (sv->max_clients > 0 && sv->num_clients >= sv->max_clients) {
        D("%s: registration failed for '%s' service: too many clients (%d)",
          __FUNCTION__, service_name, sv->num_clients);
        return -2;
    }

    /* connect a new client to the service on the given channel */
    if (qemud_service_connect_client(sv, channel_id, NULL) == NULL)
        return -1;

    return 0;
}

/* disconnect a given client from its channel id */
static void
qemud_multiplexer_disconnect( QemudMultiplexer*  m,
                              int                channel )
{
    QemudClient*  c;

    /* find the client by its channel id, then disconnect it */
    for (c = m->clients; c; c = c->next) {
        if (!_is_pipe_client(c) && c->ProtocolSelector.Serial.channel == channel) {
            D("%s: disconnecting client %d",
              __FUNCTION__, channel);
            /* note thatt this removes the client from
             * m->clients automatically.
             */
            c->ProtocolSelector.Serial.channel = -1; /* no need to send disconnect:<id> */
            qemud_client_disconnect(c, 0);
            return;
        }
    }
    D("%s: disconnecting unknown channel %d",
      __FUNCTION__, channel);
}

/* disconnects all channels, except for the control channel, without informing
 * the daemon in the guest that disconnection has occurred.
 *
 * Used to silently kill clients when restoring emulator state snapshots.
 */
static void
qemud_multiplexer_disconnect_noncontrol( QemudMultiplexer*  m )
{
    QemudClient* c;
    QemudClient* next = m->clients;

    while (next) {
        c = next;
        next = c->next;  /* disconnect frees c, remember next in advance */

        if (!_is_pipe_client(c) && c->ProtocolSelector.Serial.channel > 0) {
            /* skip control channel */
            D("%s: disconnecting client %d",
              __FUNCTION__, c->ProtocolSelector.Serial.channel);
            D("%s: disconnecting client %d\n",
              __FUNCTION__, c->ProtocolSelector.Serial.channel);
            c->ProtocolSelector.Serial.channel = -1; /* do not send disconnect:<id> */
            qemud_client_disconnect(c, 0);
        }
    }
}

/* handle control messages. This is used as the receive
 * callback for the special QemudClient setup to manage
 * channel 0.
 *
 * note that the message is zero-terminated for convenience
 * (i.e. msg[msglen] is a valid memory read that returns '\0')
 */
static void
qemud_multiplexer_control_recv( void*         opaque,
                                uint8_t*      msg,
                                int           msglen,
                                QemudClient*  client )
{
    QemudMultiplexer*  mult   = opaque;
    uint8_t*           msgend = msg + msglen;
    char               tmp[64], *p=tmp, *end=p+sizeof(tmp);

    /* handle connection attempts.
     * the client message must be "connect:<service-name>:<id>"
     * where <id> is a 2-char hexadecimal string, which must be > 0
     */
    if (msglen > 8 && !memcmp(msg, "connect:", 8))
    {
        const char*    service_name = (const char*)msg + 8;
        int            channel, ret;
        char*          q;

        q = strchr(service_name, ':');
        if (q == NULL || q+3 != (char*)msgend) {
            D("%s: malformed connect message: '%.*s' (offset=%d)",
              __FUNCTION__, msglen, (const char*)msg, q ? q-(char*)msg : -1);
            return;
        }
        *q++ = 0;  /* zero-terminate service name */
        channel = hex2int((uint8_t*)q, 2);
        if (channel <= 0) {
            D("%s: malformed channel id '%.*s",
              __FUNCTION__, 2, q);
            return;
        }

        ret = qemud_multiplexer_connect(mult, service_name, channel);
        /* the answer can be one of:
         *    ok:connect:<id>
         *    ko:connect:<id>:<reason-for-failure>
         */
        if (ret < 0) {
            if (ret == -1) {
                /* could not connect */
                p = bufprint(tmp, end, "ko:connect:%02x:unknown service", channel);
            } else {
                p = bufprint(tmp, end, "ko:connect:%02x:service busy", channel);
            }
        }
        else {
            p = bufprint(tmp, end, "ok:connect:%02x", channel);
        }
        qemud_serial_send(mult->serial, 0, 0, (uint8_t*)tmp, p-tmp);
        return;
    }

    /* handle client disconnections,
     * this message arrives when the client has closed the connection.
     * format: "disconnect:<id>" where <id> is a 2-hex channel id > 0
     */
    if (msglen == 13 && !memcmp(msg, "disconnect:", 11)) {
        int  channel_id = hex2int(msg+11, 2);
        if (channel_id <= 0) {
            D("%s: malformed disconnect channel id: '%.*s'",
              __FUNCTION__, 2, msg+11);
            return;
        }
        qemud_multiplexer_disconnect(mult, channel_id);
        return;
    }

#if SUPPORT_LEGACY_QEMUD
    /* an ok:connect:<service>:<id> message can be received if we're
     * talking to a legacy qemud daemon, i.e. one running in a 1.0 or
     * 1.1 system image.
     *
     * we should treat is as a normal "connect:" attempt, except that
     * we must not send back any acknowledgment.
     */
    if (msglen > 11 && !memcmp(msg, "ok:connect:", 11)) {
        const char*  service_name = (const char*)msg + 11;
        char*        q            = strchr(service_name, ':');
        int          channel;

        if (q == NULL || q+3 != (char*)msgend) {
            D("%s: malformed legacy connect message: '%.*s' (offset=%d)",
              __FUNCTION__, msglen, (const char*)msg, q ? q-(char*)msg : -1);
            return;
        }
        *q++ = 0;  /* zero-terminate service name */
        channel = hex2int((uint8_t*)q, 2);
        if (channel <= 0) {
            D("%s: malformed legacy channel id '%.*s",
              __FUNCTION__, 2, q);
            return;
        }

        switch (mult->serial->version) {
        case QEMUD_VERSION_UNKNOWN:
            mult->serial->version = QEMUD_VERSION_LEGACY;
            D("%s: legacy qemud daemon detected.", __FUNCTION__);
            break;

        case QEMUD_VERSION_LEGACY:
            /* nothing unusual */
            break;

        default:
            D("%s: weird, ignoring legacy qemud control message: '%.*s'",
              __FUNCTION__, msglen, msg);
            return;
        }

        /* "hw-control" was called "control" in 1.0/1.1 */
        if (!strcmp(service_name,"control"))
            service_name = "hw-control";

        qemud_multiplexer_connect(mult, service_name, channel);
        return;
    }

    /* anything else, don't answer for legacy */
    if (mult->serial->version == QEMUD_VERSION_LEGACY)
        return;
#endif /* SUPPORT_LEGACY_QEMUD */

    /* anything else is a problem */
    p = bufprint(tmp, end, "ko:unknown command");
    qemud_serial_send(mult->serial, 0, 0, (uint8_t*)tmp, p-tmp);
}

/* initialize the global QemudMultiplexer.
 */
static void
qemud_multiplexer_init( QemudMultiplexer*  mult,
                        CharDriverState*   serial_cs )
{
    QemudClient*  control;

    /* initialize serial handler */
    qemud_serial_init( mult->serial,
                       serial_cs,
                       qemud_multiplexer_serial_recv,
                       mult );

    /* setup listener for channel 0 */
    control = qemud_client_alloc( 0,
                                  NULL,
                                  mult,
                                  qemud_multiplexer_control_recv,
                                  NULL, NULL, NULL,
                                  mult->serial,
                                  &mult->clients );
}

/* the global multiplexer state */
static QemudMultiplexer  _multiplexer[1];

/** HIGH-LEVEL API
 **/

/* this function must be used in the serv_connect callback
 * of a given QemudService object (see qemud_service_register()
 * below). It is used to register a new QemudClient to acknowledge
 * a new client connection.
 *
 * 'clie_opaque', 'clie_recv' and 'clie_close' are used to
 * send incoming client messages to the corresponding service
 * implementation, or notify the service that a client has
 * disconnected.
 */
QemudClient*
qemud_client_new( QemudService*     service,
                  int               channelId,
                  const char*       client_param,
                  void*             clie_opaque,
                  QemudClientRecv   clie_recv,
                  QemudClientClose  clie_close,
                  QemudClientSave   clie_save,
                  QemudClientLoad   clie_load )
{
    QemudMultiplexer*  m = _multiplexer;
    QemudClient*       c = qemud_client_alloc( channelId,
                                               client_param,
                                               clie_opaque,
                                               clie_recv,
                                               clie_close,
                                               clie_save,
                                               clie_load,
                                               m->serial,
                                               &m->clients );

    qemud_service_add_client(service, c);
    return c;
}

/* Caches a service message into the client's descriptor.
 *
 * See comments on QemudPipeMessage structure for more info.
 */
static void
_qemud_pipe_cache_buffer(QemudClient* client, const uint8_t*  msg, int  msglen)
{
    QemudPipeMessage* buf;
    QemudPipeMessage** ins_at = &client->ProtocolSelector.Pipe.messages;

    /* Allocate descriptor big enough to contain message as well. */
    buf = (QemudPipeMessage*)malloc(msglen + sizeof(QemudPipeMessage));
    if (buf != NULL) {
        /* Message starts right after the descriptor. */
        buf->message = (uint8_t*)buf + sizeof(QemudPipeMessage);
        buf->size = msglen;
        memcpy(buf->message, msg, msglen);
        buf->offset = 0;
        buf->next = NULL;
        while (*ins_at != NULL) {
            ins_at = &(*ins_at)->next;
        }
        *ins_at = buf;
        /* Notify the pipe that there is data to read. */
        goldfish_pipe_wake(client->ProtocolSelector.Pipe.qemud_pipe->hwpipe,
                           PIPE_WAKE_READ);
    }
}

/* Sends service message to the client.
 */
static void
_qemud_pipe_send(QemudClient*  client, const uint8_t*  msg, int  msglen)
{
    uint8_t   frame[FRAME_HEADER_SIZE];
    int       avail, len = msglen;
    int framing = client->framing;

    if (msglen <= 0)
        return;

    D("%s: len=%3d '%s'",
      __FUNCTION__, msglen, quote_bytes((const void*)msg, msglen));

    if (framing) {
        len += FRAME_HEADER_SIZE;
    }

    /* packetize the payload for the serial MTU */
    while (len > 0)
    {
        avail = len;
        if (avail > MAX_SERIAL_PAYLOAD)
            avail = MAX_SERIAL_PAYLOAD;

        /* insert frame header when needed */
        if (framing) {
            int2hex(frame, FRAME_HEADER_SIZE, msglen);
            T("%s: '%.*s'", __FUNCTION__, FRAME_HEADER_SIZE, frame);
            _qemud_pipe_cache_buffer(client, frame, FRAME_HEADER_SIZE);
            avail  -= FRAME_HEADER_SIZE;
            len    -= FRAME_HEADER_SIZE;
            framing = 0;
        }

        /* write message content */
        T("%s: '%.*s'", __FUNCTION__, avail, msg);
        _qemud_pipe_cache_buffer(client, msg, avail);
        msg += avail;
        len -= avail;
    }
}

/* this can be used by a service implementation to send an answer
 * or message to a specific client.
 */
void
qemud_client_send ( QemudClient*  client, const uint8_t*  msg, int  msglen )
{
    if (_is_pipe_client(client)) {
        _qemud_pipe_send(client, msg, msglen);
    } else {
        qemud_serial_send(client->ProtocolSelector.Serial.serial,
                          client->ProtocolSelector.Serial.channel,
                          client->framing != 0, msg, msglen);
    }
}

/* enable framing for this client. When TRUE, this will
 * use internally a simple 4-hexchar header before each
 * message exchanged through the serial port.
 */
void
qemud_client_set_framing( QemudClient*  client, int  framing )
{
    /* release dynamic buffer if we're disabling framing */
    if (client->framing) {
        if (!client->need_header) {
            AFREE(client->payload->buff);
            client->need_header = 1;
        }
    }
    client->framing = !!framing;
}

/* this can be used by a service implementation to close a
 * specific client connection.
 */
void
qemud_client_close( QemudClient*  client )
{
    qemud_client_disconnect(client, 0);
}


/** SNAPSHOT SUPPORT
 **/

/* Saves the number of clients.
 */
static void
qemud_client_save_count(QEMUFile* f, QemudClient* c)
{
    unsigned int client_count = 0;
    for( ; c; c = c->next)   // walk over linked list
        /* skip control channel, which is not saved, and pipe channels that
         * are saved along with the pipe. */
        if (!_is_pipe_client(c) && c->ProtocolSelector.Serial.channel > 0)
            client_count++;

    qemu_put_be32(f, client_count);
}

/* Saves the number of services currently available.
 */
static void
qemud_service_save_count(QEMUFile* f, QemudService* s)
{
    unsigned int service_count = 0;
    for( ; s; s = s->next )  // walk over linked list
        service_count++;

    qemu_put_be32(f, service_count);
}

/* Save QemuD state to snapshot.
 *
 * The control channel has no state of its own, other than the local variables
 * in qemud_multiplexer_control_recv. We can therefore safely skip saving it,
 * which spares us dealing with the exception of a client not connected to a
 * service.
 */
static void
qemud_save(QEMUFile* f, void* opaque)
{
    QemudMultiplexer *m = opaque;

    qemud_serial_save(f, m->serial);

    /* save service states */
    qemud_service_save_count(f, m->services);
    QemudService *s;
    for (s = m->services; s; s = s->next)
        qemud_service_save(f, s);

    /* save client channels */
    qemud_client_save_count(f, m->clients);
    QemudClient *c;
    for (c = m->clients; c; c = c->next) {
        /* skip control channel, and pipe clients */
        if (!_is_pipe_client(c) && c->ProtocolSelector.Serial.channel > 0) {
            qemud_serial_client_save(f, c);
        }
    }

}


/* Checks whether the same services are available at this point as when the
 * snapshot was made.
 */
static int
qemud_load_services( QEMUFile*  f, QemudService*  current_services )
{
    int i, ret;
    int service_count = qemu_get_be32(f);
    for (i = 0; i < service_count; i++) {
        if ((ret = qemud_service_load(f, current_services)))
            return ret;
    }

    return 0;
}

/* Removes all active non-control clients, then creates new ones with state
 * taken from the snapshot.
 *
 * We do not send "disconnect" commands, over the channel. If we did, we might
 * stop clients in the restored guest, resulting in an incorrect restore.
 *
 * Instead, we silently replace the clients that were running before the
 * restore with new clients, whose state we copy from the snapshot. Since
 * everything is multiplexed over one link, only the multiplexer notices the
 * changes, there is no communication with the guest.
 */
static int
qemud_load_clients(QEMUFile* f, QemudMultiplexer* m, int version )
{
    /* Remove all clients, except on the control channel.*/
    qemud_multiplexer_disconnect_noncontrol(m);

    /* Load clients from snapshot */
    int client_count = qemu_get_be32(f);
    int i, ret;
    for (i = 0; i < client_count; i++) {
        if ((ret = qemud_serial_client_load(f, m->services, version))) {
            return ret;
        }
    }

    return 0;
}

/* Load QemuD state from file.
 */
static int
qemud_load(QEMUFile *f, void* opaque, int version)
{
    QemudMultiplexer *m = opaque;

    int ret;

    if ((ret = qemud_serial_load(f, m->serial)))
        return ret;
    if ((ret = qemud_load_services(f, m->services)))
        return ret;
    if ((ret = qemud_load_clients(f, m, version)))
        return ret;

    return 0;
}

/*------------------------------------------------------------------------------
 *
 * QEMUD PIPE service callbacks
 *
 * ----------------------------------------------------------------------------*/

/* Saves pending pipe message to the snapshot file. */
static void
_save_pipe_message(QEMUFile* f, QemudPipeMessage* msg)
{
    qemu_put_be32(f, msg->size);
    qemu_put_be32(f, msg->offset);
    qemu_put_buffer(f, msg->message, msg->size);
}

/* Loads pending pipe messages from the snapshot file.
 * Return:
 *  List of pending pipe messages loaded from snapshot, or NULL if snapshot didn't
 *  contain saved messages.
 */
static QemudPipeMessage*
_load_pipe_message(QEMUFile* f)
{
    QemudPipeMessage* ret = NULL;
    QemudPipeMessage** next = &ret;

    uint32_t size = qemu_get_be32(f);
    while (size != 0) {
        QemudPipeMessage* wrk;
        ANEW0(wrk);
        *next = wrk;
        wrk->size = size;
        wrk->offset = qemu_get_be32(f);
        wrk->message = malloc(wrk->size);
        if (wrk->message == NULL) {
            APANIC("Unable to allocate buffer for pipe's pending message.");
        }
        qemu_get_buffer(f, wrk->message, wrk->size);
        next = &wrk->next;
        *next = NULL;
        size = qemu_get_be32(f);
    }

    return ret;
}

/* This is a callback that gets invoked when guest is connecting to the service.
 *
 * Here we will create a new client as well as pipe descriptor representing new
 * connection.
 */
static void*
_qemudPipe_init(void* hwpipe, void* _looper, const char* args)
{
    QemudMultiplexer *m = _multiplexer;
    QemudService* sv = m->services;
    QemudClient* client;
    QemudPipe* pipe = NULL;
    char service_name[512];
    const char* client_args;
    size_t srv_name_len;

    /* 'args' passed in this callback represents name of the service the guest is
     * connecting to. It can't be NULL. */
    if (args == NULL) {
        D("%s: Missing address!", __FUNCTION__);
        return NULL;
    }

    /* 'args' contain service name, and optional parameters for the client that
     * is about to be created in this call. The parameters are separated from the
     * service name wit ':'. Separate service name from the client param. */
    client_args = strchr(args, ':');
    if (client_args != NULL) {
        srv_name_len = min(client_args - args, sizeof(service_name) - 1);
        client_args++;  // Past the ':'
        if (*client_args == '\0') {
            /* No actual parameters. */
            client_args = NULL;
        }
    } else {
        srv_name_len = min(strlen(args), sizeof(service_name) - 1);
    }
    memcpy(service_name, args, srv_name_len);
    service_name[srv_name_len] = '\0';

    /* Lookup registered service by its name. */
    while (sv != NULL && strcmp(sv->name, service_name)) {
        sv = sv->next;
    }
    if (sv == NULL) {
        D("%s: Service '%s' has not been registered!", __FUNCTION__, service_name);
        return NULL;
    }

    /* Create a client for this connection. -1 as a channel ID signals that this
     * is a pipe client. */
    client = qemud_service_connect_client(sv, -1, client_args);
    if (client != NULL) {
        ANEW0(pipe);
        pipe->hwpipe = hwpipe;
        pipe->looper = _looper;
        pipe->service = sv;
        pipe->client = client;
        client->ProtocolSelector.Pipe.qemud_pipe = pipe;
    }

    return pipe;
}

/* Called when the guest wants to close the channel.
*/
static void
_qemudPipe_closeFromGuest( void* opaque )
{
    QemudPipe* pipe = opaque;
    QemudClient*  client = pipe->client;
    D("%s", __FUNCTION__);
    if (client != NULL) {
        qemud_client_disconnect(client, 1);
    } else {
        D("%s: Unexpected NULL client", __FUNCTION__);
    }
}

/* Called when the guest has sent some data to the client.
 */
static int
_qemudPipe_sendBuffers(void* opaque,
                       const GoldfishPipeBuffer* buffers,
                       int numBuffers)
{
    QemudPipe* pipe = opaque;
    QemudClient*  client = pipe->client;
    size_t transferred = 0;

    if (client == NULL) {
        D("%s: Unexpected NULL client", __FUNCTION__);
        return -1;
    }

    if (numBuffers == 1) {
        /* Simple case: all data are in one buffer. */
        D("%s: %s", __FUNCTION__, quote_bytes((char*)buffers->data, buffers->size));
        qemud_client_recv(client, buffers->data, buffers->size);
        transferred = buffers->size;
    } else {
        /* If there are multiple buffers involved, collect all data in one buffer
         * before calling the high level client. */
        uint8_t* msg, *wrk;
        int n;
        for (n = 0; n < numBuffers; n++) {
            transferred += buffers[n].size;
        }
        msg = malloc(transferred);
        wrk = msg;
        for (n = 0; n < numBuffers; n++) {
            memcpy(wrk, buffers[n].data, buffers[n].size);
            wrk += buffers[n].size;
        }
        D("%s: %s", __FUNCTION__, quote_bytes((char*)msg, transferred));
        qemud_client_recv(client, msg, transferred);
        free(msg);
    }

    return transferred;
}

/* Called when the guest is reading data from the client.
 */
static int
_qemudPipe_recvBuffers(void* opaque, GoldfishPipeBuffer* buffers, int numBuffers)
{
    QemudPipe* pipe = opaque;
    QemudClient*  client = pipe->client;
    QemudPipeMessage** msg_list;
    GoldfishPipeBuffer* buff = buffers;
    GoldfishPipeBuffer* endbuff = buffers + numBuffers;
    size_t sent_bytes = 0;
    size_t off_in_buff = 0;

    if (client == NULL) {
        D("%s: Unexpected NULL client", __FUNCTION__);
        return -1;
    }

    msg_list = &client->ProtocolSelector.Pipe.messages;
    if (*msg_list == NULL) {
        /* No data to send. Let it block until we wake it up with
         * PIPE_WAKE_READ when service sends data to the client. */
        return PIPE_ERROR_AGAIN;
    }

    /* Fill in goldfish buffers while they are still available, and there are
     * messages in the client's message list. */
    while (buff != endbuff && *msg_list != NULL) {
        QemudPipeMessage* msg = *msg_list;
        /* Message data fiting the current pipe's buffer. */
        size_t to_copy = min(msg->size - msg->offset, buff->size - off_in_buff);
        memcpy(buff->data + off_in_buff, msg->message + msg->offset, to_copy);
        /* Update offsets. */
        off_in_buff += to_copy;
        msg->offset += to_copy;
        sent_bytes += to_copy;
        if (msg->size == msg->offset) {
            /* We're done with the current message. Go to the next one. */
            *msg_list = msg->next;
            free(msg);
        }
        if (off_in_buff == buff->size) {
            /* Current pipe buffer is full. Continue with the next one. */
            buff++;
            off_in_buff = 0;
        }
    }

    D("%s: -> %u (of %u)", __FUNCTION__, sent_bytes, buffers->size);

    return sent_bytes;
}

static unsigned
_qemudPipe_poll(void* opaque)
{
    QemudPipe* pipe = opaque;
    QemudClient*  client = pipe->client;
    unsigned ret = 0;

    if (client != NULL) {
        ret |= PIPE_POLL_OUT;
        if (client->ProtocolSelector.Pipe.messages != NULL) {
            ret |= PIPE_POLL_IN;
        }
    } else {
        D("%s: Unexpected NULL client", __FUNCTION__);
    }

    return ret;
}

static void
_qemudPipe_wakeOn(void* opaque, int flags)
{
    D("%s: -> %X", __FUNCTION__, flags);
}

static void
_qemudPipe_save(void* opaque, QEMUFile* f )
{
    QemudPipe* qemud_pipe = (QemudPipe*)opaque;
    QemudClient* c = qemud_pipe->client;
    QemudPipeMessage* msg = c->ProtocolSelector.Pipe.messages;

    /* save generic information */
    qemud_service_save_name(f, c->service);
    //qemu_put_string(f, c->param);

    /* Save pending messages. */
    while (msg != NULL) {
        _save_pipe_message(f, msg);
        msg = msg->next;
    }
    /* End of pending messages. */
    qemu_put_be32(f, 0);

    /* save client-specific state */
    if (c->clie_save)
        c->clie_save(f, c, c->clie_opaque);

    /* save framing configuration */
    qemu_put_be32(f, c->framing);
    if (c->framing) {
        qemu_put_be32(f, c->need_header);
        /* header sink always connected to c->header0, no need to save */
        qemu_put_be32(f, FRAME_HEADER_SIZE);
        qemu_put_buffer(f, c->header0, FRAME_HEADER_SIZE);
        /* payload sink */
        qemud_sink_save(f, c->payload);
        qemu_put_buffer(f, c->payload->buff, c->payload->size);
    }
}

static void*
_qemudPipe_load(void* hwpipe, void* pipeOpaque, const char* args, QEMUFile* f)
{
    QemudPipe* qemud_pipe = NULL;
    char* param;
    char *service_name = qemud_service_load_name(f);
    if (service_name == NULL)
        return NULL;
    /* get service instance for the loading client*/
    QemudService *sv = qemud_service_find(_multiplexer->services, service_name);
    if (sv == NULL) {
        D("%s: load failed: unknown service \"%s\"\n",
          __FUNCTION__, service_name);
        return NULL;
    }

    /* Load saved parameters. */
    param = "";//qemu_get_string(f);

    /* re-connect client */
    QemudClient* c = qemud_service_connect_client(sv, -1, param);
    if(c == NULL)
        return NULL;

    /* Load pending messages. */
    c->ProtocolSelector.Pipe.messages = _load_pipe_message(f);

    /* load client-specific state */
    if (c->clie_load && c->clie_load(f, c, c->clie_opaque)) {
        /* load failure */
        return NULL;
    }

    /* load framing configuration */
    c->framing = qemu_get_be32(f);
    if (c->framing) {

        /* header buffer */
        c->need_header = qemu_get_be32(f);
        int header_size = qemu_get_be32(f);
        if (header_size > FRAME_HEADER_SIZE) {
            D("%s: load failed: payload buffer requires %d bytes, %d available\n",
              __FUNCTION__, header_size, FRAME_HEADER_SIZE);
            return NULL;
        }
        int ret;
        if ((ret = qemu_get_buffer(f, c->header0, header_size)) != header_size) {
            D("%s: frame header buffer load failed: expected %d bytes, got %d\n",
              __FUNCTION__, header_size, ret);
            return NULL;
        }

        /* payload sink */
        if ((ret = qemud_sink_load(f, c->payload)))
            return NULL;

        /* replace payload buffer by saved data */
        if (c->payload->buff) {
            AFREE(c->payload->buff);
        }
        AARRAY_NEW(c->payload->buff, c->payload->size+1);  /* +1 for terminating zero */
        if ((ret = qemu_get_buffer(f, c->payload->buff, c->payload->size)) != c->payload->size) {
            D("%s: frame payload buffer load failed: expected %d bytes, got %d\n",
              __FUNCTION__, c->payload->size, ret);
            AFREE(c->payload->buff);
            return NULL;
        }
    }

    /* Associate the client with the pipe. */
    ANEW0(qemud_pipe);
    qemud_pipe->hwpipe = hwpipe;
    qemud_pipe->looper = pipeOpaque;
    qemud_pipe->service = sv;
    qemud_pipe->client = c;
    c->ProtocolSelector.Pipe.qemud_pipe = qemud_pipe;

    return qemud_pipe;
}

/* QEMUD pipe functions.
 */
static const GoldfishPipeFuncs _qemudPipe_funcs = {
    _qemudPipe_init,
    _qemudPipe_closeFromGuest,
    _qemudPipe_sendBuffers,
    _qemudPipe_recvBuffers,
    _qemudPipe_poll,
    _qemudPipe_wakeOn,
    _qemudPipe_save,
    _qemudPipe_load,
};

/* Initializes QEMUD pipe interface.
 */
static void
_android_qemud_pipe_init(void)
{
    static bool _qemud_pipe_initialized = false;

    if (!_qemud_pipe_initialized) {
        goldfish_pipe_add_type( "qemud", looper_newCore(), &_qemudPipe_funcs );
        _qemud_pipe_initialized = true;
    }
}

/* this is the end of the serial charpipe that must be passed
 * to the emulated tty implementation. The other end of the
 * charpipe must be passed to qemud_multiplexer_init().
 */
static CharDriverState*  android_qemud_cs;

/* Initializes QEMUD serial interface.
 */
static void
_android_qemud_serial_init(void)
{
    CharDriverState*    cs;

    if (android_qemud_cs != NULL)
        return;

    if (qemu_chr_open_charpipe( &android_qemud_cs, &cs ) < 0) {
        derror( "%s: can't create charpipe to serial port",
                __FUNCTION__ );
        exit(1);
    }

    qemud_multiplexer_init(_multiplexer, cs);

    //register_savevm( "qemud", 0, QEMUD_SAVE_VERSION,
     //                 qemud_save, qemud_load, _multiplexer);
}

extern void
android_qemud_init( void )
{
    D("%s", __FUNCTION__);
    /* We don't know in advance whether the guest system supports qemud pipes,
     * so we will initialize both qemud machineries, the legacy (over serial
     * port), and the new one (over qemu pipe). Then we let the guest to connect
     * via one, or the other. */
    _android_qemud_serial_init();
    _android_qemud_pipe_init();
}

/* return the serial charpipe endpoint that must be used
 * by the emulated tty implementation.
 */
CharDriverState*  android_qemud_get_cs( void )
{
    if (android_qemud_cs == NULL)
        android_qemud_init();

    return android_qemud_cs;
}

/* this function is used to register a new named qemud-based
 * service. You must provide 'serv_opaque' and 'serv_connect'
 * which will be called whenever a new client tries to connect
 * to the services.
 *
 * 'serv_connect' shall return NULL if the connection is refused,
 * or a handle to a new QemudClient otherwise. The latter can be
 * created through qemud_client_new() defined above.
 *
 * 'max_clients' is the maximum number of clients accepted by
 * the service concurrently. If this value is 0, then any number
 * of clients can connect.
 */
QemudService*
qemud_service_register( const char*          service_name,
                        int                  max_clients,
                        void*                serv_opaque,
                        QemudServiceConnect  serv_connect,
                        QemudServiceSave     serv_save,
                        QemudServiceLoad     serv_load )
{
    QemudService*      sv;
    QemudMultiplexer*  m  = _multiplexer;

    android_qemud_init();

    sv = qemud_service_new(service_name,
                           max_clients,
                           serv_opaque,
                           serv_connect,
                           serv_save,
                           serv_load,
                           &m->services);
    D("Registered QEMUD service %s", service_name);
    return sv;
}

/* broadcast a given message to all clients of a given QemudService
 */
extern void
qemud_service_broadcast( QemudService*  sv,
                         const uint8_t*  msg,
                         int             msglen )
{
    QemudClient*  c;

    for (c = sv->clients; c; c = c->next_serv)
        qemud_client_send(c, msg, msglen);
}



/*
 * The following code is used for backwards compatibility reasons.
 * It allows you to implement a given qemud-based service through
 * a charpipe.
 *
 * In other words, this implements a QemudService and corresponding
 * QemudClient that connects a qemud client running in the emulated
 * system, to a CharDriverState object implemented through a charpipe.
 *
 *   QemudCharClient <===charpipe====> (char driver user)
 *
 * For example, this is used to implement the "gsm" service when the
 * modem emulation is provided through an external serial device.
 *
 * A QemudCharService can have only one client by definition.
 * There is no QemudCharClient object because we can store a single
 * CharDriverState handle in the 'opaque' field for simplicity.
 */

typedef struct {
    QemudService*     service;
    CharDriverState*  cs;
} QemudCharService;

/* called whenever a new message arrives from a qemud client.
 * this simply sends the message through the charpipe to the user.
 */
static void
_qemud_char_client_recv( void*  opaque, uint8_t*  msg, int  msglen,
                         QemudClient*  client )
{
    CharDriverState*  cs = opaque;
    qemu_chr_fe_write(cs, msg, msglen);
}

/* we don't expect clients of char. services to exit. Just
 * print an error to signal an unexpected situation. We should
 * be able to recover from these though, so don't panic.
 */
static void
_qemud_char_client_close( void*  opaque )

{
    QemudClient* client = opaque;

    /* At this point modem driver still uses char pipe to communicate with
     * hw-qemud, while communication with the guest is done over qemu pipe.
     * So, when guest disconnects from the qemu pipe, and emulator-side client
     * goes through the disconnection process, this routine is called, since it
     * has been set to called during service registration. Unless modem driver
     * is changed to drop char pipe communication, this routine will be called
     * due to guest disconnection. As long as the client was a qemu pipe - based
     * client, it's fine, since we don't really need to do anything in this case.
     */
    if (!_is_pipe_client(client)) {
        derror("unexpected qemud char. channel close");
    }
}


/* called by the charpipe to know how much data can be read from
 * the user. Since we send everything directly to the serial port
 * we can return an arbitrary number.
 */
static int
_qemud_char_service_can_read( void*  opaque )
{
    return 8192;  /* whatever */
}

/* called to read data from the charpipe and send it to the client.
 * used qemud_service_broadcast() even if there is a single client
 * because we don't need a QemudCharClient object this way.
 */
static void
_qemud_char_service_read( void*  opaque, const uint8_t*  from, int  len )
{
    QemudService*  sv = opaque;
    qemud_service_broadcast( sv, from, len );
}

/* called when a qemud client tries to connect to a char. service.
 * we simply create a new client and open the charpipe to receive
 * data from it.
 */
static QemudClient*
_qemud_char_service_connect(void*          opaque,
                            QemudService*  sv,
                            int            channel,
                            const char*    client_param )
{
    CharDriverState*   cs = opaque;
    QemudClient*       c  = qemud_client_new( sv, channel, client_param,
                                              cs,
                                              _qemud_char_client_recv,
                                              _qemud_char_client_close,
                                              NULL, NULL );

    /* now we can open the gates :-) */
    qemu_chr_add_handlers( cs,
                           _qemud_char_service_can_read,
                           _qemud_char_service_read,
                           NULL,
                           sv );

    return c;
}

/* returns a charpipe endpoint that can be used by an emulated
 * device or external serial port to implement a char. service
 */
int
android_qemud_get_channel( const char*  name, CharDriverState* *pcs )
{
    CharDriverState*   cs;

    if (qemu_chr_open_charpipe(&cs, pcs) < 0) {
        derror("can't open charpipe for '%s' qemud service", name);
        exit(2);
    }
    qemud_service_register(name, 1, cs, _qemud_char_service_connect, NULL, NULL);
    return 0;
}

/* set the character driver state for a given qemud communication channel. this
 * is used to attach the channel to an external char driver device directly.
 * returns 0 on success, -1 on error
 */
int
android_qemud_set_channel( const char*  name, CharDriverState*  peer_cs )
{
    CharDriverState*  char_buffer = qemu_chr_open_buffer(peer_cs);

    if (char_buffer == NULL)
        return -1;

    qemud_service_register(name, 1, char_buffer, _qemud_char_service_connect,
                           NULL, NULL);
    return 0;
}
