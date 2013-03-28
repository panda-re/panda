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
#include "qemu-char.h"
#include "cbuffer.h"

#define  xxDEBUG

#ifdef DEBUG
#  include <stdio.h>
#  define  D(...)   ( fprintf( stderr, __VA_ARGS__ ), fprintf(stderr, "\n") )
#else
#  define  D(...)   ((void)0)
#endif

/* we want to implement a bi-directionnal communication channel
 * between two QEMU character drivers that merge well into the
 * QEMU event loop.
 *
 * each half of the channel has its own object and buffer, and
 * we implement communication through charpipe_poll() which
 * must be called by the main event loop after its call to select()
 *
 */

#define  BIP_BUFFER_SIZE  512

typedef struct BipBuffer {
    struct BipBuffer*  next;
    CBuffer            cb[1];
    char               buff[ BIP_BUFFER_SIZE ];
} BipBuffer;

static BipBuffer*  _free_bip_buffers;

static BipBuffer*
bip_buffer_alloc( void )
{
    BipBuffer*  bip = _free_bip_buffers;
    if (bip != NULL) {
        _free_bip_buffers = bip->next;
    } else {
        bip = malloc( sizeof(*bip) );
        if (bip == NULL) {
            D( "%s: not enough memory", __FUNCTION__ );
            exit(1);
        }
    }
    bip->next = NULL;
    cbuffer_reset( bip->cb, bip->buff, sizeof(bip->buff) );
    return bip;
}

static void
bip_buffer_free( BipBuffer*  bip )
{
    bip->next         = _free_bip_buffers;
    _free_bip_buffers = bip;
}

/* this models each half of the charpipe */
typedef struct CharPipeHalf {
    CharDriverState       cs[1];
    BipBuffer*            bip_first;
    BipBuffer*            bip_last;
    struct CharPipeHalf*  peer;         /* NULL if closed */
} CharPipeHalf;



static void
charpipehalf_close( CharDriverState*  cs )
{
    CharPipeHalf*  ph = cs->opaque;

    while (ph->bip_first) {
        BipBuffer*  bip = ph->bip_first;
        ph->bip_first = bip->next;
        bip_buffer_free(bip);
    }
    ph->bip_last    = NULL;
    ph->peer        = NULL;
}


static int
charpipehalf_write( CharDriverState*  cs, const uint8_t*  buf, int  len )
{
    CharPipeHalf*  ph   = cs->opaque;
    CharPipeHalf*  peer = ph->peer;
    BipBuffer*     bip  = ph->bip_last;
    int            ret  = 0;

    D("%s: writing %d bytes to %p: '%s'", __FUNCTION__,
      len, ph, quote_bytes( buf, len ));

    if (bip == NULL && peer != NULL && peer->cs->chr_read != NULL) {
        /* no buffered data, try to write directly to the peer */
        while (len > 0) {
            int  size;

            if (peer->cs->chr_can_read) {
                size = qemu_chr_be_can_write( peer->cs );
                if (size == 0)
                    break;

                if (size > len)
                    size = len;
            } else
                size = len;

            qemu_chr_be_write( peer->cs, (uint8_t*)buf, size );
            buf += size;
            len -= size;
            ret += size;
        }
    }

    if (len == 0)
        return ret;

    /* buffer the remaining data */
    if (bip == NULL) {
        bip = bip_buffer_alloc();
        ph->bip_first = ph->bip_last = bip;
    }

    while (len > 0) {
        int  len2 = cbuffer_write( bip->cb, buf, len );

        buf += len2;
        ret += len2;
        len -= len2;
        if (len == 0)
            break;

        /* ok, we need another buffer */
        ph->bip_last = bip_buffer_alloc();
        bip->next = ph->bip_last;
        bip       = ph->bip_last;
    }
    return  ret;
}


static void
charpipehalf_poll( CharPipeHalf*  ph )
{
    CharPipeHalf*   peer = ph->peer;
    int             size;

    if (peer == NULL || peer->cs->chr_read == NULL)
        return;

    while (1) {
        BipBuffer*  bip = ph->bip_first;
        uint8_t*    base;
        int         avail;

        if (bip == NULL)
            break;

        size = cbuffer_read_avail(bip->cb);
        if (size == 0) {
            ph->bip_first = bip->next;
            if (ph->bip_first == NULL)
                ph->bip_last = NULL;
            bip_buffer_free(bip);
            continue;
        }

        if (ph->cs->chr_can_read) {
            int  size2 = qemu_chr_be_can_write(peer->cs);

            if (size2 == 0)
                break;

            if (size > size2)
                size = size2;
        }

        avail = cbuffer_read_peek( bip->cb, &base );
        if (avail > size)
            avail = size;
        D("%s: sending %d bytes from %p: '%s'", __FUNCTION__,
            avail, ph, quote_bytes( base, avail ));

        qemu_chr_be_write( peer->cs, base, avail );
        cbuffer_read_step( bip->cb, avail );
    }
}


static void
charpipehalf_init( CharPipeHalf*  ph, CharPipeHalf*  peer )
{
    CharDriverState*  cs = ph->cs;

    ph->bip_first   = NULL;
    ph->bip_last    = NULL;
    ph->peer        = peer;

    cs->chr_write            = charpipehalf_write;
    cs->chr_ioctl            = NULL;
    //cs->chr_send_event       = NULL;
    cs->chr_close            = charpipehalf_close;
    cs->opaque               = ph;
}


typedef struct CharPipeState {
    CharPipeHalf  a[1];
    CharPipeHalf  b[1];
} CharPipeState;



#define   MAX_CHAR_PIPES   8

static CharPipeState  _s_charpipes[ MAX_CHAR_PIPES ];

int
qemu_chr_open_charpipe( CharDriverState*  *pfirst, CharDriverState*  *psecond )
{
    CharPipeState*  cp     = _s_charpipes;
    CharPipeState*  cp_end = cp + MAX_CHAR_PIPES;

    for ( ; cp < cp_end; cp++ ) {
        if ( cp->a->peer == NULL && cp->b->peer == NULL )
            break;
    }

    if (cp == cp_end) {  /* can't allocate one */
        *pfirst  = NULL;
        *psecond = NULL;
        return -1;
    }

    charpipehalf_init( cp->a, cp->b );
    charpipehalf_init( cp->b, cp->a );

    *pfirst  = cp->a->cs;
    *psecond = cp->b->cs;
    return 0;
}

/** This models a charbuffer, an object used to buffer
 ** the data that is sent to a given endpoint CharDriverState
 ** object.
 **
 ** On the other hand, any can_read() / read() request performed
 ** by the endpoint will be passed to the CharBuffer's corresponding
 ** handlers.
 **/

typedef struct CharBuffer {
    CharDriverState  cs[1];
    BipBuffer*       bip_first;
    BipBuffer*       bip_last;
    CharDriverState* endpoint;  /* NULL if closed */
    char             closing;
} CharBuffer;


static void
charbuffer_close( CharDriverState*  cs )
{
    CharBuffer*  cbuf = cs->opaque;

    while (cbuf->bip_first) {
        BipBuffer*  bip = cbuf->bip_first;
        cbuf->bip_first = bip->next;
        bip_buffer_free(bip);
    }
    cbuf->bip_last = NULL;
    cbuf->endpoint = NULL;

    if (cbuf->endpoint != NULL) {
        qemu_chr_fe_close(cbuf->endpoint);
        cbuf->endpoint = NULL;
    }
}

static int
charbuffer_write( CharDriverState*  cs, const uint8_t*  buf, int  len )
{
    CharBuffer*       cbuf = cs->opaque;
    CharDriverState*  peer = cbuf->endpoint;
    BipBuffer*        bip  = cbuf->bip_last;
    int               ret  = 0;

    D("%s: writing %d bytes to %p: '%s'", __FUNCTION__,
      len, cbuf, quote_bytes( buf, len ));

    if (bip == NULL && peer != NULL) {
        /* no buffered data, try to write directly to the peer */
        int  size = qemu_chr_fe_write(peer, buf, len);

        if (size < 0)  /* just to be safe */
            size = 0;
        else if (size > len)
            size = len;

        buf += size;
        ret += size;
        len -= size;
    }

    if (len == 0)
        return ret;

    /* buffer the remaining data */
    if (bip == NULL) {
        bip = bip_buffer_alloc();
        cbuf->bip_first = cbuf->bip_last = bip;
    }

    while (len > 0) {
        int  len2 = cbuffer_write( bip->cb, buf, len );

        buf += len2;
        ret += len2;
        len -= len2;
        if (len == 0)
            break;

        /* ok, we need another buffer */
        cbuf->bip_last = bip_buffer_alloc();
        bip->next = cbuf->bip_last;
        bip       = cbuf->bip_last;
    }
    return  ret;
}


static void
charbuffer_poll( CharBuffer*  cbuf )
{
    CharDriverState*  peer = cbuf->endpoint;

    if (peer == NULL)
        return;

    while (1) {
        BipBuffer*  bip = cbuf->bip_first;
        uint8_t*    base;
        int         avail;
        int         size;

        if (bip == NULL)
            break;

        avail = cbuffer_read_peek( bip->cb, &base );
        if (avail == 0) {
            cbuf->bip_first = bip->next;
            if (cbuf->bip_first == NULL)
                cbuf->bip_last = NULL;
            bip_buffer_free(bip);
            continue;
        }

        size = qemu_chr_fe_write( peer, base, avail );

        if (size < 0)  /* just to be safe */
            size = 0;
        else if (size > avail)
            size = avail;

        cbuffer_read_step( bip->cb, size );

        if (size < avail)
            break;
    }
}


static void
charbuffer_update_handlers( CharDriverState*  cs )
{
    CharBuffer*  cbuf = cs->opaque;

    qemu_chr_add_handlers( cbuf->endpoint,
                           cs->chr_can_read,
                           cs->chr_read,
                           cs->chr_event,
                           cs->handler_opaque );
}


static void
charbuffer_init( CharBuffer*  cbuf, CharDriverState*  endpoint )
{
    CharDriverState*  cs = cbuf->cs;

    cbuf->bip_first   = NULL;
    cbuf->bip_last    = NULL;
    cbuf->endpoint    = endpoint;

    cs->chr_write               = charbuffer_write;
    cs->chr_ioctl               = NULL;
    //cs->chr_send_event          = NULL;
    cs->chr_close               = charbuffer_close;
    cs->chr_update_read_handler = charbuffer_update_handlers;
    cs->opaque                  = cbuf;
}

#define MAX_CHAR_BUFFERS  8

static CharBuffer  _s_charbuffers[ MAX_CHAR_BUFFERS ];

CharDriverState*
qemu_chr_open_buffer( CharDriverState*  endpoint )
{
    CharBuffer*  cbuf     = _s_charbuffers;
    CharBuffer*  cbuf_end = cbuf + MAX_CHAR_BUFFERS;

    if (endpoint == NULL)
        return NULL;

    for ( ; cbuf < cbuf_end; cbuf++ ) {
        if (cbuf->endpoint == NULL)
            break;
    }

    if (cbuf == cbuf_end)
        return NULL;

    charbuffer_init(cbuf, endpoint);
    return cbuf->cs;
}


void
charpipe_poll( void )
{
    CharPipeState*  cp     = _s_charpipes;
    CharPipeState*  cp_end = cp + MAX_CHAR_PIPES;

    CharBuffer*     cb     = _s_charbuffers;
    CharBuffer*     cb_end = cb + MAX_CHAR_BUFFERS;

    /* poll the charpipes */
    for ( ; cp < cp_end; cp++ ) {
        CharPipeHalf*  half;

        half = cp->a;
        if (half->peer != NULL)
            charpipehalf_poll(half);

        half = cp->b;
        if (half->peer != NULL)
            charpipehalf_poll(half);
    }

    /* poll the charbuffers */
    for ( ; cb < cb_end; cb++ ) {
        if (cb->endpoint != NULL)
            charbuffer_poll(cb);
    }
}
