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
#include "cbuffer.h"
#include "android/utils/stralloc.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#define  DEBUG  0

#if DEBUG
#  define  ASSERT(cond,fmt,...)  ({ if (!(cond)) { fprintf(stderr, fmt, __VA_ARGS__); assert(cond); } })
#else
#  define  ASSERT(cond,fmt,...)  ((void)0)
#endif

#if DEBUG
void
cbuffer_assert( CBuffer*  cb, const char*  file, long  lineno )
{
    const char*  reason = NULL;

    if (cb->rpos < 0 || cb->rpos >= cb->size) {
        reason = "rpos is out of bounds";
    }
    else if (cb->count < 0 || cb->count > cb->size) {
        reason = "count is incorrect";
    }
    if (!reason)
        return;

    fprintf(stderr, "assert:%s:%ld: assertion failed: %s (pos=%d count=%d size=%d)\n",
            file, lineno, reason, cb->rpos, cb->count, cb->size);
    assert(0);
}
#  define  CBUFFER_ASSERT(cb)  cbuffer_assert(cb,__FUNCTION__,__LINE__)
#else
#  define  CBUFFER_ASSERT(cb)  ((void)0)
#endif

int
cbuffer_write_peek( CBuffer*  cb, uint8_t*  *pbase )
{
    int  wpos  = cb->rpos + cb->count;
    int  avail = cb->size - cb->count;

    CBUFFER_ASSERT(cb);

    if (wpos >= cb->size)
        wpos -= cb->size;

    if (wpos + avail > cb->size)
        avail = cb->size - wpos;

    *pbase = cb->buff + wpos;
    return avail;
}

void
cbuffer_write_step( CBuffer*  cb, int  len )
{
    CBUFFER_ASSERT(cb);

    cb->count += len;
    if (cb->count > cb->size)
        cb->count = cb->size;
}


int
cbuffer_write( CBuffer*  cb, const void*  from, int  len )
{
    int  len2 = len;

    CBUFFER_ASSERT(cb);

    while (len2 > 0) {
        int  avail = cb->size - cb->count;
        int  wpos  = cb->rpos + cb->count;

        ASSERT(avail >= 0, "avail is negative: %d", avail);

        if (avail == 0)
            break;

        if (wpos >= cb->size)
            wpos -= cb->size;

        ASSERT( wpos >= 0 && wpos < cb->size, "wpos is out-of-bounds: %d (rpos=%d)", wpos, cb->rpos);

        if (wpos + avail > cb->size)
            avail = cb->size - wpos;

        if (avail > len2)
            avail = len2;

        memcpy( cb->buff + wpos, (const char*)from, avail );

        from  = (char*)from + avail;
        len2 -= avail;
        cb->count += avail;
    }
    return len - len2;
}

int
cbuffer_read( CBuffer*  cb, void*  to, int  len )
{
    int   len2 = len;

    CBUFFER_ASSERT(cb);

    while (len2 > 0) {
        int  avail = cb->count;
        int  rpos = cb->rpos;

        ASSERT(avail >= 0, "avail is negative: %d", avail);

        if (avail == 0)
            break;

        ASSERT((rpos >= 0 && rpos < cb->size), "rpos is out-of-bounds: %d", rpos);

        if (rpos+avail > cb->size)
            avail = cb->size - rpos;

        if (avail > len2)
            avail = len2;

        memcpy( (char*)to, (const char*)cb->buff + rpos, avail );
        to    = (char*)to + avail;
        len2 -= avail;
        cb->count -= avail;
        cb->rpos  += avail;
        if (cb->rpos >= cb->size)
            cb->rpos -= cb->size;
    }
    return len - len2;
}

int
cbuffer_read_peek( CBuffer*  cb, uint8_t*  *pbase )
{
    int   rpos  = cb->rpos;
    int   avail = cb->count;

    CBUFFER_ASSERT(cb);

    if (rpos + avail > cb->size)
        avail = cb->size - rpos;

    *pbase = cb->buff + rpos;
    return avail;
}


void
cbuffer_read_step( CBuffer*  cb, int  len )
{
    CBUFFER_ASSERT(cb);

    if (len > cb->count)
        len = cb->count;

    cb->rpos  += len;
    if (cb->rpos >= cb->size)
        cb->rpos -= cb->size;

    cb->count -= len;
}

const char*
cbuffer_quote( CBuffer*  cb )
{
    STRALLOC_DEFINE(s);
    char* q;

    stralloc_format( s, "cbuffer %p (pos=%d count=%d size=%d)",
                     cb, cb->rpos, cb->count, cb->size );

    q = stralloc_to_tempstr( s );
    stralloc_reset(s);

    return q;
}

const char*
cbuffer_quote_data( CBuffer*  cb )
{
    STRALLOC_DEFINE(s);
    int   len  = cb->count;
    int   rpos = cb->rpos;
    char* result;

    while (len > 0) {
        int  avail = len;

        if (rpos >= cb->size)
            rpos -= cb->size;

        if (rpos + avail > cb->size)
            avail = cb->size - rpos;

        stralloc_add_quote_bytes( s, cb->buff + rpos, avail );
        rpos += avail;
        len  -= avail;
    }

    result = stralloc_to_tempstr(s);
    stralloc_reset(s);

    return result;
}

void
cbuffer_print( CBuffer*  cb )
{
    /* print the content of a cbuffer */
    printf( "%s: %s", cbuffer_quote(cb), cbuffer_quote_data(cb) );
}

