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

#include "android/utils/stralloc.h"
#include "android/utils/debug.h"
#include "android/utils/misc.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

extern void
stralloc_tabular( stralloc_t*  out,
                  const char** strings, int  count,
                  const char*  prefix,  int  width )
{
    int  nrows, ncols, r, c, n, maxw = 0;

    for (n = 0; n < count; n++) {
        int  len = strlen(strings[n]);
        if (len > maxw)
            maxw = len;
    }
    maxw += 2;
    ncols = width/maxw;
    nrows = (count + ncols-1)/ncols;

    for (r = 0; r < nrows; r++) {
        stralloc_add_str( out, prefix );
        for (c = 0; c < ncols; c++) {
            int  index = c*nrows + r;
            if (index >= count) {
                break;
            }
            stralloc_add_format( out, "%-*s", maxw, strings[index] );
        }
        stralloc_add_str( out, "\n" );
    }
}

/** DYNAMIC STRINGS
 **/

extern void
stralloc_reset( stralloc_t*  s )
{
    free(s->s);
    s->s = NULL;
    s->n = 0;
    s->a = 0;
}

extern void
stralloc_ready( stralloc_t*  s, unsigned int  len )
{
    unsigned  old_max = s->a;
    unsigned  new_max = old_max;

    while (new_max < len) {
        unsigned  new_max2 = new_max + (new_max >> 1) + 16;
        if (new_max2 < new_max)
            new_max2 = UINT_MAX;
        new_max = new_max2;
    }

    s->s = realloc( s->s, new_max );
    if (s->s == NULL) {
        derror( "%s: not enough memory to reallocate %ld bytes",
                __FUNCTION__, new_max );
        exit(1);
    }
    s->a = new_max;
}

extern void
stralloc_readyplus( stralloc_t*  s, unsigned int  len )
{
    unsigned  len2 = s->n + len;

    if (len2 < s->n) { /* overflow ? */
        derror("%s: trying to grow by too many bytes: %ld",
               __FUNCTION__, len);
        exit(1);
    }
    stralloc_ready( s, len2 );
}

extern void
stralloc_copy( stralloc_t*  s, stralloc_t*  from )
{
    stralloc_ready(s, from->n);
    memcpy( s->s, from->s, from->n );
    s->n = from->n;
}

extern void
stralloc_append( stralloc_t*  s, stralloc_t*  from )
{
    stralloc_readyplus( s, from->n );
    memcpy( s->s + s->n, from->s, from->n );
    s->n += from->n;
}

extern void
stralloc_add_c( stralloc_t*  s, int  c )
{
    stralloc_add_bytes( s, (char*)&c, 1 );
}

extern void
stralloc_add_str( stralloc_t*  s, const char*  str )
{
    stralloc_add_bytes( s, str, strlen(str) );
}

extern void
stralloc_add_bytes( stralloc_t*  s, const void*  from, unsigned len )
{
    stralloc_readyplus( s, len );
    memcpy( s->s + s->n, from, len );
    s->n += len;
}

extern char*
stralloc_cstr( stralloc_t*  s )
{
    stralloc_readyplus( s, 1 );
    s->s[s->n] = 0;
    return s->s;
}

void
stralloc_lstrip( stralloc_t*  s )
{
    int  count;

    for (count = 0; count < s->n; count++) {
        if (s->s[count] != ' ' && s->s[count] != '\t')
            break;
    }

    if (count > 0) {
        memmove(s->s, s->s + count, s->n - count);
        s->n -= count;
    }
}

void
stralloc_rstrip( stralloc_t*  s )
{
    int  count = s->n;

    while (count > 0 && (s->s[count-1] == ' ' || s->s[count-1] == '\t'))
        count--;

    s->n = count;
}

void
stralloc_strip( stralloc_t* s )
{
    stralloc_rstrip(s);
    stralloc_lstrip(s);
}

extern char*
stralloc_to_tempstr( stralloc_t*  s )
{
    char*  q = tempstr_get( s->n );

    memcpy( q, s->s, s->n );
    q[s->n] = 0;
    return q;
}

extern void
stralloc_formatv( stralloc_t*  s, const char*  fmt, va_list  args )
{
    stralloc_reset(s);
    stralloc_ready(s,10);

    while (1) {
        int      n;
        va_list  args2;

        va_copy(args2, args);
        n = vsnprintf( s->s, s->a, fmt, args2 );
        va_end(args2);

        /* funky old C libraries returns -1 when truncation occurs */
        if (n > -1 && n < s->a) {
            s->n = n;
            break;
        }
        if (n > -1) {  /* we now precisely what we need */
            stralloc_ready( s, n+1 );
        } else {
            stralloc_ready( s, s->a*2 );
        }
    }
}


extern void
stralloc_format( stralloc_t*  s, const char*  fmt, ... )
{
    va_list  args;
    va_start(args, fmt);
    stralloc_formatv(s, fmt, args);
    va_end(args);
}

extern void
stralloc_add_formatv( stralloc_t*  s, const char*  fmt, va_list  args )
{
    STRALLOC_DEFINE(s2);
    stralloc_formatv(s2, fmt, args);
    stralloc_append( s, s2 );
    stralloc_reset( s2 );
}

extern void
stralloc_add_format( stralloc_t*  s, const char*  fmt, ... )
{
    va_list  args;
    va_start(args, fmt);
    stralloc_add_formatv( s, fmt, args );
    va_end(args);
}

extern void
stralloc_add_quote_c( stralloc_t*  s, int  c )
{
    stralloc_add_quote_bytes( s, (char*)&c, 1 );
}

extern void
stralloc_add_quote_str( stralloc_t*  s, const char*  str )
{
    stralloc_add_quote_bytes( s, str, strlen(str) );
}

extern void
stralloc_add_quote_bytes( stralloc_t*  s, const void*  from, unsigned  len )
{
    uint8_t*   p   = (uint8_t*) from;
    uint8_t*   end = p + len;

    for ( ; p < end; p++ ) {
        int  c = p[0];

        if (c == '\\') {
            stralloc_add_str( s, "\\\\" );
        } else if (c >= ' ' && c < 128) {
            stralloc_add_c( s, c );
        } else if (c == '\n') {
            stralloc_add_str( s, "\\n" );
        } else if (c == '\t') {
            stralloc_add_str( s, "\\t" );
        } else if (c == '\r') {
            stralloc_add_str( s, "\\r" );
        } else {
            stralloc_add_format( s, "\\x%02x", c );
        }
    }
}

extern void
stralloc_add_hex( stralloc_t*  s, unsigned  value, int  num_digits )
{
    const char   hexdigits[16] = "0123456789abcdef";
    int          nn;

    if (num_digits <= 0)
        return;

    stralloc_readyplus(s, num_digits);
    for (nn = num_digits-1; nn >= 0; nn--) {
        s->s[s->n+nn] = hexdigits[value & 15];
        value >>= 4;
    }
    s->n += num_digits;
}

extern void
stralloc_add_hexdump( stralloc_t*  s, void*  base, int  size, const char*  prefix )
{
    uint8_t*   p          = (uint8_t*)base;
    const int  max_count  = 16;
    int        prefix_len = strlen(prefix);

    while (size > 0) {
        int          count = size > max_count ? max_count : size;
        int          count2;
        int          n;

        stralloc_add_bytes( s, prefix, prefix_len );
        stralloc_add_hex( s, p[0], 2 );

        for (n = 1; n < count; n++) {
            stralloc_add_c( s, ' ' );
            stralloc_add_hex( s, p[n], 2 );
        }

        count2 = 4 + 3*(max_count - count);
        stralloc_readyplus( s, count2 );
        memset( s->s + s->n, ' ', count2 );
        s->n += count2;

        stralloc_readyplus(s, count+1);
        for (n = 0; n < count; n++) {
            int  c = p[n];

            if (c < 32 || c > 127)
                c = '.';

            s->s[s->n++] = c;
        }
        s->s[s->n++] = '\n';

        size -= count;
        p    += count;
    }
}

