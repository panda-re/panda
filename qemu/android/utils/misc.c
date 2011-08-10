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

#include "android/utils/misc.h"
#include "android/utils/stralloc.h"
#include "android/utils/debug.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern void
print_tabular( const char** strings, int  count,
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
        printf( "%s", prefix );
        for (c = 0; c < ncols; c++) {
            int  index = c*nrows + r;
            if (index >= count) {
                break;
            }
            printf( "%-*s", maxw, strings[index] );
        }
        printf( "\n" );
    }
}

extern void
string_translate_char( char*  str, char from, char to )
{
    char*  p = str;
    while (p != NULL && (p = strchr(p, from)) != NULL)
        *p++ = to;
}

extern void
buffer_translate_char( char*        buff,
                       unsigned     buffLen,
                       const char*  src,
                       char         fromChar,
                       char         toChar )
{
    int    len = strlen(src);

    if (len >= buffLen)
        len = buffLen-1;

    memcpy(buff, src, len);
    buff[len] = 0;

    string_translate_char( buff, fromChar, toChar );
}


/** TEMP CHAR STRINGS
 **
 ** implement a circular ring of temporary string buffers
 **/

typedef struct Temptring {
    struct TempString*  next;
    char*               buffer;
    int                 size;
} TempString;

#define  MAX_TEMP_STRINGS   16

static TempString  _temp_strings[ MAX_TEMP_STRINGS ];
static int         _temp_string_n;

extern char*
tempstr_get( int  size )
{
    TempString*  t = &_temp_strings[_temp_string_n];

    if ( ++_temp_string_n >= MAX_TEMP_STRINGS )
        _temp_string_n = 0;

    size += 1;  /* reserve 1 char for terminating zero */

    if (t->size < size) {
        t->buffer = realloc( t->buffer, size );
        if (t->buffer == NULL) {
            derror( "%s: could not allocate %d bytes",
                    __FUNCTION__, size );
            exit(1);
        }
        t->size   = size;
    }
    return  t->buffer;
}

extern char*
tempstr_format( const char*  fmt, ... )
{
    va_list  args;
    char*    result;
    STRALLOC_DEFINE(s);
    va_start(args, fmt);
    stralloc_formatv(s, fmt, args);
    va_end(args);
    result = stralloc_to_tempstr(s);
    stralloc_reset(s);
    return result;
}

/** QUOTING
 **
 ** dumps a human-readable version of a string. this replaces
 ** newlines with \n, etc...
 **/

extern const char*
quote_bytes( const char*  str, int  len )
{
    STRALLOC_DEFINE(s);
    char*  q;

    stralloc_add_quote_bytes( s, str, len );
    q = stralloc_to_tempstr( s );
    stralloc_reset(s);
    return q;
}

extern const char*
quote_str( const char*  str )
{
    int  len = strlen(str);
    return quote_bytes( str, len );
}

/** HEXADECIMAL CHARACTER SEQUENCES
 **/

static int
hexdigit( int  c )
{
    unsigned  d;

    d = (unsigned)(c - '0');
    if (d < 10) return d;

    d = (unsigned)(c - 'a');
    if (d < 6) return d+10;

    d = (unsigned)(c - 'A');
    if (d < 6) return d+10;

    return -1;
}

int
hex2int( const uint8_t*  hex, int  len )
{
    int  result = 0;
    while (len > 0) {
        int  c = hexdigit(*hex++);
        if (c < 0)
            return -1;

        result = (result << 4) | c;
        len --;
    }
    return result;
}

void
int2hex( uint8_t*  hex, int  len, int  val )
{
    static const uint8_t  hexchars[16] = "0123456789abcdef";
    while ( --len >= 0 )
        *hex++ = hexchars[(val >> (len*4)) & 15];
}
