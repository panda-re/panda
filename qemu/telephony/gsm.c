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
#include "gsm.h"
#include <stdlib.h>
#include <string.h>

/** UTILITIES
 **/
byte_t
gsm_int_to_bcdi( int  value )
{
    return (byte_t)((value / 10) | ((value % 10) << 4));
}

int
gsm_int_from_bcdi( byte_t  val )
{
    int  ret = 0;

    if ((val & 0xf0) <= 0x90)
        ret = (val >> 4);

    if ((val & 0x0f) <= 0x90)
        ret |= (val % 0xf)*10;

    return ret;
}

#if 0
static int
gsm_bcdi_to_ascii( cbytes_t  bcd, int  bcdlen, bytes_t  dst )
{
    static byte_t  bcdichars[14] = "0123456789*#,N";

    int  result = 0;
    int  shift  = 0;

    while (bcdlen > 0) {
        int  c = (bcd[0] >> shift) & 0xf;

        if (c == 0xf && bcdlen == 1)
            break;

        if (c < 14) {
            if (dst) dst[result] = bcdichars[c];
            result += 1;
        }
        bcdlen --;
        shift += 4;
        if (shift == 8) {
            bcd++;
            shift = 0;
        }
    }
    return result;
}
#endif

#if 0
static int
gsm_bcdi_from_ascii( cbytes_t  ascii, int  asciilen, bytes_t  dst )
{
    cbytes_t  end    = ascii + asciilen;
    int       result = 0;
    int       phase  = 0x01;

    while (ascii < end) {
        int  c = *ascii++;

        if (c == '*')
            c = 11;
        else if (c == '#')
            c = 12;
        else if (c == ',')
            c = 13;
        else if (c == 'N')
            c = 14;
        else {
            c -= '0';
            if ((unsigned)c >= 10)
                break;
        }
        phase = (phase << 4) | c;
        if (phase & 0x100) {
            if (dst) dst[result] = (byte_t) phase;
            result += 1;
            phase   = 0x01;
        }
    }
    if (phase != 0x01) {
        if (dst) dst[result] = (byte_t)( phase | 0xf0 );
        result += 1;
    }
    return  result;
}
#endif

int
gsm_hexchar_to_int( char  c )
{
    if ((unsigned)(c - '0') < 10)
        return c - '0';
    if ((unsigned)(c - 'a') < 6)
        return 10 + (c - 'a');
    if ((unsigned)(c - 'A') < 6)
        return 10 + (c - 'A');
    return -1;
}

int
gsm_hexchar_to_int0( char  c )
{
    int  ret = gsm_hexchar_to_int(c);

    return (ret < 0) ? 0 : ret;
}

int
gsm_hex2_to_byte( const char*  hex )
{
    int  hi = gsm_hexchar_to_int(hex[0]);
    int  lo = gsm_hexchar_to_int(hex[1]);

    if (hi < 0 || lo < 0)
        return -1;

    return ( (hi << 4) | lo );
}

int
gsm_hex4_to_short( const char*  hex )
{
    int  hi = gsm_hex2_to_byte(hex);
    int  lo = gsm_hex2_to_byte(hex+2);

    if (hi < 0 || lo < 0)
        return -1;

    return ((hi << 8) | lo);
}

int
gsm_hex2_to_byte0( const char*  hex )
{
    int  hi = gsm_hexchar_to_int0(hex[0]);
    int  lo = gsm_hexchar_to_int0(hex[1]);

    return (byte_t)( (hi << 4) | lo );
}

void
gsm_hex_from_byte( char*  hex, int val )
{
    static const char  hexdigits[] = "0123456789abcdef";

    hex[0] = hexdigits[(val >> 4) & 15];
    hex[1] = hexdigits[val & 15];
}

void
gsm_hex_from_short( char*  hex, int  val )
{
    gsm_hex_from_byte( hex,   (val >> 8) );
    gsm_hex_from_byte( hex+2, val );
}



/** HEX
 **/
void
gsm_hex_to_bytes0( cbytes_t  hex, int  hexlen, bytes_t  dst )
{
    int  nn;

    for (nn = 0; nn < hexlen/2; nn++ ) {
        dst[nn] = (byte_t) gsm_hex2_to_byte0( (const char*)hex+2*nn );
    }
    if (hexlen & 1) {
        dst[nn] = gsm_hexchar_to_int0( hex[2*nn] ) << 4;
    }
}

int
gsm_hex_to_bytes( cbytes_t  hex, int  hexlen, bytes_t  dst )
{
    int  nn;

    if (hexlen & 1)  /* must be even */
        return -1;

    for (nn = 0; nn < hexlen/2; nn++ ) {
        int  c = gsm_hex2_to_byte( (const char*)hex+2*nn );
        if (c < 0) return -1;
        dst[nn] = (byte_t) c;
    }
    return hexlen/2;
}

void
gsm_hex_from_bytes( char*  hex, cbytes_t  src, int  srclen )
{
    int  nn;

    for (nn = 0; nn < srclen; nn++) {
        gsm_hex_from_byte( hex + 2*nn, src[nn] );
    }
}

/** ROPES
 **/

void
gsm_rope_init( GsmRope  rope )
{
    rope->data  = NULL;
    rope->pos   = 0;
    rope->max   = 0;
    rope->error = 0;
}

void
gsm_rope_init_alloc( GsmRope  rope, int  count )
{
    rope->data  = rope->data0;
    rope->pos   = 0;
    rope->max   = sizeof(rope->data0);
    rope->error = 0;

    if (count > 0) {
        rope->data = calloc( count, 1 );
        rope->max  = count;

        if (rope->data == NULL) {
            rope->error = 1;
            rope->max   = 0;
        }
    }
}

int
gsm_rope_done( GsmRope  rope )
{
    int  result = rope->error;

    if (rope->data && rope->data != rope->data0)
        free(rope->data);

    rope->data  = NULL;
    rope->pos   = 0;
    rope->max   = 0;
    rope->error = 0;

    return result;
}


bytes_t
gsm_rope_done_acquire( GsmRope  rope, int  *psize )
{
    bytes_t  result = rope->data;

    *psize = rope->pos;
    if (result == rope->data0) {
        result = malloc(  rope->pos );
        if (result != NULL)
            memcpy( result, rope->data, rope->pos );
    }
    return result;
}


int
gsm_rope_ensure( GsmRope  rope, int  new_count )
{
    if (rope->data != NULL) {
        int       old_max  = rope->max;
        bytes_t   old_data = rope->data == rope->data0 ? NULL : rope->data;
        int       new_max  = old_max;
        bytes_t   new_data;

        while (new_max < new_count) {
            new_max += (new_max >> 1) + 4;
        }
        new_data = realloc( old_data, new_max );
        if (new_data == NULL) {
            rope->error = 1;
            return -1;
        }
        rope->data = new_data;
        rope->max  = new_max;
    } else {
        rope->max = new_count;
    }
    return 0;
}

static int
gsm_rope_can_grow( GsmRope  rope, int  count )
{
    if (!rope->data || rope->error)
        return 0;

    if (rope->pos + count > rope->max)
    {
        if (rope->data == NULL)
            rope->max = rope->pos + count;

        else if (rope->error ||
                 gsm_rope_ensure( rope, rope->pos + count ) < 0)
            return 0;
    }
    return 1;
}

void
gsm_rope_add_c( GsmRope  rope,  char  c )
{
    if (gsm_rope_can_grow(rope, 1)) {
        rope->data[ rope->pos ] = (byte_t) c;
    }
    rope->pos += 1;
}

void
gsm_rope_add( GsmRope  rope, const void*  buf, int  buflen )
{
    if (gsm_rope_can_grow(rope, buflen)) {
        memcpy( rope->data + rope->pos, (const char*)buf, buflen );
    }
    rope->pos += buflen;
}

void*
gsm_rope_reserve( GsmRope  rope, int  count )
{
    void*  result = NULL;

    if (gsm_rope_can_grow(rope, count))
    {
        if (rope->data != NULL)
            result = rope->data + rope->pos;
    }
    rope->pos += count;

    return result;
}

/* skip a given number of Unicode characters in a utf-8 byte string */
cbytes_t
utf8_skip( cbytes_t   utf8,
           cbytes_t   utf8end,
           int        count)
{
    cbytes_t  p   = utf8;
    cbytes_t  end = utf8end;

    for ( ; count > 0; count-- ) {
        int  c;

        if (p >= end)
            break;

        c = *p++;
        if (c > 128) {
            while (p < end && (p[0] & 0xc0) == 0x80)
                p++;
        }
    }
    return  p;
}


static __inline__ int
utf8_next( cbytes_t  *pp, cbytes_t  end )
{
    cbytes_t  p      = *pp;
    int       result = -1;

    if (p < end) {
        int  c= *p++;
        if (c >= 128) {
            if ((c & 0xe0) == 0xc0)
                c &= 0x1f;
            else if ((c & 0xf0) == 0xe0)
                c &= 0x0f;
            else
                c &= 0x07;

            while (p < end && (p[0] & 0xc0) == 0x80) {
                c = (c << 6) | (p[0] & 0x3f);
                p ++;
            }
        }
        result = c;
        *pp    = p;
    }
    return result;
}


__inline__ int
utf8_write( bytes_t  utf8, int  offset, int  v )
{
    int  result;

    if (v < 128) {
        result = 1;
        if (utf8)
            utf8[offset] = (byte_t) v;
    } else if (v < 0x800) {
        result = 2;
        if (utf8) {
            utf8[offset+0] = (byte_t)( 0xc0 | (v >> 6) );
            utf8[offset+1] = (byte_t)( 0x80 | (v & 0x3f) );
        }
    } else if (v < 0x10000) {
        result = 3;
        if (utf8) {
            utf8[offset+0] = (byte_t)( 0xe0 |  (v >> 12) );
            utf8[offset+1] = (byte_t)( 0x80 | ((v >> 6) & 0x3f) );
            utf8[offset+2] = (byte_t)( 0x80 |  (v & 0x3f) );
        }
    } else {
        result = 4;
        if (utf8) {
            utf8[offset+0] = (byte_t)( 0xf0 | ((v >> 18) & 0x7) );
            utf8[offset+1] = (byte_t)( 0x80 | ((v >> 12) & 0x3f) );
            utf8[offset+2] = (byte_t)( 0x80 | ((v >> 6) & 0x3f) );
            utf8[offset+3] = (byte_t)( 0x80 |  (v & 0x3f) );
        }
    }
    return  result;
}

static __inline__ int
ucs2_write( bytes_t  ucs2, int  offset, int  v )
{
    if (ucs2) {
        ucs2[offset+0] = (byte_t) (v >> 8);
        ucs2[offset+1] = (byte_t) (v);
    }
    return 2;
}

int
utf8_check( cbytes_t   p, int  utf8len )
{
    cbytes_t  end    = p + utf8len;
    int       result = 0;

    if (p) {
        while (p < end) {
            int  c = *p++;
            if (c >= 128) {
                int  len;
                if ((c & 0xe0) == 0xc0) {
                    len = 1;
                }
                else if ((c & 0xf0) == 0xe0) {
                    len = 2;
                }
                else if ((c & 0xf8) == 0xf0) {
                    len = 3;
                }
                else
                    goto Exit;  /* malformed utf-8 */

                if (p+len > end) /* string too short */
                    goto Exit;

                for ( ; len > 0; len--, p++ ) {
                    if ((p[0] & 0xc0) != 0x80)
                        goto Exit;
                }
            }
        }
        result = 1;
    }
Exit:
    return result;
}

/** UCS2 to UTF8
 **/

/* convert a UCS2 string into a UTF8 byte string, assumes 'buf' is correctly sized */
int
ucs2_to_utf8( cbytes_t  ucs2,
              int       ucs2len,
              bytes_t   buf )
{
    int  nn;
    int  result = 0;

    for (nn = 0; nn < ucs2len; ucs2 += 2, nn++) {
        int  c= (ucs2[0] << 8) | ucs2[1];
        result += utf8_write(buf, result, c);
    }
    return result;
}

/* count the number of UCS2 chars contained in a utf8 byte string */
int
utf8_to_ucs2( cbytes_t  utf8,
              int       utf8len,
              bytes_t   ucs2 )
{
    cbytes_t  p      = utf8;
    cbytes_t  end    = p + utf8len;
    int       result = 0;

    while (p < end) {
        int  c = utf8_next(&p, end);

        if (c < 0)
            break;

        result += ucs2_write(ucs2, result, c);
    }
    return result/2;
}



/** GSM ALPHABET
 **/

#define  GSM_7BITS_ESCAPE   0x1b
#define  GSM_7BITS_UNKNOWN  0

static const unsigned short   gsm7bits_to_unicode[128] = {
  '@', 0xa3,  '$', 0xa5, 0xe8, 0xe9, 0xf9, 0xec, 0xf2, 0xc7, '\n', 0xd8, 0xf8, '\r', 0xc5, 0xe5,
0x394,  '_',0x3a6,0x393,0x39b,0x3a9,0x3a0,0x3a8,0x3a3,0x398,0x39e,    0, 0xc6, 0xe6, 0xdf, 0xc9,
  ' ',  '!',  '"',  '#', 0xa4,  '%',  '&', '\'',  '(',  ')',  '*',  '+',  ',',  '-',  '.',  '/',
  '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',  '8',  '9',  ':',  ';',  '<',  '=',  '>',  '?',
 0xa1,  'A',  'B',  'C',  'D',  'E',  'F',  'G',  'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
  'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',  'X',  'Y',  'Z', 0xc4, 0xd6,0x147, 0xdc, 0xa7,
 0xbf,  'a',  'b',  'c',  'd',  'e',  'f',  'g',  'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
  'p',  'q',  'r',  's',  't',  'u',  'v',  'w',  'x',  'y',  'z', 0xe4, 0xf6, 0xf1, 0xfc, 0xe0,
};

static const unsigned short  gsm7bits_extend_to_unicode[128] = {
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,'\f',   0,   0,   0,   0,   0,
    0,   0,   0,   0, '^',   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0, '{', '}',   0,   0,   0,   0,   0,'\\',
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0, '[', '~', ']',   0,
  '|',   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,0x20ac, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
};


static int
unichar_to_gsm7( int  unicode )
{
    int  nn;
    for (nn = 0; nn < 128; nn++) {
        if (gsm7bits_to_unicode[nn] == unicode) {
            return nn;
        }
    }
    return -1;
}

static int
unichar_to_gsm7_extend( int  unichar )
{
    int  nn;
    for (nn = 0; nn < 128; nn++) {
        if (gsm7bits_extend_to_unicode[nn] == unichar) {
            return nn;
        }
    }
    return -1;
}


/* return the number of septets needed to encode a unicode charcode */
static int
unichar_to_gsm7_count( int  unicode )
{
    int  nn;

    nn = unichar_to_gsm7(unicode);
    if (nn >= 0)
        return 1;

    nn = unichar_to_gsm7_extend(unicode);
    if (nn >= 0)
        return 2;

    return 0;
}


cbytes_t
utf8_skip_gsm7( cbytes_t  utf8, cbytes_t  utf8end, int  gsm7len )
{
    cbytes_t  p   = utf8;
    cbytes_t  end = utf8end;

    while (gsm7len >0) {
        cbytes_t  q = p;
        int       c = utf8_next( &q, end );
        int       len;

        if (c < 0)
            break;

        len = unichar_to_gsm7_count( c );
        if (len == 0)  /* unknown chars are replaced by spaces */
            len = 1;

        if (len > gsm7len)
            break;

        gsm7len -= len;
        p        = q;
    }
    return  p;
}


int
utf8_check_gsm7( cbytes_t  utf8,
                 int       utf8len )
{
    cbytes_t  utf8end = utf8 + utf8len;

    while (utf8 < utf8end) {
        int  c = utf8_next( &utf8, utf8end );
        if (unichar_to_gsm7_count(c) == 0)
            return 0;
    }
    return 1;
}


int
utf8_from_gsm7( cbytes_t  src,
                int       septet_offset,
                int       septet_count,
                bytes_t   utf8 )
{
    int  shift   = (septet_offset & 7);
    int  escaped = 0;
    int  result  = 0;

    src += (septet_offset >> 3);
    for ( ; septet_count > 0; septet_count-- )
    {
        int  c = (src[0] >> shift) & 0x7f;
        int  v;

        if (shift > 1) {
            c = ((src[1] << (8-shift)) | c) & 0x7f;
        }

        if (escaped) {
            v = gsm7bits_extend_to_unicode[c];
        } else if (c == GSM_7BITS_ESCAPE) {
            escaped = 1;
            goto NextSeptet;
        } else {
            v = gsm7bits_to_unicode[c];
        }

        result += utf8_write( utf8, result, v );

    NextSeptet:
        shift += 7;
        if (shift >= 8) {
            shift -= 8;
            src   += 1;
        }
    }
    return  result;
}


int
utf8_from_gsm8( cbytes_t  src, int  count, bytes_t  utf8 )
{
    int  result  = 0;
    int  escaped = 0;


    for ( ; count > 0; count-- )
    {
        int  c = *src++;

        if (c == 0xff)
            break;

        if (c == GSM_7BITS_ESCAPE) {
            if (escaped) { /* two escape characters => one space */
                c = 0x20;
                escaped = 0;
            } else {
                escaped = 1;
                continue;
            }
        }
        else
        {
            if (c >= 0x80) {
                c       = 0x20;
                escaped = 0;
            } else if (escaped) {
                c = gsm7bits_extend_to_unicode[c];
            } else
                c = gsm7bits_to_unicode[c];
        }

        result += utf8_write( utf8, result, c );
    }
    return  result;
}

/* convert a GSM 7-bit message into a unicode character array
 * the 'dst' array must contain at least 160 chars. the function
 * returns the number of characters decoded
 *
 * assumes the 'dst' array has at least septet_count items, returns the
 * number of unichars really written
 */
int
ucs2_from_gsm7( bytes_t   ucs2,
                cbytes_t  src,
                int       septet_offset,
                int       septet_count )
{
    const unsigned char*  p     = src + (septet_offset >> 3);
    int                   shift = (septet_offset & 7);
    int                   escaped = 0;
    int                   result  = 0;

    for ( ; septet_count > 0; septet_count-- )
    {
        unsigned  val  = (p[0] >> shift) & 0x7f;

        if (shift > 1)
            val = (val | (p[1] << (8-shift))) & 0x7f;

        if (escaped) {
            int  c = gsm7bits_to_unicode[val];

            result += ucs2_write(ucs2, result, c);
            escaped = 0;
        }
        else if (val == GSM_7BITS_ESCAPE) {
            escaped = 1;
        }
        else {
            val = gsm7bits_extend_to_unicode[val];
            if (val == 0)
                val = 0x20;

            result += ucs2_write( ucs2, result, val );
        }
    }
    return result/2;
}


/* count the number of septets required to write a utf8 string */
static int
utf8_to_gsm7_count( cbytes_t  utf8, int  utf8len )
{
    cbytes_t  utf8end = utf8 + utf8len;
    int       result  = 0;

    while ( utf8 < utf8end ) {
        int  len;
        int  c = utf8_next( &utf8, utf8end );

        if (c < 0)
            break;

        len = unichar_to_gsm7_count(c);
        if (len == 0)    /* replace non-representables with space */
            len = 1;

        result += len;
    }
    return result;
}

typedef struct {
    bytes_t   dst;
    unsigned  pad;
    int       bits;
    int       offset;
} BWriterRec, *BWriter;

static void
bwriter_init( BWriter  writer, bytes_t  dst, int  start )
{
    int  shift = start & 7;

    writer->dst    = dst + (start >> 3);
    writer->pad    = 0;
    writer->bits   = shift;
    writer->offset = start;

    if (shift > 0) {
        writer->pad  = writer->dst[0] & ~(0xFF << shift);
    }
}

static void
bwriter_add7( BWriter  writer, unsigned  value )
{
    writer->pad  |= (unsigned)(value << writer->bits);
    writer->bits += 7;
    if (writer->bits >= 8) {
        writer->dst[0] = (byte_t)writer->pad;
        writer->bits  -= 8;
        writer->pad  >>= 8;
        writer->dst   += 1;
    }
    writer->offset += 7;
}

static int
bwriter_done( BWriter  writer )
{
    if (writer->bits > 0) {
        writer->dst[0] = (byte_t)writer->pad;
        writer->pad    = 0;
        writer->bits   = 0;
        writer->dst   += 1;
    }
    return writer->offset;
}

/* convert a utf8 string to a gsm7 byte string - return the number of septets written */
int
utf8_to_gsm7( cbytes_t  utf8, int  utf8len, bytes_t  dst, int offset )
{
    const unsigned char*  utf8end = utf8 + utf8len;
    BWriterRec            writer[1];

    if (dst == NULL)
        return utf8_to_gsm7_count(utf8, utf8len);

    bwriter_init( writer, dst, offset );
    while ( utf8 < utf8end ) {
        int  c = utf8_next( &utf8, utf8end );
        int  nn;

        if (c < 0)
            break;

        nn = unichar_to_gsm7(c);
        if (nn >= 0) {
            bwriter_add7( writer, nn );
            continue;
        }

        nn = unichar_to_gsm7_extend(c);
        if (nn >= 0) {
            bwriter_add7( writer, GSM_7BITS_ESCAPE );
            bwriter_add7( writer, nn );
            continue;
        }

        /* unknown => replaced by space */
        bwriter_add7( writer, 0x20 );
    }
    return  bwriter_done( writer );
}


int
utf8_to_gsm8( cbytes_t  utf8, int  utf8len, bytes_t  dst )
{
    const unsigned char*  utf8end = utf8 + utf8len;
    int                   result  = 0;

    while ( utf8 < utf8end ) {
        int  c = utf8_next( &utf8, utf8end );
        int  nn;

        if (c < 0)
            break;

        nn = unichar_to_gsm7(c);
        if (nn >= 0) {
            if (dst)
                dst[result] = (byte_t)nn;
            result += 1;
            continue;
        }

        nn = unichar_to_gsm7_extend(c);
        if (nn >= 0) {
            if (dst) {
                dst[result+0] = (byte_t) GSM_7BITS_ESCAPE;
                dst[result+1] = (byte_t) nn;
            }
            result += 2;
            continue;
        }

        /* unknown => space */
        if (dst)
            dst[result] = 0x20;
        result += 1;
    }
    return  result;
}


int
ucs2_to_gsm7( cbytes_t  ucs2, int  ucs2len, bytes_t  dst, int offset )
{
    const unsigned char*  ucs2end = ucs2 + ucs2len*2;
    BWriterRec            writer[1];

    bwriter_init( writer, dst, offset );
    while ( ucs2 < ucs2end ) {
        int  c = *ucs2++;
        int  nn;

        for (nn = 0; nn < 128; nn++) {
            if ( gsm7bits_to_unicode[nn] == c ) {
                bwriter_add7( writer, nn );
                goto NextUnicode;
            }
        }
        for (nn = 0; nn < 128; nn++) {
            if ( gsm7bits_extend_to_unicode[nn] == c ) {
                bwriter_add7( writer, GSM_7BITS_ESCAPE );
                bwriter_add7( writer, nn );
                goto NextUnicode;
            }
        }

        /* unknown */
        bwriter_add7( writer, 0x20 );

    NextUnicode:
        ;
    }
    return  bwriter_done( writer );
}


int
ucs2_to_gsm8( cbytes_t  ucs2, int  ucs2len, bytes_t  dst )
{
    const unsigned char*  ucs2end = ucs2 + ucs2len*2;
    bytes_t               dst0    = dst;

    while ( ucs2 < ucs2end ) {
        int  c = *ucs2++;
        int  nn;

        for (nn = 0; nn < 128; nn++) {
            if ( gsm7bits_to_unicode[nn] == c ) {
                *dst++ = (byte_t)nn;
                goto NextUnicode;
            }
        }
        for (nn = 0; nn < 128; nn++) {
            if ( gsm7bits_extend_to_unicode[nn] == c ) {
                dst[0] = (byte_t) GSM_7BITS_ESCAPE;
                dst[1] = (byte_t) nn;
                dst   += 2;
                goto NextUnicode;
            }
        }

        /* unknown */
        *dst++ = 0x20;

    NextUnicode:
        ;
    }
    return (dst - dst0);
}

int
gsm_bcdnum_to_ascii( cbytes_t  bcd, int  count, bytes_t  dst )
{
    int  result = 0;
    int  shift  = 0;

    while (count > 0) {
        int  c = (bcd[0] >> shift) & 0xf;

        if (c == 15 && count == 1)  /* ignore trailing 0xf */
            break;

        if (c >= 14)
            c = 0;

        if (dst) dst[result] = "0123456789*#,N"[c];
        result += 1;

        shift += 4;
        if (shift == 8) {
            shift = 0;
            bcd += 1;
        }
    }
    return  result;
}


int
gsm_bcdnum_from_ascii( cbytes_t  ascii, int  asciilen, bytes_t  dst )
{
    cbytes_t  end = ascii + asciilen;
    int  result   = 0;
    int  phase = 0x01;

    while (ascii < end) {
        int  c = *ascii++;

        if (c == '*')
            c = 10;
        else if (c == '#')
            c = 11;
        else if (c == ',')
            c = 12;
        else if (c == 'N')
            c = 13;
        else {
            c -= '0';
            if ((unsigned)c >= 10U)
                return -1;
        }
        phase   = (phase << 4) | c;
        result += 1;
        if (phase & 0x100) {
            if (dst) dst[result/2] = (byte_t) phase;
            phase   = 0x01;
        }
    }

    if (result & 1) {
        if (dst) dst[result/2] = (byte_t)(phase | 0xf0);
    }
    return result;
}

/** ADN: Abbreviated Dialing Number
 **/

#define  ADN_FOOTER_SIZE     14
#define  ADN_OFFSET_NUMBER_LENGTH   0
#define  ADN_OFFSET_TON_NPI         1
#define  ADN_OFFSET_NUMBER_START    2
#define  ADN_OFFSET_NUMBER_END      11
#define  ADN_OFFSET_CAPABILITY_ID   12
#define  ADN_OFFSET_EXTENSION_ID    13

/* see 10.5.1 of 3GPP 51.011 */
static int
sim_adn_alpha_to_utf8( cbytes_t  alpha, cbytes_t  end, bytes_t  dst )
{
    int  result = 0;

    /* ignore trailing 0xff */
    while (alpha < end && end[-1] == 0xff)
        end--;

    if (alpha >= end)
        return 0;

    if (alpha[0] == 0x80) { /* UCS/2 source encoding */
        alpha += 1;
        result = ucs2_to_utf8( alpha, (end-alpha)/2, dst );
    }
    else
    {
        int  is_ucs2 = 0;
        int  len = 0, base = 0;

        if (alpha+3 <= end && alpha[0] == 0x81) {
            is_ucs2 = 1;
            len     = alpha[1];
            base    = alpha[2] << 7;
            alpha  += 3;
            if (len > end-alpha)
                len = end-alpha;
        } else if (alpha+4 <= end && alpha[0] == 0x82) {
            is_ucs2 = 1;
            len     = alpha[1];
            base    = (alpha[2] << 8) | alpha[3];
            alpha  += 4;
            if (len > end-alpha)
                len = end-alpha;
        }

        if (is_ucs2) {
            end = alpha + len;
            while (alpha < end) {
                int  c = alpha[0];
                if (c >= 0x80) {
                    result += utf8_write(dst, result, base + (c & 0x7f));
                    alpha  += 1;
                } else {
                    /* GSM character set */
                    int   count;
                    for (count = 0; alpha+count < end && alpha[count] < 128; count++)
                        ;
                    result += utf8_from_gsm8(alpha, count, (dst ? dst+result : NULL));
                    alpha  += count;
                }
            }
        }
        else {
            result = utf8_from_gsm8(alpha, end-alpha, dst);
        }
    }
    return result;
}

#if 0
static int
sim_adn_alpha_from_utf8( cbytes_t  utf8, int  utf8len, bytes_t  dst )
{
    int   result = 0;

    if (utf8_check_gsm7(utf8, utf8len)) {
        /* GSM 7-bit compatible, encode directly as 8-bit string */
        result = utf8_to_gsm8(utf8, utf8len, dst);
    } else {
        /* otherwise, simply try UCS-2 encoding, nothing more serious at the moment */
        if (dst) {
            dst[0] = 0x80;
        }
        result = 1 + utf8_to_ucs2(utf8, utf8len, dst ? (dst+1) : NULL)*2;
    }
    return  result;
}
#endif

int
sim_adn_record_from_bytes( SimAdnRecord  rec, cbytes_t  data, int  len )
{
    cbytes_t  end    = data + len;
    cbytes_t  footer = end - ADN_FOOTER_SIZE;
    int       num_len;

    rec->adn.alpha[0]  = 0;
    rec->adn.number[0] = 0;
    rec->ext_record    = 0xff;

    if (len < ADN_FOOTER_SIZE)
        return -1;

    /* alpha is optional */
    if (len > ADN_FOOTER_SIZE) {
        cbytes_t  dataend = data + len - ADN_FOOTER_SIZE;
        int       count   = sim_adn_alpha_to_utf8(data, dataend, NULL);

        if (count > sizeof(rec->adn.alpha)-1)  /* too long */
            return -1;

        sim_adn_alpha_to_utf8(data, dataend, rec->adn.alpha);
        rec->adn.alpha[count] = 0;
    }

    num_len = footer[ADN_OFFSET_NUMBER_LENGTH];
    if (num_len > 11)
        return -1;

    /* decode TON and number to ASCII, NOTE: this is lossy !! */
    {
        int      ton    = footer[ADN_OFFSET_TON_NPI];
        bytes_t  number = (bytes_t) rec->adn.number;
        int      len    = sizeof(rec->adn.number)-1;
        int      count;

        if (ton != 0x81 && ton != 0x91)
            return -1;

        if (ton == 0x91) {
            *number++ = '+';
            len      -= 1;
        }

        count = gsm_bcdnum_to_ascii( footer + ADN_OFFSET_NUMBER_START,
                                     num_len*2, number );
        number[count] = 0;
    }
    return 0;
}

int
sim_adn_record_to_bytes( SimAdnRecord  rec, bytes_t   data, int  datalen )
{
    bytes_t   end    = data + datalen;
    bytes_t   footer = end - ADN_FOOTER_SIZE;
    int       ton    = 0x81;
    cbytes_t  number = (cbytes_t) rec->adn.number;

    if (number[0] == '+') {
        ton     = 0x91;
        number += 1;
    }
    footer[0] = (strlen((const char*)number)+1)/2 + 1;
    /* XXXX: TODO */
    return 0;
}
