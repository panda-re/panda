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
#ifndef _ANDROID_UTILS_MISC_H
#define _ANDROID_UTILS_MISC_H

#include <stdint.h>

/** TABULAR OUTPUT
 **
 ** prints a list of strings in row/column format
 **
 **/

extern void   print_tabular( const char** strings, int  count,
                             const char*  prefix,  int  width );

/** CHARACTER TRANSLATION
 **
 ** converts one character into another in strings
 **/

extern void   buffer_translate_char( char*        buff,
                                     unsigned     buffLen,
                                     const char*  src,
                                     char         fromChar,
                                     char         toChar );

extern void   string_translate_char( char*  str, char from, char to );

/** TEMP CHAR STRINGS
 **
 ** implement a circular ring of temporary string buffers
 **/

extern char*  tempstr_get( int   size );
extern char*  tempstr_format( const char*  fmt, ... );

/** QUOTING
 **
 ** dumps a human-readable version of a string. this replaces
 ** newlines with \n, etc...
 **/

extern const char*   quote_bytes( const char*  str, int  len );
extern const char*   quote_str( const char*  str );

/** DECIMAL AND HEXADECIMAL CHARACTER SEQUENCES
 **/

/* decodes a sequence of 'len' hexadecimal chars from 'hex' into
 * an integer. returns -1 in case of error (i.e. badly formed chars)
 */
extern int    hex2int( const uint8_t*  hex, int  len );

/* encodes an integer 'val' into 'len' hexadecimal charaters into 'hex' */
extern void   int2hex( uint8_t*  hex, int  len, int  val );

#endif /* _ANDROID_UTILS_MISC_H */
