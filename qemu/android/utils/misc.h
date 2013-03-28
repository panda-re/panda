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

/** STRING PARAMETER PARSING
 **/

/* A strict 'int' version of the 'strtol'.
 * This routine is implemented on top of the standard 'strtol' for 32/64 bit
 * portability.
 */
extern int strtoi(const char *nptr, char **endptr, int base);

/* Gets a parameter value out of the parameter string.
 * Parameter format for this routine is as such:
 *      "<name1>=<value1> <name2>=<value2> ... <nameN>=<valueN>"
 * I.e.:
 *  - Every parameter must have a name, and a value.
 *  - Name and value must be separated with '='.
 *  - No spaces are allowed around '=' separating name and value.
 *  - Parameters must be separated with a single ' ' character.
 *  - No '=' character is allowed in name and in value.
 * Param:
 *  params - String, containing the parameters.
 *  name - Parameter name.
 *  value - Upon success contains value for the given parameter.
 *  val_size - Size of the 'value' string buffer.
 * Return:
 *  0 on success, -1 if requested parameter is not found, or (a positive) number
 *  of bytes, required to make a copy of the parameter's value if 'value' string
 *  was too small to contain it.
 */
extern int get_token_value(const char* params, const char* name, char* value, int val_size);

/* Gets a parameter value out of the parameter string.
 * This routine is similar to get_token_value, except it will always allocate
 * a string buffer for the value.
 * Param:
 *  params - String, containing the parameters.
 *  name - Parameter name.
 *  value - Upon success contains an allocated string containint the value for
 *      the given parameter. The caller is responsible for freeing the buffer
 *      returned in this parameter on success.
 * Return:
 *  0 on success, -1 if requested parameter is not found, or -2 on
 *  memory failure.
 */
extern int get_token_value_alloc(const char* params, const char* name, char** value);

/* Gets an integer parameter value out of the parameter string.
 * Param:
 *  params - String, containing the parameters. See comments to get_token_value
 *      routine on the parameters format.
 *  name - Parameter name. Parameter value must be a decimal number.
 *  value - Upon success contains integer value for the given parameter.
 * Return:
 *  0 on success, or -1 if requested parameter is not found, or -2 if parameter's
 *  format was bad (i.e. value was not a decimal number).
 */
extern int get_token_value_int(const char* params, const char* name, int* value);

#endif /* _ANDROID_UTILS_MISC_H */
