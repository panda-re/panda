/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/base16.h>

/** @file
 *
 * Base16 encoding
 *
 */

/**
 * Base16-encode data
 *
 * @v raw		Raw data
 * @v len		Length of raw data
 * @v encoded		Buffer for encoded string
 *
 * The buffer must be the correct length for the encoded string.  Use
 * something like
 *
 *     char buf[ base16_encoded_len ( len ) + 1 ];
 *
 * (the +1 is for the terminating NUL) to provide a buffer of the
 * correct size.
 */
void base16_encode ( const uint8_t *raw, size_t len, char *encoded ) {
	const uint8_t *raw_bytes = raw;
	char *encoded_bytes = encoded;
	size_t remaining = len;

	for ( ; remaining-- ; encoded_bytes += 2 ) {
		sprintf ( encoded_bytes, "%02x", *(raw_bytes++) );
	}

	DBG ( "Base16-encoded to \"%s\":\n", encoded );
	DBG_HDA ( 0, raw, len );
	assert ( strlen ( encoded ) == base16_encoded_len ( len ) );
}

/**
 * Base16-decode data
 *
 * @v encoded		Encoded string
 * @v raw		Raw data
 * @ret len		Length of raw data, or negative error
 *
 * The buffer must be large enough to contain the decoded data.  Use
 * something like
 *
 *     char buf[ base16_decoded_max_len ( encoded ) ];
 *
 * to provide a buffer of the correct size.
 */
int base16_decode ( const char *encoded, uint8_t *raw ) {
	const char *encoded_bytes = encoded;
	uint8_t *raw_bytes = raw;
	char buf[3];
	char *endp;
	size_t len;

	while ( encoded_bytes[0] ) {
		if ( ! encoded_bytes[1] ) {
			DBG ( "Base16-encoded string \"%s\" has invalid "
			      "length\n", encoded );
			return -EINVAL;
		}
		memcpy ( buf, encoded_bytes, 2 );
		buf[2] = '\0';
		*(raw_bytes++) = strtoul ( buf, &endp, 16 );
		if ( *endp != '\0' ) {
			DBG ( "Base16-encoded string \"%s\" has invalid "
			      "byte \"%s\"\n", encoded, buf );
			return -EINVAL;
		}
		encoded_bytes += 2;
	}
	len = ( raw_bytes - raw );

	DBG ( "Base16-decoded \"%s\" to:\n", encoded );
	DBG_HDA ( 0, raw, len );
	assert ( len <= base16_decoded_max_len ( encoded ) );

	return ( len );
}
