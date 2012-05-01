/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <stddef.h>
#include <errno.h>
#include <ipxe/asn1.h>

/** @file
 *
 * ASN.1 encoding
 *
 */

/**
 * Start parsing ASN.1 object
 *
 * @v cursor		ASN.1 object cursor
 * @v type		Expected type
 * @ret len		Length of object body, or negative error
 *
 * The object cursor will be updated to point to the start of the
 * object body (i.e. the first byte following the length byte(s)), and
 * the length of the object body (i.e. the number of bytes until the
 * following object tag, if any) is returned.
 *
 * If any error occurs (i.e. if the object is not of the expected
 * type, or if we overflow beyond the end of the ASN.1 object), then
 * the cursor will be invalidated and a negative value will be
 * returned.
 */
static int asn1_start ( struct asn1_cursor *cursor,
			       unsigned int type ) {
	unsigned int len_len;
	unsigned int len;
	int rc;

	/* Sanity check */
	if ( cursor->len < 2 /* Tag byte and first length byte */ ) {
		if ( cursor->len )
			DBGC ( cursor, "ASN1 %p too short\n", cursor );
		rc = -EINVAL;
		goto notfound;
	}

	/* Check the tag byte */
	if ( *( ( uint8_t * ) cursor->data ) != type ) {
		DBGC ( cursor, "ASN1 %p type mismatch (expected %d, got %d)\n",
		       cursor, type, *( ( uint8_t * ) cursor->data ) );
		rc = -ENXIO;
		goto notfound;
	}
	cursor->data++;
	cursor->len--;

	/* Extract length of the length field and sanity check */
	len_len = *( ( uint8_t * ) cursor->data );
	if ( len_len & 0x80 ) {
		len_len = ( len_len & 0x7f );
		cursor->data++;
		cursor->len--;
	} else {
		len_len = 1;
	}
	if ( cursor->len < len_len ) {
		DBGC ( cursor, "ASN1 %p bad length field length %d (max "
		       "%zd)\n", cursor, len_len, cursor->len );
		rc = -EINVAL;
		goto notfound;
	}

	/* Extract the length and sanity check */
	for ( len = 0 ; len_len ; len_len-- ) {
		len <<= 8;
		len |= *( ( uint8_t * ) cursor->data );
		cursor->data++;
		cursor->len--;
	}
	if ( cursor->len < len ) {
		DBGC ( cursor, "ASN1 %p bad length %d (max %zd)\n",
		       cursor, len, cursor->len );
		rc = -EINVAL;
		goto notfound;
	}

	return len;

 notfound:
	cursor->data = NULL;
	cursor->len = 0;
	return rc;
}

/**
 * Enter ASN.1 object
 *
 * @v cursor		ASN.1 object cursor
 * @v type		Expected type
 * @ret rc		Return status code
 *
 * The object cursor will be updated to point to the body of the
 * current ASN.1 object.  If any error occurs, the object cursor will
 * be invalidated.
 */
int asn1_enter ( struct asn1_cursor *cursor, unsigned int type ) {
	int len;

	len = asn1_start ( cursor, type );
	if ( len < 0 )
		return len;

	cursor->len = len;
	DBGC ( cursor, "ASN1 %p entered object type %02x (len %x)\n",
	       cursor, type, len );

	return 0;
}

/**
 * Skip ASN.1 object
 *
 * @v cursor		ASN.1 object cursor
 * @v type		Expected type
 * @ret rc		Return status code
 *
 * The object cursor will be updated to point to the next ASN.1
 * object.  If any error occurs, the object cursor will be
 * invalidated.
 */
int asn1_skip ( struct asn1_cursor *cursor, unsigned int type ) {
	int len;

	len = asn1_start ( cursor, type );
	if ( len < 0 )
		return len;

	cursor->data += len;
	cursor->len -= len;
	DBGC ( cursor, "ASN1 %p skipped object type %02x (len %x)\n",
	       cursor, type, len );

	if ( ! cursor->len ) {
		DBGC ( cursor, "ASN1 %p reached end of object\n", cursor );
		cursor->data = NULL;
		return -ENOENT;
	}

	return 0;
}
