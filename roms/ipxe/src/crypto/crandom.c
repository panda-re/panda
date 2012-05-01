/*
 * Copyright (c) 2009 Joshua Oreman <oremanj@rwcr.net>.
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

/** @file
 *
 * Cryptographically strong random number generator
 *
 * Currently the cryptographic part is not implemented, and this just
 * uses random().
 */

#include <ipxe/crypto.h>
#include <stdlib.h>

/**
 * Get cryptographically strong random bytes
 *
 * @v buf	Buffer in which to store random bytes
 * @v len	Number of random bytes to generate
 *
 * @b WARNING: This function is currently underimplemented, and does
 * not give numbers any stronger than random()!
 */
void get_random_bytes ( void *buf, size_t len )
{
	u8 *bufp = buf;

	/*
	 * Somewhat arbitrarily, choose the 0x00FF0000-masked byte
	 * returned by random() as having good entropy. PRNGs often
	 * don't provide good entropy in lower bits, and the top byte
	 * might show a pattern because of sign issues.
	 */

	while ( len-- ) {
		*bufp++ = ( random() >> 16 ) & 0xFF;
	}
}
