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

/** @file
 *
 * Optimised string operations
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <string.h>

/**
 * Copy memory area
 *
 * @v dest		Destination address
 * @v src		Source address
 * @v len		Length
 * @ret dest		Destination address
 */
void * __memcpy ( void *dest, const void *src, size_t len ) {
	void *edi = dest;
	const void *esi = src;
	int discard_ecx;

	/* We often do large dword-aligned and dword-length block
	 * moves.  Using movsl rather than movsb speeds these up by
	 * around 32%.
	 */
	if ( len >> 2 ) {
		__asm__ __volatile__ ( "rep movsl"
				       : "=&D" ( edi ), "=&S" ( esi ),
				         "=&c" ( discard_ecx )
				       : "0" ( edi ), "1" ( esi ),
				         "2" ( len >> 2 )
				       : "memory" );
	}
	if ( len & 0x02 ) {
		__asm__ __volatile__ ( "movsw" : "=&D" ( edi ), "=&S" ( esi )
				       : "0" ( edi ), "1" ( esi ) : "memory" );
	}
	if ( len & 0x01 ) {
		__asm__ __volatile__ ( "movsb" : "=&D" ( edi ), "=&S" ( esi )
				       : "0" ( edi ), "1" ( esi ) : "memory" );
	}
	return dest;
}
