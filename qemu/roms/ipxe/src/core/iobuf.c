/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <errno.h>
#include <ipxe/malloc.h>
#include <ipxe/iobuf.h>

/** @file
 *
 * I/O buffers
 *
 */

/**
 * Allocate I/O buffer
 *
 * @v len	Required length of buffer
 * @ret iobuf	I/O buffer, or NULL if none available
 *
 * The I/O buffer will be physically aligned to a multiple of
 * @c IOBUF_SIZE.
 */
struct io_buffer * alloc_iob ( size_t len ) {
	struct io_buffer *iobuf = NULL;
	void *data;

	/* Pad to minimum length */
	if ( len < IOB_ZLEN )
		len = IOB_ZLEN;

	/* Align buffer length */
	len = ( len + __alignof__( *iobuf ) - 1 ) &
		~( __alignof__( *iobuf ) - 1 );
	
	/* Allocate memory for buffer plus descriptor */
	data = malloc_dma ( len + sizeof ( *iobuf ), IOB_ALIGN );
	if ( ! data )
		return NULL;

	iobuf = ( struct io_buffer * ) ( data + len );
	iobuf->head = iobuf->data = iobuf->tail = data;
	iobuf->end = iobuf;
	return iobuf;
}

/**
 * Free I/O buffer
 *
 * @v iobuf	I/O buffer
 */
void free_iob ( struct io_buffer *iobuf ) {
	if ( iobuf ) {
		assert ( iobuf->head <= iobuf->data );
		assert ( iobuf->data <= iobuf->tail );
		assert ( iobuf->tail <= iobuf->end );
		free_dma ( iobuf->head,
			   ( iobuf->end - iobuf->head ) + sizeof ( *iobuf ) );
	}
}

/**
 * Ensure I/O buffer has sufficient headroom
 *
 * @v iobuf	I/O buffer
 * @v len	Required headroom
 *
 * This function currently only checks for the required headroom; it
 * does not reallocate the I/O buffer if required.  If we ever have a
 * code path that requires this functionality, it's a fairly trivial
 * change to make.
 */
int iob_ensure_headroom ( struct io_buffer *iobuf, size_t len ) {

	if ( iob_headroom ( iobuf ) >= len )
		return 0;
	return -ENOBUFS;
}

