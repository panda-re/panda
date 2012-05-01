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

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <ipxe/io.h>
#include <ipxe/console.h>

/**
 * Pause until a key is pressed
 *
 */
void dbg_pause ( void ) {
	printf ( "\nPress a key..." );
	getchar();
	printf ( "\r              \r" );
}

/**
 * Indicate more data to follow and pause until a key is pressed
 *
 */
void dbg_more ( void ) {
	printf ( "---more---" );
	getchar();
	printf ( "\r          \r" );
}

/**
 * Print row of a hex dump with specified display address
 *
 * @v dispaddr		Display address
 * @v data		Data to print
 * @v len		Length of data
 * @v offset		Starting offset within data
 */
static void dbg_hex_dump_da_row ( unsigned long dispaddr, const void *data,
				  unsigned long len, unsigned int offset ) {
	const uint8_t *bytes = data;
	unsigned int i;
	uint8_t byte;

	printf ( "%08lx :", ( dispaddr + offset ) );
	for ( i = offset ; i < ( offset + 16 ) ; i++ ) {
		if ( i >= len ) {
			printf ( "   " );
			continue;
		}
		printf ( "%c%02x",
			 ( ( ( i % 16 ) == 8 ) ? '-' : ' ' ), bytes[i] );
	}
	printf ( " : " );
	for ( i = offset ; i < ( offset + 16 ) ; i++ ) {
		if ( i >= len ) {
			printf ( " " );
			continue;
		}
		byte = bytes[i];
		if ( ( byte < 0x20 ) || ( byte >= 0x7f ) )
			byte = '.';
		printf ( "%c", byte );
	}
	printf ( "\n" );
}

/**
 * Print hex dump with specified display address
 *
 * @v dispaddr		Display address
 * @v data		Data to print
 * @v len		Length of data
 */
void dbg_hex_dump_da ( unsigned long dispaddr, const void *data,
		       unsigned long len ) {
	unsigned int offset;

	for ( offset = 0 ; offset < len ; offset += 16 ) {
		dbg_hex_dump_da_row ( dispaddr, data, len, offset );
	}
}

/**
 * Maximum number of separately coloured message streams
 *
 * Six is the realistic maximum; there are 8 basic ANSI colours, one
 * of which will be the terminal default and one of which will be
 * invisible on the terminal because it matches the background colour.
 */
#define NUM_AUTO_COLOURS 6

/** A colour assigned to an autocolourised debug message stream */
struct autocolour {
	/** Message stream ID */
	unsigned long stream;
	/** Last recorded usage */
	unsigned long last_used;
};

/**
 * Choose colour index for debug autocolourisation
 *
 * @v stream		Message stream ID
 * @ret colour		Colour ID
 */
static int dbg_autocolour ( unsigned long stream ) {
	static struct autocolour acs[NUM_AUTO_COLOURS];
	static unsigned long use;
	unsigned int i;
	unsigned int oldest;
	unsigned int oldest_last_used;

	/* Increment usage iteration counter */
	use++;

	/* Scan through list for a currently assigned colour */
	for ( i = 0 ; i < ( sizeof ( acs ) / sizeof ( acs[0] ) ) ; i++ ) {
		if ( acs[i].stream == stream ) {
			acs[i].last_used = use;
			return i;
		}
	}

	/* No colour found; evict the oldest from the list */
	oldest = 0;
	oldest_last_used = use;
	for ( i = 0 ; i < ( sizeof ( acs ) / sizeof ( acs[0] ) ) ; i++ ) {
		if ( acs[i].last_used < oldest_last_used ) {
			oldest_last_used = acs[i].last_used;
			oldest = i;
		}
	}
	acs[oldest].stream = stream;
	acs[oldest].last_used = use;
	return oldest;
}

/**
 * Select automatic colour for debug messages
 *
 * @v stream		Message stream ID
 */
void dbg_autocolourise ( unsigned long stream ) {
	printf ( "\033[%dm",
		 ( stream ? ( 31 + dbg_autocolour ( stream ) ) : 0 ) );
}

/**
 * Revert to normal colour
 *
 */
void dbg_decolourise ( void ) {
	printf ( "\033[0m" );
}
