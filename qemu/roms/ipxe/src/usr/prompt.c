/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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
 * Prompt for keypress
 *
 */

#include <errno.h>
#include <stdio.h>
#include <ipxe/console.h>
#include <ipxe/timer.h>
#include <usr/prompt.h>

/**
 * Prompt for keypress
 *
 * @v text		Prompt string
 * @v wait_ms		Time to wait, in milliseconds (0=indefinite)
 * @v key		Key to wait for (0=any key)
 * @ret rc		Return status code
 *
 * Returns success if the specified key was pressed within the
 * specified timeout period.
 */
int prompt ( const char *text, unsigned int wait_ms, int key ) {
	int key_pressed;

	/* Display prompt */
	printf ( "%s", text );

	/* Wait for key */
	key_pressed = getkey ( ( wait_ms * TICKS_PER_SEC ) / 1000 );

	/* Clear the prompt line */
	while ( *(text++) )
		printf ( "\b \b" );

	/* Check for timeout */
	if ( key_pressed < 0 )
		return -ETIMEDOUT;

	/* Check for correct key pressed */
	if ( key && ( key_pressed != key ) )
		return -ECANCELED;

	return 0;
}
