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
 * Command line passed to iPXE
 *
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <ipxe/init.h>
#include <ipxe/image.h>
#include <ipxe/script.h>
#include <realmode.h>

/** Command line physical address
 *
 * This can be set by the prefix.
 */
uint32_t __bss16 ( cmdline_phys );
#define cmdline_phys __use_data16 ( cmdline_phys )

/** Internal copy of the command line */
static char *cmdline_copy;

/** Free command line image */
static void cmdline_image_free ( struct refcnt *refcnt ) {
	struct image *image = container_of ( refcnt, struct image, refcnt );

	DBGC ( image, "CMDLINE freeing command line\n" );
	free ( cmdline_copy );
}

/** Embedded script representing the command line */
static struct image cmdline_image = {
	.refcnt = REF_INIT ( cmdline_image_free ),
	.name = "<CMDLINE>",
	.type = &script_image_type,
};

/**
 * Initialise command line
 *
 */
static void cmdline_init ( void ) {
	struct image *image = &cmdline_image;
	userptr_t cmdline_user;
	char *cmdline;
	char *tmp;
	size_t len;

	/* Do nothing if no command line was specified */
	if ( ! cmdline_phys ) {
		DBGC ( image, "CMDLINE found no command line\n" );
		return;
	}
	cmdline_user = phys_to_user ( cmdline_phys );
	len = ( strlen_user ( cmdline_user, 0 ) + 1 /* NUL */ );

	/* Allocate and copy command line */
	cmdline_copy = malloc ( len );
	if ( ! cmdline_copy ) {
		DBGC ( image, "CMDLINE could not allocate %zd bytes\n", len );
		/* No way to indicate failure */
		return;
	}
	cmdline = cmdline_copy;
	copy_from_user ( cmdline, cmdline_user, 0, len );
	DBGC ( image, "CMDLINE found \"%s\"\n", cmdline );

	/* Check for unwanted cruft in the command line */
	while ( isspace ( *cmdline ) )
		cmdline++;
	if ( ( tmp = strstr ( cmdline, "BOOT_IMAGE=" ) ) != NULL ) {
		DBGC ( image, "CMDLINE stripping \"%s\"\n", tmp );
		*tmp = '\0';
	}
	DBGC ( image, "CMDLINE using \"%s\"\n", cmdline );

	/* Prepare and register image */
	cmdline_image.data = virt_to_user ( cmdline );
	cmdline_image.len = strlen ( cmdline );
	if ( cmdline_image.len )
		register_image ( &cmdline_image );

	/* Drop our reference to the image */
	image_put ( &cmdline_image );
}

/** Command line initialisation function */
struct init_fn cmdline_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = cmdline_init,
};
