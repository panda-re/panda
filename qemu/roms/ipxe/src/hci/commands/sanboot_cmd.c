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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/uri.h>
#include <usr/autoboot.h>

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * SAN commands
 *
 */

/** "sanboot" options */
struct sanboot_options {};

/** "sanboot" option list */
static struct option_descriptor sanboot_opts[] = {};

/** "sanboot" command descriptor */
static struct command_descriptor sanboot_cmd =
	COMMAND_DESC ( struct sanboot_options, sanboot_opts, 1, 1,
		       "<root-path>" );

/**
 * The "sanboot" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int sanboot_exec ( int argc, char **argv ) {
	struct sanboot_options opts;
	const char *root_path;
	struct uri *uri;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &sanboot_cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse root path */
	root_path = argv[optind];
	uri = parse_uri ( root_path );
	if ( ! uri ) {
		rc = -ENOMEM;
		goto err_parse_uri;
	}

	/* Boot from root path */
	if ( ( rc = uriboot ( NULL, uri ) ) != 0 ) {
		printf ( "Could not boot from %s: %s\n",
			 root_path, strerror ( rc ) );
		goto err_uriboot;
	}

 err_uriboot:
	uri_put ( uri );
 err_parse_uri:
 err_parse_options:
	return rc;
}

/** SAN commands */
struct command sanboot_command __command = {
	.name = "sanboot",
	.exec = sanboot_exec,
};
