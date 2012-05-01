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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/settings.h>
#include <ipxe/settings_ui.h>

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * Configuration UI commands
 *
 */

/** "config" options */
struct config_options {};

/** "config" option list */
static struct option_descriptor config_opts[] = {};

/** "config" command descriptor */
static struct command_descriptor config_cmd =
	COMMAND_DESC ( struct config_options, config_opts, 0, 1, "[<scope>]" );

/**
 * Parse settings scope name
 *
 * @v text		Text
 * @ret value		Integer value
 * @ret rc		Return status code
 */
static int parse_settings ( const char *text, struct settings **value ) {

	/* Sanity check */
	assert ( text != NULL );

	/* Parse scope name */
	*value = find_settings ( text );
	if ( ! *value ) {
		printf ( "\"%s\": no such scope\n", text );
		return -EINVAL;
	}

	return 0;
}

/**
 * "config" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int config_exec ( int argc, char **argv ) {
	struct config_options opts;
	struct settings *settings;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &config_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse settings option, if present */
	if ( ( rc = parse_settings ( ( ( optind < argc ) ? argv[optind] : "" ),
				     &settings ) ) != 0 )
		return rc;

	/* Run settings UI */
	if ( ( rc = settings_ui ( settings ) ) != 0 ) {
		printf ( "Could not save settings: %s\n", strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** Configuration UI commands */
struct command config_command __command = {
	.name = "config",
	.exec = config_exec,
};
