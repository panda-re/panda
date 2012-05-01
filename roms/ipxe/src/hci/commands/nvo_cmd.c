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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/settings.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <readline/readline.h>

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * Non-volatile option commands
 *
 */

/** "show" options */
struct show_options {};

/** "show" option list */
static struct option_descriptor show_opts[] = {};

/** "show" command descriptor */
static struct command_descriptor show_cmd =
	COMMAND_DESC ( struct show_options, show_opts, 1, 1, "<setting>" );

/**
 * "show" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int show_exec ( int argc, char **argv ) {
	struct show_options opts;
	const char *name;
	char name_buf[32];
	char value_buf[256];
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &show_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse setting name */
	name = argv[optind];

	/* Fetch setting */
	if ( ( rc = fetchf_named_setting ( name, name_buf, sizeof ( name_buf ),
					   value_buf,
					   sizeof ( value_buf ) ) ) < 0 ) {
		printf ( "Could not find \"%s\": %s\n",
			 name, strerror ( rc ) );
		return rc;
	}

	/* Print setting value */
	printf ( "%s = %s\n", name_buf, value_buf );

	return 0;
}

/** "set", "clear", and "read" options */
struct set_core_options {};

/** "set", "clear", and "read" option list */
static struct option_descriptor set_core_opts[] = {};

/** "set" command descriptor */
static struct command_descriptor set_cmd =
	COMMAND_DESC ( struct set_core_options, set_core_opts, 1, MAX_ARGUMENTS,
		       "<setting> <value>" );

/** "clear" and "read" command descriptor */
static struct command_descriptor clear_read_cmd =
	COMMAND_DESC ( struct set_core_options, set_core_opts, 1, 1,
		       "<setting>" );

/**
 * "set", "clear", and "read" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v cmd		Command descriptor
 * @v get_value		Method to obtain setting value
 * @ret rc		Return status code
 */
static int set_core_exec ( int argc, char **argv,
			   struct command_descriptor *cmd,
			   int ( * get_value ) ( char **args, char **value ) ) {
	struct set_core_options opts;
	const char *name;
	char *value;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse setting name */
	name = argv[optind];

	/* Parse setting value */
	if ( ( rc = get_value ( &argv[ optind + 1 ], &value ) ) != 0 )
		goto err_get_value;

	/* Determine total length of command line */
	if ( ( rc = storef_named_setting ( name, value ) ) != 0 ) {
		printf ( "Could not %s \"%s\": %s\n",
			 argv[0], name, strerror ( rc ) );
		goto err_store;
	}

	free ( value );
	return 0;

 err_store:
	free ( value );
 err_get_value:
 err_parse_options:
	return rc;
}

/**
 * Get setting value for "set" command
 *
 * @v args		Remaining arguments
 * @ret value		Setting value
 * @ret rc		Return status code
 */
static int set_value ( char **args, char **value ) {

	*value = concat_args ( args );
	if ( ! *value )
		return -ENOMEM;

	return 0;
}

/**
 * "set" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int set_exec ( int argc, char **argv ) {
	return set_core_exec ( argc, argv, &set_cmd, set_value );
}

/**
 * Get setting value for "clear" command
 *
 * @v args		Remaining arguments
 * @ret value		Setting value
 * @ret rc		Return status code
 */
static int clear_value ( char **args __unused, char **value ) {

	*value = NULL;
	return 0;
}

/**
 * "clear" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int clear_exec ( int argc, char **argv ) {
	return set_core_exec ( argc, argv, &clear_read_cmd, clear_value );
}

/**
 * Get setting value for "read" command
 *
 * @ret value		Setting value
 * @ret rc		Return status code
 */
static int read_value ( char **args __unused, char **value ) {

	*value = readline ( NULL );
	if ( ! *value )
		return -ENOMEM;

	return 0;
}

/**
 * "read" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int read_exec ( int argc, char **argv ) {
	return set_core_exec ( argc, argv, &clear_read_cmd, read_value );
}

/** Non-volatile option commands */
struct command nvo_commands[] __command = {
	{
		.name = "show",
		.exec = show_exec,
	},
	{
		.name = "set",
		.exec = set_exec,
	},	
	{
		.name = "clear",
		.exec = clear_exec,
	},
	{
		.name = "read",
		.exec = read_exec,
	},
};
