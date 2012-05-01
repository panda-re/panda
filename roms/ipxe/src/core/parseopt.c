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

FILE_LICENCE ( GPL2_OR_LATER );

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/netdevice.h>
#include <ipxe/image.h>
#include <ipxe/parseopt.h>

/** @file
 *
 * Command line option parsing
 *
 */

/** Return status code for "--help" option */
#define ECANCELED_NO_OP __einfo_error ( EINFO_ECANCELED_NO_OP )
#define EINFO_ECANCELED_NO_OP \
	__einfo_uniqify ( EINFO_ECANCELED, 0x01, "Nothing to do" )

/**
* Parse string value
 *
 * @v text		Text
 * @ret value		String value
 * @ret rc		Return status code
 */
int parse_string ( const char *text, const char **value ) {

	/* Sanity check */
	assert ( text != NULL );

	/* Parse string */
	*value = text;

	return 0;
}

/**
 * Parse integer value
 *
 * @v text		Text
 * @ret value		Integer value
 * @ret rc		Return status code
 */
int parse_integer ( const char *text, unsigned int *value ) {
	char *endp;

	/* Sanity check */
	assert ( text != NULL );

	/* Parse integer */
	*value = strtoul ( text, &endp, 0 );
	if ( *endp ) {
		printf ( "\"%s\": invalid integer value\n", text );
		return -EINVAL;
	}

	return 0;
}

/**
 * Parse network device name
 *
 * @v text		Text
 * @ret netdev		Network device
 * @ret rc		Return status code
 */
int parse_netdev ( const char *text, struct net_device **netdev ) {

	/* Sanity check */
	assert ( text != NULL );

	/* Find network device */
	*netdev = find_netdev ( text );
	if ( ! *netdev ) {
		printf ( "\"%s\": no such network device\n", text );
		return -ENODEV;
	}

	return 0;
}

/**
 * Parse image name
 *
 * @v text		Text
 * @ret image		Image
 * @ret rc		Return status code
 */
int parse_image ( const char *text, struct image **image ) {

	/* Sanity check */
	assert ( text != NULL );

	/* Find network device */
	*image = find_image ( text );
	if ( ! *image ) {
		printf ( "\"%s\": no such image\n", text );
		return -ENOENT;
	}

	return 0;
}

/**
 * Parse flag
 *
 * @v text		Text (ignored)
 * @ret flag		Flag to set
 * @ret rc		Return status code
 */
int parse_flag ( const char *text __unused, int *flag ) {

	/* Set flag */
	*flag = 1;

	return 0;
}

/**
 * Print command usage message
 *
 * @v cmd		Command descriptor
 * @v argv		Argument list
 */
void print_usage ( struct command_descriptor *cmd, char **argv ) {
	printf ( "Usage:\n\n  %s %s\n\nSee http://ipxe.org/cmd/%s for further "
		 "information\n", argv[0], cmd->usage, argv[0] );
}

/**
 * Parse command-line options
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v cmd		Command descriptor
 * @v opts		Options
 * @ret rc		Return status code
 */
int parse_options ( int argc, char **argv, struct command_descriptor *cmd,
		    void *opts ) {
	struct option longopts[ cmd->num_options + 1 /* help */ + 1 /* end */ ];
	char shortopts[ cmd->num_options * 3 /* possible "::" */ + 1 /* "h" */
			+ 1 /* NUL */ ];
	unsigned int shortopt_idx = 0;
	int ( * parse ) ( const char *text, void *value );
	void *value;
	unsigned int i;
	unsigned int j;
	unsigned int num_args;
	int c;
	int rc;

	/* Construct long and short option lists for getopt_long() */
	memset ( longopts, 0, sizeof ( longopts ) );
	for ( i = 0 ; i < cmd->num_options ; i++ ) {
		longopts[i].name = cmd->options[i].longopt;
		longopts[i].has_arg = cmd->options[i].has_arg;
		longopts[i].val = cmd->options[i].shortopt;
		shortopts[shortopt_idx++] = cmd->options[i].shortopt;
		assert ( cmd->options[i].has_arg <= optional_argument );
		for ( j = cmd->options[i].has_arg ; j > 0 ; j-- )
			shortopts[shortopt_idx++] = ':';
	}
	longopts[i].name = "help";
	longopts[i].val = 'h';
	shortopts[shortopt_idx++] = 'h';
	shortopts[shortopt_idx++] = '\0';
	assert ( shortopt_idx <= sizeof ( shortopts ) );
	DBGC ( cmd,  "Command \"%s\" has options \"%s\", %d-%d args, len %d\n",
	       argv[0], shortopts, cmd->min_args, cmd->max_args, cmd->len );

	/* Clear options */
	memset ( opts, 0, cmd->len );

	/* Parse options */
	while ( ( c = getopt_long ( argc, argv, shortopts, longopts,
				    NULL ) ) >= 0 ) {
		switch ( c ) {
		case 'h' :
			/* Print help */
			print_usage ( cmd, argv );
			return -ECANCELED_NO_OP;
		case '?' :
		case ':' :
			/* Print usage message */
			print_usage ( cmd, argv );
			return -EINVAL;
		default:
			/* Search for an option to parse */
			for ( i = 0 ; i < cmd->num_options ; i++ ) {
				if ( c != cmd->options[i].shortopt )
					continue;
				parse = cmd->options[i].parse;
				value = ( opts + cmd->options[i].offset );
				if ( ( rc = parse ( optarg, value ) ) != 0 )
					return rc;
				break;
			}
			assert ( i < cmd->num_options );
		}
	}

	/* Check remaining arguments */
	num_args = ( argc - optind );
	if ( ( num_args < cmd->min_args ) || ( num_args > cmd->max_args ) ) {
		print_usage ( cmd, argv );
		return -ERANGE;
	}

	return 0;
}
