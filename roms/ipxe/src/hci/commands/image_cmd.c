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

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/image.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <usr/imgmgmt.h>

/** @file
 *
 * Image management commands
 *
 */

/** "imgfetch" options */
struct imgfetch_options {
	/** Image name */
	const char *name;
};

/** "imgfetch" option list */
static struct option_descriptor imgfetch_opts[] = {
	OPTION_DESC ( "name", 'n', required_argument,
		      struct imgfetch_options, name, parse_string ),
};

/** "imgfetch" command descriptor */
static struct command_descriptor imgfetch_cmd =
	COMMAND_DESC ( struct imgfetch_options, imgfetch_opts, 1, MAX_ARGUMENTS,
		       "[--name <name>] <uri> [<arguments>...]" );

/**
 * The "imgfetch" and friends command body
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v cmd		Command descriptor
 * @v action_name	Action name (for error messages)
 * @v action		Action to take upon a successful download
 * @ret rc		Return status code
 */
static int imgfetch_core_exec ( int argc, char **argv,
				const char *action_name,
				int ( * action ) ( struct image *image ) ) {
	struct imgfetch_options opts;
	char *uri_string;
	char *cmdline = NULL;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &imgfetch_cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse URI string */
	uri_string = argv[optind];

	/* Parse command line */
	if ( argv[ optind + 1 ] != NULL ) {
		cmdline = concat_args ( &argv[ optind + 1 ] );
		if ( ! cmdline ) {
			rc = -ENOMEM;
			goto err_cmdline;
		}
	}

	/* Fetch the image */
	if ( ( rc = imgdownload_string ( uri_string, opts.name, cmdline,
					 action ) ) != 0 ) {
		printf ( "Could not %s %s: %s\n",
			 action_name, uri_string, strerror ( rc ) );
		goto err_imgdownload;
	}

	/* Free command line */
	free ( cmdline );

	return 0;

 err_imgdownload:
	free ( cmdline );
 err_cmdline:
 err_parse_options:
	return rc;
}

/**
 * The "imgfetch"/"module" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgfetch_exec ( int argc, char **argv ) {

	return imgfetch_core_exec ( argc, argv, "fetch",
				    register_and_put_image );
}

/**
 * The "kernel" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int kernel_exec ( int argc, char **argv ) {

	return imgfetch_core_exec ( argc, argv, "select",
				    register_and_select_image );
}

/**
 * The "chain" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int chain_exec ( int argc, char **argv) {

	return imgfetch_core_exec ( argc, argv, "boot",
				    register_and_boot_image );
}

/** "imgselect" options */
struct imgselect_options {};

/** "imgselect" option list */
static struct option_descriptor imgselect_opts[] = {};

/** "imgselect" command descriptor */
static struct command_descriptor imgselect_cmd =
	COMMAND_DESC ( struct imgselect_options, imgselect_opts, 1, 1,
		       "<image>" );

/**
 * The "imgselect" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgselect_exec ( int argc, char **argv ) {
	struct imgselect_options opts;
	struct image *image;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &imgselect_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse image name */
	if ( ( rc = parse_image ( argv[optind], &image ) ) != 0 )
		return rc;

	/* Load image */
	if ( ( rc = imgselect ( image ) ) != 0 ) {
		printf ( "Could not select %s: %s\n",
			 image->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** "imgargs" options */
struct imgargs_options {};

/** "imgargs" option list */
static struct option_descriptor imgargs_opts[] = {};

/** "imgargs" command descriptor */
static struct command_descriptor imgargs_cmd =
	COMMAND_DESC ( struct imgargs_options, imgargs_opts, 1, MAX_ARGUMENTS,
		       "<image> [<arguments>...]" );

/**
 * The "imgargs" command body
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgargs_exec ( int argc, char **argv ) {
	struct imgargs_options opts;
	struct image *image;
	char *cmdline = NULL;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &imgargs_cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse image name */
	if ( ( rc = parse_image ( argv[optind], &image ) ) != 0 )
		goto err_parse_image;

	/* Parse command line */
	if ( argv[ optind + 1 ] != NULL ) {
		cmdline = concat_args ( &argv[ optind + 1 ] );
		if ( ! cmdline ) {
			rc = -ENOMEM;
			goto err_cmdline;
		}
	}

	/* Set command line */
	if ( ( rc = image_set_cmdline ( image, cmdline ) ) != 0 )
		goto err_set_cmdline;

	/* Free command line */
	free ( cmdline );

	return 0;

 err_set_cmdline:
	free ( cmdline );
 err_cmdline:
 err_parse_image:
 err_parse_options:
	return rc;
}

/** "imgexec" options */
struct imgexec_options {};

/** "imgexec" option list */
static struct option_descriptor imgexec_opts[] = {};

/** "imgexec" command descriptor */
static struct command_descriptor imgexec_cmd =
	COMMAND_DESC ( struct imgexec_options, imgexec_opts, 0, 1,
		       "[<image>]" );

/**
 * The "imgexec" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgexec_exec ( int argc, char **argv ) {
	struct imgexec_options opts;
	struct image *image;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &imgexec_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse image name */
	if ( optind < argc ) {
		if ( ( rc = parse_image ( argv[optind], &image ) ) != 0 )
			return rc;
	} else {
		image = imgautoselect();
		if ( ! image ) {
			rc = -ENOTTY;
			printf ( "No image selected: %s\n", strerror ( rc ) );
			return rc;
		}
	}

	/* Execute image */
	if ( ( rc = imgexec ( image ) ) != 0 ) {
		printf ( "Could not execute %s: %s\n",
			 image->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** "imgstat" options */
struct imgstat_options {};

/** "imgstat" option list */
static struct option_descriptor imgstat_opts[] = {};

/** "imgstat" command descriptor */
static struct command_descriptor imgstat_cmd =
	COMMAND_DESC ( struct imgstat_options, imgstat_opts, 0, 0, "" );

/**
 * The "imgstat" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgstat_exec ( int argc, char **argv ) {
	struct imgstat_options opts;
	struct image *image;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &imgstat_cmd, &opts ) ) != 0 )
		return rc;

	/* Show status of all images */
	for_each_image ( image ) {
		imgstat ( image );
	}

	return 0;
}

/** "imgfree" options */
struct imgfree_options {};

/** "imgfree" option list */
static struct option_descriptor imgfree_opts[] = {};

/** "imgfree" command descriptor */
static struct command_descriptor imgfree_cmd =
	COMMAND_DESC ( struct imgfree_options, imgfree_opts, 0, 1,
		       "[<image>]" );

/**
 * The "imgfree" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int imgfree_exec ( int argc, char **argv ) {
	struct imgfree_options opts;
	struct image *image;
	struct image *tmp;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &imgfree_cmd, &opts ) ) != 0 )
		return rc;

	if ( optind < argc ) {
		/* Free specified image */
		if ( ( rc = parse_image ( argv[optind], &image ) ) != 0 )
			return rc;
		imgfree ( image );
	} else {
		/* Free all images */
		list_for_each_entry_safe ( image, tmp, &images, list ) {
			imgfree ( image );
		}
	}

	return 0;
}

/** Image management commands */
struct command image_commands[] __command = {
	{
		.name = "imgfetch",
		.exec = imgfetch_exec,
	},
	{
		.name = "module",
		.exec = imgfetch_exec, /* synonym for "imgfetch" */
	},
	{
		.name = "initrd",
		.exec = imgfetch_exec, /* synonym for "imgfetch" */
	},
	{
		.name = "kernel",
		.exec = kernel_exec,
	},
	{
		.name = "chain",
		.exec = chain_exec,
	},
	{
		.name = "imgselect",
		.exec = imgselect_exec,
	},
	{
		.name = "imgload", /* synonym for "imgselect" */
		.exec = imgselect_exec,
	},
	{
		.name = "imgargs",
		.exec = imgargs_exec,
	},
	{
		.name = "imgexec",
		.exec = imgexec_exec,
	},
	{
		.name = "boot", /* synonym for "imgexec" */
		.exec = imgexec_exec,
	},
	{
		.name = "imgstat",
		.exec = imgstat_exec,
	},
	{
		.name = "imgfree",
		.exec = imgfree_exec,
	},
};
