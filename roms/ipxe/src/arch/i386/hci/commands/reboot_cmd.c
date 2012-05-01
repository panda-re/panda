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

#include <realmode.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * Reboot command
 *
 */

/** "reboot" options */
struct reboot_options {};

/** "reboot" option list */
static struct option_descriptor reboot_opts[] = {};

/** "reboot" command descriptor */
static struct command_descriptor reboot_cmd =
	COMMAND_DESC ( struct reboot_options, reboot_opts, 0, 0, "" );

/**
 * The "reboot" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int reboot_exec ( int argc, char **argv ) {
	struct reboot_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &reboot_cmd, &opts ) ) != 0 )
		return rc;

	/* Reboot system */
	__asm__ __volatile__ ( REAL_CODE ( "ljmp $0xf000, $0xfff0" ) : : );

	return 0;
}

/** "reboot" command */
struct command reboot_command __command = {
	.name = "reboot",
	.exec = reboot_exec,
};
