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
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/netdevice.h>
#include <hci/ifmgmt_cmd.h>
#include <usr/autoboot.h>

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * Booting commands
 *
 */

/** "autoboot" command descriptor */
static struct command_descriptor autoboot_cmd =
	COMMAND_DESC ( struct ifcommon_options, ifcommon_opts, 0, MAX_ARGUMENTS,
		       "[<interface>...]" );

/**
 * "autoboot" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int autoboot_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &autoboot_cmd, netboot, 0 );
}

/** Booting commands */
struct command autoboot_commands[] __command = {
	{
		.name = "autoboot",
		.exec = autoboot_exec,
	},
};
