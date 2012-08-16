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

#include <ipxe/netdevice.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <hci/ifmgmt_cmd.h>
#include <pxe_call.h>

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * PXE commands
 *
 */

/** "startpxe" command descriptor */
static struct command_descriptor startpxe_cmd =
	COMMAND_DESC ( struct ifcommon_options, ifcommon_opts, 0, MAX_ARGUMENTS,
		       "[<interface>]" );

/**
 * "startpxe" payload
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int startpxe_payload ( struct net_device *netdev ) {

	if ( netdev_is_open ( netdev ) )
		pxe_activate ( netdev );

	return 0;
}

/**
 * The "startpxe" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int startpxe_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &startpxe_cmd, startpxe_payload, 0 );
}

/** "stoppxe" options */
struct stoppxe_options {};

/** "stoppxe" option list */
static struct option_descriptor stoppxe_opts[] = {};

/** "stoppxe" command descriptor */
static struct command_descriptor stoppxe_cmd =
	COMMAND_DESC ( struct stoppxe_options, stoppxe_opts, 0, 0, "" );

/**
 * The "stoppxe" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int stoppxe_exec ( int argc __unused, char **argv __unused ) {
	struct stoppxe_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &stoppxe_cmd, &opts ) ) != 0 )
		return rc;

	pxe_deactivate();

	return 0;
}

/** PXE commands */
struct command pxe_commands[] __command = {
	{
		.name = "startpxe",
		.exec = startpxe_exec,
	},
	{
		.name = "stoppxe",
		.exec = stoppxe_exec,
	},
};
