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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <ipxe/netdevice.h>
#include <ipxe/in.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <usr/dhcpmgmt.h>
#include <hci/ifmgmt_cmd.h>

/** @file
 *
 * DHCP management commands
 *
 */

/** "dhcp" command descriptor */
static struct command_descriptor dhcp_cmd =
	COMMAND_DESC ( struct ifcommon_options, ifcommon_opts, 0, MAX_ARGUMENTS,
		       "[<interface>...]" );

/**
 * Execute "dhcp" command for a network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int dhcp_payload ( struct net_device *netdev ) {
	int rc;

	if ( ( rc = dhcp ( netdev ) ) != 0 ) {
		printf ( "Could not configure %s: %s\n",
			 netdev->name, strerror ( rc ) );

		/* Close device on failure, to avoid memory exhaustion */
		netdev_close ( netdev );

		return rc;
	}

	return 0;
}

/**
 * The "dhcp" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int dhcp_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &dhcp_cmd, dhcp_payload, 1 );
}

/** "pxebs" options */
struct pxebs_options {};

/** "pxebs" option list */
static struct option_descriptor pxebs_opts[] = {};

/** "pxebs" command descriptor */
static struct command_descriptor pxebs_cmd =
	COMMAND_DESC ( struct pxebs_options, pxebs_opts, 2, 2,
		       "<interface> <server type>" );

/**
 * The "pxebs" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int pxebs_exec ( int argc, char **argv ) {
	struct pxebs_options opts;
	struct net_device *netdev;
	unsigned int pxe_type;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &pxebs_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse net device name */
	if ( ( rc = parse_netdev ( argv[optind], &netdev ) ) != 0 )
		return rc;

	/* Parse boot server type */
	if ( ( rc = parse_integer ( argv[ optind + 1 ], &pxe_type ) ) != 0 )
		return rc;

	/* Perform Boot Server Discovery */
	if ( ( rc = pxebs ( netdev, pxe_type ) ) != 0 ) {
		printf ( "Could not discover boot server on %s: %s\n",
			 netdev->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** DHCP management commands */
struct command dhcp_commands[] __command = {
	{
		.name = "dhcp",
		.exec = dhcp_exec,
	},
	{
		.name = "pxebs",
		.exec = pxebs_exec,
	},
};
