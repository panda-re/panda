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
#include <errno.h>
#include <getopt.h>
#include <ipxe/netdevice.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <usr/ifmgmt.h>
#include <hci/ifmgmt_cmd.h>

/** @file
 *
 * Network interface management commands
 *
 */

/** "if<xxx>" command options */
struct option_descriptor ifcommon_opts[0];

/**
 * Execute if<xxx> command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v cmd		Command descriptor
 * @v payload		Command to execute
 * @v verb		Verb describing the action of the command
 * @ret rc		Return status code
 */
int ifcommon_exec ( int argc, char **argv,
		    struct command_descriptor *cmd,
		    int ( * payload ) ( struct net_device * ),
		    int stop_on_first_success ) {
	struct ifcommon_options opts;
	struct net_device *netdev;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, cmd, &opts ) ) != 0 )
		return rc;

	if ( optind != argc ) {
		/* Treat arguments as a list of interfaces to try */
		while ( optind != argc ) {
			if ( ( rc = parse_netdev ( argv[optind++],
						   &netdev ) ) != 0 ) {
				continue;
			}
			if ( ( ( rc = payload ( netdev ) ) == 0 ) &&
			     stop_on_first_success ) {
				return 0;
			}
		}
	} else {
		/* Try all interfaces */
		rc = -ENODEV;
		for_each_netdev ( netdev ) {
			if ( ( ( rc = payload ( netdev ) ) == 0 ) &&
			     stop_on_first_success ) {
				return 0;
			}
		}
	}

	return rc;
}

/** "ifopen" command descriptor */
static struct command_descriptor ifopen_cmd =
	COMMAND_DESC ( struct ifcommon_options, ifcommon_opts, 0, MAX_ARGUMENTS,
		       "[<interface>...]" );

/**
 * "ifopen" payload
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int ifopen_payload ( struct net_device *netdev ) {
	return ifopen ( netdev );
}

/**
 * The "ifopen" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int ifopen_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &ifopen_cmd, ifopen_payload, 0 );
}

/** "ifclose" command descriptor */
static struct command_descriptor ifclose_cmd =
	COMMAND_DESC ( struct ifcommon_options, ifcommon_opts, 0, MAX_ARGUMENTS,
		       "[<interface>...]" );

/**
 * "ifclose" payload
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int ifclose_payload ( struct net_device *netdev ) {
	ifclose ( netdev );
	return 0;
}

/**
 * The "ifclose" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int ifclose_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &ifclose_cmd, ifclose_payload, 0 );
}

/** "ifstat" command descriptor */
static struct command_descriptor ifstat_cmd =
	COMMAND_DESC ( struct ifcommon_options, ifcommon_opts, 0, MAX_ARGUMENTS,
		       "[<interface>...]" );

/**
 * "ifstat" payload
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int ifstat_payload ( struct net_device *netdev ) {
	ifstat ( netdev );
	return 0;
}

/**
 * The "ifstat" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int ifstat_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &ifstat_cmd, ifstat_payload, 0 );
}

/** Interface management commands */
struct command ifmgmt_commands[] __command = {
	{
		.name = "ifopen",
		.exec = ifopen_exec,
	},
	{
		.name = "ifclose",
		.exec = ifclose_exec,
	},
	{
		.name = "ifstat",
		.exec = ifstat_exec,
	},
};
