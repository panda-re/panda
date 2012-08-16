/*
 * Copyright (C) 2009 Joshua Oreman <oremanj@rwcr.net>.
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

#include <ipxe/netdevice.h>
#include <ipxe/net80211.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <usr/iwmgmt.h>
#include <hci/ifmgmt_cmd.h>

/** @file
 *
 * Wireless interface management commands
 *
 */

/** "iwstat" command descriptor */
static struct command_descriptor iwstat_cmd =
	COMMAND_DESC ( struct ifcommon_options, ifcommon_opts, 0, MAX_ARGUMENTS,
		       "[<interface>...]" );

/**
 * "iwstat" payload
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int iwstat_payload ( struct net_device *netdev ) {
	struct net80211_device *dev = net80211_get ( netdev );

	if ( dev )
		iwstat ( dev );

	return 0;
}

/**
 * The "iwstat" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int iwstat_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &iwstat_cmd, iwstat_payload, 0 );
}

/** "iwlist" command descriptor */
static struct command_descriptor iwlist_cmd =
	COMMAND_DESC ( struct ifcommon_options, ifcommon_opts, 0, MAX_ARGUMENTS,
		       "[<interface>...]" );

/**
 * "iwlist" payload
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int iwlist_payload ( struct net_device *netdev ) {
	struct net80211_device *dev = net80211_get ( netdev );

	if ( dev )
		return iwlist ( dev );

	return 0;
}

/**
 * The "iwlist" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int iwlist_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &iwlist_cmd, iwlist_payload, 0 );
}

/** Wireless interface management commands */
struct command iwmgmt_commands[] __command = {
	{
		.name = "iwstat",
		.exec = iwstat_exec,
	},
	{
		.name = "iwlist",
		.exec = iwlist_exec,
	},
};
