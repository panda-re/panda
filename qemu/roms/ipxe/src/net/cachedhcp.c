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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ipxe/dhcp.h>
#include <ipxe/dhcppkt.h>
#include <ipxe/netdevice.h>
#include <ipxe/iobuf.h>
#include <ipxe/uaccess.h>

/** @file
 *
 * Cached DHCP packet handling
 *
 */

/**
 * Store cached DHCPACK packet
 *
 * @v data		User pointer to cached DHCP packet data
 * @v len		Length of cached DHCP packet data
 * @ret rc		Return status code
 *
 * This function should be called by the architecture-specific
 * get_cached_dhcpack() handler.
 */
void store_cached_dhcpack ( userptr_t data, size_t len ) {
	struct dhcp_packet *dhcppkt;
	struct dhcphdr *dhcphdr;
	struct settings *parent;
	int rc;

	/* Create DHCP packet */
	dhcppkt = zalloc ( sizeof ( *dhcppkt ) + len );
	if ( ! dhcppkt )
		return;

	/* Fill in data for DHCP packet */
	dhcphdr = ( ( ( void * ) dhcppkt ) + sizeof ( * dhcppkt ) );
	copy_from_user ( dhcphdr, data, 0, len );
	dhcppkt_init ( dhcppkt, dhcphdr, len );
	DBG_HD ( dhcppkt->options.data, dhcppkt->options.used_len );

	/* Register settings on the last opened network device.
	 * This will have the effect of registering cached settings
	 * with a network device when "dhcp netX" is performed for that
	 * device, which is usually what we want.
	 */
	parent = netdev_settings ( last_opened_netdev() );
	if ( ( rc = register_settings ( &dhcppkt->settings, parent,
					DHCP_SETTINGS_NAME ) ) != 0 )
		DBG ( "DHCP could not register cached settings: %s\n",
		      strerror ( rc ) );

	dhcppkt_put ( dhcppkt );

	DBG ( "DHCP registered cached settings\n" );
}
