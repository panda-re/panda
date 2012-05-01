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
#include <ipxe/netdevice.h>
#include <ipxe/ip.h>
#include <usr/route.h>

/** @file
 *
 * Routing table management
 *
 */

void route ( void ) {
	struct ipv4_miniroute *miniroute;

	list_for_each_entry ( miniroute, &ipv4_miniroutes, list ) {
		printf ( "%s: %s/", miniroute->netdev->name,
			 inet_ntoa ( miniroute->address ) );
		printf ( "%s", inet_ntoa ( miniroute->netmask ) );
		if ( miniroute->gateway.s_addr )
			printf ( " gw %s", inet_ntoa ( miniroute->gateway ) );
		if ( ! netdev_is_open ( miniroute->netdev ) )
			printf ( " (inaccessible)" );
		printf ( "\n" );
	}
}
