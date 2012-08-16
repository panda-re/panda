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

#include <string.h>
#include <ipxe/dhcp.h>
#include <ipxe/netdevice.h>
#include <undipreload.h>
#include <pxeparent.h>
#include <realmode.h>
#include <pxe_api.h>

/**
 * Present cached DHCP packet if it exists
 */
void get_cached_dhcpack ( void ) {
	struct undi_device *undi;
	struct s_PXENV_GET_CACHED_INFO get_cached_info;
	int rc;

	/* Use preloaded UNDI device to get at PXE entry point */
	undi = &preloaded_undi;
	if ( ! undi->entry.segment ) {
		DBG ( "PXEDHCP no preloaded UNDI device found\n" );
		return;
	}

	/* Check that stack is available to get cached info */
	if ( ! ( undi->flags & UNDI_FL_KEEP_ALL ) ) {
		DBG ( "PXEDHCP stack was unloaded, no cache available\n" );
		return;
	}

	/* Obtain cached DHCP packet */
	memset ( &get_cached_info, 0, sizeof ( get_cached_info ) );
	get_cached_info.PacketType = PXENV_PACKET_TYPE_DHCP_ACK;

	if ( ( rc = pxeparent_call ( undi->entry, PXENV_GET_CACHED_INFO,
				     &get_cached_info,
				     sizeof ( get_cached_info ) ) ) != 0 ) {
		DBG ( "PXEDHCP GET_CACHED_INFO failed: %s\n", strerror ( rc ) );
		return;
	}

	DBG ( "PXEDHCP got cached info at %04x:%04x length %d\n",
	      get_cached_info.Buffer.segment, get_cached_info.Buffer.offset,
	      get_cached_info.BufferSize );

	/* Present cached DHCP packet */
	store_cached_dhcpack ( real_to_user ( get_cached_info.Buffer.segment,
					      get_cached_info.Buffer.offset ),
			       get_cached_info.BufferSize );
}
