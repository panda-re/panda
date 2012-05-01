/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <errno.h>
#include <byteswap.h>
#include <ipxe/dhcp.h>
#include <ipxe/dhcpopts.h>
#include <ipxe/settings.h>
#include <ipxe/device.h>
#include <ipxe/netdevice.h>

/** @file
 *
 * Network device configuration settings
 *
 */

/** Network device named settings */
struct setting mac_setting __setting ( SETTING_NETDEV ) = {
	.name = "mac",
	.description = "MAC address",
	.type = &setting_type_hex,
	.tag = NETDEV_SETTING_TAG_MAC,
};
struct setting busid_setting __setting ( SETTING_NETDEV ) = {
	.name = "busid",
	.description = "Bus ID",
	.type = &setting_type_hex,
	.tag = NETDEV_SETTING_TAG_BUS_ID,
};

/**
 * Check applicability of network device setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
static int netdev_applies ( struct settings *settings __unused,
			    struct setting *setting ) {

	return ( IS_NETDEV_SETTING_TAG ( setting->tag ) ||
		 dhcpopt_applies ( setting->tag ) );
}

/**
 * Store value of network device setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v data		Setting data, or NULL to clear setting
 * @v len		Length of setting data
 * @ret rc		Return status code
 */
static int netdev_store ( struct settings *settings, struct setting *setting,
			  const void *data, size_t len ) {
	struct net_device *netdev = container_of ( settings, struct net_device,
						   settings.settings );

	if ( setting_cmp ( setting, &mac_setting ) == 0 ) {
		if ( len != netdev->ll_protocol->ll_addr_len )
			return -EINVAL;
		memcpy ( netdev->ll_addr, data, len );
		return 0;
	}
	if ( setting_cmp ( setting, &busid_setting ) == 0 )
		return -ENOTSUP;

	return generic_settings_store ( settings, setting, data, len );
}

/**
 * Fetch value of network device setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Setting data, or NULL to clear setting
 * @v len		Length of setting data
 * @ret rc		Return status code
 */
static int netdev_fetch ( struct settings *settings, struct setting *setting,
			  void *data, size_t len ) {
	struct net_device *netdev = container_of ( settings, struct net_device,
						   settings.settings );
	struct device_description *desc = &netdev->dev->desc;
	struct dhcp_netdev_desc dhcp_desc;

	if ( setting_cmp ( setting, &mac_setting ) == 0 ) {
		if ( len > netdev->ll_protocol->ll_addr_len )
			len = netdev->ll_protocol->ll_addr_len;
		memcpy ( data, netdev->ll_addr, len );
		return netdev->ll_protocol->ll_addr_len;
	}
	if ( setting_cmp ( setting, &busid_setting ) == 0 ) {
		dhcp_desc.type = desc->bus_type;
		dhcp_desc.vendor = htons ( desc->vendor );
		dhcp_desc.device = htons ( desc->device );
		if ( len > sizeof ( dhcp_desc ) )
			len = sizeof ( dhcp_desc );
		memcpy ( data, &dhcp_desc, len );
		return sizeof ( dhcp_desc );
	}

	return generic_settings_fetch ( settings, setting, data, len );
}

/**
 * Clear network device settings
 *
 * @v settings		Settings block
 */
static void netdev_clear ( struct settings *settings ) {
	generic_settings_clear ( settings );
}

/** Network device configuration settings operations */
struct settings_operations netdev_settings_operations = {
	.applies = netdev_applies,
	.store = netdev_store,
	.fetch = netdev_fetch,
	.clear = netdev_clear,
};
