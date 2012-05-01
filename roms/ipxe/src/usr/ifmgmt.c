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

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <ipxe/console.h>
#include <ipxe/netdevice.h>
#include <ipxe/device.h>
#include <ipxe/process.h>
#include <ipxe/keys.h>
#include <usr/ifmgmt.h>

/** @file
 *
 * Network interface management
 *
 */

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
int ifopen ( struct net_device *netdev ) {
	int rc;

	if ( ( rc = netdev_open ( netdev ) ) != 0 ) {
		printf ( "Could not open %s: %s\n",
			 netdev->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
void ifclose ( struct net_device *netdev ) {
	netdev_close ( netdev );
}

/**
 * Print network device error breakdown
 *
 * @v stats		Network device statistics
 * @v prefix		Message prefix
 */
static void ifstat_errors ( struct net_device_stats *stats,
			    const char *prefix ) {
	unsigned int i;

	for ( i = 0 ; i < ( sizeof ( stats->errors ) /
			    sizeof ( stats->errors[0] ) ) ; i++ ) {
		if ( stats->errors[i].count )
			printf ( "  [%s: %d x \"%s\"]\n", prefix,
				 stats->errors[i].count,
				 strerror ( stats->errors[i].rc ) );
	}
}

/**
 * Print status of network device
 *
 * @v netdev		Network device
 */
void ifstat ( struct net_device *netdev ) {
	printf ( "%s: %s using %s on %s (%s)\n"
		 "  [Link:%s, TX:%d TXE:%d RX:%d RXE:%d]\n",
		 netdev->name, netdev_addr ( netdev ),
		 netdev->dev->driver_name, netdev->dev->name,
		 ( netdev_is_open ( netdev ) ? "open" : "closed" ),
		 ( netdev_link_ok ( netdev ) ? "up" : "down" ),
		 netdev->tx_stats.good, netdev->tx_stats.bad,
		 netdev->rx_stats.good, netdev->rx_stats.bad );
	if ( ! netdev_link_ok ( netdev ) ) {
		printf ( "  [Link status: %s]\n",
			 strerror ( netdev->link_rc ) );
	}
	ifstat_errors ( &netdev->tx_stats, "TXE" );
	ifstat_errors ( &netdev->rx_stats, "RXE" );
}

/**
 * Wait for link-up, with status indication
 *
 * @v netdev		Network device
 * @v max_wait_ms	Maximum time to wait, in ms
 */
int iflinkwait ( struct net_device *netdev, unsigned int max_wait_ms ) {
	int key;
	int rc;

	if ( netdev_link_ok ( netdev ) )
		return 0;

	printf ( "Waiting for link-up on %s...", netdev->name );

	while ( 1 ) {
		if ( netdev_link_ok ( netdev ) ) {
			rc = 0;
			break;
		}
		if ( max_wait_ms-- == 0 ) {
			rc = netdev->link_rc;
			break;
		}
		step();
		if ( iskey() ) {
			key = getchar();
			if ( key == CTRL_C ) {
				rc = -ECANCELED;
				break;
			}
		}
		mdelay ( 1 );
	}

	if ( rc == 0 ) {
		printf ( " ok\n" );
	} else {
		printf ( " failed: %s\n", strerror ( rc ) );
	}

	return rc;
}
