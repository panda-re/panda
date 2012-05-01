/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <byteswap.h>
#include <string.h>
#include <errno.h>
#include <config/general.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/tables.h>
#include <ipxe/process.h>
#include <ipxe/init.h>
#include <ipxe/device.h>
#include <ipxe/errortab.h>
#include <ipxe/netdevice.h>

/** @file
 *
 * Network device management
 *
 */

/** List of network devices */
struct list_head net_devices = LIST_HEAD_INIT ( net_devices );

/** List of open network devices, in reverse order of opening */
static struct list_head open_net_devices = LIST_HEAD_INIT ( open_net_devices );

/** Default unknown link status code */
#define EUNKNOWN_LINK_STATUS __einfo_error ( EINFO_EUNKNOWN_LINK_STATUS )
#define EINFO_EUNKNOWN_LINK_STATUS \
	__einfo_uniqify ( EINFO_EINPROGRESS, 0x01, "Unknown" )

/** Default link-down status code */
#define ENOTCONN_LINK_DOWN __einfo_error ( EINFO_ENOTCONN_LINK_DOWN )
#define EINFO_ENOTCONN_LINK_DOWN \
	__einfo_uniqify ( EINFO_ENOTCONN, 0x01, "Down" )

/** Human-readable message for the default link statuses */
struct errortab netdev_errors[] __errortab = {
	__einfo_errortab ( EINFO_EUNKNOWN_LINK_STATUS ),
	__einfo_errortab ( EINFO_ENOTCONN_LINK_DOWN ),
};

/**
 * Notify drivers of network device or link state change
 *
 * @v netdev		Network device
 */
static void netdev_notify ( struct net_device *netdev ) {
	struct net_driver *driver;

	for_each_table_entry ( driver, NET_DRIVERS )
		driver->notify ( netdev );
}

/**
 * Mark network device as having a specific link state
 *
 * @v netdev		Network device
 * @v rc		Link status code
 */
void netdev_link_err ( struct net_device *netdev, int rc ) {

	/* Record link state */
	netdev->link_rc = rc;
	if ( netdev->link_rc == 0 ) {
		DBGC ( netdev, "NETDEV %s link is up\n", netdev->name );
	} else {
		DBGC ( netdev, "NETDEV %s link is down: %s\n",
		       netdev->name, strerror ( netdev->link_rc ) );
	}

	/* Notify drivers of link state change */
	netdev_notify ( netdev );
}

/**
 * Mark network device as having link down
 *
 * @v netdev		Network device
 */
void netdev_link_down ( struct net_device *netdev ) {

	/* Avoid clobbering a more detailed link status code, if one
	 * is already set.
	 */
	if ( ( netdev->link_rc == 0 ) ||
	     ( netdev->link_rc == -EUNKNOWN_LINK_STATUS ) ) {
		netdev_link_err ( netdev, -ENOTCONN_LINK_DOWN );
	}
}

/**
 * Record network device statistic
 *
 * @v stats		Network device statistics
 * @v rc		Status code
 */
static void netdev_record_stat ( struct net_device_stats *stats, int rc ) {
	struct net_device_error *error;
	struct net_device_error *least_common_error;
	unsigned int i;

	/* If this is not an error, just update the good counter */
	if ( rc == 0 ) {
		stats->good++;
		return;
	}

	/* Update the bad counter */
	stats->bad++;

	/* Locate the appropriate error record */
	least_common_error = &stats->errors[0];
	for ( i = 0 ; i < ( sizeof ( stats->errors ) /
			    sizeof ( stats->errors[0] ) ) ; i++ ) {
		error = &stats->errors[i];
		/* Update matching record, if found */
		if ( error->rc == rc ) {
			error->count++;
			return;
		}
		if ( error->count < least_common_error->count )
			least_common_error = error;
	}

	/* Overwrite the least common error record */
	least_common_error->rc = rc;
	least_common_error->count = 1;
}

/**
 * Transmit raw packet via network device
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 *
 * Transmits the packet via the specified network device.  This
 * function takes ownership of the I/O buffer.
 */
int netdev_tx ( struct net_device *netdev, struct io_buffer *iobuf ) {
	int rc;

	DBGC ( netdev, "NETDEV %s transmitting %p (%p+%zx)\n",
	       netdev->name, iobuf, iobuf->data, iob_len ( iobuf ) );

	/* Enqueue packet */
	list_add_tail ( &iobuf->list, &netdev->tx_queue );

	/* Avoid calling transmit() on unopened network devices */
	if ( ! netdev_is_open ( netdev ) ) {
		rc = -ENETUNREACH;
		goto err;
	}

	/* Discard packet (for test purposes) if applicable */
	if ( ( NETDEV_DISCARD_RATE > 0 ) &&
	     ( ( random() % NETDEV_DISCARD_RATE ) == 0 ) ) {
		rc = -EAGAIN;
		goto err;
	}

	/* Transmit packet */
	if ( ( rc = netdev->op->transmit ( netdev, iobuf ) ) != 0 )
		goto err;

	return 0;

 err:
	netdev_tx_complete_err ( netdev, iobuf, rc );
	return rc;
}

/**
 * Complete network transmission
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @v rc		Packet status code
 *
 * The packet must currently be in the network device's TX queue.
 */
void netdev_tx_complete_err ( struct net_device *netdev,
			      struct io_buffer *iobuf, int rc ) {

	/* Update statistics counter */
	netdev_record_stat ( &netdev->tx_stats, rc );
	if ( rc == 0 ) {
		DBGC ( netdev, "NETDEV %s transmission %p complete\n",
		       netdev->name, iobuf );
	} else {
		DBGC ( netdev, "NETDEV %s transmission %p failed: %s\n",
		       netdev->name, iobuf, strerror ( rc ) );
	}

	/* Catch data corruption as early as possible */
	assert ( iobuf->list.next != NULL );
	assert ( iobuf->list.prev != NULL );

	/* Dequeue and free I/O buffer */
	list_del ( &iobuf->list );
	free_iob ( iobuf );
}

/**
 * Complete network transmission
 *
 * @v netdev		Network device
 * @v rc		Packet status code
 *
 * Completes the oldest outstanding packet in the TX queue.
 */
void netdev_tx_complete_next_err ( struct net_device *netdev, int rc ) {
	struct io_buffer *iobuf;

	list_for_each_entry ( iobuf, &netdev->tx_queue, list ) {
		netdev_tx_complete_err ( netdev, iobuf, rc );
		return;
	}
}

/**
 * Flush device's transmit queue
 *
 * @v netdev		Network device
 */
static void netdev_tx_flush ( struct net_device *netdev ) {

	/* Discard any packets in the TX queue */
	while ( ! list_empty ( &netdev->tx_queue ) ) {
		netdev_tx_complete_next_err ( netdev, -ECANCELED );
	}
}

/**
 * Add packet to receive queue
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer, or NULL
 *
 * The packet is added to the network device's RX queue.  This
 * function takes ownership of the I/O buffer.
 */
void netdev_rx ( struct net_device *netdev, struct io_buffer *iobuf ) {

	DBGC ( netdev, "NETDEV %s received %p (%p+%zx)\n",
	       netdev->name, iobuf, iobuf->data, iob_len ( iobuf ) );

	/* Discard packet (for test purposes) if applicable */
	if ( ( NETDEV_DISCARD_RATE > 0 ) &&
	     ( ( random() % NETDEV_DISCARD_RATE ) == 0 ) ) {
		netdev_rx_err ( netdev, iobuf, -EAGAIN );
		return;
	}

	/* Enqueue packet */
	list_add_tail ( &iobuf->list, &netdev->rx_queue );

	/* Update statistics counter */
	netdev_record_stat ( &netdev->rx_stats, 0 );
}

/**
 * Discard received packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer, or NULL
 * @v rc		Packet status code
 *
 * The packet is discarded and an RX error is recorded.  This function
 * takes ownership of the I/O buffer.  @c iobuf may be NULL if, for
 * example, the net device wishes to report an error due to being
 * unable to allocate an I/O buffer.
 */
void netdev_rx_err ( struct net_device *netdev,
		     struct io_buffer *iobuf, int rc ) {

	DBGC ( netdev, "NETDEV %s failed to receive %p: %s\n",
	       netdev->name, iobuf, strerror ( rc ) );

	/* Discard packet */
	free_iob ( iobuf );

	/* Update statistics counter */
	netdev_record_stat ( &netdev->rx_stats, rc );
}

/**
 * Poll for completed and received packets on network device
 *
 * @v netdev		Network device
 *
 * Polls the network device for completed transmissions and received
 * packets.  Any received packets will be added to the RX packet queue
 * via netdev_rx().
 */
void netdev_poll ( struct net_device *netdev ) {

	if ( netdev_is_open ( netdev ) )
		netdev->op->poll ( netdev );
}

/**
 * Remove packet from device's receive queue
 *
 * @v netdev		Network device
 * @ret iobuf		I/O buffer, or NULL
 *
 * Removes the first packet from the device's RX queue and returns it.
 * Ownership of the packet is transferred to the caller.
 */
struct io_buffer * netdev_rx_dequeue ( struct net_device *netdev ) {
	struct io_buffer *iobuf;

	iobuf = list_first_entry ( &netdev->rx_queue, struct io_buffer, list );
	if ( ! iobuf )
		return NULL;

	list_del ( &iobuf->list );
	return iobuf;
}

/**
 * Flush device's receive queue
 *
 * @v netdev		Network device
 */
static void netdev_rx_flush ( struct net_device *netdev ) {
	struct io_buffer *iobuf;

	/* Discard any packets in the RX queue */
	while ( ( iobuf = netdev_rx_dequeue ( netdev ) ) ) {
		netdev_rx_err ( netdev, iobuf, -ECANCELED );
	}
}

/**
 * Free network device
 *
 * @v refcnt		Network device reference counter
 */
static void free_netdev ( struct refcnt *refcnt ) {
	struct net_device *netdev =
		container_of ( refcnt, struct net_device, refcnt );
	
	netdev_tx_flush ( netdev );
	netdev_rx_flush ( netdev );
	clear_settings ( netdev_settings ( netdev ) );
	free ( netdev );
}

/**
 * Allocate network device
 *
 * @v priv_size		Size of private data area (net_device::priv)
 * @ret netdev		Network device, or NULL
 *
 * Allocates space for a network device and its private data area.
 */
struct net_device * alloc_netdev ( size_t priv_size ) {
	struct net_device *netdev;
	size_t total_len;

	total_len = ( sizeof ( *netdev ) + priv_size );
	netdev = zalloc ( total_len );
	if ( netdev ) {
		ref_init ( &netdev->refcnt, free_netdev );
		netdev->link_rc = -EUNKNOWN_LINK_STATUS;
		INIT_LIST_HEAD ( &netdev->tx_queue );
		INIT_LIST_HEAD ( &netdev->rx_queue );
		netdev_settings_init ( netdev );
		netdev->priv = ( ( ( void * ) netdev ) + sizeof ( *netdev ) );
	}
	return netdev;
}

/**
 * Register network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 *
 * Gives the network device a name and adds it to the list of network
 * devices.
 */
int register_netdev ( struct net_device *netdev ) {
	static unsigned int ifindex = 0;
	struct net_driver *driver;
	int rc;

	/* Create device name */
	if ( netdev->name[0] == '\0' ) {
		snprintf ( netdev->name, sizeof ( netdev->name ), "net%d",
			   ifindex++ );
	}

	/* Set initial link-layer address */
	netdev->ll_protocol->init_addr ( netdev->hw_addr, netdev->ll_addr );

	/* Add to device list */
	netdev_get ( netdev );
	list_add_tail ( &netdev->list, &net_devices );
	DBGC ( netdev, "NETDEV %s registered (phys %s hwaddr %s)\n",
	       netdev->name, netdev->dev->name,
	       netdev_addr ( netdev ) );

	/* Register per-netdev configuration settings */
	if ( ( rc = register_settings ( netdev_settings ( netdev ),
					NULL, netdev->name ) ) != 0 ) {
		DBGC ( netdev, "NETDEV %s could not register settings: %s\n",
		       netdev->name, strerror ( rc ) );
		goto err_register_settings;
	}

	/* Probe device */
	for_each_table_entry ( driver, NET_DRIVERS ) {
		if ( ( rc = driver->probe ( netdev ) ) != 0 ) {
			DBGC ( netdev, "NETDEV %s could not add %s device: "
			       "%s\n", netdev->name, driver->name,
			       strerror ( rc ) );
			goto err_probe;
		}
	}

	return 0;

 err_probe:
	for_each_table_entry_continue_reverse ( driver, NET_DRIVERS )
		driver->remove ( netdev );
	unregister_settings ( netdev_settings ( netdev ) );
 err_register_settings:
	return rc;
}

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
int netdev_open ( struct net_device *netdev ) {
	int rc;

	/* Do nothing if device is already open */
	if ( netdev->state & NETDEV_OPEN )
		return 0;

	DBGC ( netdev, "NETDEV %s opening\n", netdev->name );

	/* Open the device */
	if ( ( rc = netdev->op->open ( netdev ) ) != 0 )
		return rc;

	/* Mark as opened */
	netdev->state |= NETDEV_OPEN;

	/* Add to head of open devices list */
	list_add ( &netdev->open_list, &open_net_devices );

	/* Notify drivers of device state change */
	netdev_notify ( netdev );

	return 0;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
void netdev_close ( struct net_device *netdev ) {

	/* Do nothing if device is already closed */
	if ( ! ( netdev->state & NETDEV_OPEN ) )
		return;

	DBGC ( netdev, "NETDEV %s closing\n", netdev->name );

	/* Remove from open devices list */
	list_del ( &netdev->open_list );

	/* Mark as closed */
	netdev->state &= ~NETDEV_OPEN;

	/* Notify drivers of device state change */
	netdev_notify ( netdev );

	/* Close the device */
	netdev->op->close ( netdev );

	/* Flush TX and RX queues */
	netdev_tx_flush ( netdev );
	netdev_rx_flush ( netdev );
}

/**
 * Unregister network device
 *
 * @v netdev		Network device
 *
 * Removes the network device from the list of network devices.
 */
void unregister_netdev ( struct net_device *netdev ) {
	struct net_driver *driver;

	/* Ensure device is closed */
	netdev_close ( netdev );

	/* Remove device */
	for_each_table_entry_reverse ( driver, NET_DRIVERS )
		driver->remove ( netdev );

	/* Unregister per-netdev configuration settings */
	unregister_settings ( netdev_settings ( netdev ) );

	/* Remove from device list */
	list_del ( &netdev->list );
	netdev_put ( netdev );
	DBGC ( netdev, "NETDEV %s unregistered\n", netdev->name );
}

/** Enable or disable interrupts
 *
 * @v netdev		Network device
 * @v enable		Interrupts should be enabled
 */
void netdev_irq ( struct net_device *netdev, int enable ) {

	/* Do nothing if device does not support interrupts */
	if ( ! netdev_irq_supported ( netdev ) )
		return;

	/* Enable or disable device interrupts */
	netdev->op->irq ( netdev, enable );

	/* Record interrupt enabled state */
	netdev->state &= ~NETDEV_IRQ_ENABLED;
	if ( enable )
		netdev->state |= NETDEV_IRQ_ENABLED;
}

/**
 * Get network device by name
 *
 * @v name		Network device name
 * @ret netdev		Network device, or NULL
 */
struct net_device * find_netdev ( const char *name ) {
	struct net_device *netdev;

	list_for_each_entry ( netdev, &net_devices, list ) {
		if ( strcmp ( netdev->name, name ) == 0 )
			return netdev;
	}

	return NULL;
}

/**
 * Get network device by PCI bus:dev.fn address
 *
 * @v bus_type		Bus type
 * @v location		Bus location
 * @ret netdev		Network device, or NULL
 */
struct net_device * find_netdev_by_location ( unsigned int bus_type,
					      unsigned int location ) {
	struct net_device *netdev;

	list_for_each_entry ( netdev, &net_devices, list ) {
		if ( ( netdev->dev->desc.bus_type == bus_type ) &&
		     ( netdev->dev->desc.location == location ) )
			return netdev;
	}

	return NULL;	
}

/**
 * Get most recently opened network device
 *
 * @ret netdev		Most recently opened network device, or NULL
 */
struct net_device * last_opened_netdev ( void ) {
	struct net_device *netdev;

	netdev = list_first_entry ( &open_net_devices, struct net_device,
				    open_list );
	if ( ! netdev )
		return NULL;

	assert ( netdev_is_open ( netdev ) );
	return netdev;
}

/**
 * Transmit network-layer packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v net_protocol	Network-layer protocol
 * @v ll_dest		Destination link-layer address
 * @v ll_source		Source link-layer address
 * @ret rc		Return status code
 *
 * Prepends link-layer headers to the I/O buffer and transmits the
 * packet via the specified network device.  This function takes
 * ownership of the I/O buffer.
 */
int net_tx ( struct io_buffer *iobuf, struct net_device *netdev,
	     struct net_protocol *net_protocol, const void *ll_dest,
	     const void *ll_source ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	int rc;

	/* Force a poll on the netdevice to (potentially) clear any
	 * backed-up TX completions.  This is needed on some network
	 * devices to avoid excessive losses due to small TX ring
	 * sizes.
	 */
	netdev_poll ( netdev );

	/* Add link-layer header */
	if ( ( rc = ll_protocol->push ( netdev, iobuf, ll_dest, ll_source,
					net_protocol->net_proto ) ) != 0 ) {
		free_iob ( iobuf );
		return rc;
	}

	/* Transmit packet */
	return netdev_tx ( netdev, iobuf );
}

/**
 * Process received network-layer packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v net_proto		Network-layer protocol, in network-byte order
 * @v ll_dest		Destination link-layer address
 * @v ll_source		Source link-layer address
 * @ret rc		Return status code
 */
int net_rx ( struct io_buffer *iobuf, struct net_device *netdev,
	     uint16_t net_proto, const void *ll_dest, const void *ll_source ) {
	struct net_protocol *net_protocol;

	/* Hand off to network-layer protocol, if any */
	for_each_table_entry ( net_protocol, NET_PROTOCOLS ) {
		if ( net_protocol->net_proto == net_proto )
			return net_protocol->rx ( iobuf, netdev, ll_dest,
						  ll_source );
	}

	DBGC ( netdev, "NETDEV %s unknown network protocol %04x\n",
	       netdev->name, ntohs ( net_proto ) );
	free_iob ( iobuf );
	return -ENOTSUP;
}

/**
 * Poll the network stack
 *
 * This polls all interfaces for received packets, and processes
 * packets from the RX queue.
 */
void net_poll ( void ) {
	struct net_device *netdev;
	struct io_buffer *iobuf;
	struct ll_protocol *ll_protocol;
	const void *ll_dest;
	const void *ll_source;
	uint16_t net_proto;
	int rc;

	/* Poll and process each network device */
	list_for_each_entry ( netdev, &net_devices, list ) {

		/* Poll for new packets */
		netdev_poll ( netdev );

		/* Leave received packets on the queue if receive
		 * queue processing is currently frozen.  This will
		 * happen when the raw packets are to be manually
		 * dequeued using netdev_rx_dequeue(), rather than
		 * processed via the usual networking stack.
		 */
		if ( netdev_rx_frozen ( netdev ) )
			continue;

		/* Process at most one received packet.  Give priority
		 * to getting packets out of the NIC over processing
		 * the received packets, because we advertise a window
		 * that assumes that we can receive packets from the
		 * NIC faster than they arrive.
		 */
		if ( ( iobuf = netdev_rx_dequeue ( netdev ) ) ) {

			DBGC ( netdev, "NETDEV %s processing %p (%p+%zx)\n",
			       netdev->name, iobuf, iobuf->data,
			       iob_len ( iobuf ) );

			/* Remove link-layer header */
			ll_protocol = netdev->ll_protocol;
			if ( ( rc = ll_protocol->pull ( netdev, iobuf,
							&ll_dest, &ll_source,
							&net_proto ) ) != 0 ) {
				free_iob ( iobuf );
				continue;
			}

			/* Hand packet to network layer */
			if ( ( rc = net_rx ( iob_disown ( iobuf ), netdev,
					     net_proto, ll_dest,
					     ll_source ) ) != 0 ) {
				/* Record error for diagnosis */
				netdev_rx_err ( netdev, NULL, rc );
			}
		}
	}
}

/**
 * Single-step the network stack
 *
 * @v process		Network stack process
 */
static void net_step ( struct process *process __unused ) {
	net_poll();
}

/** Networking stack process */
struct process net_process __permanent_process = {
	.list = LIST_HEAD_INIT ( net_process.list ),
	.step = net_step,
};
