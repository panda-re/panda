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

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/if_ether.h>
#include <ipxe/keys.h>
#include <ipxe/console.h>
#include <usr/ifmgmt.h>
#include <usr/lotest.h>

/** @file
 *
 * Loopback testing
 *
 */

#define LINK_WAIT_MS 15000

/**
 * Process received packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer source address
 * @ret rc		Return status code
 */
static int lotest_rx ( struct io_buffer *iobuf,
		       struct net_device *netdev __unused,
		       const void *ll_dest __unused,
		       const void *ll_source __unused ) {
	free_iob ( iobuf );
	return -ENOTSUP;
}

/**
 * Transcribe network-layer address
 *
 * @v net_addr		Network-layer address
 * @ret string		Human-readable transcription of address
 */
static const char * lotest_ntoa ( const void *net_addr __unused ) {
	return "<INVALID>";
}

/**
 * Loopback test network-layer protocol
 *
 * Using a dedicated network-layer protocol avoids problems caused by
 * cards supporting features such as IPv4 checksum offload trying to
 * interpret the (randomly generated) network-layer content.
 */
static struct net_protocol lotest_protocol __net_protocol = {
	.name = "LOTEST",
	.rx = lotest_rx,
	.ntoa = lotest_ntoa,
	.net_proto = htons ( 0x6950 ), /* Not a genuine protocol number */
	.net_addr_len = 0,
};

/**
 * Perform loopback test between two network devices
 *
 * @v sender		Sending network device
 * @v receiver		Received network device
 * @v mtu		Packet size (excluding link-layer headers)
 * @ret rc		Return status code
 */
int loopback_test ( struct net_device *sender, struct net_device *receiver,
		    size_t mtu ) {
	uint8_t buf[mtu];
	struct io_buffer *iobuf;
	const void *ll_dest;
	const void *ll_source;
	uint16_t net_proto;
	unsigned int i;
	unsigned int successes;
	int rc;

	/* Open network devices */
	if ( ( rc = ifopen ( sender ) ) != 0 )
		return rc;
	if ( ( rc = ifopen ( receiver ) ) != 0 )
		return rc;

	/* Wait for link-up */
	if ( ( rc = iflinkwait ( sender, LINK_WAIT_MS ) ) != 0 )
		return rc;
	if ( ( rc = iflinkwait ( receiver, LINK_WAIT_MS ) ) != 0 )
		return rc;

	/* Print initial statistics */
	printf ( "Performing loopback test from %s to %s with %zd byte MTU\n",
		 sender->name, receiver->name, mtu );
	ifstat ( sender );
	ifstat ( receiver );

	/* Freeze receive queue processing on the receiver, so that we
	 * can extract all received packets.
	 */
	netdev_rx_freeze ( receiver );

	/* Perform loopback test */
	for ( successes = 0 ; ; successes++ ) {

		/* Print running total */
		printf ( "\r%d", successes );

		/* Generate random packet */
		for ( i = 0 ; i < sizeof ( buf ) ; i++ )
			buf[i] = random();
		iobuf = alloc_iob ( MAX_LL_HEADER_LEN + sizeof ( buf ) );
		if ( ! iobuf ) {
			printf ( "\nFailed to allocate I/O buffer" );
			rc = -ENOMEM;
			goto done;
		}
		iob_reserve ( iobuf, MAX_LL_HEADER_LEN );
		memcpy ( iob_put ( iobuf, sizeof ( buf ) ),
			 buf, sizeof ( buf ) );

		/* Transmit packet */
		if ( ( rc = net_tx ( iob_disown ( iobuf ), sender,
				     &lotest_protocol, receiver->ll_addr,
				     sender->ll_addr ) ) != 0 ) {
			printf ( "\nFailed to transmit packet: %s",
				 strerror ( rc ) );
			goto done;
		}

		/* Poll until packet arrives */
		do {
			/* Check for cancellation */
			if ( iskey() && ( getchar() == CTRL_C ) ) {
				rc = -ECANCELED;
				goto done;
			}
			/* Poll network devices */
			net_poll();
		} while ( ( iobuf = netdev_rx_dequeue ( receiver ) ) == NULL );

		/* Check received packet */
		if ( ( rc = receiver->ll_protocol->pull ( receiver, iobuf,
							  &ll_dest, &ll_source,
							  &net_proto ) ) != 0 ){
			printf ( "\nFailed to strip link-layer header: %s",
				 strerror ( rc ) );
			goto done;
		}
		if ( net_proto == lotest_protocol.net_proto ) {
			if ( iob_len ( iobuf ) != sizeof ( buf ) ) {
				printf ( "\nLength mismatch: sent %zd, "
					 "received %zd",
					 sizeof ( buf ), iob_len ( iobuf ) );
				DBG ( "\nSent:\n" );
				DBG_HDA ( 0, buf, sizeof ( buf ) );
				DBG ( "Received:\n" );
				DBG_HDA ( 0, iobuf->data, iob_len ( iobuf ) );
				rc = -EINVAL;
				goto done;
			}
			if ( memcmp ( iobuf->data, buf, sizeof ( buf ) ) != 0){
				printf ( "\nContent mismatch" );
				DBG ( "\nSent:\n" );
				DBG_HDA ( 0, buf, sizeof ( buf ) );
				DBG ( "Received:\n" );
				DBG_HDA ( 0, iobuf->data, iob_len ( iobuf ) );
				rc = -EINVAL;
				goto done;
			}
		} else {
			printf ( "\nReceived spurious packet type %04x\n",
				 ntohs ( net_proto ) );
			/* Continue; this allows for the fact that
			 * there may have been packets outstanding on
			 * the wire when we started the test.
			 */
		}

		free_iob ( iob_disown ( iobuf ) );
	}

 done:
	printf ( "\n");
	free_iob ( iobuf );
	netdev_rx_unfreeze ( receiver );

	/* Dump final statistics */
	ifstat ( sender );
	ifstat ( receiver );

	return 0;
}
