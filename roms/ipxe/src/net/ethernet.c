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
#include <stdio.h>
#include <string.h>
#include <byteswap.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/if_arp.h>
#include <ipxe/if_ether.h>
#include <ipxe/in.h>
#include <ipxe/netdevice.h>
#include <ipxe/iobuf.h>
#include <ipxe/ethernet.h>

/** @file
 *
 * Ethernet protocol
 *
 */

/** Ethernet broadcast MAC address */
static uint8_t eth_broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/**
 * Add Ethernet link-layer header
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Source link-layer address
 * @v net_proto		Network-layer protocol, in network-byte order
 * @ret rc		Return status code
 */
static int eth_push ( struct net_device *netdev __unused,
		      struct io_buffer *iobuf, const void *ll_dest,
		      const void *ll_source, uint16_t net_proto ) {
	struct ethhdr *ethhdr = iob_push ( iobuf, sizeof ( *ethhdr ) );

	/* Build Ethernet header */
	memcpy ( ethhdr->h_dest, ll_dest, ETH_ALEN );
	memcpy ( ethhdr->h_source, ll_source, ETH_ALEN );
	ethhdr->h_protocol = net_proto;

	return 0;
}

/**
 * Remove Ethernet link-layer header
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret ll_dest		Link-layer destination address
 * @ret ll_source	Source link-layer address
 * @ret net_proto	Network-layer protocol, in network-byte order
 * @ret rc		Return status code
 */
static int eth_pull ( struct net_device *netdev __unused, 
		      struct io_buffer *iobuf, const void **ll_dest,
		      const void **ll_source, uint16_t *net_proto ) {
	struct ethhdr *ethhdr = iobuf->data;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *ethhdr ) ) {
		DBG ( "Ethernet packet too short (%zd bytes)\n",
		      iob_len ( iobuf ) );
		return -EINVAL;
	}

	/* Strip off Ethernet header */
	iob_pull ( iobuf, sizeof ( *ethhdr ) );

	/* Fill in required fields */
	*ll_dest = ethhdr->h_dest;
	*ll_source = ethhdr->h_source;
	*net_proto = ethhdr->h_protocol;

	return 0;
}

/**
 * Initialise Ethernet address
 *
 * @v hw_addr		Hardware address
 * @v ll_addr		Link-layer address
 */
void eth_init_addr ( const void *hw_addr, void *ll_addr ) {
	memcpy ( ll_addr, hw_addr, ETH_ALEN );
}

/**
 * Transcribe Ethernet address
 *
 * @v ll_addr		Link-layer address
 * @ret string		Link-layer address in human-readable format
 */
const char * eth_ntoa ( const void *ll_addr ) {
	static char buf[18]; /* "00:00:00:00:00:00" */
	const uint8_t *eth_addr = ll_addr;

	sprintf ( buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		  eth_addr[0], eth_addr[1], eth_addr[2],
		  eth_addr[3], eth_addr[4], eth_addr[5] );
	return buf;
}

/**
 * Hash multicast address
 *
 * @v af		Address family
 * @v net_addr		Network-layer address
 * @v ll_addr		Link-layer address to fill in
 * @ret rc		Return status code
 */
int eth_mc_hash ( unsigned int af, const void *net_addr, void *ll_addr ) {
	const uint8_t *net_addr_bytes = net_addr;
	uint8_t *ll_addr_bytes = ll_addr;

	switch ( af ) {
	case AF_INET:
		ll_addr_bytes[0] = 0x01;
		ll_addr_bytes[1] = 0x00;
		ll_addr_bytes[2] = 0x5e;
		ll_addr_bytes[3] = net_addr_bytes[1] & 0x7f;
		ll_addr_bytes[4] = net_addr_bytes[2];
		ll_addr_bytes[5] = net_addr_bytes[3];
		return 0;
	default:
		return -ENOTSUP;
	}
}

/**
 * Generate Ethernet-compatible compressed link-layer address
 *
 * @v ll_addr		Link-layer address
 * @v eth_addr		Ethernet-compatible address to fill in
 */
int eth_eth_addr ( const void *ll_addr, void *eth_addr ) {
	memcpy ( eth_addr, ll_addr, ETH_ALEN );
	return 0;
}

/** Ethernet protocol */
struct ll_protocol ethernet_protocol __ll_protocol = {
	.name		= "Ethernet",
	.ll_proto	= htons ( ARPHRD_ETHER ),
	.hw_addr_len	= ETH_ALEN,
	.ll_addr_len	= ETH_ALEN,
	.ll_header_len	= ETH_HLEN,
	.push		= eth_push,
	.pull		= eth_pull,
	.init_addr	= eth_init_addr,
	.ntoa		= eth_ntoa,
	.mc_hash	= eth_mc_hash,
	.eth_addr	= eth_eth_addr,
};

/**
 * Allocate Ethernet device
 *
 * @v priv_size		Size of driver private data
 * @ret netdev		Network device, or NULL
 */
struct net_device * alloc_etherdev ( size_t priv_size ) {
	struct net_device *netdev;

	netdev = alloc_netdev ( priv_size );
	if ( netdev ) {
		netdev->ll_protocol = &ethernet_protocol;
		netdev->ll_broadcast = eth_broadcast;
		netdev->max_pkt_len = ETH_FRAME_LEN;
	}
	return netdev;
}

/* Drag in Ethernet slow protocols */
REQUIRE_OBJECT ( eth_slow );
