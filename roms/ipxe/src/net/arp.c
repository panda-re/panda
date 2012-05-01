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
#include <string.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/if_ether.h>
#include <ipxe/if_arp.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/arp.h>

/** @file
 *
 * Address Resolution Protocol
 *
 * This file implements the address resolution protocol as defined in
 * RFC826.  The implementation is media-independent and
 * protocol-independent; it is not limited to Ethernet or to IPv4.
 *
 */

/** An ARP cache entry */
struct arp_entry {
	/** Network-layer protocol */
	struct net_protocol *net_protocol;
	/** Link-layer protocol */
	struct ll_protocol *ll_protocol;
	/** Network-layer address */
	uint8_t net_addr[MAX_NET_ADDR_LEN];
	/** Link-layer address */
	uint8_t ll_addr[MAX_LL_ADDR_LEN];
};

/** Number of entries in the ARP cache
 *
 * This is a global cache, covering all network interfaces,
 * network-layer protocols and link-layer protocols.
 */
#define NUM_ARP_ENTRIES 4

/** The ARP cache */
static struct arp_entry arp_table[NUM_ARP_ENTRIES];
#define arp_table_end &arp_table[NUM_ARP_ENTRIES]

static unsigned int next_new_arp_entry = 0;

struct net_protocol arp_protocol __net_protocol;

/**
 * Find entry in the ARP cache
 *
 * @v ll_protocol	Link-layer protocol
 * @v net_protocol	Network-layer protocol
 * @v net_addr		Network-layer address
 * @ret arp		ARP cache entry, or NULL if not found
 *
 */
static struct arp_entry *
arp_find_entry ( struct ll_protocol *ll_protocol,
		 struct net_protocol *net_protocol,
		 const void *net_addr ) {
	struct arp_entry *arp;

	for ( arp = arp_table ; arp < arp_table_end ; arp++ ) {
		if ( ( arp->ll_protocol == ll_protocol ) &&
		     ( arp->net_protocol == net_protocol ) &&
		     ( memcmp ( arp->net_addr, net_addr,
				net_protocol->net_addr_len ) == 0 ) )
			return arp;
	}
	return NULL;
}

/**
 * Look up media-specific link-layer address in the ARP cache
 *
 * @v netdev		Network device
 * @v net_protocol	Network-layer protocol
 * @v dest_net_addr	Destination network-layer address
 * @v source_net_addr	Source network-layer address
 * @ret dest_ll_addr	Destination link layer address
 * @ret rc		Return status code
 *
 * This function will use the ARP cache to look up the link-layer
 * address for the link-layer protocol associated with the network
 * device and the given network-layer protocol and addresses.  If
 * found, the destination link-layer address will be filled in in @c
 * dest_ll_addr.
 *
 * If no address is found in the ARP cache, an ARP request will be
 * transmitted on the specified network device and -ENOENT will be
 * returned.
 */
int arp_resolve ( struct net_device *netdev, struct net_protocol *net_protocol,
		  const void *dest_net_addr, const void *source_net_addr,
		  void *dest_ll_addr ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	const struct arp_entry *arp;
	struct io_buffer *iobuf;
	struct arphdr *arphdr;
	int rc;

	/* Look for existing entry in ARP table */
	arp = arp_find_entry ( ll_protocol, net_protocol, dest_net_addr );
	if ( arp ) {
		DBG ( "ARP cache hit: %s %s => %s %s\n",
		      net_protocol->name, net_protocol->ntoa ( arp->net_addr ),
		      ll_protocol->name, ll_protocol->ntoa ( arp->ll_addr ) );
		memcpy ( dest_ll_addr, arp->ll_addr, ll_protocol->ll_addr_len);
		return 0;
	}
	DBG ( "ARP cache miss: %s %s\n", net_protocol->name,
	      net_protocol->ntoa ( dest_net_addr ) );

	/* Allocate ARP packet */
	iobuf = alloc_iob ( MAX_LL_HEADER_LEN + sizeof ( *arphdr ) +
			  2 * ( MAX_LL_ADDR_LEN + MAX_NET_ADDR_LEN ) );
	if ( ! iobuf )
		return -ENOMEM;
	iob_reserve ( iobuf, MAX_LL_HEADER_LEN );

	/* Build up ARP request */
	arphdr = iob_put ( iobuf, sizeof ( *arphdr ) );
	arphdr->ar_hrd = ll_protocol->ll_proto;
	arphdr->ar_hln = ll_protocol->ll_addr_len;
	arphdr->ar_pro = net_protocol->net_proto;
	arphdr->ar_pln = net_protocol->net_addr_len;
	arphdr->ar_op = htons ( ARPOP_REQUEST );
	memcpy ( iob_put ( iobuf, ll_protocol->ll_addr_len ),
		 netdev->ll_addr, ll_protocol->ll_addr_len );
	memcpy ( iob_put ( iobuf, net_protocol->net_addr_len ),
		 source_net_addr, net_protocol->net_addr_len );
	memset ( iob_put ( iobuf, ll_protocol->ll_addr_len ),
		 0, ll_protocol->ll_addr_len );
	memcpy ( iob_put ( iobuf, net_protocol->net_addr_len ),
		 dest_net_addr, net_protocol->net_addr_len );

	/* Transmit ARP request */
	if ( ( rc = net_tx ( iobuf, netdev, &arp_protocol,
			     netdev->ll_broadcast, netdev->ll_addr ) ) != 0 )
		return rc;

	return -ENOENT;
}

/**
 * Identify ARP protocol
 *
 * @v net_proto			Network-layer protocol, in network-endian order
 * @ret arp_net_protocol	ARP protocol, or NULL
 *
 */
static struct arp_net_protocol * arp_find_protocol ( uint16_t net_proto ) {
	struct arp_net_protocol *arp_net_protocol;

	for_each_table_entry ( arp_net_protocol, ARP_NET_PROTOCOLS ) {
		if ( arp_net_protocol->net_protocol->net_proto == net_proto ) {
			return arp_net_protocol;
		}
	}
	return NULL;
}

/**
 * Process incoming ARP packets
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_source		Link-layer source address
 * @ret rc		Return status code
 *
 * This handles ARP requests and responses as detailed in RFC826.  The
 * method detailed within the RFC is pretty optimised, handling
 * requests and responses with basically a single code path and
 * avoiding the need for extraneous ARP requests; read the RFC for
 * details.
 */
static int arp_rx ( struct io_buffer *iobuf, struct net_device *netdev,
		    const void *ll_dest __unused,
		    const void *ll_source __unused ) {
	struct arphdr *arphdr = iobuf->data;
	struct arp_net_protocol *arp_net_protocol;
	struct net_protocol *net_protocol;
	struct ll_protocol *ll_protocol;
	struct arp_entry *arp;
	int merge = 0;

	/* Identify network-layer and link-layer protocols */
	arp_net_protocol = arp_find_protocol ( arphdr->ar_pro );
	if ( ! arp_net_protocol )
		goto done;
	net_protocol = arp_net_protocol->net_protocol;
	ll_protocol = netdev->ll_protocol;

	/* Sanity checks */
	if ( ( arphdr->ar_hrd != ll_protocol->ll_proto ) ||
	     ( arphdr->ar_hln != ll_protocol->ll_addr_len ) ||
	     ( arphdr->ar_pln != net_protocol->net_addr_len ) )
		goto done;

	/* See if we have an entry for this sender, and update it if so */
	arp = arp_find_entry ( ll_protocol, net_protocol,
			       arp_sender_pa ( arphdr ) );
	if ( arp ) {
		memcpy ( arp->ll_addr, arp_sender_ha ( arphdr ),
			 arphdr->ar_hln );
		merge = 1;
		DBG ( "ARP cache update: %s %s => %s %s\n",
		      net_protocol->name, net_protocol->ntoa ( arp->net_addr ),
		      ll_protocol->name, ll_protocol->ntoa ( arp->ll_addr ) );
	}

	/* See if we own the target protocol address */
	if ( arp_net_protocol->check ( netdev, arp_target_pa ( arphdr ) ) != 0)
		goto done;
	
	/* Create new ARP table entry if necessary */
	if ( ! merge ) {
		arp = &arp_table[next_new_arp_entry++ % NUM_ARP_ENTRIES];
		arp->ll_protocol = ll_protocol;
		arp->net_protocol = net_protocol;
		memcpy ( arp->ll_addr, arp_sender_ha ( arphdr ),
			 arphdr->ar_hln );
		memcpy ( arp->net_addr, arp_sender_pa ( arphdr ),
			 arphdr->ar_pln);
		DBG ( "ARP cache add: %s %s => %s %s\n",
		      net_protocol->name, net_protocol->ntoa ( arp->net_addr ),
		      ll_protocol->name, ll_protocol->ntoa ( arp->ll_addr ) );
	}

	/* If it's not a request, there's nothing more to do */
	if ( arphdr->ar_op != htons ( ARPOP_REQUEST ) )
		goto done;

	/* Change request to a reply */
	DBG ( "ARP reply: %s %s => %s %s\n", net_protocol->name,
	      net_protocol->ntoa ( arp_target_pa ( arphdr ) ),
	      ll_protocol->name, ll_protocol->ntoa ( netdev->ll_addr ) );
	arphdr->ar_op = htons ( ARPOP_REPLY );
	memswap ( arp_sender_ha ( arphdr ), arp_target_ha ( arphdr ),
		 arphdr->ar_hln + arphdr->ar_pln );
	memcpy ( arp_sender_ha ( arphdr ), netdev->ll_addr, arphdr->ar_hln );

	/* Send reply */
	net_tx ( iob_disown ( iobuf ), netdev, &arp_protocol,
		 arp_target_ha ( arphdr ), netdev->ll_addr );

 done:
	free_iob ( iobuf );
	return 0;
}

/**
 * Transcribe ARP address
 *
 * @v net_addr	ARP address
 * @ret string	"<ARP>"
 *
 * This operation is meaningless for the ARP protocol.
 */
static const char * arp_ntoa ( const void *net_addr __unused ) {
	return "<ARP>";
}

/** ARP protocol */
struct net_protocol arp_protocol __net_protocol = {
	.name = "ARP",
	.net_proto = htons ( ETH_P_ARP ),
	.rx = arp_rx,
	.ntoa = arp_ntoa,
};
