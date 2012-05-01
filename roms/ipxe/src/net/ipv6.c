#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <byteswap.h>
#include <ipxe/in.h>
#include <ipxe/ip6.h>
#include <ipxe/ndp.h>
#include <ipxe/list.h>
#include <ipxe/icmp6.h>
#include <ipxe/tcpip.h>
#include <ipxe/socket.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/if_ether.h>

/* Unspecified IP6 address */
static struct in6_addr ip6_none = {
        .in6_u.u6_addr32 = { 0,0,0,0 }
};

/** An IPv6 routing table entry */
struct ipv6_miniroute {
	/* List of miniroutes */
	struct list_head list;

	/* Network device */
	struct net_device *netdev;

	/* Destination prefix */
	struct in6_addr prefix;
	/* Prefix length */
	int prefix_len;
	/* IPv6 address of interface */
	struct in6_addr address;
	/* Gateway address */
	struct in6_addr gateway;
};

/** List of IPv6 miniroutes */
static LIST_HEAD ( miniroutes );

/**
 * Add IPv6 minirouting table entry
 *
 * @v netdev		Network device
 * @v prefix		Destination prefix
 * @v address		Address of the interface
 * @v gateway		Gateway address (or ::0 for no gateway)
 * @ret miniroute	Routing table entry, or NULL
 */
static struct ipv6_miniroute * __malloc 
add_ipv6_miniroute ( struct net_device *netdev, struct in6_addr prefix,
		     int prefix_len, struct in6_addr address,
		     struct in6_addr gateway ) {
	struct ipv6_miniroute *miniroute;
	
	miniroute = malloc ( sizeof ( *miniroute ) );
	if ( miniroute ) {
		/* Record routing information */
		miniroute->netdev = netdev_get ( netdev );
		miniroute->prefix = prefix;
		miniroute->prefix_len = prefix_len;
		miniroute->address = address;
		miniroute->gateway = gateway;
		
		/* Add miniroute to list of miniroutes */
		if ( !IP6_EQUAL ( gateway, ip6_none ) ) {
			list_add_tail ( &miniroute->list, &miniroutes );
		} else {
			list_add ( &miniroute->list, &miniroutes );
		}
	}

	return miniroute;
}

/**
 * Delete IPv6 minirouting table entry
 *
 * @v miniroute		Routing table entry
 */
static void del_ipv6_miniroute ( struct ipv6_miniroute *miniroute ) {
	netdev_put ( miniroute->netdev );
	list_del ( &miniroute->list );
	free ( miniroute );
}

/**
 * Add IPv6 interface
 *
 * @v netdev	Network device
 * @v prefix	Destination prefix
 * @v address	Address of the interface
 * @v gateway	Gateway address (or ::0 for no gateway)
 */
int add_ipv6_address ( struct net_device *netdev, struct in6_addr prefix,
		       int prefix_len, struct in6_addr address,
		       struct in6_addr gateway ) {
	struct ipv6_miniroute *miniroute;

	/* Clear any existing address for this net device */
	del_ipv6_address ( netdev );

	/* Add new miniroute */
	miniroute = add_ipv6_miniroute ( netdev, prefix, prefix_len, address,
					 gateway );
	if ( ! miniroute )
		return -ENOMEM;

	return 0;
}

/**
 * Remove IPv6 interface
 *
 * @v netdev	Network device
 */
void del_ipv6_address ( struct net_device *netdev ) {
	struct ipv6_miniroute *miniroute;

	list_for_each_entry ( miniroute, &miniroutes, list ) {
		if ( miniroute->netdev == netdev ) {
			del_ipv6_miniroute ( miniroute );
			break;
		}
	}
}

/**
 * Calculate TCPIP checksum
 *
 * @v iobuf	I/O buffer
 * @v tcpip	TCP/IP protocol
 *
 * This function constructs the pseudo header and completes the checksum in the
 * upper layer header.
 */
static uint16_t ipv6_tx_csum ( struct io_buffer *iobuf, uint16_t csum ) {
	struct ip6_header *ip6hdr = iobuf->data;
	struct ipv6_pseudo_header pshdr;

	/* Calculate pseudo header */
	memset ( &pshdr, 0, sizeof ( pshdr ) );
	pshdr.src = ip6hdr->src;
	pshdr.dest = ip6hdr->dest;
	pshdr.len = htons ( iob_len ( iobuf ) - sizeof ( *ip6hdr ) );
	pshdr.nxt_hdr = ip6hdr->nxt_hdr;

	/* Update checksum value */
	return tcpip_continue_chksum ( csum, &pshdr, sizeof ( pshdr ) );
}

/**
 * Dump IP6 header for debugging
 *
 * ip6hdr	IPv6 header
 */
void ipv6_dump ( struct ip6_header *ip6hdr ) {
	DBG ( "IP6 %p src %s dest %s nxt_hdr %d len %d\n", ip6hdr,
	      inet6_ntoa ( ip6hdr->src ), inet6_ntoa ( ip6hdr->dest ),
	      ip6hdr->nxt_hdr, ntohs ( ip6hdr->payload_len ) );
}

/**
 * Transmit IP6 packet
 *
 * iobuf		I/O buffer
 * tcpip	TCP/IP protocol
 * st_dest	Destination socket address
 *
 * This function prepends the IPv6 headers to the payload an transmits it.
 */
static int ipv6_tx ( struct io_buffer *iobuf,
		     struct tcpip_protocol *tcpip,
		     struct sockaddr_tcpip *st_src __unused,
		     struct sockaddr_tcpip *st_dest,
		     struct net_device *netdev,
		     uint16_t *trans_csum ) {
	struct sockaddr_in6 *dest = ( struct sockaddr_in6* ) st_dest;
	struct in6_addr next_hop;
	struct ipv6_miniroute *miniroute;
	uint8_t ll_dest_buf[MAX_LL_ADDR_LEN];
	const uint8_t *ll_dest = ll_dest_buf;
	int rc;

	/* Construct the IPv6 packet */
	struct ip6_header *ip6hdr = iob_push ( iobuf, sizeof ( *ip6hdr ) );
	memset ( ip6hdr, 0, sizeof ( *ip6hdr) );
	ip6hdr->ver_traffic_class_flow_label = htonl ( 0x60000000 );//IP6_VERSION;
	ip6hdr->payload_len = htons ( iob_len ( iobuf ) - sizeof ( *ip6hdr ) );
	ip6hdr->nxt_hdr = tcpip->tcpip_proto;
	ip6hdr->hop_limit = IP6_HOP_LIMIT; // 255

	/* Determine the next hop address and interface
	 *
	 * TODO: Implement the routing table.
	 */
	next_hop = dest->sin6_addr;
	list_for_each_entry ( miniroute, &miniroutes, list ) {
		if ( ( memcmp ( &ip6hdr->dest, &miniroute->prefix,
					miniroute->prefix_len ) == 0 ) ||
		     ( IP6_EQUAL ( miniroute->gateway, ip6_none ) ) ) {
			netdev = miniroute->netdev;
			ip6hdr->src = miniroute->address;
			if ( ! ( IS_UNSPECIFIED ( miniroute->gateway ) ) ) {
				next_hop = miniroute->gateway;
			}
			break;
		}
	}
	/* No network interface identified */
	if ( !netdev ) {
		DBG ( "No route to host %s\n", inet6_ntoa ( ip6hdr->dest ) );
		rc = -ENETUNREACH;
		goto err;
	}

	/* Complete the transport layer checksum */
	if ( trans_csum )
		*trans_csum = ipv6_tx_csum ( iobuf, *trans_csum );

	/* Print IPv6 header */
	ipv6_dump ( ip6hdr );
	
	/* Resolve link layer address */
	if ( next_hop.in6_u.u6_addr8[0] == 0xff ) {
		ll_dest_buf[0] = 0x33;
		ll_dest_buf[1] = 0x33;
		ll_dest_buf[2] = next_hop.in6_u.u6_addr8[12];
		ll_dest_buf[3] = next_hop.in6_u.u6_addr8[13];
		ll_dest_buf[4] = next_hop.in6_u.u6_addr8[14];
		ll_dest_buf[5] = next_hop.in6_u.u6_addr8[15];
	} else {
		/* Unicast address needs to be resolved by NDP */
		if ( ( rc = ndp_resolve ( netdev, &next_hop, &ip6hdr->src,
					  ll_dest_buf ) ) != 0 ) {
			DBG ( "No entry for %s\n", inet6_ntoa ( next_hop ) );
			goto err;
		}
	}

	/* Transmit packet */
	return net_tx ( iobuf, netdev, &ipv6_protocol, ll_dest,
			netdev->ll_addr );

  err:
	free_iob ( iobuf );
	return rc;
}

/**
 * Process next IP6 header
 *
 * @v iobuf	I/O buffer
 * @v nxt_hdr	Next header number
 * @v src	Source socket address
 * @v dest	Destination socket address
 *
 * Refer http://www.iana.org/assignments/ipv6-parameters for the numbers
 */
static int ipv6_process_nxt_hdr ( struct io_buffer *iobuf, uint8_t nxt_hdr,
		struct sockaddr_tcpip *src, struct sockaddr_tcpip *dest ) {
	switch ( nxt_hdr ) {
	case IP6_HOPBYHOP: 
	case IP6_ROUTING: 
	case IP6_FRAGMENT: 
	case IP6_AUTHENTICATION: 
	case IP6_DEST_OPTS: 
	case IP6_ESP: 
		DBG ( "Function not implemented for header %d\n", nxt_hdr );
		return -ENOSYS;
	case IP6_ICMP6: 
		break;
	case IP6_NO_HEADER: 
		DBG ( "No next header\n" );
		return 0;
	}
	/* Next header is not a IPv6 extension header */
	return tcpip_rx ( iobuf, nxt_hdr, src, dest, 0 /* fixme */ );
}

/**
 * Process incoming IP6 packets
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer source address
 *
 * This function processes a IPv6 packet
 */
static int ipv6_rx ( struct io_buffer *iobuf,
		     __unused struct net_device *netdev,
		     __unused const void *ll_dest,
		     __unused const void *ll_source ) {

	struct ip6_header *ip6hdr = iobuf->data;
	union {
		struct sockaddr_in6 sin6;
		struct sockaddr_tcpip st;
	} src, dest;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *ip6hdr ) ) {
		DBG ( "Packet too short (%zd bytes)\n", iob_len ( iobuf ) );
		goto drop;
	}

	/* TODO: Verify checksum */

	/* Print IP6 header for debugging */
	ipv6_dump ( ip6hdr );

	/* Check header version */
	if ( ( ip6hdr->ver_traffic_class_flow_label & 0xf0000000 ) != 0x60000000 ) {
		DBG ( "Invalid protocol version\n" );
		goto drop;
	}

	/* Check the payload length */
	if ( ntohs ( ip6hdr->payload_len ) > iob_len ( iobuf ) ) {
		DBG ( "Inconsistent packet length (%d bytes)\n",
			ip6hdr->payload_len );
		goto drop;
	}

	/* Ignore the traffic class and flow control values */

	/* Construct socket address */
	memset ( &src, 0, sizeof ( src ) );
	src.sin6.sin_family = AF_INET6;
	src.sin6.sin6_addr = ip6hdr->src;
	memset ( &dest, 0, sizeof ( dest ) );
	dest.sin6.sin_family = AF_INET6;
	dest.sin6.sin6_addr = ip6hdr->dest;

	/* Strip header */
	iob_unput ( iobuf, iob_len ( iobuf ) - ntohs ( ip6hdr->payload_len ) -
							sizeof ( *ip6hdr ) );
	iob_pull ( iobuf, sizeof ( *ip6hdr ) );

	/* Send it to the transport layer */
	return ipv6_process_nxt_hdr ( iobuf, ip6hdr->nxt_hdr, &src.st, &dest.st );

  drop:
	DBG ( "Packet dropped\n" );
	free_iob ( iobuf );
	return -1;
}

/**
 * Print a IP6 address as xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
 */
char * inet6_ntoa ( struct in6_addr in6 ) {
	static char buf[40];
	uint16_t *bytes = ( uint16_t* ) &in6;
	sprintf ( buf, "%x:%x:%x:%x:%x:%x:%x:%x", bytes[0], bytes[1], bytes[2],
			bytes[3], bytes[4], bytes[5], bytes[6], bytes[7] );
	return buf;
}

static const char * ipv6_ntoa ( const void *net_addr ) {
	return inet6_ntoa ( * ( ( struct in6_addr * ) net_addr ) );
}

/** IPv6 protocol */
struct net_protocol ipv6_protocol __net_protocol = {
	.name = "IPv6",
	.net_proto = htons ( ETH_P_IPV6 ),
	.net_addr_len = sizeof ( struct in6_addr ),
	.rx = ipv6_rx,
	.ntoa = ipv6_ntoa,
};

/** IPv6 TCPIP net protocol */
struct tcpip_net_protocol ipv6_tcpip_protocol __tcpip_net_protocol = {
	.name = "IPv6",
	.sa_family = AF_INET6,
	.tx = ipv6_tx,
};
