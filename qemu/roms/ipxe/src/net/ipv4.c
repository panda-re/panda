#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/list.h>
#include <ipxe/in.h>
#include <ipxe/arp.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/ip.h>
#include <ipxe/tcpip.h>
#include <ipxe/dhcp.h>
#include <ipxe/settings.h>

/** @file
 *
 * IPv4 protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

/* Unique IP datagram identification number */
static uint16_t next_ident = 0;

/** List of IPv4 miniroutes */
struct list_head ipv4_miniroutes = LIST_HEAD_INIT ( ipv4_miniroutes );

/** List of fragment reassembly buffers */
static LIST_HEAD ( frag_buffers );

/**
 * Add IPv4 minirouting table entry
 *
 * @v netdev		Network device
 * @v address		IPv4 address
 * @v netmask		Subnet mask
 * @v gateway		Gateway address (if any)
 * @ret miniroute	Routing table entry, or NULL
 */
static struct ipv4_miniroute * __malloc
add_ipv4_miniroute ( struct net_device *netdev, struct in_addr address,
		     struct in_addr netmask, struct in_addr gateway ) {
	struct ipv4_miniroute *miniroute;

	DBG ( "IPv4 add %s", inet_ntoa ( address ) );
	DBG ( "/%s ", inet_ntoa ( netmask ) );
	if ( gateway.s_addr )
		DBG ( "gw %s ", inet_ntoa ( gateway ) );
	DBG ( "via %s\n", netdev->name );

	/* Allocate and populate miniroute structure */
	miniroute = malloc ( sizeof ( *miniroute ) );
	if ( ! miniroute ) {
		DBG ( "IPv4 could not add miniroute\n" );
		return NULL;
	}

	/* Record routing information */
	miniroute->netdev = netdev_get ( netdev );
	miniroute->address = address;
	miniroute->netmask = netmask;
	miniroute->gateway = gateway;
		
	/* Add to end of list if we have a gateway, otherwise
	 * to start of list.
	 */
	if ( gateway.s_addr ) {
		list_add_tail ( &miniroute->list, &ipv4_miniroutes );
	} else {
		list_add ( &miniroute->list, &ipv4_miniroutes );
	}

	return miniroute;
}

/**
 * Delete IPv4 minirouting table entry
 *
 * @v miniroute		Routing table entry
 */
static void del_ipv4_miniroute ( struct ipv4_miniroute *miniroute ) {

	DBG ( "IPv4 del %s", inet_ntoa ( miniroute->address ) );
	DBG ( "/%s ", inet_ntoa ( miniroute->netmask ) );
	if ( miniroute->gateway.s_addr )
		DBG ( "gw %s ", inet_ntoa ( miniroute->gateway ) );
	DBG ( "via %s\n", miniroute->netdev->name );

	netdev_put ( miniroute->netdev );
	list_del ( &miniroute->list );
	free ( miniroute );
}

/**
 * Perform IPv4 routing
 *
 * @v dest		Final destination address
 * @ret dest		Next hop destination address
 * @ret miniroute	Routing table entry to use, or NULL if no route
 *
 * If the route requires use of a gateway, the next hop destination
 * address will be overwritten with the gateway address.
 */
static struct ipv4_miniroute * ipv4_route ( struct in_addr *dest ) {
	struct ipv4_miniroute *miniroute;
	int local;
	int has_gw;

	/* Never attempt to route the broadcast address */
	if ( dest->s_addr == INADDR_BROADCAST )
		return NULL;

	/* Find first usable route in routing table */
	list_for_each_entry ( miniroute, &ipv4_miniroutes, list ) {
		if ( ! netdev_is_open ( miniroute->netdev ) )
			continue;
		local = ( ( ( dest->s_addr ^ miniroute->address.s_addr )
			    & miniroute->netmask.s_addr ) == 0 );
		has_gw = ( miniroute->gateway.s_addr );
		if ( local || has_gw ) {
			if ( ! local )
				*dest = miniroute->gateway;
			return miniroute;
		}
	}

	return NULL;
}

/**
 * Fragment reassembly counter timeout
 *
 * @v timer	Retry timer
 * @v over	If asserted, the timer is greater than @c MAX_TIMEOUT 
 */
static void ipv4_frag_expired ( struct retry_timer *timer __unused,
				int over ) {
	if ( over ) {
		DBG ( "Fragment reassembly timeout" );
		/* Free the fragment buffer */
	}
}

/**
 * Free fragment buffer
 *
 * @v fragbug	Fragment buffer
 */
static void free_fragbuf ( struct frag_buffer *fragbuf ) {
	free ( fragbuf );
}

/**
 * Fragment reassembler
 *
 * @v iobuf		I/O buffer, fragment of the datagram
 * @ret frag_iob	Reassembled packet, or NULL
 */
static struct io_buffer * ipv4_reassemble ( struct io_buffer * iobuf ) {
	struct iphdr *iphdr = iobuf->data;
	struct frag_buffer *fragbuf;
	
	/**
	 * Check if the fragment belongs to any fragment series
	 */
	list_for_each_entry ( fragbuf, &frag_buffers, list ) {
		if ( fragbuf->ident == iphdr->ident &&
		     fragbuf->src.s_addr == iphdr->src.s_addr ) {
			/**
			 * Check if the packet is the expected fragment
			 * 
			 * The offset of the new packet must be equal to the
			 * length of the data accumulated so far (the length of
			 * the reassembled I/O buffer
			 */
			if ( iob_len ( fragbuf->frag_iob ) == 
			      ( iphdr->frags & IP_MASK_OFFSET ) ) {
				/**
				 * Append the contents of the fragment to the
				 * reassembled I/O buffer
				 */
				iob_pull ( iobuf, sizeof ( *iphdr ) );
				memcpy ( iob_put ( fragbuf->frag_iob,
							iob_len ( iobuf ) ),
					 iobuf->data, iob_len ( iobuf ) );
				free_iob ( iobuf );

				/** Check if the fragment series is over */
				if ( ! ( iphdr->frags & IP_MASK_MOREFRAGS ) ) {
					iobuf = fragbuf->frag_iob;
					free_fragbuf ( fragbuf );
					return iobuf;
				}

			} else {
				/* Discard the fragment series */
				free_fragbuf ( fragbuf );
				free_iob ( iobuf );
			}
			return NULL;
		}
	}
	
	/** Check if the fragment is the first in the fragment series */
	if ( iphdr->frags & IP_MASK_MOREFRAGS &&
			( ( iphdr->frags & IP_MASK_OFFSET ) == 0 ) ) {
	
		/** Create a new fragment buffer */
		fragbuf = ( struct frag_buffer* ) malloc ( sizeof( *fragbuf ) );
		fragbuf->ident = iphdr->ident;
		fragbuf->src = iphdr->src;

		/* Set up the reassembly I/O buffer */
		fragbuf->frag_iob = alloc_iob ( IP_FRAG_IOB_SIZE );
		iob_pull ( iobuf, sizeof ( *iphdr ) );
		memcpy ( iob_put ( fragbuf->frag_iob, iob_len ( iobuf ) ),
			 iobuf->data, iob_len ( iobuf ) );
		free_iob ( iobuf );

		/* Set the reassembly timer */
		timer_init ( &fragbuf->frag_timer, ipv4_frag_expired, NULL );
		start_timer_fixed ( &fragbuf->frag_timer, IP_FRAG_TIMEOUT );

		/* Add the fragment buffer to the list of fragment buffers */
		list_add ( &fragbuf->list, &frag_buffers );
	}
	
	return NULL;
}

/**
 * Add IPv4 pseudo-header checksum to existing checksum
 *
 * @v iobuf		I/O buffer
 * @v csum		Existing checksum
 * @ret csum		Updated checksum
 */
static uint16_t ipv4_pshdr_chksum ( struct io_buffer *iobuf, uint16_t csum ) {
	struct ipv4_pseudo_header pshdr;
	struct iphdr *iphdr = iobuf->data;
	size_t hdrlen = ( ( iphdr->verhdrlen & IP_MASK_HLEN ) * 4 );

	/* Build pseudo-header */
	pshdr.src = iphdr->src;
	pshdr.dest = iphdr->dest;
	pshdr.zero_padding = 0x00;
	pshdr.protocol = iphdr->protocol;
	pshdr.len = htons ( iob_len ( iobuf ) - hdrlen );

	/* Update the checksum value */
	return tcpip_continue_chksum ( csum, &pshdr, sizeof ( pshdr ) );
}

/**
 * Determine link-layer address
 *
 * @v dest		IPv4 destination address
 * @v src		IPv4 source address
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address buffer
 * @ret rc		Return status code
 */
static int ipv4_ll_addr ( struct in_addr dest, struct in_addr src,
			  struct net_device *netdev, uint8_t *ll_dest ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;

	if ( dest.s_addr == INADDR_BROADCAST ) {
		/* Broadcast address */
		memcpy ( ll_dest, netdev->ll_broadcast,
			 ll_protocol->ll_addr_len );
		return 0;
	} else if ( IN_MULTICAST ( ntohl ( dest.s_addr ) ) ) {
		return ll_protocol->mc_hash ( AF_INET, &dest, ll_dest );
	} else {
		/* Unicast address: resolve via ARP */
		return arp_resolve ( netdev, &ipv4_protocol, &dest,
				     &src, ll_dest );
	}
}

/**
 * Transmit IP packet
 *
 * @v iobuf		I/O buffer
 * @v tcpip		Transport-layer protocol
 * @v st_src		Source network-layer address
 * @v st_dest		Destination network-layer address
 * @v netdev		Network device to use if no route found, or NULL
 * @v trans_csum	Transport-layer checksum to complete, or NULL
 * @ret rc		Status
 *
 * This function expects a transport-layer segment and prepends the IP header
 */
static int ipv4_tx ( struct io_buffer *iobuf,
		     struct tcpip_protocol *tcpip_protocol,
		     struct sockaddr_tcpip *st_src,
		     struct sockaddr_tcpip *st_dest,
		     struct net_device *netdev,
		     uint16_t *trans_csum ) {
	struct iphdr *iphdr = iob_push ( iobuf, sizeof ( *iphdr ) );
	struct sockaddr_in *sin_src = ( ( struct sockaddr_in * ) st_src );
	struct sockaddr_in *sin_dest = ( ( struct sockaddr_in * ) st_dest );
	struct ipv4_miniroute *miniroute;
	struct in_addr next_hop;
	uint8_t ll_dest[MAX_LL_ADDR_LEN];
	int rc;

	/* Fill up the IP header, except source address */
	memset ( iphdr, 0, sizeof ( *iphdr ) );
	iphdr->verhdrlen = ( IP_VER | ( sizeof ( *iphdr ) / 4 ) );
	iphdr->service = IP_TOS;
	iphdr->len = htons ( iob_len ( iobuf ) );	
	iphdr->ident = htons ( ++next_ident );
	iphdr->ttl = IP_TTL;
	iphdr->protocol = tcpip_protocol->tcpip_proto;
	iphdr->dest = sin_dest->sin_addr;

	/* Use routing table to identify next hop and transmitting netdev */
	next_hop = iphdr->dest;
	if ( sin_src )
		iphdr->src = sin_src->sin_addr;
	if ( ( next_hop.s_addr != INADDR_BROADCAST ) &&
	     ( ! IN_MULTICAST ( ntohl ( next_hop.s_addr ) ) ) &&
	     ( ( miniroute = ipv4_route ( &next_hop ) ) != NULL ) ) {
		iphdr->src = miniroute->address;
		netdev = miniroute->netdev;
	}
	if ( ! netdev ) {
		DBG ( "IPv4 has no route to %s\n", inet_ntoa ( iphdr->dest ) );
		rc = -ENETUNREACH;
		goto err;
	}

	/* Determine link-layer destination address */
	if ( ( rc = ipv4_ll_addr ( next_hop, iphdr->src, netdev,
				   ll_dest ) ) != 0 ) {
		DBG ( "IPv4 has no link-layer address for %s: %s\n",
		      inet_ntoa ( next_hop ), strerror ( rc ) );
		goto err;
	}

	/* Fix up checksums */
	if ( trans_csum )
		*trans_csum = ipv4_pshdr_chksum ( iobuf, *trans_csum );
	iphdr->chksum = tcpip_chksum ( iphdr, sizeof ( *iphdr ) );

	/* Print IP4 header for debugging */
	DBG ( "IPv4 TX %s->", inet_ntoa ( iphdr->src ) );
	DBG ( "%s len %d proto %d id %04x csum %04x\n",
	      inet_ntoa ( iphdr->dest ), ntohs ( iphdr->len ), iphdr->protocol,
	      ntohs ( iphdr->ident ), ntohs ( iphdr->chksum ) );

	/* Hand off to link layer */
	if ( ( rc = net_tx ( iobuf, netdev, &ipv4_protocol, ll_dest,
			     netdev->ll_addr ) ) != 0 ) {
		DBG ( "IPv4 could not transmit packet via %s: %s\n",
		      netdev->name, strerror ( rc ) );
		return rc;
	}

	return 0;

 err:
	free_iob ( iobuf );
	return rc;
}

/**
 * Process incoming packets
 *
 * @v iobuf	I/O buffer
 * @v netdev	Network device
 * @v ll_dest	Link-layer destination address
 * @v ll_source	Link-layer destination source
 *
 * This function expects an IP4 network datagram. It processes the headers 
 * and sends it to the transport layer.
 */
static int ipv4_rx ( struct io_buffer *iobuf,
		     struct net_device *netdev __unused,
		     const void *ll_dest __unused,
		     const void *ll_source __unused ) {
	struct iphdr *iphdr = iobuf->data;
	size_t hdrlen;
	size_t len;
	union {
		struct sockaddr_in sin;
		struct sockaddr_tcpip st;
	} src, dest;
	uint16_t csum;
	uint16_t pshdr_csum;
	int rc;

	/* Sanity check the IPv4 header */
	if ( iob_len ( iobuf ) < sizeof ( *iphdr ) ) {
		DBG ( "IPv4 packet too short at %zd bytes (min %zd bytes)\n",
		      iob_len ( iobuf ), sizeof ( *iphdr ) );
		goto err;
	}
	if ( ( iphdr->verhdrlen & IP_MASK_VER ) != IP_VER ) {
		DBG ( "IPv4 version %#02x not supported\n", iphdr->verhdrlen );
		goto err;
	}
	hdrlen = ( ( iphdr->verhdrlen & IP_MASK_HLEN ) * 4 );
	if ( hdrlen < sizeof ( *iphdr ) ) {
		DBG ( "IPv4 header too short at %zd bytes (min %zd bytes)\n",
		      hdrlen, sizeof ( *iphdr ) );
		goto err;
	}
	if ( hdrlen > iob_len ( iobuf ) ) {
		DBG ( "IPv4 header too long at %zd bytes "
		      "(packet is %zd bytes)\n", hdrlen, iob_len ( iobuf ) );
		goto err;
	}
	if ( ( csum = tcpip_chksum ( iphdr, hdrlen ) ) != 0 ) {
		DBG ( "IPv4 checksum incorrect (is %04x including checksum "
		      "field, should be 0000)\n", csum );
		goto err;
	}
	len = ntohs ( iphdr->len );
	if ( len < hdrlen ) {
		DBG ( "IPv4 length too short at %zd bytes "
		      "(header is %zd bytes)\n", len, hdrlen );
		goto err;
	}
	if ( len > iob_len ( iobuf ) ) {
		DBG ( "IPv4 length too long at %zd bytes "
		      "(packet is %zd bytes)\n", len, iob_len ( iobuf ) );
		goto err;
	}

	/* Print IPv4 header for debugging */
	DBG ( "IPv4 RX %s<-", inet_ntoa ( iphdr->dest ) );
	DBG ( "%s len %d proto %d id %04x csum %04x\n",
	      inet_ntoa ( iphdr->src ), ntohs ( iphdr->len ), iphdr->protocol,
	      ntohs ( iphdr->ident ), ntohs ( iphdr->chksum ) );

	/* Truncate packet to correct length, calculate pseudo-header
	 * checksum and then strip off the IPv4 header.
	 */
	iob_unput ( iobuf, ( iob_len ( iobuf ) - len ) );
	pshdr_csum = ipv4_pshdr_chksum ( iobuf, TCPIP_EMPTY_CSUM );
	iob_pull ( iobuf, hdrlen );

	/* Fragment reassembly */
	if ( ( iphdr->frags & htons ( IP_MASK_MOREFRAGS ) ) || 
	     ( ( iphdr->frags & htons ( IP_MASK_OFFSET ) ) != 0 ) ) {
		/* Pass the fragment to ipv4_reassemble() which either
		 * returns a fully reassembled I/O buffer or NULL.
		 */
		iobuf = ipv4_reassemble ( iobuf );
		if ( ! iobuf )
			return 0;
	}

	/* Construct socket addresses and hand off to transport layer */
	memset ( &src, 0, sizeof ( src ) );
	src.sin.sin_family = AF_INET;
	src.sin.sin_addr = iphdr->src;
	memset ( &dest, 0, sizeof ( dest ) );
	dest.sin.sin_family = AF_INET;
	dest.sin.sin_addr = iphdr->dest;
	if ( ( rc = tcpip_rx ( iobuf, iphdr->protocol, &src.st,
			       &dest.st, pshdr_csum ) ) != 0 ) {
		DBG ( "IPv4 received packet rejected by stack: %s\n",
		      strerror ( rc ) );
		return rc;
	}

	return 0;

 err:
	free_iob ( iobuf );
	return -EINVAL;
}

/** 
 * Check existence of IPv4 address for ARP
 *
 * @v netdev		Network device
 * @v net_addr		Network-layer address
 * @ret rc		Return status code
 */
static int ipv4_arp_check ( struct net_device *netdev, const void *net_addr ) {
	const struct in_addr *address = net_addr;
	struct ipv4_miniroute *miniroute;

	list_for_each_entry ( miniroute, &ipv4_miniroutes, list ) {
		if ( ( miniroute->netdev == netdev ) &&
		     ( miniroute->address.s_addr == address->s_addr ) ) {
			/* Found matching address */
			return 0;
		}
	}
	return -ENOENT;
}

/**
 * Convert IPv4 address to dotted-quad notation
 *
 * @v in	IP address
 * @ret string	IP address in dotted-quad notation
 */
char * inet_ntoa ( struct in_addr in ) {
	static char buf[16]; /* "xxx.xxx.xxx.xxx" */
	uint8_t *bytes = ( uint8_t * ) &in;
	
	sprintf ( buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3] );
	return buf;
}

/**
 * Transcribe IP address
 *
 * @v net_addr	IP address
 * @ret string	IP address in dotted-quad notation
 *
 */
static const char * ipv4_ntoa ( const void *net_addr ) {
	return inet_ntoa ( * ( ( struct in_addr * ) net_addr ) );
}

/** IPv4 protocol */
struct net_protocol ipv4_protocol __net_protocol = {
	.name = "IP",
	.net_proto = htons ( ETH_P_IP ),
	.net_addr_len = sizeof ( struct in_addr ),
	.rx = ipv4_rx,
	.ntoa = ipv4_ntoa,
};

/** IPv4 TCPIP net protocol */
struct tcpip_net_protocol ipv4_tcpip_protocol __tcpip_net_protocol = {
	.name = "IPv4",
	.sa_family = AF_INET,
	.tx = ipv4_tx,
};

/** IPv4 ARP protocol */
struct arp_net_protocol ipv4_arp_protocol __arp_net_protocol = {
	.net_protocol = &ipv4_protocol,
	.check = ipv4_arp_check,
};

/******************************************************************************
 *
 * Settings
 *
 ******************************************************************************
 */

/** IPv4 address setting */
struct setting ip_setting __setting ( SETTING_IPv4 ) = {
	.name = "ip",
	.description = "IP address",
	.tag = DHCP_EB_YIADDR,
	.type = &setting_type_ipv4,
};

/** IPv4 subnet mask setting */
struct setting netmask_setting __setting ( SETTING_IPv4 ) = {
	.name = "netmask",
	.description = "Subnet mask",
	.tag = DHCP_SUBNET_MASK,
	.type = &setting_type_ipv4,
};

/** Default gateway setting */
struct setting gateway_setting __setting ( SETTING_IPv4 ) = {
	.name = "gateway",
	.description = "Default gateway",
	.tag = DHCP_ROUTERS,
	.type = &setting_type_ipv4,
};

/**
 * Create IPv4 routing table based on configured settings
 *
 * @ret rc		Return status code
 */
static int ipv4_create_routes ( void ) {
	struct ipv4_miniroute *miniroute;
	struct ipv4_miniroute *tmp;
	struct net_device *netdev;
	struct settings *settings;
	struct in_addr address = { 0 };
	struct in_addr netmask = { 0 };
	struct in_addr gateway = { 0 };

	/* Delete all existing routes */
	list_for_each_entry_safe ( miniroute, tmp, &ipv4_miniroutes, list )
		del_ipv4_miniroute ( miniroute );

	/* Create a route for each configured network device */
	for_each_netdev ( netdev ) {
		settings = netdev_settings ( netdev );
		/* Get IPv4 address */
		address.s_addr = 0;
		fetch_ipv4_setting ( settings, &ip_setting, &address );
		if ( ! address.s_addr )
			continue;
		/* Get subnet mask */
		fetch_ipv4_setting ( settings, &netmask_setting, &netmask );
		/* Calculate default netmask, if necessary */
		if ( ! netmask.s_addr ) {
			if ( IN_CLASSA ( ntohl ( address.s_addr ) ) ) {
				netmask.s_addr = htonl ( IN_CLASSA_NET );
			} else if ( IN_CLASSB ( ntohl ( address.s_addr ) ) ) {
				netmask.s_addr = htonl ( IN_CLASSB_NET );
			} else if ( IN_CLASSC ( ntohl ( address.s_addr ) ) ) {
				netmask.s_addr = htonl ( IN_CLASSC_NET );
			}
		}
		/* Get default gateway, if present */
		fetch_ipv4_setting ( settings, &gateway_setting, &gateway );
		/* Configure route */
		miniroute = add_ipv4_miniroute ( netdev, address,
						 netmask, gateway );
		if ( ! miniroute )
			return -ENOMEM;
	}

	return 0;
}

/** IPv4 settings applicator */
struct settings_applicator ipv4_settings_applicator __settings_applicator = {
	.apply = ipv4_create_routes,
};

/* Drag in ICMP */
REQUIRE_OBJECT ( icmp );
