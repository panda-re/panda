#ifndef _IPXE_IP6_H
#define _IPXE_IP6_H

/** @file
 *
 * IP6 protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <ipxe/in.h>
#include <ipxe/netdevice.h>
#include <ipxe/tcpip.h>

/* IP6 constants */

#define IP6_VERSION	0x6
#define IP6_HOP_LIMIT	255

/**
 * I/O buffer contents
 * This is duplicated in tcp.h and here. Ideally it should go into iobuf.h
 */
#define MAX_HDR_LEN	100
#define MAX_IOB_LEN	1500
#define MIN_IOB_LEN	MAX_HDR_LEN + 100 /* To account for padding by LL */

#define IP6_EQUAL( in6_addr1, in6_addr2 ) \
        ( memcmp ( ( char* ) &( in6_addr1 ), ( char* ) &( in6_addr2 ),\
	sizeof ( struct in6_addr ) ) == 0 )

#define IS_UNSPECIFIED( addr ) \
	( ( (addr).in6_u.u6_addr32[0] == 0x00000000 ) && \
	( (addr).in6_u.u6_addr32[1] == 0x00000000 ) && \
	( (addr).in6_u.u6_addr32[2] == 0x00000000 ) && \
	( (addr).in6_u.u6_addr32[3] == 0x00000000 ) )
/* IP6 header */
struct ip6_header {
	uint32_t 	ver_traffic_class_flow_label;
	uint16_t 	payload_len;
	uint8_t 	nxt_hdr;
	uint8_t 	hop_limit;
	struct in6_addr src;
	struct in6_addr dest;
};

/* IP6 pseudo header */
struct ipv6_pseudo_header {
	struct in6_addr src;
	struct in6_addr dest;
	uint8_t zero_padding;
	uint8_t nxt_hdr;
	uint16_t len;
};

/* Next header numbers */
#define IP6_HOPBYHOP 		0x00
#define IP6_ROUTING 		0x43
#define IP6_FRAGMENT		0x44
#define IP6_AUTHENTICATION	0x51
#define IP6_DEST_OPTS		0x60
#define IP6_ESP			0x50
#define IP6_ICMP6		0x58
#define IP6_NO_HEADER		0x59

struct io_buffer;

extern struct net_protocol ipv6_protocol __net_protocol;
extern struct tcpip_net_protocol ipv6_tcpip_protocol __tcpip_net_protocol;
extern char * inet6_ntoa ( struct in6_addr in6 );

extern int add_ipv6_address ( struct net_device *netdev,
			      struct in6_addr prefix, int prefix_len,
			      struct in6_addr address,
			      struct in6_addr gateway );
extern void del_ipv6_address ( struct net_device *netdev );

#endif /* _IPXE_IP6_H */
