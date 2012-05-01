#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/in.h>
#include <ipxe/ip6.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/ndp.h>
#include <ipxe/icmp6.h>
#include <ipxe/tcpip.h>
#include <ipxe/netdevice.h>

/**
 * Send neighbour solicitation packet
 *
 * @v netdev	Network device
 * @v src	Source address
 * @v dest	Destination address
 *
 * This function prepares a neighbour solicitation packet and sends it to the
 * network layer.
 */
int icmp6_send_solicit ( struct net_device *netdev, struct in6_addr *src __unused,
			 struct in6_addr *dest ) {
	union {
		struct sockaddr_in6 sin6;
		struct sockaddr_tcpip st;
	} st_dest;
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	struct neighbour_solicit *nsolicit;
	struct io_buffer *iobuf = alloc_iob ( sizeof ( *nsolicit ) + MIN_IOB_LEN );
	iob_reserve ( iobuf, MAX_HDR_LEN );
	nsolicit = iob_put ( iobuf, sizeof ( *nsolicit ) );

	/* Fill up the headers */
	memset ( nsolicit, 0, sizeof ( *nsolicit ) );
	nsolicit->type = ICMP6_NSOLICIT;
	nsolicit->code = 0;
	nsolicit->target = *dest;
	nsolicit->opt_type = 1;
	nsolicit->opt_len = ( 2 + ll_protocol->ll_addr_len ) / 8;
	memcpy ( nsolicit->opt_ll_addr, netdev->ll_addr,
				netdev->ll_protocol->ll_addr_len );
	/* Partial checksum */
	nsolicit->csum = 0;
	nsolicit->csum = tcpip_chksum ( nsolicit, sizeof ( *nsolicit ) );

	/* Solicited multicast address */
	st_dest.sin6.sin_family = AF_INET6;
	st_dest.sin6.sin6_addr.in6_u.u6_addr8[0] = 0xff;
	st_dest.sin6.sin6_addr.in6_u.u6_addr8[2] = 0x02;
	st_dest.sin6.sin6_addr.in6_u.u6_addr16[1] = 0x0000;
	st_dest.sin6.sin6_addr.in6_u.u6_addr32[1] = 0x00000000;
	st_dest.sin6.sin6_addr.in6_u.u6_addr16[4] = 0x0000;
	st_dest.sin6.sin6_addr.in6_u.u6_addr16[5] = 0x0001;
	st_dest.sin6.sin6_addr.in6_u.u6_addr32[3] = dest->in6_u.u6_addr32[3];
	st_dest.sin6.sin6_addr.in6_u.u6_addr8[13] = 0xff;
	
	/* Send packet over IP6 */
	return tcpip_tx ( iobuf, &icmp6_protocol, NULL, &st_dest.st,
			  NULL, &nsolicit->csum );
}

/**
 * Process ICMP6 headers
 *
 * @v iobuf	I/O buffer
 * @v st_src	Source address
 * @v st_dest	Destination address
 */
static int icmp6_rx ( struct io_buffer *iobuf, struct sockaddr_tcpip *st_src,
		      struct sockaddr_tcpip *st_dest, __unused uint16_t pshdr_csum ) {
	struct icmp6_header *icmp6hdr = iobuf->data;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *icmp6hdr ) ) {
		DBG ( "Packet too short (%zd bytes)\n", iob_len ( iobuf ) );
		free_iob ( iobuf );
		return -EINVAL;
	}

	/* TODO: Verify checksum */

	/* Process the ICMP header */
	switch ( icmp6hdr->type ) {
	case ICMP6_NADVERT:
		return ndp_process_advert ( iobuf, st_src, st_dest );
	}
	return -ENOSYS;
}

#if 0
void icmp6_test_nadvert (struct net_device *netdev, struct sockaddr_in6 *server_p, char *ll_addr) {

		struct sockaddr_in6 server;
		memcpy ( &server, server_p, sizeof ( server ) );
                struct io_buffer *rxiobuf = alloc_iob ( 500 );
                iob_reserve ( rxiobuf, MAX_HDR_LEN );
                struct neighbour_advert *nadvert = iob_put ( rxiobuf, sizeof ( *nadvert ) );
                nadvert->type = 136;
                nadvert->code = 0;
                nadvert->flags = ICMP6_FLAGS_SOLICITED;
		nadvert->csum = 0xffff;
		nadvert->target = server.sin6_addr;
                nadvert->opt_type = 2;
                nadvert->opt_len = 1;
                memcpy ( nadvert->opt_ll_addr, ll_addr, 6 );
                struct ip6_header *ip6hdr = iob_push ( rxiobuf, sizeof ( *ip6hdr ) );
                ip6hdr->ver_traffic_class_flow_label = htonl ( 0x60000000 );
		ip6hdr->hop_limit = 255;
		ip6hdr->nxt_hdr = 58;
		ip6hdr->payload_len = htons ( sizeof ( *nadvert ) );
                ip6hdr->src = server.sin6_addr;
                ip6hdr->dest = server.sin6_addr;
		hex_dump ( rxiobuf->data, iob_len ( rxiobuf ) );
                net_rx ( rxiobuf, netdev, htons ( ETH_P_IPV6 ), ll_addr );
}
#endif

/** ICMP6 protocol */
struct tcpip_protocol icmp6_protocol __tcpip_protocol = {
	.name = "ICMP6",
	.rx = icmp6_rx,
	.tcpip_proto = IP_ICMP6, // 58
};
