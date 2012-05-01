#ifndef _IPXE_ICMP6_H
#define _IPXE_ICMP6_H

/** @file
 *
 * ICMP6 protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/ip6.h>
#include <ipxe/ndp.h>

#define ICMP6_NSOLICIT 135
#define ICMP6_NADVERT 136

extern struct tcpip_protocol icmp6_protocol __tcpip_protocol;

struct icmp6_header {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	/* Message body */
};

struct neighbour_solicit {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	uint32_t reserved;
	struct in6_addr target;
	/* "Compulsory" options */
	uint8_t opt_type;
	uint8_t opt_len;
  /* FIXME:  hack alert */
	uint8_t opt_ll_addr[6];
};

struct neighbour_advert {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	uint8_t flags;
	uint8_t reserved;
	struct in6_addr target;
	uint8_t opt_type;
	uint8_t opt_len;
  /* FIXME:  hack alert */
	uint8_t opt_ll_addr[6];
};

#define ICMP6_FLAGS_ROUTER 0x80
#define ICMP6_FLAGS_SOLICITED 0x40
#define ICMP6_FLAGS_OVERRIDE 0x20

int icmp6_send_solicit ( struct net_device *netdev, struct in6_addr *src, struct in6_addr *dest );

#endif /* _IPXE_ICMP6_H */
