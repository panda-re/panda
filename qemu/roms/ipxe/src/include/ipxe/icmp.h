#ifndef _IPXE_ICMP_H
#define _IPXE_ICMP_H

/** @file
 *
 * ICMP protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

/** An ICMP header */
struct icmp_header {
	/** Type */
	uint8_t type;
	/** Code */
	uint8_t code;
	/** Checksum */
	uint16_t chksum;
} __attribute__ (( packed ));

#define ICMP_ECHO_RESPONSE 0
#define ICMP_ECHO_REQUEST 8

#endif /* _IPXE_ICMP_H */
