#ifndef _IPXE_IPOIB_H
#define _IPXE_IPOIB_H

/** @file
 *
 * IP over Infiniband
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/infiniband.h>

/** IPoIB MAC address length */
#define IPOIB_ALEN 20

/** An IPoIB MAC address */
struct ipoib_mac {
	/** Queue pair number
	 *
	 * MSB indicates support for IPoIB "connected mode".  Lower 24
	 * bits are the QPN.
	 */
	uint32_t flags__qpn;
	/** Port GID */
	union ib_gid gid;
} __attribute__ (( packed ));

/** IPoIB link-layer header length */
#define IPOIB_HLEN 4

/** IPoIB link-layer header */
struct ipoib_hdr {
	/** Network-layer protocol */
	uint16_t proto;
	/** Reserved, must be zero */
	union {
		/** Reserved, must be zero */
		uint16_t reserved;
		/** Peer addresses
		 *
		 * We use these fields internally to represent the
		 * peer addresses using a lookup key.  There simply
		 * isn't enough room in the IPoIB header to store
		 * literal source or destination MAC addresses.
		 */
		struct {
			/** Destination address key */
			uint8_t dest;
			/** Source address key */
			uint8_t src;
		} __attribute__ (( packed )) peer;
	} __attribute__ (( packed )) u;
} __attribute__ (( packed ));

extern const char * ipoib_ntoa ( const void *ll_addr );
extern struct net_device * alloc_ipoibdev ( size_t priv_size );

#endif /* _IPXE_IPOIB_H */
