#ifndef _IPXE_ETHERNET_H
#define _IPXE_ETHERNET_H

/** @file
 *
 * Ethernet protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>

/**
 * Check if Ethernet address is all zeroes
 *
 * @v addr		Ethernet address
 * @ret is_zero		Address is all zeroes
 */
static inline int is_zero_ether_addr ( const void *addr ) {
	const uint8_t *addr_bytes = addr;

	return ( ! ( addr_bytes[0] | addr_bytes[1] | addr_bytes[2] |
		     addr_bytes[3] | addr_bytes[4] | addr_bytes[5] ) );
}

/**
 * Check if Ethernet address is a multicast address
 *
 * @v addr		Ethernet address
 * @ret is_mcast	Address is a multicast address
 *
 * Note that the broadcast address is also a multicast address.
 */
static inline int is_multicast_ether_addr ( const void *addr ) {
	const uint8_t *addr_bytes = addr;

	return ( addr_bytes[0] & 0x01 );
}

/**
 * Check if Ethernet address is locally assigned
 *
 * @v addr		Ethernet address
 * @ret is_local	Address is locally assigned
 */
static inline int is_local_ether_addr ( const void *addr ) {
	const uint8_t *addr_bytes = addr;

	return ( addr_bytes[0] & 0x02 );
}

/**
 * Check if Ethernet address is the broadcast address
 *
 * @v addr		Ethernet address
 * @ret is_bcast	Address is the broadcast address
 */
static inline int is_broadcast_ether_addr ( const void *addr ) {
	const uint8_t *addr_bytes = addr;

	return ( ( addr_bytes[0] & addr_bytes[1] & addr_bytes[2] &
		   addr_bytes[3] & addr_bytes[4] & addr_bytes[5] ) == 0xff );
}

/**
 * Check if Ethernet address is valid
 *
 * @v addr		Ethernet address
 * @ret is_valid	Address is valid
 *
 * Check that the Ethernet address (MAC) is not 00:00:00:00:00:00, is
 * not a multicast address, and is not ff:ff:ff:ff:ff:ff.
 */
static inline int is_valid_ether_addr ( const void *addr ) {
	return ( ( ! is_multicast_ether_addr ( addr ) ) &&
		 ( ! is_zero_ether_addr ( addr ) ) );
}

extern void eth_init_addr ( const void *hw_addr, void *ll_addr );
extern const char * eth_ntoa ( const void *ll_addr );
extern int eth_mc_hash ( unsigned int af, const void *net_addr,
			 void *ll_addr );
extern int eth_eth_addr ( const void *ll_addr, void *eth_addr );
extern struct net_device * alloc_etherdev ( size_t priv_size );

#endif /* _IPXE_ETHERNET_H */
