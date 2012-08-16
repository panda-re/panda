#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/ndp.h>
#include <ipxe/icmp6.h>
#include <ipxe/ip6.h>
#include <ipxe/netdevice.h>

/** @file
 *
 * Neighbour Discovery Protocol
 *
 * This file implements address resolution as specified by the neighbour
 * discovery protocol in RFC2461. This protocol is part of the IPv6 protocol
 * family.
 */

/* A neighbour entry */
struct ndp_entry {
	/** Target IP6 address */
	struct in6_addr in6;
	/** Link layer protocol */
	struct ll_protocol *ll_protocol;
	/** Link-layer address */
	uint8_t ll_addr[MAX_LL_ADDR_LEN];
	/** State of the neighbour entry */
	int state;
};

/** Number of entries in the neighbour cache table */
#define NUM_NDP_ENTRIES 4

/** The neighbour cache table */
static struct ndp_entry ndp_table[NUM_NDP_ENTRIES];
#define ndp_table_end &ndp_table[NUM_NDP_ENTRIES]

static unsigned int next_new_ndp_entry = 0;

/**
 * Find entry in the neighbour cache
 *
 * @v in6	IP6 address
 */
static struct ndp_entry *
ndp_find_entry ( struct in6_addr *in6 ) {
	struct ndp_entry *ndp;

	for ( ndp = ndp_table ; ndp < ndp_table_end ; ndp++ ) {
		if ( IP6_EQUAL ( ( *in6 ), ndp->in6 ) && 
		     ( ndp->state != NDP_STATE_INVALID ) ) {
			return ndp;
		}
	}
	return NULL;
}

/**
 * Add NDP entry
 * 
 * @v netdev	Network device
 * @v in6	IP6 address
 * @v ll_addr	Link-layer address
 * @v state	State of the entry - one of the NDP_STATE_XXX values
 */
static void 
add_ndp_entry ( struct net_device *netdev, struct in6_addr *in6,
		void *ll_addr, int state ) {
	struct ndp_entry *ndp;
	ndp = &ndp_table[next_new_ndp_entry++ % NUM_NDP_ENTRIES];

	/* Fill up entry */
	ndp->ll_protocol = netdev->ll_protocol;
	memcpy ( &ndp->in6, &( *in6 ), sizeof ( *in6 ) );
	if ( ll_addr ) {
		memcpy ( ndp->ll_addr, ll_addr, netdev->ll_protocol->ll_addr_len );
	} else {
		memset ( ndp->ll_addr, 0, netdev->ll_protocol->ll_addr_len );
	}
	ndp->state = state;
	DBG ( "New neighbour cache entry: IP6 %s => %s %s\n",
	      inet6_ntoa ( ndp->in6 ), netdev->ll_protocol->name,
	      netdev->ll_protocol->ntoa ( ndp->ll_addr ) );
}

/**
 * Resolve the link-layer address
 *
 * @v netdev		Network device
 * @v dest		Destination address
 * @v src		Source address
 * @ret dest_ll_addr	Destination link-layer address or NULL
 * @ret rc		Status
 *
 * This function looks up the neighbour cache for an entry corresponding to the
 * destination address. If it finds a valid entry, it fills up dest_ll_addr and
 * returns 0. Otherwise it sends a neighbour solicitation to the solicited
 * multicast address.
 */
int ndp_resolve ( struct net_device *netdev, struct in6_addr *dest,
		  struct in6_addr *src, void *dest_ll_addr ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	struct ndp_entry *ndp;
	int rc;

	ndp = ndp_find_entry ( dest );
	/* Check if the entry is valid */
	if ( ndp && ndp->state == NDP_STATE_REACHABLE ) {
		DBG ( "Neighbour cache hit: IP6 %s => %s %s\n",
		      inet6_ntoa ( *dest ), ll_protocol->name,
		      ll_protocol->ntoa ( ndp->ll_addr ) );
		memcpy ( dest_ll_addr, ndp->ll_addr, ll_protocol->ll_addr_len );
		return 0;
	}

	/* Check if the entry was already created */
	if ( ndp ) {
		DBG ( "Awaiting neighbour advertisement\n" );
		/* For test */
//		ndp->state = NDP_STATE_REACHABLE;
//		memcpy ( ndp->ll_addr, netdev->ll_addr, 6 );
//		assert ( ndp->ll_protocol->ll_addr_len == 6 );
//		icmp6_test_nadvert ( netdev, dest, ndp->ll_addr );
//		assert ( ndp->state == NDP_STATE_REACHABLE );
		/* Take it out till here */
		return -ENOENT;
	}
	DBG ( "Neighbour cache miss: IP6 %s\n", inet6_ntoa ( *dest ) );

	/* Add entry in the neighbour cache */
	add_ndp_entry ( netdev, dest, NULL, NDP_STATE_INCOMPLETE );

	/* Send neighbour solicitation */
	if ( ( rc = icmp6_send_solicit ( netdev, src, dest ) ) != 0 ) {
		return rc;
	}
	return -ENOENT;
}

/**
 * Process neighbour advertisement
 *
 * @v iobuf	I/O buffer
 * @v st_src	Source address
 * @v st_dest	Destination address 
 */
int ndp_process_advert ( struct io_buffer *iobuf, struct sockaddr_tcpip *st_src __unused,
			   struct sockaddr_tcpip *st_dest __unused ) {
	struct neighbour_advert *nadvert = iobuf->data;
	struct ndp_entry *ndp;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *nadvert ) ) {
		DBG ( "Packet too short (%zd bytes)\n", iob_len ( iobuf ) );
		return -EINVAL;
	}

	assert ( nadvert->code == 0 );
	assert ( nadvert->flags & ICMP6_FLAGS_SOLICITED );
	assert ( nadvert->opt_type == 2 );

	/* Update the neighbour cache, if entry is present */
	ndp = ndp_find_entry ( &nadvert->target );
	if ( ndp ) {

	assert ( nadvert->opt_len ==
			( ( 2 + ndp->ll_protocol->ll_addr_len ) / 8 ) );

		if ( IP6_EQUAL ( ndp->in6, nadvert->target ) ) {
			memcpy ( ndp->ll_addr, nadvert->opt_ll_addr,
				 ndp->ll_protocol->ll_addr_len );
			ndp->state = NDP_STATE_REACHABLE;
			return 0;
		}
	}
	DBG ( "Unsolicited advertisement (dropping packet)\n" );
	return 0;
}
