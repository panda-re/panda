#ifndef _IPXE_TCP_H
#define _IPXE_TCP_H

/** @file
 *
 * TCP protocol
 *
 * This file defines the iPXE TCP API.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/tcpip.h>

/**
 * A TCP header
 */
struct tcp_header {
	uint16_t src;		/* Source port */
	uint16_t dest;		/* Destination port */
	uint32_t seq;		/* Sequence number */
	uint32_t ack;		/* Acknowledgement number */
	uint8_t hlen;		/* Header length (4), Reserved (4) */
	uint8_t flags;		/* Reserved (2), Flags (6) */
	uint16_t win;		/* Advertised window */
	uint16_t csum;		/* Checksum */
	uint16_t urg;		/* Urgent pointer */
};

/** @defgroup tcpopts TCP options
 * @{
 */

/** End of TCP options list */
#define TCP_OPTION_END 0

/** TCP option pad */
#define TCP_OPTION_NOP 1

/** Generic TCP option */
struct tcp_option {
	uint8_t kind;
	uint8_t length;
} __attribute__ (( packed ));

/** TCP MSS option */
struct tcp_mss_option {
	uint8_t kind;
	uint8_t length;
	uint16_t mss;
} __attribute__ (( packed ));

/** Code for the TCP MSS option */
#define TCP_OPTION_MSS 2

/** TCP timestamp option */
struct tcp_timestamp_option {
	uint8_t kind;
	uint8_t length;
	uint32_t tsval;
	uint32_t tsecr;
} __attribute__ (( packed ));

/** Padded TCP timestamp option (used for sending) */
struct tcp_timestamp_padded_option {
	uint8_t nop[2];
	struct tcp_timestamp_option tsopt;
} __attribute__ (( packed ));

/** Code for the TCP timestamp option */
#define TCP_OPTION_TS 8

/** Parsed TCP options */
struct tcp_options {
	/** MSS option, if present */
	const struct tcp_mss_option *mssopt;
	/** Timestampe option, if present */
	const struct tcp_timestamp_option *tsopt;
};

/** @} */

/*
 * TCP flags
 */
#define TCP_CWR		0x80
#define TCP_ECE		0x40
#define TCP_URG		0x20
#define TCP_ACK		0x10
#define TCP_PSH		0x08
#define TCP_RST		0x04
#define TCP_SYN		0x02
#define TCP_FIN		0x01

/**
* @defgroup tcpstates TCP states
*
* The TCP state is defined by a combination of the flags that have
* been sent to the peer, the flags that have been acknowledged by the
* peer, and the flags that have been received from the peer.
*
* @{
*/

/** TCP flags that have been sent in outgoing packets */
#define TCP_STATE_SENT(flags) ( (flags) << 0 )
#define TCP_FLAGS_SENT(state) ( ( (state) >> 0 ) & 0xff )

/** TCP flags that have been acknowledged by the peer
 *
 * Note that this applies only to SYN and FIN.
 */
#define TCP_STATE_ACKED(flags) ( (flags) << 8 )
#define TCP_FLAGS_ACKED(state) ( ( (state) >> 8 ) & 0xff )

/** TCP flags that have been received from the peer
 *
 * Note that this applies only to SYN and FIN, and that once SYN has
 * been received, we should always be sending ACK.
 */
#define TCP_STATE_RCVD(flags) ( (flags) << 16 )
#define TCP_FLAGS_RCVD(state) ( ( (state) >> 16 ) & 0xff )

/** TCP flags that are currently being sent in outgoing packets */
#define TCP_FLAGS_SENDING(state) \
	( TCP_FLAGS_SENT ( state ) & ~TCP_FLAGS_ACKED ( state ) )

/** CLOSED
 *
 * The connection has not yet been used for anything.
 */
#define TCP_CLOSED TCP_RST

/** LISTEN
 *
 * Not currently used as a state; we have no support for listening
 * connections.  Given a unique value to avoid compiler warnings.
 */
#define TCP_LISTEN 0

/** SYN_SENT
 *
 * SYN has been sent, nothing has yet been received or acknowledged.
 */
#define TCP_SYN_SENT	( TCP_STATE_SENT ( TCP_SYN ) )

/** SYN_RCVD
 *
 * SYN has been sent but not acknowledged, SYN has been received.
 */
#define TCP_SYN_RCVD	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK ) |	    \
			  TCP_STATE_RCVD ( TCP_SYN ) )

/** ESTABLISHED
 *
 * SYN has been sent and acknowledged, SYN has been received.
 */
#define TCP_ESTABLISHED	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK ) |	    \
			  TCP_STATE_ACKED ( TCP_SYN ) |			    \
			  TCP_STATE_RCVD ( TCP_SYN ) )

/** FIN_WAIT_1
 *
 * SYN has been sent and acknowledged, SYN has been received, FIN has
 * been sent but not acknowledged, FIN has not been received.
 *
 * RFC 793 shows that we can enter FIN_WAIT_1 without have had SYN
 * acknowledged, i.e. if the application closes the connection after
 * sending and receiving SYN, but before having had SYN acknowledged.
 * However, we have to *pretend* that SYN has been acknowledged
 * anyway, otherwise we end up sending SYN and FIN in the same
 * sequence number slot.  Therefore, when we transition from SYN_RCVD
 * to FIN_WAIT_1, we have to remember to set TCP_STATE_ACKED(TCP_SYN)
 * and increment our sequence number.
 */
#define TCP_FIN_WAIT_1	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK | TCP_FIN ) |  \
			  TCP_STATE_ACKED ( TCP_SYN ) |			    \
			  TCP_STATE_RCVD ( TCP_SYN ) )

/** FIN_WAIT_2
 *
 * SYN has been sent and acknowledged, SYN has been received, FIN has
 * been sent and acknowledged, FIN ha not been received.
 */
#define TCP_FIN_WAIT_2	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK | TCP_FIN ) |  \
			  TCP_STATE_ACKED ( TCP_SYN | TCP_FIN ) |	    \
			  TCP_STATE_RCVD ( TCP_SYN ) )

/** CLOSING / LAST_ACK
 *
 * SYN has been sent and acknowledged, SYN has been received, FIN has
 * been sent but not acknowledged, FIN has been received.
 *
 * This state actually encompasses both CLOSING and LAST_ACK; they are
 * identical with the definition of state that we use.  I don't
 * *believe* that they need to be distinguished.
 */
#define TCP_CLOSING_OR_LAST_ACK						    \
			( TCP_STATE_SENT ( TCP_SYN | TCP_ACK | TCP_FIN ) |  \
			  TCP_STATE_ACKED ( TCP_SYN ) |			    \
			  TCP_STATE_RCVD ( TCP_SYN | TCP_FIN ) )

/** TIME_WAIT
 *
 * SYN has been sent and acknowledged, SYN has been received, FIN has
 * been sent and acknowledged, FIN has been received.
 */
#define TCP_TIME_WAIT	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK | TCP_FIN ) |  \
			  TCP_STATE_ACKED ( TCP_SYN | TCP_FIN ) |	    \
			  TCP_STATE_RCVD ( TCP_SYN | TCP_FIN ) )

/** CLOSE_WAIT
 *
 * SYN has been sent and acknowledged, SYN has been received, FIN has
 * been received.
 */
#define TCP_CLOSE_WAIT	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK ) |	    \
			  TCP_STATE_ACKED ( TCP_SYN ) |			    \
			  TCP_STATE_RCVD ( TCP_SYN | TCP_FIN ) )

/** Can send data in current state
 *
 * We can send data if and only if we have had our SYN acked and we
 * have not yet sent our FIN.
 */
#define TCP_CAN_SEND_DATA(state)					    \
	( ( (state) & ( TCP_STATE_ACKED ( TCP_SYN ) |			    \
			TCP_STATE_SENT ( TCP_FIN ) ) )			    \
	  == TCP_STATE_ACKED ( TCP_SYN ) )

/** Have ever been fully established
 *
 * We have been fully established if we have both received a SYN and
 * had our own SYN acked.
 */
#define TCP_HAS_BEEN_ESTABLISHED(state)					    \
	( ( (state) & ( TCP_STATE_ACKED ( TCP_SYN ) |			    \
			TCP_STATE_RCVD ( TCP_SYN ) ) )			    \
	  == ( TCP_STATE_ACKED ( TCP_SYN ) | TCP_STATE_RCVD ( TCP_SYN ) ) )

/** Have closed gracefully
 *
 * We have closed gracefully if we have both received a FIN and had
 * our own FIN acked.
 */
#define TCP_CLOSED_GRACEFULLY(state)					    \
	( ( (state) & ( TCP_STATE_ACKED ( TCP_FIN ) |			    \
			TCP_STATE_RCVD ( TCP_FIN ) ) )			    \
	  == ( TCP_STATE_ACKED ( TCP_FIN ) | TCP_STATE_RCVD ( TCP_FIN ) ) )

/** @} */

/** Mask for TCP header length field */
#define TCP_MASK_HLEN	0xf0

/** Smallest port number on which a TCP connection can listen */
#define TCP_MIN_PORT 1

/**
 * Maxmimum advertised TCP window size
 *
 * We estimate the TCP window size as the amount of free memory we
 * have.  This is not strictly accurate (since it ignores any space
 * already allocated as RX buffers), but it will do for now.
 *
 * Since we don't store out-of-order received packets, the
 * retransmission penalty is that the whole window contents must be
 * resent.  This suggests keeping the window size small, but bear in
 * mind that the maximum bandwidth on any link is limited to
 *
 *    max_bandwidth = ( tcp_window / round_trip_time )
 *
 * With a 48kB window, which probably accurately reflects our amount
 * of free memory, and a WAN RTT of say 200ms, this gives a maximum
 * bandwidth of 240kB/s.  This is sufficiently close to realistic that
 * we will need to be careful that our advertised window doesn't end
 * up limiting WAN download speeds.
 *
 * Finally, since the window goes into a 16-bit field and we cannot
 * actually use 65536, we use a window size of (65536-4) to ensure
 * that payloads remain dword-aligned.
 */
//#define TCP_MAX_WINDOW_SIZE	( 65536 - 4 )
#define TCP_MAX_WINDOW_SIZE	8192

/**
 * Path MTU
 *
 * We really ought to implement Path MTU discovery.  Until we do,
 * anything with a path MTU greater than this may fail.
 */
#define TCP_PATH_MTU 1460

/**
 * Advertised TCP MSS
 *
 * We currently hardcode this to a reasonable value and hope that the
 * sender uses path MTU discovery.  The alternative is breaking the
 * abstraction layer so that we can find out the MTU from the IP layer
 * (which would have to find out from the net device layer).
 */
#define TCP_MSS 1460

/** TCP maximum segment lifetime
 *
 * Currently set to 2 minutes, as per RFC 793.
 */
#define TCP_MSL ( 2 * 60 * TICKS_PER_SEC )

/**
 * Compare TCP sequence numbers
 *
 * @v seq1		Sequence number 1
 * @v seq2		Sequence number 2
 * @ret diff		Sequence difference
 *
 * Analogous to memcmp(), returns an integer less than, equal to, or
 * greater than zero if @c seq1 is found, respectively, to be before,
 * equal to, or after @c seq2.
 */
static inline __attribute__ (( always_inline )) int32_t
tcp_cmp ( uint32_t seq1, uint32_t seq2 ) {
	return ( ( int32_t ) ( seq1 - seq2 ) );
}

/**
 * Check if TCP sequence number lies within window
 *
 * @v seq		Sequence number
 * @v start		Start of window
 * @v len		Length of window
 * @ret in_window	Sequence number is within window
 */
static inline int tcp_in_window ( uint32_t seq, uint32_t start,
				  uint32_t len ) {
	return ( ( seq - start ) < len );
}

extern struct tcpip_protocol tcp_protocol __tcpip_protocol;

#endif /* _IPXE_TCP_H */
