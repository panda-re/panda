/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <string.h>
#include <errno.h>
#include <ipxe/iobuf.h>
#include <ipxe/in.h>
#include <ipxe/tcpip.h>
#include <ipxe/icmp.h>

/** @file
 *
 * ICMP protocol
 *
 */

struct tcpip_protocol icmp_protocol __tcpip_protocol;

/**
 * Process a received packet
 *
 * @v iobuf		I/O buffer
 * @v st_src		Partially-filled source address
 * @v st_dest		Partially-filled destination address
 * @v pshdr_csum	Pseudo-header checksum
 * @ret rc		Return status code
 */
static int icmp_rx ( struct io_buffer *iobuf, struct sockaddr_tcpip *st_src,
		     struct sockaddr_tcpip *st_dest,
		     uint16_t pshdr_csum __unused ) {
	struct icmp_header *icmp = iobuf->data;
	size_t len = iob_len ( iobuf );
	unsigned int csum;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *icmp ) ) {
		DBG ( "ICMP packet too short at %zd bytes (min %zd bytes)\n",
		      len, sizeof ( *icmp ) );
		rc = -EINVAL;
		goto done;
	}

	/* Verify checksum */
	csum = tcpip_chksum ( icmp, len );
	if ( csum != 0 ) {
		DBG ( "ICMP checksum incorrect (is %04x, should be 0000)\n",
		      csum );
		DBG_HD ( icmp, len );
		rc = -EINVAL;
		goto done;
	}

	/* We respond only to pings */
	if ( icmp->type != ICMP_ECHO_REQUEST ) {
		DBG ( "ICMP ignoring type %d\n", icmp->type );
		rc = 0;
		goto done;
	}

	DBG ( "ICMP responding to ping\n" );

	/* Change type to response and recalculate checksum */
	icmp->type = ICMP_ECHO_RESPONSE;
	icmp->chksum = 0;
	icmp->chksum = tcpip_chksum ( icmp, len );

	/* Transmit the response */
	if ( ( rc = tcpip_tx ( iob_disown ( iobuf ), &icmp_protocol, st_dest,
			       st_src, NULL, NULL ) ) != 0 ) {
		DBG ( "ICMP could not transmit ping response: %s\n",
		      strerror ( rc ) );
		goto done;
	}

 done:
	free_iob ( iobuf );
	return rc;
}

/** ICMP TCP/IP protocol */
struct tcpip_protocol icmp_protocol __tcpip_protocol = {
	.name = "ICMP",
	.rx = icmp_rx,
	.tcpip_proto = IP_ICMP,
};
