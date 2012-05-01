/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * Portions copyright (C) 2004 Anselm M. Hoffmeister
 * <stockholm@users.sourceforge.net>.
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/refcnt.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/resolv.h>
#include <ipxe/retry.h>
#include <ipxe/tcpip.h>
#include <ipxe/settings.h>
#include <ipxe/features.h>
#include <ipxe/dns.h>

/** @file
 *
 * DNS protocol
 *
 */

FEATURE ( FEATURE_PROTOCOL, "DNS", DHCP_EB_FEATURE_DNS, 1 );

/* Disambiguate the various error causes */
#define ENXIO_NO_RECORD __einfo_error ( EINFO_ENXIO_NO_RECORD )
#define EINFO_ENXIO_NO_RECORD \
	__einfo_uniqify ( EINFO_ENXIO, 0x01, "DNS name does not exist" )
#define ENXIO_NO_NAMESERVER __einfo_error ( EINFO_ENXIO_NO_NAMESERVER )
#define EINFO_ENXIO_NO_NAMESERVER \
	__einfo_uniqify ( EINFO_ENXIO, 0x02, "No DNS servers available" )

/** The DNS server */
static struct sockaddr_tcpip nameserver = {
	.st_port = htons ( DNS_PORT ),
};

/** The local domain */
static char *localdomain;

/** A DNS request */
struct dns_request {
	/** Reference counter */
	struct refcnt refcnt;
	/** Name resolution interface */
	struct interface resolv;
	/** Data transfer interface */
	struct interface socket;
	/** Retry timer */
	struct retry_timer timer;

	/** Socket address to fill in with resolved address */
	struct sockaddr sa;
	/** Current query packet */
	struct dns_query query;
	/** Location of query info structure within current packet
	 *
	 * The query info structure is located immediately after the
	 * compressed name.
	 */
	struct dns_query_info *qinfo;
	/** Recursion counter */
	unsigned int recursion;
};

/**
 * Mark DNS request as complete
 *
 * @v dns		DNS request
 * @v rc		Return status code
 */
static void dns_done ( struct dns_request *dns, int rc ) {

	/* Stop the retry timer */
	stop_timer ( &dns->timer );

	/* Shut down interfaces */
	intf_shutdown ( &dns->socket, rc );
	intf_shutdown ( &dns->resolv, rc );
}

/**
 * Compare DNS reply name against the query name from the original request
 *
 * @v dns		DNS request
 * @v reply		DNS reply
 * @v rname		Reply name
 * @ret	zero		Names match
 * @ret non-zero	Names do not match
 */
static int dns_name_cmp ( struct dns_request *dns,
			  const struct dns_header *reply, 
			  const char *rname ) {
	const char *qname = dns->query.payload;
	int i;

	while ( 1 ) {
		/* Obtain next section of rname */
		while ( ( *rname ) & 0xc0 ) {
			rname = ( ( ( char * ) reply ) +
				  ( ntohs( *((uint16_t *)rname) ) & ~0xc000 ));
		}
		/* Check that lengths match */
		if ( *rname != *qname )
			return -1;
		/* If length is zero, we have reached the end */
		if ( ! *qname )
			return 0;
		/* Check that data matches */
		for ( i = *qname + 1; i > 0 ; i-- ) {
			if ( *(rname++) != *(qname++) )
				return -1;
		}
	}
}

/**
 * Skip over a (possibly compressed) DNS name
 *
 * @v name		DNS name
 * @ret name		Next DNS name
 */
static const char * dns_skip_name ( const char *name ) {
	while ( 1 ) {
		if ( ! *name ) {
			/* End of name */
			return ( name + 1);
		}
		if ( *name & 0xc0 ) {
			/* Start of a compressed name */
			return ( name + 2 );
		}
		/* Uncompressed name portion */
		name += *name + 1;
	}
}

/**
 * Find an RR in a reply packet corresponding to our query
 *
 * @v dns		DNS request
 * @v reply		DNS reply
 * @ret rr		DNS RR, or NULL if not found
 */
static union dns_rr_info * dns_find_rr ( struct dns_request *dns,
					 const struct dns_header *reply ) {
	int i, cmp;
	const char *p = ( ( char * ) reply ) + sizeof ( struct dns_header );
	union dns_rr_info *rr_info;

	/* Skip over the questions section */
	for ( i = ntohs ( reply->qdcount ) ; i > 0 ; i-- ) {
		p = dns_skip_name ( p ) + sizeof ( struct dns_query_info );
	}

	/* Process the answers section */
	for ( i = ntohs ( reply->ancount ) ; i > 0 ; i-- ) {
		cmp = dns_name_cmp ( dns, reply, p );
		p = dns_skip_name ( p );
		rr_info = ( ( union dns_rr_info * ) p );
		if ( cmp == 0 )
			return rr_info;
		p += ( sizeof ( rr_info->common ) +
		       ntohs ( rr_info->common.rdlength ) );
	}

	return NULL;
}

/**
 * Append DHCP domain name if available and name is not fully qualified
 *
 * @v string		Name as a NUL-terminated string
 * @ret fqdn		Fully-qualified domain name, malloc'd copy
 *
 * The caller must free fqdn which is allocated even if the name is already
 * fully qualified.
 */
static char * dns_qualify_name ( const char *string ) {
	char *fqdn;

	/* Leave unchanged if already fully-qualified or no local domain */
	if ( ( ! localdomain ) || ( strchr ( string, '.' ) != 0 ) )
		return strdup ( string );

	/* Append local domain to name */
	asprintf ( &fqdn, "%s.%s", string, localdomain );
	return fqdn;
}

/**
 * Convert a standard NUL-terminated string to a DNS name
 *
 * @v string		Name as a NUL-terminated string
 * @v buf		Buffer in which to place DNS name
 * @ret next		Byte following constructed DNS name
 *
 * DNS names consist of "<length>element" pairs.
 */
static char * dns_make_name ( const char *string, char *buf ) {
	char *length_byte = buf++;
	char c;

	while ( ( c = *(string++) ) ) {
		if ( c == '.' ) {
			*length_byte = buf - length_byte - 1;
			length_byte = buf;
		}
		*(buf++) = c;
	}
	*length_byte = buf - length_byte - 1;
	*(buf++) = '\0';
	return buf;
}

/**
 * Convert an uncompressed DNS name to a NUL-terminated string
 *
 * @v name		DNS name
 * @ret string		NUL-terminated string
 *
 * Produce a printable version of a DNS name.  Used only for debugging.
 */
static inline char * dns_unmake_name ( char *name ) {
	char *p;
	unsigned int len;

	p = name;
	while ( ( len = *p ) ) {
		*(p++) = '.';
		p += len;
	}

	return name + 1;
}

/**
 * Decompress a DNS name
 *
 * @v reply		DNS replay
 * @v name		DNS name
 * @v buf		Buffer into which to decompress DNS name
 * @ret next		Byte following decompressed DNS name
 */
static char * dns_decompress_name ( const struct dns_header *reply,
				    const char *name, char *buf ) {
	int i, len;

	do {
		/* Obtain next section of name */
		while ( ( *name ) & 0xc0 ) {
			name = ( ( char * ) reply +
				 ( ntohs ( *((uint16_t *)name) ) & ~0xc000 ) );
		}
		/* Copy data */
		len = *name;
		for ( i = len + 1 ; i > 0 ; i-- ) {
			*(buf++) = *(name++);
		}
	} while ( len );
	return buf;
}

/**
 * Send next packet in DNS request
 *
 * @v dns		DNS request
 */
static int dns_send_packet ( struct dns_request *dns ) {
	static unsigned int qid = 0;
	size_t qlen;

	/* Increment query ID */
	dns->query.dns.id = htons ( ++qid );

	DBGC ( dns, "DNS %p sending query ID %d\n", dns, qid );

	/* Start retransmission timer */
	start_timer ( &dns->timer );

	/* Send the data */
	qlen = ( ( ( void * ) dns->qinfo ) - ( ( void * ) &dns->query )
		 + sizeof ( dns->qinfo ) );
	return xfer_deliver_raw ( &dns->socket, &dns->query, qlen );
}

/**
 * Handle DNS retransmission timer expiry
 *
 * @v timer		Retry timer
 * @v fail		Failure indicator
 */
static void dns_timer_expired ( struct retry_timer *timer, int fail ) {
	struct dns_request *dns =
		container_of ( timer, struct dns_request, timer );

	if ( fail ) {
		dns_done ( dns, -ETIMEDOUT );
	} else {
		dns_send_packet ( dns );
	}
}

/**
 * Receive new data
 *
 * @v dns		DNS request
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int dns_xfer_deliver ( struct dns_request *dns,
			      struct io_buffer *iobuf,
			      struct xfer_metadata *meta __unused ) {
	const struct dns_header *reply = iobuf->data;
	union dns_rr_info *rr_info;
	struct sockaddr_in *sin;
	unsigned int qtype = dns->qinfo->qtype;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *reply ) ) {
		DBGC ( dns, "DNS %p received underlength packet length %zd\n",
		       dns, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto done;
	}

	/* Check reply ID matches query ID */
	if ( reply->id != dns->query.dns.id ) {
		DBGC ( dns, "DNS %p received unexpected reply ID %d "
		       "(wanted %d)\n", dns, ntohs ( reply->id ),
		       ntohs ( dns->query.dns.id ) );
		rc = -EINVAL;
		goto done;
	}

	DBGC ( dns, "DNS %p received reply ID %d\n", dns, ntohs ( reply->id ));

	/* Stop the retry timer.  After this point, each code path
	 * must either restart the timer by calling dns_send_packet(),
	 * or mark the DNS operation as complete by calling
	 * dns_done()
	 */
	stop_timer ( &dns->timer );

	/* Search through response for useful answers.  Do this
	 * multiple times, to take advantage of useful nameservers
	 * which send us e.g. the CNAME *and* the A record for the
	 * pointed-to name.
	 */
	while ( ( rr_info = dns_find_rr ( dns, reply ) ) ) {
		switch ( rr_info->common.type ) {

		case htons ( DNS_TYPE_A ):

			/* Found the target A record */
			DBGC ( dns, "DNS %p found address %s\n",
			       dns, inet_ntoa ( rr_info->a.in_addr ) );
			sin = ( struct sockaddr_in * ) &dns->sa;
			sin->sin_family = AF_INET;
			sin->sin_addr = rr_info->a.in_addr;

			/* Return resolved address */
			resolv_done ( &dns->resolv, &dns->sa );

			/* Mark operation as complete */
			dns_done ( dns, 0 );
			rc = 0;
			goto done;

		case htons ( DNS_TYPE_CNAME ):

			/* Found a CNAME record; update query and recurse */
			DBGC ( dns, "DNS %p found CNAME\n", dns );
			dns->qinfo = ( void * ) dns_decompress_name ( reply,
							 rr_info->cname.cname,
							 dns->query.payload );
			dns->qinfo->qtype = htons ( DNS_TYPE_A );
			dns->qinfo->qclass = htons ( DNS_CLASS_IN );
			
			/* Terminate the operation if we recurse too far */
			if ( ++dns->recursion > DNS_MAX_CNAME_RECURSION ) {
				DBGC ( dns, "DNS %p recursion exceeded\n",
				       dns );
				dns_done ( dns, -ELOOP );
				rc = 0;
				goto done;
			}
			break;

		default:
			DBGC ( dns, "DNS %p got unknown record type %d\n",
			       dns, ntohs ( rr_info->common.type ) );
			break;
		}
	}
	
	/* Determine what to do next based on the type of query we
	 * issued and the reponse we received
	 */
	switch ( qtype ) {

	case htons ( DNS_TYPE_A ):
		/* We asked for an A record and got nothing;
		 * try the CNAME.
		 */
		DBGC ( dns, "DNS %p found no A record; trying CNAME\n", dns );
		dns->qinfo->qtype = htons ( DNS_TYPE_CNAME );
		dns_send_packet ( dns );
		rc = 0;
		goto done;

	case htons ( DNS_TYPE_CNAME ):
		/* We asked for a CNAME record.  If we got a response
		 * (i.e. if the next A query is already set up), then
		 * issue it, otherwise abort.
		 */
		if ( dns->qinfo->qtype == htons ( DNS_TYPE_A ) ) {
			dns_send_packet ( dns );
			rc = 0;
			goto done;
		} else {
			DBGC ( dns, "DNS %p found no CNAME record\n", dns );
			dns_done ( dns, -ENXIO_NO_RECORD );
			rc = 0;
			goto done;
		}

	default:
		assert ( 0 );
		dns_done ( dns, -EINVAL );
		rc = -EINVAL;
		goto done;
	}

 done:
	/* Free I/O buffer */
	free_iob ( iobuf );
	return rc;
}

/**
 * Receive new data
 *
 * @v dns		DNS request
 * @v rc		Reason for close
 */
static void dns_xfer_close ( struct dns_request *dns, int rc ) {

	if ( ! rc )
		rc = -ECONNABORTED;

	dns_done ( dns, rc );
}

/** DNS socket interface operations */
static struct interface_operation dns_socket_operations[] = {
	INTF_OP ( xfer_deliver, struct dns_request *, dns_xfer_deliver ),
	INTF_OP ( intf_close, struct dns_request *, dns_xfer_close ),
};

/** DNS socket interface descriptor */
static struct interface_descriptor dns_socket_desc =
	INTF_DESC ( struct dns_request, socket, dns_socket_operations );

/** DNS resolver interface operations */
static struct interface_operation dns_resolv_op[] = {
	INTF_OP ( intf_close, struct dns_request *, dns_done ),
};

/** DNS resolver interface descriptor */
static struct interface_descriptor dns_resolv_desc =
	INTF_DESC ( struct dns_request, resolv, dns_resolv_op );

/**
 * Resolve name using DNS
 *
 * @v resolv		Name resolution interface
 * @v name		Name to resolve
 * @v sa		Socket address to fill in
 * @ret rc		Return status code
 */
static int dns_resolv ( struct interface *resolv,
			const char *name, struct sockaddr *sa ) {
	struct dns_request *dns;
	char *fqdn;
	int rc;

	/* Fail immediately if no DNS servers */
	if ( ! nameserver.st_family ) {
		DBG ( "DNS not attempting to resolve \"%s\": "
		      "no DNS servers\n", name );
		rc = -ENXIO_NO_NAMESERVER;
		goto err_no_nameserver;
	}

	/* Ensure fully-qualified domain name if DHCP option was given */
	fqdn = dns_qualify_name ( name );
	if ( ! fqdn ) {
		rc = -ENOMEM;
		goto err_qualify_name;
	}

	/* Allocate DNS structure */
	dns = zalloc ( sizeof ( *dns ) );
	if ( ! dns ) {
		rc = -ENOMEM;
		goto err_alloc_dns;
	}
	ref_init ( &dns->refcnt, NULL );
	intf_init ( &dns->resolv, &dns_resolv_desc, &dns->refcnt );
	intf_init ( &dns->socket, &dns_socket_desc, &dns->refcnt );
	timer_init ( &dns->timer, dns_timer_expired, &dns->refcnt );
	memcpy ( &dns->sa, sa, sizeof ( dns->sa ) );

	/* Create query */
	dns->query.dns.flags = htons ( DNS_FLAG_QUERY | DNS_FLAG_OPCODE_QUERY |
				       DNS_FLAG_RD );
	dns->query.dns.qdcount = htons ( 1 );
	dns->qinfo = ( void * ) dns_make_name ( fqdn, dns->query.payload );
	dns->qinfo->qtype = htons ( DNS_TYPE_A );
	dns->qinfo->qclass = htons ( DNS_CLASS_IN );

	/* Open UDP connection */
	if ( ( rc = xfer_open_socket ( &dns->socket, SOCK_DGRAM,
				       ( struct sockaddr * ) &nameserver,
				       NULL ) ) != 0 ) {
		DBGC ( dns, "DNS %p could not open socket: %s\n",
		       dns, strerror ( rc ) );
		goto err_open_socket;
	}

	/* Send first DNS packet */
	dns_send_packet ( dns );

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &dns->resolv, resolv );
	ref_put ( &dns->refcnt );
	free ( fqdn );
	return 0;	

 err_open_socket:
 err_alloc_dns:
	ref_put ( &dns->refcnt );
 err_qualify_name:
	free ( fqdn );
 err_no_nameserver:
	return rc;
}

/** DNS name resolver */
struct resolver dns_resolver __resolver ( RESOLV_NORMAL ) = {
	.name = "DNS",
	.resolv = dns_resolv,
};

/******************************************************************************
 *
 * Settings
 *
 ******************************************************************************
 */

/** DNS server setting */
struct setting dns_setting __setting ( SETTING_IPv4_EXTRA ) = {
	.name = "dns",
	.description = "DNS server",
	.tag = DHCP_DNS_SERVERS,
	.type = &setting_type_ipv4,
};

/** Domain name setting */
struct setting domain_setting __setting ( SETTING_IPv4_EXTRA ) = {
	.name = "domain",
	.description = "DNS domain",
	.tag = DHCP_DOMAIN_NAME,
	.type = &setting_type_string,
};

/**
 * Apply DNS settings
 *
 * @ret rc		Return status code
 */
static int apply_dns_settings ( void ) {
	struct sockaddr_in *sin_nameserver =
		( struct sockaddr_in * ) &nameserver;
	int len;

	/* Fetch DNS server address */
	nameserver.st_family = 0;
	if ( ( len = fetch_ipv4_setting ( NULL, &dns_setting,
					  &sin_nameserver->sin_addr ) ) >= 0 ){
		nameserver.st_family = AF_INET;
		DBG ( "DNS using nameserver %s\n",
		      inet_ntoa ( sin_nameserver->sin_addr ) );
	}

	/* Get local domain DHCP option */
	free ( localdomain );
	if ( ( len = fetch_string_setting_copy ( NULL, &domain_setting,
						 &localdomain ) ) < 0 ) {
		DBG ( "DNS could not fetch local domain: %s\n",
		      strerror ( len ) );
	}
	if ( localdomain )
		DBG ( "DNS local domain %s\n", localdomain );

	return 0;
}

/** DNS settings applicator */
struct settings_applicator dns_applicator __settings_applicator = {
	.apply = apply_dns_settings,
};
