#ifndef _IPXE_ASN1_H
#define _IPXE_ASN1_H

/** @file
 *
 * ASN.1 encoding
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#define ASN1_INTEGER 0x02
#define ASN1_BIT_STRING 0x03
#define ASN1_OCTET_STRING 0x04
#define ASN1_NULL 0x05
#define ASN1_OID 0x06
#define ASN1_SEQUENCE 0x30
#define ASN1_IP_ADDRESS 0x40
#define ASN1_EXPLICIT_TAG 0xa0

/**
 * A DER-encoded ASN.1 object cursor
 */
struct asn1_cursor {
	/** Start of data */
	void *data;
	/** Length of data */
	size_t len;
};

extern int asn1_enter ( struct asn1_cursor *cursor, unsigned int type );
extern int asn1_skip ( struct asn1_cursor *cursor, unsigned int type );

#endif /* _IPXE_ASN1_H */
