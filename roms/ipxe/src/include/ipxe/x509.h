#ifndef _IPXE_X509_H
#define _IPXE_X509_H

/** @file
 *
 * X.509 certificates
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>

struct asn1_cursor;

/** An X.509 RSA public key */
struct x509_rsa_public_key {
	/** Modulus */
	uint8_t *modulus;
	/** Modulus length */
	size_t modulus_len;
	/** Exponent */
	uint8_t *exponent;
	/** Exponent length */
	size_t exponent_len;
};

/**
 * Free X.509 RSA public key
 *
 * @v rsa_pubkey	RSA public key
 */
static inline void
x509_free_rsa_public_key ( struct x509_rsa_public_key *rsa_pubkey ) {
	free ( rsa_pubkey->modulus );
}

extern int x509_rsa_public_key ( const struct asn1_cursor *certificate,
				 struct x509_rsa_public_key *rsa_pubkey );

#endif /* _IPXE_X509_H */
