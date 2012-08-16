/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/asn1.h>
#include <ipxe/x509.h>

/** @file
 *
 * X.509 certificates
 *
 * The structure of X.509v3 certificates is concisely documented in
 * RFC5280 section 4.1.  The structure of RSA public keys is
 * documented in RFC2313.
 */

/** Object Identifier for "rsaEncryption" (1.2.840.113549.1.1.1) */
static const uint8_t oid_rsa_encryption[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,
					      0x0d, 0x01, 0x01, 0x01 };

/**
 * Identify X.509 certificate public key
 *
 * @v certificate	Certificate
 * @v algorithm		Public key algorithm to fill in
 * @v pubkey		Public key value to fill in
 * @ret rc		Return status code
 */
static int x509_public_key ( const struct asn1_cursor *certificate,
			     struct asn1_cursor *algorithm,
			     struct asn1_cursor *pubkey ) {
	struct asn1_cursor cursor;
	int rc;

	/* Locate subjectPublicKeyInfo */
	memcpy ( &cursor, certificate, sizeof ( cursor ) );
	rc = ( asn1_enter ( &cursor, ASN1_SEQUENCE ), /* Certificate */
	       asn1_enter ( &cursor, ASN1_SEQUENCE ), /* tbsCertificate */
	       asn1_skip ( &cursor, ASN1_EXPLICIT_TAG ), /* version */
	       asn1_skip ( &cursor, ASN1_INTEGER ), /* serialNumber */
	       asn1_skip ( &cursor, ASN1_SEQUENCE ), /* signature */
	       asn1_skip ( &cursor, ASN1_SEQUENCE ), /* issuer */
	       asn1_skip ( &cursor, ASN1_SEQUENCE ), /* validity */
	       asn1_skip ( &cursor, ASN1_SEQUENCE ), /* name */
	       asn1_enter ( &cursor, ASN1_SEQUENCE )/* subjectPublicKeyInfo*/);
	if ( rc != 0 ) {
		DBG ( "Cannot locate subjectPublicKeyInfo in:\n" );
		DBG_HDA ( 0, certificate->data, certificate->len );
		return rc;
	}

	/* Locate algorithm */
	memcpy ( algorithm, &cursor, sizeof ( *algorithm ) );
	rc = ( asn1_enter ( algorithm, ASN1_SEQUENCE ) /* algorithm */ );
	if ( rc != 0 ) {
		DBG ( "Cannot locate algorithm in:\n" );
		DBG_HDA ( 0, certificate->data, certificate->len );
		return rc;
	}

	/* Locate subjectPublicKey */
	memcpy ( pubkey, &cursor, sizeof ( *pubkey ) );
	rc = ( asn1_skip ( pubkey, ASN1_SEQUENCE ), /* algorithm */
	       asn1_enter ( pubkey, ASN1_BIT_STRING ) /* subjectPublicKey*/ );
	if ( rc != 0 ) {
		DBG ( "Cannot locate subjectPublicKey in:\n" );
		DBG_HDA ( 0, certificate->data, certificate->len );
		return rc;
	}

	return 0;
}

/**
 * Identify X.509 certificate RSA modulus and public exponent
 *
 * @v certificate	Certificate
 * @v rsa		RSA public key to fill in
 * @ret rc		Return status code
 *
 * The caller is responsible for eventually calling
 * x509_free_rsa_public_key() to free the storage allocated to hold
 * the RSA modulus and exponent.
 */
int x509_rsa_public_key ( const struct asn1_cursor *certificate,
			  struct x509_rsa_public_key *rsa_pubkey ) {
	struct asn1_cursor algorithm;
	struct asn1_cursor pubkey;
	struct asn1_cursor modulus;
	struct asn1_cursor exponent;
	int rc;

	/* First, extract the public key algorithm and key data */
	if ( ( rc = x509_public_key ( certificate, &algorithm,
				      &pubkey ) ) != 0 )
		return rc;

	/* Check that algorithm is RSA */
	rc = ( asn1_enter ( &algorithm, ASN1_OID ) /* algorithm */ );
	if ( rc != 0 ) {
		DBG ( "Cannot locate algorithm:\n" );
		DBG_HDA ( 0, certificate->data, certificate->len );
	return rc;
	}
	if ( ( algorithm.len != sizeof ( oid_rsa_encryption ) ) ||
	     ( memcmp ( algorithm.data, &oid_rsa_encryption,
			sizeof ( oid_rsa_encryption ) ) != 0 ) ) {
		DBG ( "algorithm is not rsaEncryption in:\n" );
		DBG_HDA ( 0, certificate->data, certificate->len );
		return -ENOTSUP;
	}

	/* Check that public key is a byte string, i.e. that the
	 * "unused bits" byte contains zero.
	 */
	if ( ( pubkey.len < 1 ) ||
	     ( ( *( uint8_t * ) pubkey.data ) != 0 ) ) {
		DBG ( "subjectPublicKey is not a byte string in:\n" );
		DBG_HDA ( 0, certificate->data, certificate->len );
		return -ENOTSUP;
	}
	pubkey.data++;
	pubkey.len--;

	/* Pick out the modulus and exponent */
	rc = ( asn1_enter ( &pubkey, ASN1_SEQUENCE ) /* RSAPublicKey */ );
	if ( rc != 0 ) {
		DBG ( "Cannot locate RSAPublicKey in:\n" );
		DBG_HDA ( 0, certificate->data, certificate->len );
		return -ENOTSUP;
	}
	memcpy ( &modulus, &pubkey, sizeof ( modulus ) );
	rc = ( asn1_enter ( &modulus, ASN1_INTEGER ) /* modulus */ );
	if ( rc != 0 ) {
		DBG ( "Cannot locate modulus in:\n" );
		DBG_HDA ( 0, certificate->data, certificate->len );
		return -ENOTSUP;
	}
	memcpy ( &exponent, &pubkey, sizeof ( exponent ) );
	rc = ( asn1_skip ( &exponent, ASN1_INTEGER ), /* modulus */
	       asn1_enter ( &exponent, ASN1_INTEGER ) /* publicExponent */ );
	if ( rc != 0 ) {
		DBG ( "Cannot locate publicExponent in:\n" );
		DBG_HDA ( 0, certificate->data, certificate->len );
		return -ENOTSUP;
	}

	/* Allocate space and copy out modulus and exponent */
	rsa_pubkey->modulus = malloc ( modulus.len + exponent.len );
	if ( ! rsa_pubkey->modulus )
		return -ENOMEM;
	rsa_pubkey->exponent = ( rsa_pubkey->modulus + modulus.len );
	memcpy ( rsa_pubkey->modulus, modulus.data, modulus.len );
	rsa_pubkey->modulus_len = modulus.len;
	memcpy ( rsa_pubkey->exponent, exponent.data, exponent.len );
	rsa_pubkey->exponent_len = exponent.len;

	DBG2 ( "RSA modulus:\n" );
	DBG2_HDA ( 0, rsa_pubkey->modulus, rsa_pubkey->modulus_len );
	DBG2 ( "RSA exponent:\n" );
	DBG2_HDA ( 0, rsa_pubkey->exponent, rsa_pubkey->exponent_len );

	return 0;
}
