#ifndef _IPXE_SHA1_H
#define _IPXE_SHA1_H

FILE_LICENCE ( GPL2_OR_LATER );

#include "crypto/axtls/crypto.h"

struct digest_algorithm;

#define SHA1_CTX_SIZE sizeof ( SHA1_CTX )
#define SHA1_DIGEST_SIZE SHA1_SIZE

extern struct digest_algorithm sha1_algorithm;

/* SHA1-wrapping functions defined in sha1extra.c: */

void prf_sha1 ( const void *key, size_t key_len, const char *label,
		const void *data, size_t data_len, void *prf, size_t prf_len );

void pbkdf2_sha1 ( const void *passphrase, size_t pass_len,
		   const void *salt, size_t salt_len,
		   int iterations, void *key, size_t key_len );

#endif /* _IPXE_SHA1_H */
