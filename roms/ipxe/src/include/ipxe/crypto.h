#ifndef _IPXE_CRYPTO_H
#define _IPXE_CRYPTO_H

/** @file
 *
 * Cryptographic API
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stddef.h>

/** A message digest algorithm */
struct digest_algorithm {
	/** Algorithm name */
	const char *name;
	/** Context size */
	size_t ctxsize;
	/** Block size */
	size_t blocksize;
	/** Digest size */
	size_t digestsize;
	/** Initialise digest
	 *
	 * @v ctx		Context
	 */
	void ( * init ) ( void *ctx );
	/** Update digest with new data
	 *
	 * @v ctx		Context
	 * @v src		Data to digest
	 * @v len		Length of data
	 *
	 * @v len is not necessarily a multiple of @c blocksize.
	 */
	void ( * update ) ( void *ctx, const void *src, size_t len );
	/** Finalise digest
	 *
	 * @v ctx		Context
	 * @v out		Buffer for digest output
	 */
	void ( * final ) ( void *ctx, void *out );
};

/** A cipher algorithm */
struct cipher_algorithm {
	/** Algorithm name */
	const char *name;
	/** Context size */
	size_t ctxsize;
	/** Block size */
	size_t blocksize;
	/** Set key
	 *
	 * @v ctx		Context
	 * @v key		Key
	 * @v keylen		Key length
	 * @ret rc		Return status code
	 */
	int ( * setkey ) ( void *ctx, const void *key, size_t keylen );
	/** Set initialisation vector
	 *
	 * @v ctx		Context
	 * @v iv		Initialisation vector
	 */
	void ( * setiv ) ( void *ctx, const void *iv );
	/** Encrypt data
	 *
	 * @v ctx		Context
	 * @v src		Data to encrypt
	 * @v dst		Buffer for encrypted data
	 * @v len		Length of data
	 *
	 * @v len is guaranteed to be a multiple of @c blocksize.
	 */
	void ( * encrypt ) ( void *ctx, const void *src, void *dst,
			     size_t len );
	/** Decrypt data
	 *
	 * @v ctx		Context
	 * @v src		Data to decrypt
	 * @v dst		Buffer for decrypted data
	 * @v len		Length of data
	 *
	 * @v len is guaranteed to be a multiple of @c blocksize.
	 */
	void ( * decrypt ) ( void *ctx, const void *src, void *dst,
			     size_t len );
};

/** A public key algorithm */
struct pubkey_algorithm {
	/** Algorithm name */
	const char *name;
	/** Context size */
	size_t ctxsize;
};

static inline void digest_init ( struct digest_algorithm *digest,
				 void *ctx ) {
	digest->init ( ctx );
}

static inline void digest_update ( struct digest_algorithm *digest,
				   void *ctx, const void *data, size_t len ) {
	digest->update ( ctx, data, len );
}

static inline void digest_final ( struct digest_algorithm *digest,
				  void *ctx, void *out ) {
	digest->final ( ctx, out );
}

static inline int cipher_setkey ( struct cipher_algorithm *cipher,
				  void *ctx, const void *key, size_t keylen ) {
	return cipher->setkey ( ctx, key, keylen );
}

static inline void cipher_setiv ( struct cipher_algorithm *cipher,
				  void *ctx, const void *iv ) {
	cipher->setiv ( ctx, iv );
}

static inline void cipher_encrypt ( struct cipher_algorithm *cipher,
				    void *ctx, const void *src, void *dst,
				    size_t len ) {
	cipher->encrypt ( ctx, src, dst, len );
}
#define cipher_encrypt( cipher, ctx, src, dst, len ) do {		\
	assert ( ( (len) & ( (cipher)->blocksize - 1 ) ) == 0 );	\
	cipher_encrypt ( (cipher), (ctx), (src), (dst), (len) );	\
	} while ( 0 )

static inline void cipher_decrypt ( struct cipher_algorithm *cipher,
				    void *ctx, const void *src, void *dst,
				    size_t len ) {
	cipher->decrypt ( ctx, src, dst, len );
}
#define cipher_decrypt( cipher, ctx, src, dst, len ) do {		\
	assert ( ( (len) & ( (cipher)->blocksize - 1 ) ) == 0 );	\
	cipher_decrypt ( (cipher), (ctx), (src), (dst), (len) );	\
	} while ( 0 )

static inline int is_stream_cipher ( struct cipher_algorithm *cipher ) {
	return ( cipher->blocksize == 1 );
}

extern struct digest_algorithm digest_null;
extern struct cipher_algorithm cipher_null;
extern struct pubkey_algorithm pubkey_null;

void get_random_bytes ( void *buf, size_t len );

#endif /* _IPXE_CRYPTO_H */
