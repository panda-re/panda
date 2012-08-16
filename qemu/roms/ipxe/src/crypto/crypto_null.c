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

/**
 * @file
 *
 * Null crypto algorithm
 */

#include <string.h>
#include <ipxe/crypto.h>

static void digest_null_init ( void *ctx __unused ) {
	/* Do nothing */
}

static void digest_null_update ( void *ctx __unused, const void *src __unused,
				 size_t len __unused ) {
	/* Do nothing */
}

static void digest_null_final ( void *ctx __unused, void *out __unused ) {
	/* Do nothing */
}

struct digest_algorithm digest_null = {
	.name = "null",
	.ctxsize = 0,
	.blocksize = 1,
	.digestsize = 0,
	.init = digest_null_init,
	.update = digest_null_update,
	.final = digest_null_final,
};

static int cipher_null_setkey ( void *ctx __unused, const void *key __unused,
				size_t keylen __unused ) {
	/* Do nothing */
	return 0;
}

static void cipher_null_setiv ( void *ctx __unused,
				const void *iv __unused ) {
	/* Do nothing */
}

static void cipher_null_encrypt ( void *ctx __unused, const void *src,
				  void *dst, size_t len ) {
	memcpy ( dst, src, len );
}

static void cipher_null_decrypt ( void *ctx __unused, const void *src,
				  void *dst, size_t len ) {
	memcpy ( dst, src, len );
}

struct cipher_algorithm cipher_null = {
	.name = "null",
	.ctxsize = 0,
	.blocksize = 1,
	.setkey = cipher_null_setkey,
	.setiv = cipher_null_setiv,
	.encrypt = cipher_null_encrypt,
	.decrypt = cipher_null_decrypt,
};

struct pubkey_algorithm pubkey_null = {
	.name = "null",
	.ctxsize = 0,
};
