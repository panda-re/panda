/* 
 * Cryptographic API.
 *
 * MD5 Message Digest Algorithm (RFC1321).
 *
 * Derived from cryptoapi implementation, originally based on the
 * public domain implementation written by Colin Plumb in 1993.
 *
 * Reduced object size by around 50% compared to the original Linux
 * version for use in Etherboot by Michael Brown.
 *
 * Copyright (c) Cryptoapi developers.
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2006 Michael Brown <mbrown@fensystems.co.uk>
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <ipxe/crypto.h>
#include <ipxe/md5.h>

struct md5_step {
	u32 ( * f ) ( u32 b, u32 c, u32 d );
	u8 coefficient;
	u8 constant;
};

static u32 f1(u32 b, u32 c, u32 d)
{
	return ( d ^ ( b & ( c ^ d ) ) );
}

static u32 f2(u32 b, u32 c, u32 d)
{
	return ( c ^ ( d & ( b ^ c ) ) );
}

static u32 f3(u32 b, u32 c, u32 d)
{
	return ( b ^ c ^ d );
}

static u32 f4(u32 b, u32 c, u32 d)
{
	return ( c ^ ( b | ~d ) );
}

static struct md5_step md5_steps[4] = {
	{
		.f = f1,
		.coefficient = 1,
		.constant = 0,
	},
	{
		.f = f2,
		.coefficient = 5,
		.constant = 1,
	},
	{
		.f = f3,
		.coefficient = 3,
		.constant = 5,
	},
	{
		.f = f4,
		.coefficient = 7,
		.constant = 0,
	}
};

static const u8 r[64] = {
	7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
	5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
	4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
	6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static const u32 k[64] = {
	0xd76aa478UL, 0xe8c7b756UL, 0x242070dbUL, 0xc1bdceeeUL,
	0xf57c0fafUL, 0x4787c62aUL, 0xa8304613UL, 0xfd469501UL,
	0x698098d8UL, 0x8b44f7afUL, 0xffff5bb1UL, 0x895cd7beUL,
	0x6b901122UL, 0xfd987193UL, 0xa679438eUL, 0x49b40821UL,
	0xf61e2562UL, 0xc040b340UL, 0x265e5a51UL, 0xe9b6c7aaUL,
	0xd62f105dUL, 0x02441453UL, 0xd8a1e681UL, 0xe7d3fbc8UL,
	0x21e1cde6UL, 0xc33707d6UL, 0xf4d50d87UL, 0x455a14edUL,
	0xa9e3e905UL, 0xfcefa3f8UL, 0x676f02d9UL, 0x8d2a4c8aUL,
	0xfffa3942UL, 0x8771f681UL, 0x6d9d6122UL, 0xfde5380cUL,
	0xa4beea44UL, 0x4bdecfa9UL, 0xf6bb4b60UL, 0xbebfbc70UL,
	0x289b7ec6UL, 0xeaa127faUL, 0xd4ef3085UL, 0x04881d05UL,
	0xd9d4d039UL, 0xe6db99e5UL, 0x1fa27cf8UL, 0xc4ac5665UL,
	0xf4292244UL, 0x432aff97UL, 0xab9423a7UL, 0xfc93a039UL,
	0x655b59c3UL, 0x8f0ccc92UL, 0xffeff47dUL, 0x85845dd1UL,
	0x6fa87e4fUL, 0xfe2ce6e0UL, 0xa3014314UL, 0x4e0811a1UL,
	0xf7537e82UL, 0xbd3af235UL, 0x2ad7d2bbUL, 0xeb86d391UL,
};

static void md5_transform(u32 *hash, const u32 *in)
{
	u32 a, b, c, d, f, g, temp;
	int i;
	struct md5_step *step;

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];

	for ( i = 0 ; i < 64 ; i++ ) {
		step = &md5_steps[i >> 4];
		f = step->f ( b, c, d );
		g = ( ( i * step->coefficient + step->constant ) & 0xf );
		temp = d;
		d = c;
		c = b;
		a += ( f + k[i] + in[g] );
		a = ( ( a << r[i] ) | ( a >> ( 32-r[i] ) ) );
		b += a;
		a = temp;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}

/* XXX: this stuff can be optimized */
static inline void le32_to_cpu_array(u32 *buf, unsigned int words)
{
	while (words--) {
		le32_to_cpus(buf);
		buf++;
	}
}

static inline void cpu_to_le32_array(u32 *buf, unsigned int words)
{
	while (words--) {
		cpu_to_le32s(buf);
		buf++;
	}
}

static inline void md5_transform_helper(struct md5_ctx *ctx)
{
	le32_to_cpu_array(ctx->block, sizeof(ctx->block) / sizeof(u32));
	md5_transform(ctx->hash, ctx->block);
}

static void md5_init(void *context)
{
	struct md5_ctx *mctx = context;

	mctx->hash[0] = 0x67452301;
	mctx->hash[1] = 0xefcdab89;
	mctx->hash[2] = 0x98badcfe;
	mctx->hash[3] = 0x10325476;
	mctx->byte_count = 0;
}

static void md5_update(void *context, const void *data, size_t len)
{
	struct md5_ctx *mctx = context;
	const u32 avail = sizeof(mctx->block) - (mctx->byte_count & 0x3f);

	mctx->byte_count += len;

	if (avail > len) {
		memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),
		       data, len);
		return;
	}

	memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),
	       data, avail);

	md5_transform_helper(mctx);
	data += avail;
	len -= avail;

	while (len >= sizeof(mctx->block)) {
		memcpy(mctx->block, data, sizeof(mctx->block));
		md5_transform_helper(mctx);
		data += sizeof(mctx->block);
		len -= sizeof(mctx->block);
	}

	memcpy(mctx->block, data, len);
}

static void md5_final(void *context, void *out)
{
	struct md5_ctx *mctx = context;
	const unsigned int offset = mctx->byte_count & 0x3f;
	char *p = (char *)mctx->block + offset;
	int padding = 56 - (offset + 1);

	*p++ = 0x80;
	if (padding < 0) {
		memset(p, 0x00, padding + sizeof (u64));
		md5_transform_helper(mctx);
		p = (char *)mctx->block;
		padding = 56;
	}

	memset(p, 0, padding);
	mctx->block[14] = mctx->byte_count << 3;
	mctx->block[15] = mctx->byte_count >> 29;
	le32_to_cpu_array(mctx->block, (sizeof(mctx->block) -
	                  sizeof(u64)) / sizeof(u32));
	md5_transform(mctx->hash, mctx->block);
	cpu_to_le32_array(mctx->hash, sizeof(mctx->hash) / sizeof(u32));
	memcpy(out, mctx->hash, sizeof(mctx->hash));
	memset(mctx, 0, sizeof(*mctx));
}

struct digest_algorithm md5_algorithm = {
	.name		= "md5",
	.ctxsize	= MD5_CTX_SIZE,
	.blocksize	= ( MD5_BLOCK_WORDS * 4 ),
	.digestsize	= MD5_DIGEST_SIZE,
	.init		= md5_init,
	.update		= md5_update,
	.final		= md5_final,
};
