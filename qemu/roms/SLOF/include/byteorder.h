/******************************************************************************
 * Copyright (c) 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

/*
 * Common byteorder (endianess) macros
 */

#ifndef BYTEORDER_H
#define BYTEORDER_H

static inline uint16_t
bswap_16 (uint16_t x)
{
	return ((x&0xff00) >> 8) | ((x&0xff) << 8);
}

static inline uint32_t
bswap_32 (uint32_t x)
{
	return bswap_16(x >> 16) | (bswap_16(x) << 16);
}

static inline uint64_t
bswap_64 (uint64_t x)
{
	return (uint64_t) bswap_32(x >> 32) | (uint64_t) bswap_32(x) << 32;
}


/* gcc defines __BIG_ENDIAN__ on big endian targets */
#ifdef __BIG_ENDIAN__

#define cpu_to_be16(x) (x)
#define cpu_to_be32(x) (x)
#define cpu_to_be64(x) (x)

#define be16_to_cpu(x) (x)
#define be32_to_cpu(x) (x)
#define be64_to_cpu(x) (x)

#define le16_to_cpu(x) bswap_16(x)
#define le32_to_cpu(x) bswap_32(x)
#define le64_to_cpu(x) bswap_64(x)

#define cpu_to_le16(x) bswap_16(x)
#define cpu_to_le32(x) bswap_32(x)
#define cpu_to_le64(x) bswap_64(x)

#else

#define cpu_to_be16(x) bswap_16(x)
#define cpu_to_be32(x) bswap_32(x)
#define cpu_to_be64(x) bswap_64(x)

#define be16_to_cpu(x) bswap_16(x)
#define be32_to_cpu(x) bswap_32(x)
#define be64_to_cpu(x) bswap_64(x)

#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)

#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)

#endif  /* __BIG_ENDIAN__ */

#endif  /* BYTEORDER_H */
