/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef __CACHE_H
#define __CACHE_H

#include <cpu.h>
#include <stdint.h>

// XXX FIXME: Use proper CI load/store */
#define cache_inhibited_access(type,name) 			\
	static inline type ci_read_##name(type * addr)		\
	{							\
		type val;					\
		val = *addr;					\
		return val;					\
	}							\
	static inline void ci_write_##name(type * addr, type data)	\
	{							\
		*addr = data;					\
	}

cache_inhibited_access(uint8_t,  8)
cache_inhibited_access(uint16_t, 16)
cache_inhibited_access(uint32_t, 32)
cache_inhibited_access(uint64_t, 64)

static inline uint16_t bswap16_load(uint64_t addr)
{
	unsigned int val;
	asm volatile ("lhbrx %0, 0, %1":"=r" (val):"r"(addr));
	return val;
}

static inline uint32_t bswap32_load(uint64_t addr)
{
	unsigned int val;
	asm volatile ("lwbrx %0, 0, %1":"=r" (val):"r"(addr));
	return val;
}

static inline void bswap16_store(uint64_t addr, uint16_t val)
{
	asm volatile ("sthbrx %0, 0, %1"::"r" (val), "r"(addr));
}

static inline void bswap32_store(uint64_t addr, uint32_t val)
{
	asm volatile ("stwbrx %0, 0, %1"::"r" (val), "r"(addr));
}

#endif /* __CACHE_H */

