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

#define cache_inhibited_access(type,name) 			\
	static inline type ci_read_##name(type * addr)		\
	{							\
		type val;					\
		set_ci();					\
		val = *addr;					\
		clr_ci();					\
		return val;					\
	}							\
	static inline void ci_write_##name(type * addr, type data)	\
	{							\
		set_ci();					\
		*addr = data;					\
		clr_ci();					\
	}

cache_inhibited_access(uint8_t,  8)
cache_inhibited_access(uint16_t, 16)
cache_inhibited_access(uint32_t, 32)
cache_inhibited_access(uint64_t, 64)

#endif
