/*
 *	<ofmem_sparc64.h>
 *
 *	OF Memory manager
 *
 *   Copyright (C) 1999, 2002 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#ifndef _H_OFMEM_SPARC64
#define _H_OFMEM_SPARC64

#include "libopenbios/ofmem.h"

extern void ofmem_map_pages(ucell phys, ucell virt, ucell size, ucell mode);

typedef int (*translation_entry_cb)(ucell phys,	ucell virt,
									ucell size, ucell mode);

extern void ofmem_walk_boot_map(translation_entry_cb cb);

extern translation_t **g_ofmem_translations;

extern void dtlb_miss_handler(void);
extern void itlb_miss_handler(void);
extern void bug(void);

#endif   /* _H_OFMEM_SPARC64 */
