/*
 *	<ofmem_sparc64.c>
 *
 *	OF Memory manager
 *
 *   Copyright (C) 1999-2004 Samuel Rydh (samuel@ibrium.se)
 *   Copyright (C) 2004 Stefan Reinauer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/string.h"
#include "ofmem_sparc64.h"
#include "spitfire.h"

#define OF_MALLOC_BASE		((char*)OFMEM + ALIGN_SIZE(sizeof(ofmem_t), 8))

#define MEMSIZE ((256 + 512) * 1024)
static union {
	char memory[MEMSIZE];
	ofmem_t ofmem;
} s_ofmem_data;

#define OFMEM      	(&s_ofmem_data.ofmem)
#define TOP_OF_RAM 	(s_ofmem_data.memory + MEMSIZE)

translation_t **g_ofmem_translations = &s_ofmem_data.ofmem.trans;

extern uint64_t qemu_mem_size;

static inline size_t ALIGN_SIZE(size_t x, size_t a)
{
    return (x + a - 1) & ~(a-1);
}

static ucell get_heap_top( void )
{
	return (ucell)(TOP_OF_RAM - ALIGN_SIZE(sizeof(retain_t), 8));
}

ofmem_t* ofmem_arch_get_private(void)
{
	return OFMEM;
}

void* ofmem_arch_get_malloc_base(void)
{
	return OF_MALLOC_BASE;
}

ucell ofmem_arch_get_heap_top(void)
{
	return get_heap_top();
}

ucell ofmem_arch_get_virt_top(void)
{
	return (ucell)TOP_OF_RAM;
}

phys_addr_t ofmem_arch_get_phys_top(void)
{
	ofmem_t *ofmem = ofmem_arch_get_private();

	return ofmem->ramsize;
}

ucell ofmem_arch_get_iomem_base(void)
{
	/* Currently unused */
	return 0;
}

ucell ofmem_arch_get_iomem_top(void)
{
	/* Currently unused */
	return 0;
}

retain_t *ofmem_arch_get_retained(void)
{
	/* Retained area is at the top of physical RAM */
	return (retain_t *)(qemu_mem_size - sizeof(retain_t));
}

int ofmem_arch_get_translation_entry_size(void)
{
	/* Return size of a single MMU package translation property entry in cells */
	return 3;
}

void ofmem_arch_create_translation_entry(ucell *transentry, translation_t *t)
{
	/* Generate translation property entry for SPARC. While there is no
	formal documentation for this, both Linux kernel and OpenSolaris sources
	expect a translation property entry to have the following layout:

		virtual address
		length
		mode 
	*/

	transentry[0] = t->virt;
	transentry[1] = t->size;
	transentry[2] = t->mode;
}

/* Return the size of a memory available entry given the phandle in cells */
int ofmem_arch_get_available_entry_size(phandle_t ph)
{
	if (ph == s_phandle_memory) {
		return 1 + ofmem_arch_get_physaddr_cellsize();
	} else {
		return 1 + 1;
	}
}

/* Generate memory available property entry for Sparc64 */
void ofmem_arch_create_available_entry(phandle_t ph, ucell *availentry, phys_addr_t start, ucell size)
{
	int i = 0;

	if (ph == s_phandle_memory) {
		i += ofmem_arch_encode_physaddr(availentry, start);
	} else {
		availentry[i++] = start;
	}
    
	availentry[i] = size;
}

/************************************************************************/
/* misc                                                                 */
/************************************************************************/

int ofmem_arch_get_physaddr_cellsize(void)
{
    return 1;
}

int ofmem_arch_encode_physaddr(ucell *p, phys_addr_t value)
{
    p[0] = value;
    return 1;
}

ucell ofmem_arch_default_translation_mode( phys_addr_t phys )
{
	/* Writable, cacheable */
	/* not privileged and not locked */
	return SPITFIRE_TTE_CP | SPITFIRE_TTE_CV | SPITFIRE_TTE_WRITABLE;
}

ucell ofmem_arch_io_translation_mode( phys_addr_t phys )
{
	/* Writable, not privileged and not locked */
	return SPITFIRE_TTE_CV | SPITFIRE_TTE_WRITABLE;
}

/************************************************************************/
/* init / cleanup                                                       */
/************************************************************************/

static int remap_page_range( phys_addr_t phys, ucell virt, ucell size, ucell mode )
{
	ofmem_claim_phys(phys, size, 0);
	ofmem_claim_virt(virt, size, 0);
	ofmem_map_page_range(phys, virt, size, mode);
	if (!(mode & SPITFIRE_TTE_LOCKED)) {
		OFMEM_TRACE("remap_page_range clearing translation " FMT_ucellx
				" -> " FMT_ucellx " " FMT_ucellx " mode " FMT_ucellx "\n",
				virt, phys, size, mode );
		ofmem_arch_unmap_pages(virt, size);
	}
	return 0;
}

#define RETAIN_MAGIC	0x1100220033004400

void ofmem_init( void )
{
	retain_t *retained = ofmem_arch_get_retained();
	int i;

	memset(&s_ofmem_data, 0, sizeof(s_ofmem_data));
	s_ofmem_data.ofmem.ramsize = qemu_mem_size;

	/* inherit translations set up by entry.S */
	ofmem_walk_boot_map(remap_page_range);

        /* Map the memory */
        ofmem_map_page_range(0, 0, qemu_mem_size, 0x36);

	if (!(retained->magic == RETAIN_MAGIC)) {
		OFMEM_TRACE("ofmem_init: no retained magic found, creating\n");
		retained->magic = RETAIN_MAGIC;
		retained->numentries = 0;
	} else {
		OFMEM_TRACE("ofmem_init: retained magic found, total %lld mappings\n", retained->numentries);	

		/* Mark physical addresses as used so they are not reallocated */
		for (i = 0; i < retained->numentries; i++) {
			ofmem_claim_phys(retained->retain_phys_range[i].start, 
				retained->retain_phys_range[i].size, 0);
		}

		/* Reset retained area for next reset */
		retained->magic = RETAIN_MAGIC;
		retained->numentries = 0;
	}
}
