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
 * External memory allocation
 *
 */

#include <limits.h>
#include <errno.h>
#include <ipxe/uaccess.h>
#include <ipxe/hidemem.h>
#include <ipxe/io.h>
#include <ipxe/umalloc.h>

/** Alignment of external allocated memory */
#define EM_ALIGN ( 4 * 1024 )

/** Equivalent of NOWHERE for user pointers */
#define UNOWHERE ( ~UNULL )

/** An external memory block */
struct external_memory {
	/** Size of this memory block (excluding this header) */
	size_t size;
	/** Block is currently in use */
	int used;
};

/** Top of heap */
static userptr_t top = UNULL;

/** Bottom of heap (current lowest allocated block) */
static userptr_t bottom = UNULL;

/**
 * Initialise external heap
 *
 * @ret rc		Return status code
 */
static int init_eheap ( void ) {
	struct memory_map memmap;
	unsigned long heap_size = 0;
	unsigned int i;

	DBG ( "Allocating external heap\n" );

	get_memmap ( &memmap );
	for ( i = 0 ; i < memmap.count ; i++ ) {
		struct memory_region *region = &memmap.regions[i];
		unsigned long r_start, r_end;
		unsigned long r_size;

		DBG ( "Considering [%llx,%llx)\n", region->start, region->end);

		/* Truncate block to 4GB */
		if ( region->start > UINT_MAX ) {
			DBG ( "...starts after 4GB\n" );
			continue;
		}
		r_start = region->start;
		if ( region->end > UINT_MAX ) {
			DBG ( "...end truncated to 4GB\n" );
			r_end = 0; /* =4GB, given the wraparound */
		} else {
			r_end = region->end;
		}

		/* Use largest block */
		r_size = ( r_end - r_start );
		if ( r_size > heap_size ) {
			DBG ( "...new best block found\n" );
			top = bottom = phys_to_user ( r_end );
			heap_size = r_size;
		}
	}

	if ( ! heap_size ) {
		DBG ( "No external heap available\n" );
		return -ENOMEM;
	}

	DBG ( "External heap grows downwards from %lx\n",
	      user_to_phys ( top, 0 ) );
	return 0;
}

/**
 * Collect free blocks
 *
 */
static void ecollect_free ( void ) {
	struct external_memory extmem;

	/* Walk the free list and collect empty blocks */
	while ( bottom != top ) {
		copy_from_user ( &extmem, bottom, -sizeof ( extmem ),
				 sizeof ( extmem ) );
		if ( extmem.used )
			break;
		DBG ( "EXTMEM freeing [%lx,%lx)\n", user_to_phys ( bottom, 0 ),
		      user_to_phys ( bottom, extmem.size ) );
		bottom = userptr_add ( bottom,
				       ( extmem.size + sizeof ( extmem ) ) );
	}
}

/**
 * Reallocate external memory
 *
 * @v old_ptr		Memory previously allocated by umalloc(), or UNULL
 * @v new_size		Requested size
 * @ret new_ptr		Allocated memory, or UNULL
 *
 * Calling realloc() with a new size of zero is a valid way to free a
 * memory block.
 */
static userptr_t memtop_urealloc ( userptr_t ptr, size_t new_size ) {
	struct external_memory extmem;
	userptr_t new = ptr;
	size_t align;
	int rc;

	/* Initialise external memory allocator if necessary */
	if ( bottom == top ) {
		if ( ( rc = init_eheap() ) != 0 )
			return UNULL;
	}

	/* Get block properties into extmem */
	if ( ptr && ( ptr != UNOWHERE ) ) {
		/* Determine old size */
		copy_from_user ( &extmem, ptr, -sizeof ( extmem ),
				 sizeof ( extmem ) );
	} else {
		/* Create a zero-length block */
		ptr = bottom = userptr_add ( bottom, -sizeof ( extmem ) );
		DBG ( "EXTMEM allocating [%lx,%lx)\n",
		      user_to_phys ( ptr, 0 ), user_to_phys ( ptr, 0 ) );
		extmem.size = 0;
	}
	extmem.used = ( new_size > 0 );

	/* Expand/shrink block if possible */
	if ( ptr == bottom ) {
		/* Update block */
		new = userptr_add ( ptr, - ( new_size - extmem.size ) );
		align = ( user_to_phys ( new, 0 ) & ( EM_ALIGN - 1 ) );
		new_size += align;
		new = userptr_add ( new, -align );
		DBG ( "EXTMEM expanding [%lx,%lx) to [%lx,%lx)\n",
		      user_to_phys ( ptr, 0 ),
		      user_to_phys ( ptr, extmem.size ),
		      user_to_phys ( new, 0 ),
		      user_to_phys ( new, new_size ));
		memmove_user ( new, 0, ptr, 0, ( ( extmem.size < new_size ) ?
						 extmem.size : new_size ) );
		extmem.size = new_size;
		bottom = new;
	} else {
		/* Cannot expand; can only pretend to shrink */
		if ( new_size > extmem.size ) {
			/* Refuse to expand */
			DBG ( "EXTMEM cannot expand [%lx,%lx)\n",
			      user_to_phys ( ptr, 0 ),
			      user_to_phys ( ptr, extmem.size ) );
			return UNULL;
		}
	}

	/* Write back block properties */
	copy_to_user ( new, -sizeof ( extmem ), &extmem,
		       sizeof ( extmem ) );

	/* Collect any free blocks and update hidden memory region */
	ecollect_free();
	hide_umalloc ( user_to_phys ( bottom, -sizeof ( extmem ) ),
		       user_to_phys ( top, 0 ) );

	return ( new_size ? new : UNOWHERE );
}

PROVIDE_UMALLOC ( memtop, urealloc, memtop_urealloc );
