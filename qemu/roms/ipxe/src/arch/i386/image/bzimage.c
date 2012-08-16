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
 * Linux bzImage image format
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <realmode.h>
#include <bzimage.h>
#include <ipxe/uaccess.h>
#include <ipxe/image.h>
#include <ipxe/segment.h>
#include <ipxe/init.h>
#include <ipxe/cpio.h>
#include <ipxe/features.h>

FEATURE ( FEATURE_IMAGE, "bzImage", DHCP_EB_FEATURE_BZIMAGE, 1 );

/**
 * bzImage context
 */
struct bzimage_context {
	/** Boot protocol version */
	unsigned int version;
	/** Real-mode kernel portion load segment address */
	unsigned int rm_kernel_seg;
	/** Real-mode kernel portion load address */
	userptr_t rm_kernel;
	/** Real-mode kernel portion file size */
	size_t rm_filesz;
	/** Real-mode heap top (offset from rm_kernel) */
	size_t rm_heap;
	/** Command line (offset from rm_kernel) */
	size_t rm_cmdline;
	/** Command line maximum length */
	size_t cmdline_size;
	/** Real-mode kernel portion total memory size */
	size_t rm_memsz;
	/** Non-real-mode kernel portion load address */
	userptr_t pm_kernel;
	/** Non-real-mode kernel portion file and memory size */
	size_t pm_sz;
	/** Video mode */
	unsigned int vid_mode;
	/** Memory limit */
	uint64_t mem_limit;
	/** Initrd address */
	physaddr_t ramdisk_image;
	/** Initrd size */
	physaddr_t ramdisk_size;

	/** Command line magic block */
	struct bzimage_cmdline cmdline_magic;
	/** bzImage header */
	struct bzimage_header bzhdr;
};

/**
 * Parse bzImage header
 *
 * @v image		bzImage file
 * @v bzimg		bzImage context
 * @v src		bzImage to parse
 * @ret rc		Return status code
 */
static int bzimage_parse_header ( struct image *image,
				  struct bzimage_context *bzimg,
				  userptr_t src ) {
	unsigned int syssize;
	int is_bzimage;

	/* Sanity check */
	if ( image->len < ( BZI_HDR_OFFSET + sizeof ( bzimg->bzhdr ) ) ) {
		DBGC ( image, "bzImage %p too short for kernel header\n",
		       image );
		return -ENOEXEC;
	}

	/* Read in header structures */
	memset ( bzimg, 0, sizeof ( *bzimg ) );
	copy_from_user ( &bzimg->cmdline_magic, src, BZI_CMDLINE_OFFSET,
			 sizeof ( bzimg->cmdline_magic ) );
	copy_from_user ( &bzimg->bzhdr, src, BZI_HDR_OFFSET,
			 sizeof ( bzimg->bzhdr ) );

	/* Calculate size of real-mode portion */
	bzimg->rm_filesz = ( ( ( bzimg->bzhdr.setup_sects ?
				 bzimg->bzhdr.setup_sects : 4 ) + 1 ) << 9 );
	if ( bzimg->rm_filesz > image->len ) {
		DBGC ( image, "bzImage %p too short for %zd byte of setup\n",
		       image, bzimg->rm_filesz );
		return -ENOEXEC;
	}
	bzimg->rm_memsz = BZI_ASSUMED_RM_SIZE;

	/* Calculate size of protected-mode portion */
	bzimg->pm_sz = ( image->len - bzimg->rm_filesz );
	syssize = ( ( bzimg->pm_sz + 15 ) / 16 );

	/* Check for signatures and determine version */
	if ( bzimg->bzhdr.boot_flag != BZI_BOOT_FLAG ) {
		DBGC ( image, "bzImage %p missing 55AA signature\n", image );
		return -ENOEXEC;
	}
	if ( bzimg->bzhdr.header == BZI_SIGNATURE ) {
		/* 2.00+ */
		bzimg->version = bzimg->bzhdr.version;
	} else {
		/* Pre-2.00.  Check that the syssize field is correct,
		 * as a guard against accepting arbitrary binary data,
		 * since the 55AA check is pretty lax.  Note that the
		 * syssize field is unreliable for protocols between
		 * 2.00 and 2.03 inclusive, so we should not always
		 * check this field.
		 */
		bzimg->version = 0x0100;
		if ( bzimg->bzhdr.syssize != syssize ) {
			DBGC ( image, "bzImage %p bad syssize %x (expected "
			       "%x)\n", image, bzimg->bzhdr.syssize, syssize );
			return -ENOEXEC;
		}
	}

	/* Determine image type */
	is_bzimage = ( ( bzimg->version >= 0x0200 ) ?
		       ( bzimg->bzhdr.loadflags & BZI_LOAD_HIGH ) : 0 );

	/* Calculate load address of real-mode portion */
	bzimg->rm_kernel_seg = ( is_bzimage ? 0x1000 : 0x9000 );
	bzimg->rm_kernel = real_to_user ( bzimg->rm_kernel_seg, 0 );

	/* Allow space for the stack and heap */
	bzimg->rm_memsz += BZI_STACK_SIZE;
	bzimg->rm_heap = bzimg->rm_memsz;

	/* Allow space for the command line */
	bzimg->rm_cmdline = bzimg->rm_memsz;
	bzimg->rm_memsz += BZI_CMDLINE_SIZE;

	/* Calculate load address of protected-mode portion */
	bzimg->pm_kernel = phys_to_user ( is_bzimage ? BZI_LOAD_HIGH_ADDR
					: BZI_LOAD_LOW_ADDR );

	/* Extract video mode */
	bzimg->vid_mode = bzimg->bzhdr.vid_mode;

	/* Extract memory limit */
	bzimg->mem_limit = ( ( bzimg->version >= 0x0203 ) ?
			     bzimg->bzhdr.initrd_addr_max : BZI_INITRD_MAX );

	/* Extract command line size */
	bzimg->cmdline_size = ( ( bzimg->version >= 0x0206 ) ?
				bzimg->bzhdr.cmdline_size : BZI_CMDLINE_SIZE );

	DBGC ( image, "bzImage %p version %04x RM %#lx+%#zx PM %#lx+%#zx "
	       "cmdlen %zd\n", image, bzimg->version,
	       user_to_phys ( bzimg->rm_kernel, 0 ), bzimg->rm_filesz,
	       user_to_phys ( bzimg->pm_kernel, 0 ), bzimg->pm_sz,
	       bzimg->cmdline_size );

	return 0;
}

/**
 * Update bzImage header in loaded kernel
 *
 * @v image		bzImage file
 * @v bzimg		bzImage context
 * @v dst		bzImage to update
 */
static void bzimage_update_header ( struct image *image,
				    struct bzimage_context *bzimg,
				    userptr_t dst ) {

	/* Set loader type */
	if ( bzimg->version >= 0x0200 )
		bzimg->bzhdr.type_of_loader = BZI_LOADER_TYPE_IPXE;

	/* Set heap end pointer */
	if ( bzimg->version >= 0x0201 ) {
		bzimg->bzhdr.heap_end_ptr = ( bzimg->rm_heap - 0x200 );
		bzimg->bzhdr.loadflags |= BZI_CAN_USE_HEAP;
	}

	/* Set command line */
	if ( bzimg->version >= 0x0202 ) {
		bzimg->bzhdr.cmd_line_ptr = user_to_phys ( bzimg->rm_kernel,
							   bzimg->rm_cmdline );
	} else {
		bzimg->cmdline_magic.magic = BZI_CMDLINE_MAGIC;
		bzimg->cmdline_magic.offset = bzimg->rm_cmdline;
		bzimg->bzhdr.setup_move_size = bzimg->rm_memsz;
	}

	/* Set video mode */
	bzimg->bzhdr.vid_mode = bzimg->vid_mode;

	/* Set initrd address */
	if ( bzimg->version >= 0x0200 ) {
		bzimg->bzhdr.ramdisk_image = bzimg->ramdisk_image;
		bzimg->bzhdr.ramdisk_size = bzimg->ramdisk_size;
	}

	/* Write out header structures */
	copy_to_user ( dst, BZI_CMDLINE_OFFSET, &bzimg->cmdline_magic,
		       sizeof ( bzimg->cmdline_magic ) );
	copy_to_user ( dst, BZI_HDR_OFFSET, &bzimg->bzhdr,
		       sizeof ( bzimg->bzhdr ) );

	DBGC ( image, "bzImage %p vidmode %d\n", image, bzimg->vid_mode );
}

/**
 * Parse kernel command line for bootloader parameters
 *
 * @v image		bzImage file
 * @v bzimg		bzImage context
 * @v cmdline		Kernel command line
 * @ret rc		Return status code
 */
static int bzimage_parse_cmdline ( struct image *image,
				   struct bzimage_context *bzimg,
				   const char *cmdline ) {
	char *vga;
	char *mem;

	/* Look for "vga=" */
	if ( ( vga = strstr ( cmdline, "vga=" ) ) ) {
		vga += 4;
		if ( strcmp ( vga, "normal" ) == 0 ) {
			bzimg->vid_mode = BZI_VID_MODE_NORMAL;
		} else if ( strcmp ( vga, "ext" ) == 0 ) {
			bzimg->vid_mode = BZI_VID_MODE_EXT;
		} else if ( strcmp ( vga, "ask" ) == 0 ) {
			bzimg->vid_mode = BZI_VID_MODE_ASK;
		} else {
			bzimg->vid_mode = strtoul ( vga, &vga, 0 );
			if ( *vga && ( *vga != ' ' ) ) {
				DBGC ( image, "bzImage %p strange \"vga=\""
				       "terminator '%c'\n", image, *vga );
			}
		}
	}

	/* Look for "mem=" */
	if ( ( mem = strstr ( cmdline, "mem=" ) ) ) {
		mem += 4;
		bzimg->mem_limit = strtoul ( mem, &mem, 0 );
		switch ( *mem ) {
		case 'G':
		case 'g':
			bzimg->mem_limit <<= 10;
		case 'M':
		case 'm':
			bzimg->mem_limit <<= 10;
		case 'K':
		case 'k':
			bzimg->mem_limit <<= 10;
			break;
		case '\0':
		case ' ':
			break;
		default:
			DBGC ( image, "bzImage %p strange \"mem=\" "
			       "terminator '%c'\n", image, *mem );
			break;
		}
		bzimg->mem_limit -= 1;
	}

	return 0;
}

/**
 * Set command line
 *
 * @v image		bzImage image
 * @v bzimg		bzImage context
 * @v cmdline		Kernel command line
 * @ret rc		Return status code
 */
static int bzimage_set_cmdline ( struct image *image,
				 struct bzimage_context *bzimg,
				 const char *cmdline ) {
	size_t cmdline_len;

	/* Copy command line down to real-mode portion */
	cmdline_len = ( strlen ( cmdline ) + 1 );
	if ( cmdline_len > bzimg->cmdline_size )
		cmdline_len = bzimg->cmdline_size;
	copy_to_user ( bzimg->rm_kernel, bzimg->rm_cmdline,
		       cmdline, cmdline_len );
	DBGC ( image, "bzImage %p command line \"%s\"\n", image, cmdline );

	return 0;
}

/**
 * Load initrd
 *
 * @v image		bzImage image
 * @v initrd		initrd image
 * @v address		Address at which to load, or UNULL
 * @ret len		Length of loaded image, rounded up to 4 bytes
 */
static size_t bzimage_load_initrd ( struct image *image,
				    struct image *initrd,
				    userptr_t address ) {
	char *filename = initrd->cmdline;
	struct cpio_header cpio;
        size_t offset = 0;

	/* Do not include kernel image itself as an initrd */
	if ( initrd == image )
		return 0;

	/* Create cpio header before non-prebuilt images */
	if ( filename && filename[0] ) {
		size_t name_len = ( strlen ( filename ) + 1 );

		DBGC ( image, "bzImage %p inserting initrd %p as %s\n",
		       image, initrd, filename );
		memset ( &cpio, '0', sizeof ( cpio ) );
		memcpy ( cpio.c_magic, CPIO_MAGIC, sizeof ( cpio.c_magic ) );
		cpio_set_field ( cpio.c_mode, 0100644 );
		cpio_set_field ( cpio.c_nlink, 1 );
		cpio_set_field ( cpio.c_filesize, initrd->len );
		cpio_set_field ( cpio.c_namesize, name_len );
		if ( address ) {
			copy_to_user ( address, offset, &cpio,
				       sizeof ( cpio ) );
		}
		offset += sizeof ( cpio );
		if ( address ) {
			copy_to_user ( address, offset, filename,
				       name_len );
		}
		offset += name_len;
		offset = ( ( offset + 0x03 ) & ~0x03 );
	}

	/* Copy in initrd image body */
	if ( address )
		memcpy_user ( address, offset, initrd->data, 0, initrd->len );
	offset += initrd->len;
	if ( address ) {
		DBGC ( image, "bzImage %p has initrd %p at [%lx,%lx)\n",
		       image, initrd, user_to_phys ( address, 0 ),
		       user_to_phys ( address, offset ) );
	}

	/* Round up to 4-byte boundary */
	offset = ( ( offset + 0x03 ) & ~0x03 );
	return offset;
}

/**
 * Load initrds, if any
 *
 * @v image		bzImage image
 * @v bzimg		bzImage context
 * @ret rc		Return status code
 */
static int bzimage_load_initrds ( struct image *image,
				  struct bzimage_context *bzimg ) {
	struct image *initrd;
	size_t total_len = 0;
	physaddr_t address;
	int rc;

	/* Add up length of all initrd images */
	for_each_image ( initrd )
		total_len += bzimage_load_initrd ( image, initrd, UNULL );

	/* Give up if no initrd images found */
	if ( ! total_len )
		return 0;

	/* Find a suitable start address.  Try 1MB boundaries,
	 * starting from the downloaded kernel image itself and
	 * working downwards until we hit an available region.
	 */
	for ( address = ( user_to_phys ( image->data, 0 ) & ~0xfffff ) ; ;
	      address -= 0x100000 ) {
		/* Check that we're not going to overwrite the
		 * kernel itself.  This check isn't totally
		 * accurate, but errs on the side of caution.
		 */
		if ( address <= ( BZI_LOAD_HIGH_ADDR + image->len ) ) {
			DBGC ( image, "bzImage %p could not find a location "
			       "for initrd\n", image );
			return -ENOBUFS;
		}
		/* Check that we are within the kernel's range */
		if ( ( address + total_len - 1 ) > bzimg->mem_limit )
			continue;
		/* Prepare and verify segment */
		if ( ( rc = prep_segment ( phys_to_user ( address ), 0,
					   total_len ) ) != 0 )
			continue;
		/* Use this address */
		break;
	}

	/* Record initrd location */
	bzimg->ramdisk_image = address;
	bzimg->ramdisk_size = total_len;

	/* Construct initrd */
	DBGC ( image, "bzImage %p constructing initrd at [%lx,%lx)\n",
	       image, address, ( address + total_len ) );
	for_each_image ( initrd ) {
		address += bzimage_load_initrd ( image, initrd,
						 phys_to_user ( address ) );
	}

	return 0;
}

/**
 * Execute bzImage image
 *
 * @v image		bzImage image
 * @ret rc		Return status code
 */
static int bzimage_exec ( struct image *image ) {
	struct bzimage_context bzimg;
	const char *cmdline = ( image->cmdline ? image->cmdline : "" );
	int rc;

	/* Read and parse header from image */
	if ( ( rc = bzimage_parse_header ( image, &bzimg,
					   image->data ) ) != 0 )
		return rc;

	/* Prepare segments */
	if ( ( rc = prep_segment ( bzimg.rm_kernel, bzimg.rm_filesz,
				   bzimg.rm_memsz ) ) != 0 ) {
		DBGC ( image, "bzImage %p could not prepare RM segment: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}
	if ( ( rc = prep_segment ( bzimg.pm_kernel, bzimg.pm_sz,
				   bzimg.pm_sz ) ) != 0 ) {
		DBGC ( image, "bzImage %p could not prepare PM segment: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	/* Load segments */
	memcpy_user ( bzimg.rm_kernel, 0, image->data,
		      0, bzimg.rm_filesz );
	memcpy_user ( bzimg.pm_kernel, 0, image->data,
		      bzimg.rm_filesz, bzimg.pm_sz );

	/* Update and write out header */
	bzimage_update_header ( image, &bzimg, bzimg.rm_kernel );

	/* Parse command line for bootloader parameters */
	if ( ( rc = bzimage_parse_cmdline ( image, &bzimg, cmdline ) ) != 0)
		return rc;

	/* Store command line */
	if ( ( rc = bzimage_set_cmdline ( image, &bzimg, cmdline ) ) != 0 )
		return rc;

	/* Load any initrds */
	if ( ( rc = bzimage_load_initrds ( image, &bzimg ) ) != 0 )
		return rc;

	/* Update kernel header */
	bzimage_update_header ( image, &bzimg, bzimg.rm_kernel );

	/* Prepare for exiting */
	shutdown_boot();

	DBGC ( image, "bzImage %p jumping to RM kernel at %04x:0000 "
	       "(stack %04x:%04zx)\n", image, ( bzimg.rm_kernel_seg + 0x20 ),
	       bzimg.rm_kernel_seg, bzimg.rm_heap );

	/* Jump to the kernel */
	__asm__ __volatile__ ( REAL_CODE ( "movw %w0, %%ds\n\t"
					   "movw %w0, %%es\n\t"
					   "movw %w0, %%fs\n\t"
					   "movw %w0, %%gs\n\t"
					   "movw %w0, %%ss\n\t"
					   "movw %w1, %%sp\n\t"
					   "pushw %w2\n\t"
					   "pushw $0\n\t"
					   "lret\n\t" )
			       : : "r" ( bzimg.rm_kernel_seg ),
			           "r" ( bzimg.rm_heap ),
			           "r" ( bzimg.rm_kernel_seg + 0x20 ) );

	/* There is no way for the image to return, since we provide
	 * no return address.
	 */
	assert ( 0 );

	return -ECANCELED; /* -EIMPOSSIBLE */
}

/**
 * Probe bzImage image
 *
 * @v image		bzImage file
 * @ret rc		Return status code
 */
int bzimage_probe ( struct image *image ) {
	struct bzimage_context bzimg;
	int rc;

	/* Read and parse header from image */
	if ( ( rc = bzimage_parse_header ( image, &bzimg,
					   image->data ) ) != 0 )
		return rc;

	return 0;
}

/** Linux bzImage image type */
struct image_type bzimage_image_type __image_type ( PROBE_NORMAL ) = {
	.name = "bzImage",
	.probe = bzimage_probe,
	.exec = bzimage_exec,
};
