/*
 *   Creation Date: <2003/12/04 17:07:05 samuel>
 *   Time-stamp: <2004/01/07 19:36:09 samuel>
 *
 *	<mac-parts.c>
 *
 *	macintosh partition support
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/load.h"
#include "mac-parts.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"
#include "packages.h"

//#define CONFIG_DEBUG_MAC_PARTS

#ifdef CONFIG_DEBUG_MAC_PARTS
#define DPRINTF(fmt, args...) \
do { printk("MAC-PARTS: " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

typedef struct {
	xt_t		seek_xt, read_xt;
	ucell	        offs_hi, offs_lo;
        ucell	        size_hi, size_lo;
	unsigned int	blocksize;
	phandle_t	filesystem_ph;
} macparts_info_t;

DECLARE_NODE( macparts, INSTALL_OPEN, sizeof(macparts_info_t), "+/packages/mac-parts" );

#define SEEK( pos )		({ DPUSH(pos); call_parent(di->seek_xt); POP(); })
#define READ( buf, size )	({ PUSH(pointer2cell(buf)); PUSH(size); call_parent(di->read_xt); POP(); })

/* ( open -- flag ) */
static void
macparts_open( macparts_info_t *di )
{
	char *str = my_args_copy();
	char *argstr = strdup("");
	char *parstr = strdup("");
	int bs, parnum=-1;
	desc_map_t dmap;
	part_entry_t par;
	int ret = 0;
	int want_bootcode = 0;
	phandle_t ph;
	ducell offs = 0, size = -1;

	DPRINTF("macparts_open '%s'\n", str );

	/* 
		Arguments that we accept:
		id: [0-7]
		[(id)][,][filespec]
	*/

	if( str ) {
		if ( !strlen(str) )
			parnum = -1;
		else {
			/* Detect the boot parameters */
			char *ptr;
			ptr = str;

			/* <id>,<file> */
			if (*ptr >= '0' && *ptr <= '9' && *(ptr + 1) == ',') {
				parstr = ptr;
				*(ptr + 1) = '\0';
				argstr = ptr + 2;
			}

			/* <id> */
			else if (*ptr >= '0' && *ptr <='9' && *(ptr + 1) == '\0') {
				parstr = ptr;
			}

			/* ,<file> */
			else if (*ptr == ',') {
				argstr = ptr + 1;
			}	

			/* <file> */
			else {
				argstr = str;
			}
		
			/* Convert the id to a partition number */
			if (strlen(parstr))
				parnum = atol(parstr);

			/* Detect if we are looking for the bootcode */
			if (strcmp(argstr, "%BOOT") == 0)
				want_bootcode = 1;
		}
	}

	DPRINTF("parstr: %s  argstr: %s  parnum: %d\n", parstr, argstr, parnum);

	DPRINTF("want_bootcode %d\n", want_bootcode);
	DPRINTF("macparts_open %d\n", parnum);

	di->filesystem_ph = 0;
	di->read_xt = find_parent_method("read");
	di->seek_xt = find_parent_method("seek");

	SEEK( 0 );
	if( READ(&dmap, sizeof(dmap)) != sizeof(dmap) )
		goto out;

	/* partition maps might support multiple block sizes; in this case,
	 * pmPyPartStart is typically given in terms of 512 byte blocks.
	 */
	bs = __be16_to_cpu(dmap.sbBlockSize);
	if( bs != 512 ) {
		SEEK( 512 );
		READ( &par, sizeof(par) );
		if( __be16_to_cpu(par.pmSig) == DESC_PART_SIGNATURE )
			bs = 512;
	}
	SEEK( bs );
	if( READ(&par, sizeof(par)) != sizeof(par) )
		goto out;
        if (__be16_to_cpu(par.pmSig) != DESC_PART_SIGNATURE)
		goto out;

	/*
	 * Implement partition selection as per the PowerPC Microprocessor CHRP bindings
	 */

	if (str == NULL || parnum == 0) {
		/* According to the spec, partition 0 as well as no arguments means the whole disk */
		offs = (long long)0;
		size = (long long)__be32_to_cpu(dmap.sbBlkCount) * bs;

		di->blocksize = (unsigned int)bs;

		di->offs_hi = offs >> BITS;
		di->offs_lo = offs & (ucell) -1;
	
		di->size_hi = size >> BITS;
		di->size_lo = size & (ucell) -1;

		ret = -1;
		goto out;

	} else if (parnum == -1 && strlen(argstr)) {

		DPRINTF("mac-parts: counted %d partitions\n", __be32_to_cpu(par.pmMapBlkCnt));

		/* No partition was explicitly requested, but an argstr was passed in.
		   So let's find a suitable partition... */
		for (parnum = 1; parnum <= __be32_to_cpu(par.pmMapBlkCnt); parnum++) {
			SEEK( bs * parnum );
			READ( &par, sizeof(par) );
			if( __be16_to_cpu(par.pmSig) != DESC_PART_SIGNATURE ||
                            !__be32_to_cpu(par.pmPartBlkCnt) )
				break;

			DPRINTF("found partition type: %s with status %x\n", par.pmPartType, __be32_to_cpu(par.pmPartStatus));

			/* If we have a valid, allocated and readable partition... */
			if( (__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsValid) &&
			(__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsAllocated) &&
			(__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsReadable) ) {
				offs = (long long)__be32_to_cpu(par.pmPyPartStart) * bs;
				size = (long long)__be32_to_cpu(par.pmPartBlkCnt) * bs;

				/* If the filename was set to %BOOT, we actually want the bootcode */
				if (want_bootcode && (__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsBootValid)) {
					offs += (long long)__be32_to_cpu(par.pmLgBootStart) * bs;
					size = (long long)__be32_to_cpu(par.pmBootSize);

					goto found;
				} else {
					/* Otherwise we were passed a filename and path. So let's
					   choose the first partition with a valid filesystem */
					DPUSH( offs );
					PUSH_ih( my_parent() );
					parword("find-filesystem");
				
					ph = POP_ph();
					if (ph)
						goto found;
				}
			}
		}

	} else {
		/* Another partition was explicitly requested */
		SEEK( bs * parnum );
		READ( &par, sizeof(par) );

		if( (__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsValid) &&
			    (__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsAllocated) &&
			    (__be32_to_cpu(par.pmPartStatus) & kPartitionAUXIsReadable) ) {

			offs = (long long)__be32_to_cpu(par.pmPyPartStart) * bs;
			size = (long long)__be32_to_cpu(par.pmPartBlkCnt) * bs;
		}
	}

	/* If we couldn't find a partition, exit */
	if (size == -1) {
		DPRINTF("Unable to automatically find partition!\n");
		goto out;
	}

found:

	ret = -1;
	di->blocksize = (unsigned int)bs;

	di->offs_hi = offs >> BITS;
	di->offs_lo = offs & (ucell) -1;

	di->size_hi = size >> BITS;
	di->size_lo = size & (ucell) -1;

	/* We have a valid partition - so probe for a filesystem at the current offset */
	DPRINTF("mac-parts: about to probe for fs\n");
	DPUSH( offs );
	PUSH_ih( my_parent() );
	parword("find-filesystem");
	DPRINTF("mac-parts: done fs probe\n");

	ph = POP_ph();
	if( ph ) {
		DPRINTF("mac-parts: filesystem found with ph " FMT_ucellx " and args %s\n", ph, argstr);
		di->filesystem_ph = ph;

		/* If the filename was %BOOT then it's not a real filename, so clear argstr before
		   attempting interpose */
		if (want_bootcode)
			argstr = strdup("");

		/* If we have been asked to open a particular file, interpose the filesystem package with 
		   the passed filename as an argument */
		if (strlen(argstr)) {
			push_str( argstr );
			PUSH_ph( ph );
			fword("interpose");
		}
	} else {
		DPRINTF("mac-parts: no filesystem found; bypassing misc-files interpose\n");
	}

	free( str );

out:
	PUSH( ret );
}

/* ( block0 -- flag? ) */
static void
macparts_probe( macparts_info_t *dummy )
{
	desc_map_t *dmap = (desc_map_t*)cell2pointer(POP());

	DPRINTF("macparts_probe %x ?= %x\n", dmap->sbSig, DESC_MAP_SIGNATURE);
	if( __be16_to_cpu(dmap->sbSig) != DESC_MAP_SIGNATURE )
		RET(0);
	RET(-1);
}

/* ( -- type offset.d size.d ) */
static void
macparts_get_info( macparts_info_t *di )
{
	DPRINTF("macparts_get_info");

	PUSH( -1 );		/* no type */
	PUSH( di->offs_lo );
	PUSH( di->offs_hi );
	PUSH( di->size_lo );
	PUSH( di->size_hi );
}

static void
macparts_block_size( macparts_info_t *di )
{
	DPRINTF("macparts_block_size = %x\n", di->blocksize);
	PUSH(di->blocksize);
}

static void
macparts_initialize( macparts_info_t *di )
{
	fword("register-partition-package");
}

/* ( pos.d -- status ) */
static void
macparts_seek(macparts_info_t *di )
{
	long long pos = DPOP();
	long long offs, size;

	DPRINTF("macparts_seek %llx:\n", pos);

	/* Seek is invalid if we reach the end of the device */
	size = ((ducell)di->size_hi << BITS) | di->size_lo;
	if (pos > size)
		RET( -1 );

	/* Calculate the seek offset for the parent */
	offs = ((ducell)di->offs_hi << BITS) | di->offs_lo;
	offs += pos;
	DPUSH(offs);

	DPRINTF("macparts_seek parent offset %llx:\n", offs);

	call_package(di->seek_xt, my_parent());
}

/* ( buf len -- actlen ) */
static void
macparts_read(macparts_info_t *di )
{
	DPRINTF("macparts_read\n");

	/* Pass the read back up to the parent */
	call_package(di->read_xt, my_parent());
}

/* ( addr -- size ) */
static void
macparts_load( __attribute__((unused))macparts_info_t *di )
{
	/* Invoke the loader */
	load(my_self());
}

/* ( pathstr len -- ) */
static void
macparts_dir( macparts_info_t *di )
{
	/* On PPC Mac, the first partition chosen according to the CHRP boot
	specification (i.e. marked as bootable) may not necessarily contain 
	a valid FS */
	if ( di->filesystem_ph ) {
		PUSH( my_self() );
		push_str("dir");
		PUSH( di->filesystem_ph );
		fword("find-method");
		POP();
		fword("execute");
	} else {
		forth_printf("mac-parts: Unable to determine filesystem\n");
		POP();
		POP();
	}
}

NODE_METHODS( macparts ) = {
	{ "probe",	macparts_probe 		},
	{ "open",	macparts_open 		},
	{ "seek",	macparts_seek 		},
	{ "read",	macparts_read 		},
	{ "load",	macparts_load 		},
	{ "dir",	macparts_dir 		},
	{ "get-info",	macparts_get_info 	},
	{ "block-size",	macparts_block_size 	},
	{ NULL,		macparts_initialize	},
};

void
macparts_init( void )
{
	REGISTER_NODE( macparts );
}
