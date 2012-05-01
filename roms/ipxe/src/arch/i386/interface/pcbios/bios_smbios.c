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

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/uaccess.h>
#include <ipxe/smbios.h>
#include <realmode.h>
#include <pnpbios.h>

/** @file
 *
 * System Management BIOS
 *
 */

/**
 * Find SMBIOS
 *
 * @v smbios		SMBIOS entry point descriptor structure to fill in
 * @ret rc		Return status code
 */
static int bios_find_smbios ( struct smbios *smbios ) {
	union {
		struct smbios_entry entry;
		uint8_t bytes[256]; /* 256 is maximum length possible */
	} u;
	static unsigned int offset = 0;
	size_t len;
	unsigned int i;
	uint8_t sum;

	/* Try to find SMBIOS */
	for ( ; offset < 0x10000 ; offset += 0x10 ) {

		/* Read start of header and verify signature */
		copy_from_real ( &u.entry, BIOS_SEG, offset,
				 sizeof ( u.entry ));
		if ( u.entry.signature != SMBIOS_SIGNATURE )
			continue;

		/* Read whole header and verify checksum */
		len = u.entry.len;
		copy_from_real ( &u.bytes, BIOS_SEG, offset, len );
		for ( i = 0 , sum = 0 ; i < len ; i++ ) {
			sum += u.bytes[i];
		}
		if ( sum != 0 ) {
			DBG ( "SMBIOS at %04x:%04x has bad checksum %02x\n",
			      BIOS_SEG, offset, sum );
			continue;
		}

		/* Fill result structure */
		DBG ( "Found SMBIOS v%d.%d entry point at %04x:%04x\n",
		      u.entry.major, u.entry.minor, BIOS_SEG, offset );
		smbios->address = phys_to_user ( u.entry.smbios_address );
		smbios->len = u.entry.smbios_len;
		smbios->count = u.entry.smbios_count;
		return 0;
	}

	DBG ( "No SMBIOS found\n" );
	return -ENODEV;
}

PROVIDE_SMBIOS ( pcbios, find_smbios, bios_find_smbios );
