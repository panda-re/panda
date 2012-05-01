/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <errno.h>
#include <ipxe/efi/efi.h>
#include <ipxe/image.h>
#include <ipxe/init.h>
#include <ipxe/features.h>

FEATURE ( FEATURE_IMAGE, "EFI", DHCP_EB_FEATURE_EFI, 1 );

/**
 * Execute EFI image
 *
 * @v image		EFI image
 * @ret rc		Return status code
 */
static int efi_image_exec ( struct image *image ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_HANDLE handle;
	UINTN exit_data_size;
	CHAR16 *exit_data;
	EFI_STATUS efirc;
	int rc;

	/* Attempt loading image */
	if ( ( efirc = bs->LoadImage ( FALSE, efi_image_handle, NULL,
				       user_to_virt ( image->data, 0 ),
				       image->len, &handle ) ) != 0 ) {
		/* Not an EFI image */
		DBGC ( image, "EFIIMAGE %p could not load: %s\n",
		       image, efi_strerror ( efirc ) );
		return -ENOEXEC;
	}

	/* Start the image */
	if ( ( efirc = bs->StartImage ( handle, &exit_data_size,
					&exit_data ) ) != 0 ) {
		DBGC ( image, "EFIIMAGE %p returned with status %s\n",
		       image, efi_strerror ( efirc ) );
	}
	rc = EFIRC_TO_RC ( efirc );

	/* Unload the image.  We can't leave it loaded, because we
	 * have no "unload" operation.
	 */
	bs->UnloadImage ( handle );

	return rc;
}

/**
 * Probe EFI image
 *
 * @v image		EFI file
 * @ret rc		Return status code
 */
static int efi_image_probe ( struct image *image ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_HANDLE handle;
	EFI_STATUS efirc;

	/* Attempt loading image */
	if ( ( efirc = bs->LoadImage ( FALSE, efi_image_handle, NULL,
				       user_to_virt ( image->data, 0 ),
				       image->len, &handle ) ) != 0 ) {
		/* Not an EFI image */
		DBGC ( image, "EFIIMAGE %p could not load: %s\n",
		       image, efi_strerror ( efirc ) );
		return -ENOEXEC;
	}

	/* Unload the image.  We can't leave it loaded, because we
	 * have no "unload" operation.
	 */
	bs->UnloadImage ( handle );

	return 0;
}

/** EFI image type */
struct image_type efi_image_type __image_type ( PROBE_NORMAL ) = {
	.name = "EFI",
	.probe = efi_image_probe,
	.exec = efi_image_exec,
};
