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

#include <string.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/LoadedImage.h>
#include <ipxe/uuid.h>
#include <ipxe/init.h>

/** Image handle passed to entry point */
EFI_HANDLE efi_image_handle;

/** Loaded image protocol for this image */
EFI_LOADED_IMAGE_PROTOCOL *efi_loaded_image;

/** System table passed to entry point */
EFI_SYSTEM_TABLE *efi_systab;

/** EFI loaded image protocol GUID */
static EFI_GUID efi_loaded_image_protocol_guid
	= EFI_LOADED_IMAGE_PROTOCOL_GUID;

/** Event used to signal shutdown */
static EFI_EVENT efi_shutdown_event;

/**
 * Shut down in preparation for booting an OS.
 *
 * This hook gets called at ExitBootServices time in order to make
 * sure that everything is properly shut down before the OS takes
 * over.
 */
static EFIAPI void efi_shutdown_hook ( EFI_EVENT event __unused,
				       void *context __unused ) {
	shutdown_boot();
}

/**
 * Look up EFI configuration table
 *
 * @v guid		Configuration table GUID
 * @ret table		Configuration table, or NULL
 */
static void * efi_find_table ( EFI_GUID *guid ) {
	unsigned int i;

	for ( i = 0 ; i < efi_systab->NumberOfTableEntries ; i++ ) {
		if ( memcmp ( &efi_systab->ConfigurationTable[i].VendorGuid,
			      guid, sizeof ( *guid ) ) == 0 )
			return efi_systab->ConfigurationTable[i].VendorTable;
	}

	return NULL;
}

/**
 * Initialise EFI environment
 *
 * @v image_handle	Image handle
 * @v systab		System table
 * @ret efirc		EFI return status code
 */
EFI_STATUS efi_init ( EFI_HANDLE image_handle,
		      EFI_SYSTEM_TABLE *systab ) {
	EFI_BOOT_SERVICES *bs;
	struct efi_protocol *prot;
	struct efi_config_table *tab;
	EFI_STATUS efirc;
	void *loaded_image;

	/* Store image handle and system table pointer for future use */
	efi_image_handle = image_handle;
	efi_systab = systab;

	/* Sanity checks */
	if ( ! systab )
		return EFI_NOT_AVAILABLE_YET;
	if ( ! systab->ConOut )
		return EFI_NOT_AVAILABLE_YET;
	if ( ! systab->BootServices ) {
		DBGC ( systab, "EFI provided no BootServices entry point\n" );
		return EFI_NOT_AVAILABLE_YET;
	}
	if ( ! systab->RuntimeServices ) {
		DBGC ( systab, "EFI provided no RuntimeServices entry "
		       "point\n" );
		return EFI_NOT_AVAILABLE_YET;
	}
	DBGC ( systab, "EFI handle %p systab %p\n", image_handle, systab );

	bs = systab->BootServices;
	efirc = bs->OpenProtocol ( image_handle,
				   &efi_loaded_image_protocol_guid,
				   &loaded_image, image_handle, NULL,
				   EFI_OPEN_PROTOCOL_GET_PROTOCOL );
	if ( efirc ) {
	   DBGC ( systab, "Could not get loaded image protocol" );
	   return efirc;
	}

	efi_loaded_image = loaded_image;
	DBG ( "Image base address = %p\n", efi_loaded_image->ImageBase );

	/* Look up used protocols */
	for_each_table_entry ( prot, EFI_PROTOCOLS ) {
		if ( ( efirc = bs->LocateProtocol ( &prot->u.guid, NULL,
						    prot->protocol ) ) == 0 ) {
			DBGC ( systab, "EFI protocol %s is at %p\n",
			       uuid_ntoa ( &prot->u.uuid ), *(prot->protocol));
		} else {
			DBGC ( systab, "EFI does not provide protocol %s\n",
			       uuid_ntoa ( &prot->u.uuid ) );
			/* All protocols are required */
			return efirc;
		}
	}

	/* Look up used configuration tables */
	for_each_table_entry ( tab, EFI_CONFIG_TABLES ) {
		if ( ( *(tab->table) = efi_find_table ( &tab->u.guid ) ) ) {
			DBGC ( systab, "EFI configuration table %s is at %p\n",
			       uuid_ntoa ( &tab->u.uuid ), *(tab->table) );
		} else {
			DBGC ( systab, "EFI does not provide configuration "
			       "table %s\n", uuid_ntoa ( &tab->u.uuid ) );
			if ( tab->required )
				return EFI_NOT_AVAILABLE_YET;
		}
	}

	/* EFI is perfectly capable of gracefully shutting down any
	 * loaded devices if it decides to fall back to a legacy boot.
	 * For no particularly comprehensible reason, it doesn't
	 * bother doing so when ExitBootServices() is called.
	 */
	if ( ( efirc = bs->CreateEvent ( EVT_SIGNAL_EXIT_BOOT_SERVICES,
					 TPL_CALLBACK, efi_shutdown_hook,
					 NULL, &efi_shutdown_event ) ) != 0 ) {
		DBGC ( systab, "EFI could not create ExitBootServices event: "
		       "%s\n", efi_strerror ( efirc ) );
		return efirc;
	}

	return 0;
}
