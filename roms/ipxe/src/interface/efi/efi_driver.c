/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stddef.h>
#include <stdio.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/DriverBinding.h>
#include <ipxe/efi/Protocol/ComponentName2.h>
#include <ipxe/efi/efi_strings.h>
#include <ipxe/efi/efi_driver.h>
#include <config/general.h>

/** @file
 *
 * EFI driver interface
 *
 */

/** EFI driver binding protocol GUID */
static EFI_GUID efi_driver_binding_protocol_guid
	= EFI_DRIVER_BINDING_PROTOCOL_GUID;

/** EFI component name protocol GUID */
static EFI_GUID efi_component_name2_protocol_guid
	= EFI_COMPONENT_NAME2_PROTOCOL_GUID;

/**
 * Find end of device path
 *
 * @v path		Path to device
 * @ret path_end	End of device path
 */
EFI_DEVICE_PATH_PROTOCOL * efi_devpath_end ( EFI_DEVICE_PATH_PROTOCOL *path ) {

	while ( path->Type != END_DEVICE_PATH_TYPE ) {
		path = ( ( ( void * ) path ) +
			 /* There's this amazing new-fangled thing known as
			  * a UINT16, but who wants to use one of those? */
			 ( ( path->Length[1] << 8 ) | path->Length[0] ) );
	}

	return path;
}

/**
 * Look up driver name
 *
 * @v wtf		Component name protocol
 * @v language		Language to use
 * @v driver_name	Driver name to fill in
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_driver_get_driver_name ( EFI_COMPONENT_NAME2_PROTOCOL *wtf,
			     CHAR8 *language __unused, CHAR16 **driver_name ) {
	struct efi_driver *efidrv =
		container_of ( wtf, struct efi_driver, wtf );

	*driver_name = efidrv->wname;
	return 0;
}

/**
 * Look up controller name
 *
 * @v wtf		Component name protocol
 * @v device		Device
 * @v child		Child device, or NULL
 * @v language		Language to use
 * @v driver_name	Device name to fill in
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_driver_get_controller_name ( EFI_COMPONENT_NAME2_PROTOCOL *wtf __unused,
				 EFI_HANDLE device __unused,
				 EFI_HANDLE child __unused,
				 CHAR8 *language __unused,
				 CHAR16 **controller_name __unused ) {

	/* Just let EFI use the default Device Path Name */
	return EFI_UNSUPPORTED;
}

/**
 * Install EFI driver
 *
 * @v efidrv		EFI driver
 * @ret efirc		EFI status code
 */
EFI_STATUS efi_driver_install ( struct efi_driver *efidrv ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_DRIVER_BINDING_PROTOCOL *driver = &efidrv->driver;
	EFI_COMPONENT_NAME2_PROTOCOL *wtf = &efidrv->wtf;
	EFI_STATUS efirc;

	/* Configure driver binding protocol */
	driver->ImageHandle = efi_image_handle;

	/* Configure component name protocol */
	wtf->GetDriverName = efi_driver_get_driver_name;
	wtf->GetControllerName = efi_driver_get_controller_name;
	wtf->SupportedLanguages = "en";

	/* Fill in driver name */
	efi_snprintf ( efidrv->wname,
		       ( sizeof ( efidrv->wname ) /
			 sizeof ( efidrv->wname[0] ) ),
		       PRODUCT_SHORT_NAME " - %s", efidrv->name );

	/* Install driver */
	if ( ( efirc = bs->InstallMultipleProtocolInterfaces (
			&driver->DriverBindingHandle,
			&efi_driver_binding_protocol_guid, driver,
			&efi_component_name2_protocol_guid, wtf,
			NULL ) ) != 0 ) {
		DBGC ( efidrv, "EFIDRV %s could not install protocol: %s\n",
		       efidrv->name, efi_strerror ( efirc ) );
		return efirc;
	}

	DBGC ( efidrv, "EFIDRV %s installed\n", efidrv->name );
	return 0;
}
