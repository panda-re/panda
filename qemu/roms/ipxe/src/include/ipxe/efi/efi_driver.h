#ifndef _IPXE_EFI_DRIVER_H
#define _IPXE_EFI_DRIVER_H

/** @file
 *
 * EFI driver interface
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/DriverBinding.h>
#include <ipxe/efi/Protocol/ComponentName2.h>
#include <ipxe/efi/Protocol/DevicePath.h>

/** An EFI driver */
struct efi_driver {
	/** Name */
	const char *name;
	/** EFI name */
	CHAR16 wname[32];
	/** EFI driver binding protocol */
	EFI_DRIVER_BINDING_PROTOCOL driver;
	/** EFI component name protocol */
	EFI_COMPONENT_NAME2_PROTOCOL wtf;
};

/** Initialise an EFI driver
 *
 * @v name		Driver name
 * @v supported		Device supported method
 * @v start		Device start method
 * @v stop		Device stop method
 */
#define EFI_DRIVER_INIT( _name, _supported, _start, _stop ) {	\
	.name = _name,						\
	.driver = {						\
		.Supported = _supported,			\
		.Start = _start,				\
		.Stop = _stop,					\
		.Version = 0x10,				\
	} }

extern EFI_DEVICE_PATH_PROTOCOL *
efi_devpath_end ( EFI_DEVICE_PATH_PROTOCOL *path );

extern EFI_STATUS efi_driver_install ( struct efi_driver *efidrv );

#endif /* _IPXE_EFI_DRIVER_H */
