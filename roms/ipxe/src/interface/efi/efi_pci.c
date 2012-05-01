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

#include <stdlib.h>
#include <errno.h>
#include <ipxe/pci.h>
#include <ipxe/init.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_pci.h>
#include <ipxe/efi/efi_driver.h>
#include <ipxe/efi/Protocol/PciIo.h>
#include <ipxe/efi/Protocol/PciRootBridgeIo.h>

/** @file
 *
 * iPXE PCI I/O API for EFI
 *
 */

/******************************************************************************
 *
 * iPXE PCI API
 *
 ******************************************************************************
 */

/** PCI root bridge I/O protocol */
static EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *efipci;
EFI_REQUIRE_PROTOCOL ( EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL, &efipci );

static unsigned long efipci_address ( struct pci_device *pci,
				      unsigned long location ) {
	return EFI_PCI_ADDRESS ( PCI_BUS ( pci->busdevfn ),
				 PCI_SLOT ( pci->busdevfn ),
				 PCI_FUNC ( pci->busdevfn ),
				 EFIPCI_OFFSET ( location ) );
}

int efipci_read ( struct pci_device *pci, unsigned long location,
		  void *value ) {
	EFI_STATUS efirc;

	if ( ( efirc = efipci->Pci.Read ( efipci, EFIPCI_WIDTH ( location ),
					  efipci_address ( pci, location ), 1,
					  value ) ) != 0 ) {
		DBG ( "EFIPCI config read from " PCI_FMT " offset %02lx "
		      "failed: %s\n", PCI_ARGS ( pci ),
		      EFIPCI_OFFSET ( location ), efi_strerror ( efirc ) );
		return -EIO;
	}

	return 0;
}

int efipci_write ( struct pci_device *pci, unsigned long location,
		   unsigned long value ) {
	EFI_STATUS efirc;

	if ( ( efirc = efipci->Pci.Write ( efipci, EFIPCI_WIDTH ( location ),
					   efipci_address ( pci, location ), 1,
					   &value ) ) != 0 ) {
		DBG ( "EFIPCI config write to " PCI_FMT " offset %02lx "
		      "failed: %s\n", PCI_ARGS ( pci ),
		      EFIPCI_OFFSET ( location ), efi_strerror ( efirc ) );
		return -EIO;
	}

	return 0;
}

PROVIDE_PCIAPI_INLINE ( efi, pci_num_bus );
PROVIDE_PCIAPI_INLINE ( efi, pci_read_config_byte );
PROVIDE_PCIAPI_INLINE ( efi, pci_read_config_word );
PROVIDE_PCIAPI_INLINE ( efi, pci_read_config_dword );
PROVIDE_PCIAPI_INLINE ( efi, pci_write_config_byte );
PROVIDE_PCIAPI_INLINE ( efi, pci_write_config_word );
PROVIDE_PCIAPI_INLINE ( efi, pci_write_config_dword );

/******************************************************************************
 *
 * EFI PCI device instantiation
 *
 ******************************************************************************
 */

/** EFI PCI I/O protocol GUID */
static EFI_GUID efi_pci_io_protocol_guid
	= EFI_PCI_IO_PROTOCOL_GUID;

/** EFI device path protocol GUID */
static EFI_GUID efi_device_path_protocol_guid
	= EFI_DEVICE_PATH_PROTOCOL_GUID;

/** EFI PCI devices */
static LIST_HEAD ( efi_pci_devices );

/**
 * Create EFI PCI device
 *
 * @v efidrv		EFI driver
 * @v device		EFI device
 * @ret efipci		EFI PCI device, or NULL
 */
struct efi_pci_device * efipci_create ( struct efi_driver *efidrv,
					EFI_HANDLE device ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct efi_pci_device *efipci;
	union {
		EFI_PCI_IO_PROTOCOL *pci_io;
		void *interface;
	} pci_io;
	union {
		EFI_DEVICE_PATH_PROTOCOL *path;
		void *interface;
	} path;
	UINTN pci_segment, pci_bus, pci_dev, pci_fn;
	EFI_STATUS efirc;
	int rc;

	/* Allocate PCI device */
	efipci = zalloc ( sizeof ( *efipci ) );
	if ( ! efipci )
		goto err_zalloc;
	efipci->device = device;
	efipci->efidrv = efidrv;

	/* See if device is a PCI device */
	if ( ( efirc = bs->OpenProtocol ( device,
					  &efi_pci_io_protocol_guid,
					  &pci_io.interface,
					  efidrv->driver.DriverBindingHandle,
					  device,
					  EFI_OPEN_PROTOCOL_BY_DRIVER )) !=0 ){
		DBGCP ( efipci, "EFIPCI device %p is not a PCI device\n",
			device );
		goto err_open_protocol;
	}
	efipci->pci_io = pci_io.pci_io;

	/* Get PCI bus:dev.fn address */
	if ( ( efirc = pci_io.pci_io->GetLocation ( pci_io.pci_io,
						    &pci_segment,
						    &pci_bus, &pci_dev,
						    &pci_fn ) ) != 0 ) {
		DBGC ( efipci, "EFIPCI device %p could not get PCI "
		       "location: %s\n", device, efi_strerror ( efirc ) );
		goto err_get_location;
	}
	DBGC2 ( efipci, "EFIPCI device %p is PCI %04lx:%02lx:%02lx.%lx\n",
		device, ( ( unsigned long ) pci_segment ),
		( ( unsigned long ) pci_bus ), ( ( unsigned long ) pci_dev ),
		( ( unsigned long ) pci_fn ) );

	/* Populate PCI device */
	pci_init ( &efipci->pci, PCI_BUSDEVFN ( pci_bus, pci_dev, pci_fn ) );
	if ( ( rc = pci_read_config ( &efipci->pci ) ) != 0 ) {
		DBGC ( efipci, "EFIPCI " PCI_FMT " cannot read PCI "
		       "configuration: %s\n",
		       PCI_ARGS ( &efipci->pci ), strerror ( rc ) );
		goto err_pci_read_config;
	}

	/* Retrieve device path */
	if ( ( efirc = bs->OpenProtocol ( device,
					  &efi_device_path_protocol_guid,
					  &path.interface,
					  efidrv->driver.DriverBindingHandle,
					  device,
					  EFI_OPEN_PROTOCOL_BY_DRIVER )) !=0 ){
		DBGC ( efipci, "EFIPCI " PCI_FMT " has no device path\n",
		       PCI_ARGS ( &efipci->pci ) );
		goto err_no_device_path;
	}
	efipci->path = path.path;

	/* Add to list of PCI devices */
	list_add ( &efipci->list, &efi_pci_devices );

	return efipci;

	bs->CloseProtocol ( device, &efi_device_path_protocol_guid,
			    efidrv->driver.DriverBindingHandle, device );
 err_no_device_path:
 err_pci_read_config:
 err_get_location:
	bs->CloseProtocol ( device, &efi_pci_io_protocol_guid,
			    efidrv->driver.DriverBindingHandle, device );
 err_open_protocol:
	free ( efipci );
 err_zalloc:
	return NULL;
}

/**
 * Enable EFI PCI device
 *
 * @v efipci		EFI PCI device
 * @ret efirc		EFI status code
 */
EFI_STATUS efipci_enable ( struct efi_pci_device *efipci ) {
	EFI_PCI_IO_PROTOCOL *pci_io = efipci->pci_io;
	EFI_STATUS efirc;

	/* Enable device */
	if ( ( efirc = pci_io->Attributes ( pci_io,
					    EfiPciIoAttributeOperationSet,
					    EFI_PCI_DEVICE_ENABLE,
					    NULL ) ) != 0 ) {
		DBGC ( efipci, "EFIPCI " PCI_FMT " could not be enabled: %s\n",
		       PCI_ARGS ( &efipci->pci ), efi_strerror ( efirc ) );
		return efirc;
	}

	return 0;
}

/**
 * Find EFI PCI device by EFI device
 *
 * @v device		EFI device
 * @ret efipci		EFI PCI device, or NULL
 */
struct efi_pci_device * efipci_find_efi ( EFI_HANDLE device ) {
	struct efi_pci_device *efipci;

	list_for_each_entry ( efipci, &efi_pci_devices, list ) {
		if ( efipci->device == device )
			return efipci;
	}
	return NULL;
}

/**
 * Find EFI PCI device by iPXE device
 *
 * @v dev		Device
 * @ret efipci		EFI PCI device, or NULL
 */
struct efi_pci_device * efipci_find ( struct device *dev ) {
	struct efi_pci_device *efipci;

	list_for_each_entry ( efipci, &efi_pci_devices, list ) {
		if ( &efipci->pci.dev == dev )
			return efipci;
	}
	return NULL;
}

/**
 * Add EFI device as child of EFI PCI device
 *
 * @v efipci		EFI PCI device
 * @v device		EFI child device
 * @ret efirc		EFI status code
 */
EFI_STATUS efipci_child_add ( struct efi_pci_device *efipci,
			      EFI_HANDLE device ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct efi_driver *efidrv = efipci->efidrv;
	union {
		EFI_PCI_IO_PROTOCOL *pci_io;
		void *interface;
	} pci_io;
	EFI_STATUS efirc;

	/* Re-open the PCI_IO_PROTOCOL */
	if ( ( efirc = bs->OpenProtocol ( efipci->device,
					  &efi_pci_io_protocol_guid,
					  &pci_io.interface,
					  efidrv->driver.DriverBindingHandle,
					  device,
					  EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER
					  ) ) != 0 ) {
		DBGC ( efipci, "EFIPCI " PCI_FMT " could not add child: %s\n",
		       PCI_ARGS ( &efipci->pci ), efi_strerror ( efirc ) );
		return efirc;
	}

	return 0;
}

/**
 * Remove EFI device as child of PCI device
 *
 * @v efipci		EFI PCI device
 * @v device		EFI child device
 * @ret efirc		EFI status code
 */
void efipci_child_del ( struct efi_pci_device *efipci, EFI_HANDLE device ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct efi_driver *efidrv = efipci->efidrv;

	bs->CloseProtocol ( efipci->device, &efi_pci_io_protocol_guid,
			    efidrv->driver.DriverBindingHandle, device );
}

/**
 * Destroy EFI PCI device
 *
 * @v efidrv		EFI driver
 * @v efipci		EFI PCI device
 */
void efipci_destroy ( struct efi_driver *efidrv,
		      struct efi_pci_device *efipci ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;

	list_del ( &efipci->list );
	bs->CloseProtocol ( efipci->device, &efi_device_path_protocol_guid,
			    efidrv->driver.DriverBindingHandle,
			    efipci->device );
	bs->CloseProtocol ( efipci->device, &efi_pci_io_protocol_guid,
			    efidrv->driver.DriverBindingHandle,
			    efipci->device );
	free ( efipci );
}

/******************************************************************************
 *
 * EFI PCI driver
 *
 ******************************************************************************
 */

/**
 * Check to see if driver supports a device
 *
 * @v driver		EFI driver
 * @v device		EFI device
 * @v child		Path to child device, if any
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efipci_supported ( EFI_DRIVER_BINDING_PROTOCOL *driver, EFI_HANDLE device,
		   EFI_DEVICE_PATH_PROTOCOL *child ) {
	struct efi_driver *efidrv =
		container_of ( driver, struct efi_driver, driver );
	struct efi_pci_device *efipci;
	EFI_STATUS efirc;
	int rc;

	DBGCP ( efidrv, "EFIPCI DRIVER_SUPPORTED %p (%p)\n", device, child );

	/* Create temporary corresponding PCI device, if any */
	efipci = efipci_create ( efidrv, device );
	if ( ! efipci ) {
		/* Non-PCI devices are simply unsupported */
		efirc = EFI_UNSUPPORTED;
		goto err_not_pci;
	}

	/* Look for a driver */
	if ( ( rc = pci_find_driver ( &efipci->pci ) ) != 0 ) {
		DBGCP ( efipci, "EFIPCI " PCI_FMT " has no driver\n",
			PCI_ARGS ( &efipci->pci ) );
		efirc = EFI_UNSUPPORTED;
		goto err_no_driver;
	}

	DBGC ( efipci, "EFIPCI " PCI_FMT " is supported by driver \"%s\"\n",
	       PCI_ARGS ( &efipci->pci ), efipci->pci.id->name );

	/* Destroy temporary PCI device */
	efipci_destroy ( efidrv, efipci );

	return 0;

 err_no_driver:
	efipci_destroy ( efidrv, efipci );
 err_not_pci:
	return efirc;
}

/**
 * Attach driver to device
 *
 * @v driver		EFI driver
 * @v device		EFI device
 * @v child		Path to child device, if any
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efipci_start ( EFI_DRIVER_BINDING_PROTOCOL *driver, EFI_HANDLE device,
	       EFI_DEVICE_PATH_PROTOCOL *child ) {
	struct efi_driver *efidrv =
		container_of ( driver, struct efi_driver, driver );
	struct efi_pci_device *efipci;
	EFI_STATUS efirc;
	int rc;

	DBGC ( efidrv, "EFIPCI DRIVER_START %p (%p)\n", device, child );

	/* Create corresponding PCI device */
	efipci = efipci_create ( efidrv, device );
	if ( ! efipci ) {
		efirc = EFI_OUT_OF_RESOURCES;
		goto err_create;
	}

	/* Find driver */
	if ( ( rc = pci_find_driver ( &efipci->pci ) ) != 0 ) {
		DBGC ( efipci, "EFIPCI " PCI_FMT " has no driver\n",
		       PCI_ARGS ( &efipci->pci ) );
		efirc = RC_TO_EFIRC ( rc );
		goto err_find_driver;
	}

	/* Enable PCI device */
	if ( ( efirc = efipci_enable ( efipci ) ) != 0 )
		goto err_enable;

	/* Probe driver */
	if ( ( rc = pci_probe ( &efipci->pci ) ) != 0 ) {
		DBGC ( efipci, "EFIPCI " PCI_FMT " could not probe driver "
		       "\"%s\": %s\n", PCI_ARGS ( &efipci->pci ),
		       efipci->pci.id->name, strerror ( rc ) );
		efirc = RC_TO_EFIRC ( rc );
		goto err_probe;
	}

	return 0;

	pci_remove ( &efipci->pci );
 err_probe:
 err_enable:
 err_find_driver:
	efipci_destroy ( efidrv, efipci );
 err_create:
	return efirc;
}

/**
 * Detach driver from device
 *
 * @v driver		EFI driver
 * @v device		EFI device
 * @v pci		PCI device
 * @v num_children	Number of child devices
 * @v children		List of child devices
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efipci_stop ( EFI_DRIVER_BINDING_PROTOCOL *driver, EFI_HANDLE device,
	      UINTN num_children, EFI_HANDLE *children ) {
	struct efi_driver *efidrv =
		container_of ( driver, struct efi_driver, driver );
	struct efi_pci_device *efipci;

	DBGC ( efidrv, "EFIPCI DRIVER_STOP %p (%ld %p)\n",
	       device, ( ( unsigned long ) num_children ), children );

	/* Find PCI device */
	efipci = efipci_find_efi ( device );
	if ( ! efipci ) {
		DBGC ( efidrv, "EFIPCI device %p not started!\n", device );
		return EFI_INVALID_PARAMETER;
	}

	/* Remove device */
	pci_remove ( &efipci->pci );

	/* Delete EFI PCI device */
	efipci_destroy ( efidrv, efipci );

	return 0;
}

/** EFI PCI driver */
static struct efi_driver efipci_driver =
	EFI_DRIVER_INIT ( "PCI", efipci_supported, efipci_start, efipci_stop );

/**
 * Install EFI PCI driver
 *
 */
static void efipci_driver_startup ( void ) {
	struct efi_driver *efidrv = &efipci_driver;
	EFI_STATUS efirc;

	/* Install driver */
	if ( ( efirc = efi_driver_install ( efidrv ) ) != 0 ) {
		DBGC ( efidrv, "EFIPCI could not install driver: %s\n",
		       efi_strerror ( efirc ) );
		return;
	}

	DBGC ( efidrv, "EFIPCI driver installed\n" );
}

/**
 * Shut down EFI PCI driver
 *
 * @v booting		System is shutting down for OS boot
 */
static void efipci_driver_shutdown ( int booting __unused ) {
	struct efi_driver *efidrv = &efipci_driver;
	struct efi_pci_device *efipci;
	struct efi_pci_device *tmp;

	/* Shut down any remaining devices */
	list_for_each_entry_safe ( efipci, tmp, &efi_pci_devices, list ) {
		DBGC ( efipci, "EFIPCI " PCI_FMT " still active at shutdown; "
		       "forcing close\n", PCI_ARGS ( &efipci->pci ) );
		pci_remove ( &efipci->pci );
		efipci_destroy ( efidrv, efipci );
	}
}

/** EFI PCI startup function */
struct startup_fn startup_pci __startup_fn ( STARTUP_NORMAL ) = {
	.startup = efipci_driver_startup,
	.shutdown = efipci_driver_shutdown,
};
