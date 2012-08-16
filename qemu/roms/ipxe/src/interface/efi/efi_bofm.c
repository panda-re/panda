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

#include <errno.h>
#include <ipxe/bofm.h>
#include <ipxe/init.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_pci.h>
#include <ipxe/efi/efi_driver.h>

/** @file
 *
 * IBM BladeCenter Open Fabric Manager (BOFM) EFI interface
 *
 */

/***************************************************************************
 *
 * EFI BOFM definitions
 *
 ***************************************************************************
 *
 * Taken from the BOFM UEFI Vendor Specification document
 *
 */

#define IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL_GUID			\
	{ 0x03207ce2, 0xd9c7, 0x11dc,					\
	  { 0xa9, 0x4d, 0x00, 0x19, 0x7d, 0x89, 0x02, 0x38 } }

#define IBM_BOFM_DRIVER_CONFIGURATION2_PROTOCOL_GUID			\
	{ 0xe82a9763, 0x0584, 0x4e41,					\
	  { 0xbb, 0x39, 0xe0, 0xcd, 0xb8, 0xc1, 0xf0, 0xfc } }

typedef struct {
	UINT8 Id;
	UINT8 ResultByte;
} __attribute__ (( packed )) BOFM_EPID_Results_t;

typedef struct {
	UINT8 Version;
	UINT8 Level;
	UINT16 Length;
	UINT8 Checksum;
	UINT8 Profile[32];
	UINT8 GlobalOption0;
	UINT8 GlobalOption1;
	UINT8 GlobalOption2;
	UINT8 GlobalOption3;
	UINT32 SequenceStamp;
	UINT8 Regions[911]; // For use by BOFM Driver
	UINT32 Reserved1;
} __attribute__ (( packed )) BOFM_Parameters_t;

typedef struct {
	UINT32 Reserved1;
	UINT8 Version;
	UINT8 Level;
	UINT8 Checksum;
	UINT32 SequenceStamp;
	UINT8 SUIDResults;
	UINT8 EntryResults[32];
	UINT8 Reserved2;
	UINT8 Reserved3;
	UINT8 FCTgtResults[2];
	UINT8 SASTgtResults[2];
	BOFM_EPID_Results_t EPIDResults[2];
	UINT8 Results4[10];
} __attribute__ (( packed )) BOFM_Results_t;

typedef struct {
	UINT32 Signature;
	UINT32 SubSignature;
	BOFM_Parameters_t Parameters;
	BOFM_Results_t Results;
} __attribute__ (( packed )) BOFM_DataStructure_t;

#define IBM_BOFM_TABLE BOFM_DataStructure_t

typedef struct _IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL
	IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL;

typedef EFI_STATUS ( EFIAPI *IBM_BOFM_DRIVER_CONFIGURATION_SUPPORT ) (
	IN IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL *This,
	EFI_HANDLE ControllerHandle,
	UINT8 SupporttedOptions,
	UINT8 iSCSI_Parameter_Version,
	UINT8 BOFM_Parameter_Version
);

typedef EFI_STATUS ( EFIAPI *IBM_BOFM_DRIVER_CONFIGURATION_STATUS ) (
	IN IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL *This,
	EFI_HANDLE ControllerHandle,
	BOOLEAN ResetRequired,
	UINT8 BOFMReturnCode
);

struct _IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL {
	IBM_BOFM_TABLE BofmTable;
	IBM_BOFM_DRIVER_CONFIGURATION_STATUS SetStatus;
	IBM_BOFM_DRIVER_CONFIGURATION_SUPPORT RegisterSupport;
};

typedef struct _IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL2 {
	UINT32 Signature;
	UINT32 Reserved1;
	UINT64 Reserved2;
	IBM_BOFM_DRIVER_CONFIGURATION_STATUS SetStatus;
	IBM_BOFM_DRIVER_CONFIGURATION_SUPPORT RegisterSupport;
	IBM_BOFM_TABLE BofmTable;
} IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL2;

/***************************************************************************
 *
 * EFI BOFM interface
 *
 ***************************************************************************
 */

/** BOFM1 protocol GUID */
static EFI_GUID bofm1_protocol_guid =
	IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL_GUID;

/** BOFM2 protocol GUID */
static EFI_GUID bofm2_protocol_guid =
	IBM_BOFM_DRIVER_CONFIGURATION2_PROTOCOL_GUID;

/**
 * Check if device is supported
 *
 * @v driver		EFI driver
 * @v device		EFI device
 * @v child		Path to child device, if any
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_bofm_supported ( EFI_DRIVER_BINDING_PROTOCOL *driver,
		     EFI_HANDLE device,
		     EFI_DEVICE_PATH_PROTOCOL *child ) {
	struct efi_driver *efidrv =
		container_of ( driver, struct efi_driver, driver );
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	union {
		IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL *bofm1;
		void *interface;
	} bofm1;
	struct efi_pci_device *efipci;
	EFI_STATUS efirc;
	int rc;

	DBGCP ( efidrv, "BOFM DRIVER_SUPPORTED %p (%p)\n", device, child );

	/* Create corresponding PCI device, if any */
	efipci = efipci_create ( efidrv, device );
	if ( ! efipci ) {
		efirc = EFI_UNSUPPORTED;
		goto err_not_pci;
	}

	/* Look for a BOFM driver */
	if ( ( rc = bofm_find_driver ( &efipci->pci ) ) != 0 ) {
		DBGC2 ( efidrv, "BOFM " PCI_FMT " has no driver\n",
			PCI_ARGS ( &efipci->pci ) );
		efirc = EFI_UNSUPPORTED;
		goto err_no_driver;
	}

	/* Locate BOFM protocol */
	if ( ( efirc = bs->LocateProtocol ( &bofm1_protocol_guid, NULL,
					    &bofm1.interface ) ) != 0 ) {
		DBGC ( efidrv, "BOFM " PCI_FMT " cannot find BOFM protocol\n",
		       PCI_ARGS ( &efipci->pci ) );
		efirc = EFI_UNSUPPORTED;
		goto err_not_bofm;
	}

	/* Register support for this device */
	if ( ( efirc = bofm1.bofm1->RegisterSupport ( bofm1.bofm1, device,
						      0x04 /* Can change MAC */,
						      0x00 /* No iSCSI */,
						      0x02 /* Version */ ))!=0){
		DBGC ( efidrv, "BOFM " PCI_FMT " could not register support: "
		       "%s\n", PCI_ARGS ( &efipci->pci ),
		       efi_strerror ( efirc ) );
		goto err_cannot_register;
	}

	DBGC ( efidrv, "BOFM " PCI_FMT " is supported by driver \"%s\"\n",
	       PCI_ARGS ( &efipci->pci ), efipci->pci.id->name );

	/* Destroy temporary PCI device */
	efipci_destroy ( efidrv, efipci );

	return 0;

 err_cannot_register:
 err_not_bofm:
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
static EFI_STATUS EFIAPI efi_bofm_start ( EFI_DRIVER_BINDING_PROTOCOL *driver,
				   EFI_HANDLE device,
				   EFI_DEVICE_PATH_PROTOCOL *child ) {
	struct efi_driver *efidrv =
		container_of ( driver, struct efi_driver, driver );
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	union {
		IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL *bofm1;
		void *interface;
	} bofm1;
	union {
		IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL2 *bofm2;
		void *interface;
	} bofm2;
	struct efi_pci_device *efipci;
	userptr_t bofmtab;
	EFI_STATUS efirc;
	int bofmrc;

	DBGCP ( efidrv, "BOFM DRIVER_START %p (%p)\n", device, child );

	/* Create corresponding PCI device */
	efipci = efipci_create ( efidrv, device );
	if ( ! efipci ) {
		efirc = EFI_OUT_OF_RESOURCES;
		goto err_create;
	}

	/* Enable PCI device */
	if ( ( efirc = efipci_enable ( efipci ) ) != 0 )
		goto err_enable;

	/* Locate BOFM protocol */
	if ( ( efirc = bs->LocateProtocol ( &bofm1_protocol_guid, NULL,
					    &bofm1.interface ) ) != 0 ) {
		DBGC ( efidrv, "BOFM " PCI_FMT " cannot find BOFM protocol\n",
		       PCI_ARGS ( &efipci->pci ) );
		goto err_locate_bofm;
	}

	/* Locate BOFM2 protocol, if available */
	if ( ( efirc = bs->LocateProtocol ( &bofm2_protocol_guid, NULL,
					    &bofm2.interface ) ) != 0 ) {
		DBGC ( efidrv, "BOFM " PCI_FMT " cannot find BOFM2 protocol\n",
		       PCI_ARGS ( &efipci->pci ) );
		/* Not a fatal error; may be a BOFM1-only system */
		bofm2.bofm2 = NULL;
	}

	/* Select appropriate BOFM table (v1 or v2) to use */
	if ( bofm2.bofm2 ) {
		DBGC ( efidrv, "BOFM " PCI_FMT " using version 2 BOFM table\n",
		       PCI_ARGS ( &efipci->pci ) );
		assert ( bofm2.bofm2->RegisterSupport ==
			 bofm1.bofm1->RegisterSupport );
		assert ( bofm2.bofm2->SetStatus == bofm1.bofm1->SetStatus );
		bofmtab = virt_to_user ( &bofm2.bofm2->BofmTable );
	} else {
		DBGC ( efidrv, "BOFM " PCI_FMT " using version 1 BOFM table\n",
		       PCI_ARGS ( &efipci->pci ) );
		bofmtab = virt_to_user ( &bofm1.bofm1->BofmTable );
	}

	/* Process BOFM table */
	bofmrc = bofm ( bofmtab, &efipci->pci );
	DBGC ( efidrv, "BOFM " PCI_FMT " status %08x\n",
	       PCI_ARGS ( &efipci->pci ), bofmrc );

	/* Return BOFM status */
	if ( ( efirc = bofm1.bofm1->SetStatus ( bofm1.bofm1, device, FALSE,
						bofmrc ) ) != 0 ) {
		DBGC ( efidrv, "BOFM " PCI_FMT " could not set BOFM status: "
		       "%s\n", PCI_ARGS ( &efipci->pci ),
		       efi_strerror ( efirc ) );
		goto err_set_status;
	}

	/* Destroy the PCI device anyway; we have no further use for it */
	efipci_destroy ( efidrv, efipci );

	/* BOFM (ab)uses the "start" method to mean "process and exit" */
	return EFI_NOT_READY;

 err_set_status:
 err_locate_bofm:
 err_enable:
	efipci_destroy ( efidrv, efipci );
 err_create:
	return efirc;
}

/**
 * Detach driver from device
 *
 * @v driver		EFI driver
 * @v device		EFI device
 * @v num_children	Number of child devices
 * @v children		List of child devices
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI efi_bofm_stop ( EFI_DRIVER_BINDING_PROTOCOL *driver,
					 EFI_HANDLE device, UINTN num_children,
					 EFI_HANDLE *children ) {
	struct efi_driver *efidrv =
		container_of ( driver, struct efi_driver, driver );

	DBGCP ( efidrv, "BOFM DRIVER_STOP %p (%ld %p)\n",
		device, ( ( unsigned long ) num_children ), children );

	return 0;
}

/** EFI BOFM driver */
static struct efi_driver efi_bofm_driver =
	EFI_DRIVER_INIT ( "BOFM",
			  efi_bofm_supported, efi_bofm_start, efi_bofm_stop );

/**
 * Install EFI BOFM driver
 *
 */
static void efi_bofm_driver_init ( void ) {
	struct efi_driver *efidrv = &efi_bofm_driver;
	EFI_STATUS efirc;

	/* Install driver */
	if ( ( efirc = efi_driver_install ( efidrv ) ) != 0 ) {
		DBGC ( efidrv, "BOFM could not install driver: %s\n",
		       efi_strerror ( efirc ) );
		return;
	}

	DBGC ( efidrv, "BOFM driver installed\n" );
}

/** EFI BOFM startup function */
struct startup_fn startup_bofm __startup_fn ( STARTUP_EARLY ) = {
	.startup = efi_bofm_driver_init,
};
