#ifndef _IPXE_EFI_PCI_H
#define _IPXE_EFI_PCI_H

/** @file
 *
 * EFI driver interface
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/PciIo.h>
#include <ipxe/efi/Protocol/DevicePath.h>

struct efi_driver;
struct device;

/** An EFI PCI device */
struct efi_pci_device {
	/** List of EFI PCI devices */
	struct list_head list;
	/** iPXE PCI device */
	struct pci_device pci;
	/** Underlying EFI device */
	EFI_HANDLE device;
	/** PCI I/O protocol */
	EFI_PCI_IO_PROTOCOL *pci_io;
	/** Device path */
	EFI_DEVICE_PATH_PROTOCOL *path;
	/** EFI driver */
	struct efi_driver *efidrv;
};

extern struct efi_pci_device * efipci_create ( struct efi_driver *efidrv,
					       EFI_HANDLE device );
extern EFI_STATUS efipci_enable ( struct efi_pci_device *efipci );
extern struct efi_pci_device * efipci_find_efi ( EFI_HANDLE device );
extern struct efi_pci_device * efipci_find ( struct device *dev );
extern EFI_STATUS efipci_child_add ( struct efi_pci_device *efipci,
				     EFI_HANDLE device );
extern void efipci_child_del ( struct efi_pci_device *efipci,
			       EFI_HANDLE device );
extern void efipci_destroy ( struct efi_driver *efidrv,
			     struct efi_pci_device *efipci );

#endif /* _IPXE_EFI_PCI_H */
