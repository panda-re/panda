/*
 * Copyright (C) 2010 VMware, Inc.  All Rights Reserved.
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <string.h>
#include <errno.h>
#include <ipxe/device.h>
#include <ipxe/init.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/SimpleNetwork.h>
#include "snp.h"
#include "snpnet.h"

/** @file
 *
 * Chain-loading Simple Network Protocol Bus Driver
 *
 * This bus driver allows iPXE to use the EFI Simple Network Protocol provided
 * by the platform to transmit and receive packets. It attaches to only the
 * device handle that iPXE was loaded from, that is, it will only use the
 * Simple Network Protocol on the current loaded image's device handle.
 *
 * Eseentially, this driver provides the EFI equivalent of the "undionly"
 * driver.
 */

/** The one and only SNP network device */
static struct snp_device snponly_dev;

/** EFI simple network protocol GUID */
static EFI_GUID efi_simple_network_protocol_guid
	= EFI_SIMPLE_NETWORK_PROTOCOL_GUID;

/**
 * Probe SNP root bus
 *
 * @v rootdev		SNP bus root device
 *
 * Look at the loaded image's device handle and see if the simple network
 * protocol exists. If so, register a driver for it.
 */
static int snpbus_probe ( struct root_device *rootdev ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_STATUS efirc;
	int rc;
	void *snp;

	efirc = bs->OpenProtocol ( efi_loaded_image->DeviceHandle,
				   &efi_simple_network_protocol_guid,
				   &snp, efi_image_handle, NULL,
				   EFI_OPEN_PROTOCOL_GET_PROTOCOL );
	if ( efirc ) {
		DBG ( "Could not find Simple Network Protocol!\n" );
		return -ENODEV;
	}
	snponly_dev.snp = snp;

	/* Add to device hierarchy */
	strncpy ( snponly_dev.dev.name, "EFI SNP",
		  ( sizeof ( snponly_dev.dev.name ) - 1 ) );
	snponly_dev.dev.parent = &rootdev->dev;
	list_add ( &snponly_dev.dev.siblings, &rootdev->dev.children);
	INIT_LIST_HEAD ( &snponly_dev.dev.children );

	/* Create network device */
	if ( ( rc = snpnet_probe ( &snponly_dev ) ) != 0 )
		goto err;

	return 0;

err:
	list_del ( &snponly_dev.dev.siblings );
	return rc;
}

/**
 * Remove SNP root bus
 *
 * @v rootdev		SNP bus root device
 */
static void snpbus_remove ( struct root_device *rootdev __unused ) {
	snpnet_remove ( &snponly_dev );
	list_del ( &snponly_dev.dev.siblings );
}

/** SNP bus root device driver */
static struct root_driver snp_root_driver = {
	.probe = snpbus_probe,
	.remove = snpbus_remove,
};

/** SNP bus root device */
struct root_device snp_root_device __root_device = {
	.dev = { .name = "EFI SNP" },
	.driver = &snp_root_driver,
};

/**
 * Prepare for exit
 *
 * @v booting		System is shutting down for OS boot
 */
static void snponly_shutdown ( int booting ) {
	/* If we are shutting down to boot an OS, make sure the SNP does not
	 * stay active.
	 */
	if ( booting )
		snponly_dev.removal_state = EfiSimpleNetworkStopped;
}

struct startup_fn startup_snponly __startup_fn ( STARTUP_LATE ) = {
	.shutdown = snponly_shutdown,
};
