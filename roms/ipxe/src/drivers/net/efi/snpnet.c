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

#include <errno.h>
#include <string.h>
#include <ipxe/io.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/SimpleNetwork.h>
#include "snp.h"
#include "snpnet.h"

/** @file
 *
 * SNP network device driver
 *
 */

/** SNP net device structure */
struct snpnet_device {
	/** The underlying simple network protocol */
	EFI_SIMPLE_NETWORK_PROTOCOL *snp;

	/** State that the SNP should be in after close */
	UINT32 close_state;
};

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int snpnet_transmit ( struct net_device *netdev,
			     struct io_buffer *iobuf ) {
	struct snpnet_device *snpnetdev = netdev->priv;
	EFI_SIMPLE_NETWORK_PROTOCOL *snp = snpnetdev->snp;
	EFI_STATUS efirc;
	size_t len = iob_len ( iobuf );

	efirc = snp->Transmit ( snp, 0, len, iobuf->data, NULL, NULL, NULL );
	return EFIRC_TO_RC ( efirc );
}

/**
 * Find a I/O buffer on the list of outstanding Tx buffers and complete it.
 *
 * @v snpnetdev		SNP network device
 * @v txbuf		Buffer address
 */
static void snpnet_complete ( struct net_device *netdev, void *txbuf ) {
	struct io_buffer *tmp;
	struct io_buffer *iobuf;

	list_for_each_entry_safe ( iobuf, tmp, &netdev->tx_queue, list ) {
		if ( iobuf->data == txbuf ) {
			netdev_tx_complete ( netdev, iobuf );
			break;
		}
	}
}

/**
 * Poll for received packets
 *
 * @v netdev		Network device
 */
static void snpnet_poll ( struct net_device *netdev ) {
	struct snpnet_device *snpnetdev = netdev->priv;
	EFI_SIMPLE_NETWORK_PROTOCOL *snp = snpnetdev->snp;
	EFI_STATUS efirc;
	struct io_buffer *iobuf = NULL;
	UINTN len;
	void *txbuf;

	/* Process Tx completions */
	while ( 1 ) {
		efirc = snp->GetStatus ( snp, NULL, &txbuf );
		if ( efirc ) {
			DBGC ( snp, "SNP %p could not get status %s\n", snp,
			       efi_strerror ( efirc ) );
			break;
		}

		if ( txbuf == NULL )
			break;

		snpnet_complete ( netdev, txbuf );
	}

	/* Process received packets */
	while ( 1 ) {
		/* The spec is not clear if the max packet size refers to the
		 * payload or the entire packet including headers. The Receive
		 * function needs a buffer large enough to contain the headers,
		 * and potentially a 4-byte CRC and 4-byte VLAN tag (?), so add
		 * some breathing room.
		 */
		len = snp->Mode->MaxPacketSize + ETH_HLEN + 8;
		iobuf = alloc_iob ( len );
		if ( iobuf == NULL ) {
			netdev_rx_err ( netdev, NULL, -ENOMEM );
			break;
		}

		efirc = snp->Receive ( snp, NULL, &len, iobuf->data,
				       NULL, NULL, NULL );

		/* No packets left? */
		if ( efirc == EFI_NOT_READY ) {
			free_iob ( iobuf );
			break;
		}

		/* Other error? */
		if ( efirc ) {
			DBGC ( snp, "SNP %p receive packet error: %s "
				    "(len was %zd, is now %zd)\n",
			       snp, efi_strerror ( efirc ), iob_len(iobuf),
			       (size_t)len );
			netdev_rx_err ( netdev, iobuf, efirc );
			break;
		}

		/* Packet is valid, deliver it */
		iob_put ( iobuf, len );
		netdev_rx ( netdev, iob_disown ( iobuf ) );
	}
}

/**
 * Open NIC
 *
 * @v netdev		Net device
 * @ret rc		Return status code
 */
static int snpnet_open ( struct net_device *netdev ) {
	struct snpnet_device *snpnetdev = netdev->priv;
	EFI_SIMPLE_NETWORK_PROTOCOL *snp = snpnetdev->snp;
	EFI_STATUS efirc;
	UINT32 enableFlags, disableFlags;

	snpnetdev->close_state = snp->Mode->State;
	if ( snp->Mode->State != EfiSimpleNetworkInitialized ) {
		efirc = snp->Initialize ( snp, 0, 0 );
		if ( efirc ) {
			DBGC ( snp, "SNP %p could not initialize: %s\n",
			       snp, efi_strerror ( efirc ) );
			return EFIRC_TO_RC ( efirc );
		}
	}

        /* Use the default MAC address */
	efirc = snp->StationAddress ( snp, FALSE,
				      (EFI_MAC_ADDRESS *)netdev->ll_addr );
	if ( efirc ) {
		DBGC ( snp, "SNP %p could not reset station address: %s\n",
		       snp, efi_strerror ( efirc ) );
	}

	/* Set up receive filters to receive unicast and broadcast packets
	 * always. Also, enable either promiscuous multicast (if possible) or
	 * promiscuous operation, in order to catch all multicast packets.
	 */
	enableFlags = snp->Mode->ReceiveFilterMask &
		      ( EFI_SIMPLE_NETWORK_RECEIVE_UNICAST |
			EFI_SIMPLE_NETWORK_RECEIVE_BROADCAST );
	disableFlags = snp->Mode->ReceiveFilterMask &
		       ( EFI_SIMPLE_NETWORK_RECEIVE_MULTICAST |
			 EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS |
			 EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS_MULTICAST );
	if ( snp->Mode->ReceiveFilterMask &
	     EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS_MULTICAST ) {
		enableFlags |= EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS_MULTICAST;
	} else if ( snp->Mode->ReceiveFilterMask &
		    EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS ) {
		enableFlags |= EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS;
	}
	disableFlags &= ~enableFlags;
	efirc = snp->ReceiveFilters ( snp, enableFlags, disableFlags,
				      FALSE, 0, NULL );
	if ( efirc ) {
		DBGC ( snp, "SNP %p could not set receive filters: %s\n",
		       snp, efi_strerror ( efirc ) );
	}

	DBGC ( snp, "SNP %p opened\n", snp );
	return 0;
}

/**
 * Close NIC
 *
 * @v netdev		Net device
 */
static void snpnet_close ( struct net_device *netdev ) {
	struct snpnet_device *snpnetdev = netdev->priv;
	EFI_SIMPLE_NETWORK_PROTOCOL *snp = snpnetdev->snp;
	EFI_STATUS efirc;

	if ( snpnetdev->close_state != EfiSimpleNetworkInitialized ) {
		efirc = snp->Shutdown ( snp );
		if ( efirc ) {
			DBGC ( snp, "SNP %p could not shut down: %s\n",
			       snp, efi_strerror ( efirc ) );
		}
	}
}

/**
 * Enable/disable interrupts
 *
 * @v netdev		Net device
 * @v enable		Interrupts should be enabled
 */
static void snpnet_irq ( struct net_device *netdev, int enable ) {
	struct snpnet_device *snpnetdev = netdev->priv;
	EFI_SIMPLE_NETWORK_PROTOCOL *snp = snpnetdev->snp;

	/* On EFI, interrupts are never necessary. (This function is only
	 * required for BIOS PXE.) If interrupts were required, they could be
	 * simulated using a fast timer.
	 */
	DBGC ( snp, "SNP %p cannot %s interrupts\n",
	       snp, ( enable ? "enable" : "disable" ) );
}

/** SNP network device operations */
static struct net_device_operations snpnet_operations = {
	.open		= snpnet_open,
	.close		= snpnet_close,
	.transmit	= snpnet_transmit,
	.poll		= snpnet_poll,
	.irq   		= snpnet_irq,
};

/**
 * Probe SNP device
 *
 * @v snpdev		SNP device
 * @ret rc		Return status code
 */
int snpnet_probe ( struct snp_device *snpdev ) {
	EFI_SIMPLE_NETWORK_PROTOCOL *snp = snpdev->snp;
	EFI_STATUS efirc;
	struct net_device *netdev;
	struct snpnet_device *snpnetdev;
	int rc;

	DBGC ( snp, "SNP %p probing...\n", snp );

	/* Allocate net device */
	netdev = alloc_etherdev ( sizeof ( struct snpnet_device ) );
	if ( ! netdev )
		return -ENOMEM;
	netdev_init ( netdev, &snpnet_operations );
	netdev->dev = &snpdev->dev;
	snpdev->netdev = netdev;
	snpnetdev = netdev->priv;
	snpnetdev->snp = snp;
	snpdev->removal_state = snp->Mode->State;

	/* Start the interface */
	if ( snp->Mode->State == EfiSimpleNetworkStopped ) {
		efirc = snp->Start ( snp );
		if ( efirc ) {
			DBGC ( snp, "SNP %p could not start: %s\n", snp,
			       efi_strerror ( efirc ) );
			rc = EFIRC_TO_RC ( efirc );
			goto err_start;
		}
	}

	if ( snp->Mode->HwAddressSize > sizeof ( netdev->hw_addr ) ) {
		DBGC ( snp, "SNP %p hardware address is too large\n", snp );
		rc = -EINVAL;
		goto err_hwaddr;
	}
	memcpy ( netdev->hw_addr, snp->Mode->PermanentAddress.Addr,
		 snp->Mode->HwAddressSize );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register;

	/* Mark as link up; we don't handle link state */
	netdev_link_up ( netdev );

	DBGC ( snp, "SNP %p added\n", snp );
	return 0;

err_register:
err_hwaddr:
	if ( snpdev->removal_state == EfiSimpleNetworkStopped )
		snp->Stop ( snp );

err_start:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
	snpdev->netdev = NULL;
	return rc;
}

/**
 * Remove SNP device
 *
 * @v snpdev		SNP device
 */
void snpnet_remove ( struct snp_device *snpdev ) {
	EFI_SIMPLE_NETWORK_PROTOCOL *snp = snpdev->snp;
	EFI_STATUS efirc;
	struct net_device *netdev = snpdev->netdev;

	if ( snp->Mode->State == EfiSimpleNetworkInitialized &&
	     snpdev->removal_state != EfiSimpleNetworkInitialized ) {
		DBGC ( snp, "SNP %p shutting down\n", snp );
		efirc = snp->Shutdown ( snp );
		if ( efirc ) {
			DBGC ( snp, "SNP %p could not shut down: %s\n",
			       snp, efi_strerror ( efirc ) );
		}
	}

	if ( snp->Mode->State == EfiSimpleNetworkStarted &&
	     snpdev->removal_state == EfiSimpleNetworkStopped ) {
		DBGC ( snp, "SNP %p stopping\n", snp );
		efirc = snp->Stop ( snp );
		if ( efirc ) {
			DBGC ( snp, "SNP %p could not be stopped\n", snp );
		}
	}

	/* Unregister net device */
	unregister_netdev ( netdev );

	/* Free network device */
	netdev_nullify ( netdev );
	netdev_put ( netdev );

	DBGC ( snp, "SNP %p removed\n", snp );
}
