/* 
   natsemi.c - iPXE driver for the NatSemi DP8381x series.
 
   Based on:

   natsemi.c: An Etherboot driver for the NatSemi DP8381x series.

   Copyright (C) 2001 Entity Cyber, Inc.
   
   This development of this Etherboot driver was funded by 
   
      Sicom Systems: http://www.sicompos.com/
   
   Author: Marty Connor <mdc@etherboot.org>
   Adapted from a Linux driver which was written by Donald Becker
   
   This software may be used and distributed according to the terms
   of the GNU Public License (GPL), incorporated herein by reference.
   
   Original Copyright Notice:
   
   Written/copyright 1999-2001 by Donald Becker.
   
   This software may be used and distributed according to the terms of
   the GNU General Public License (GPL), incorporated herein by reference.
   Drivers based on or derived from this code fall under the GPL and must
   retain the authorship, copyright and license notice.  This file is not
   a complete program and may only be used when the entire operating
   system is licensed under the GPL.  License for under other terms may be
   available.  Contact the original author for details.
   
   The original author may be reached as becker@scyld.com, or at
   Scyld Computing Corporation
   410 Severn Ave., Suite 210
   Annapolis MD 21403
   
   Support information and updates available at
   http://www.scyld.com/network/netsemi.html
   
   References:
   
   http://www.scyld.com/expert/100mbps.html
   http://www.scyld.com/expert/NWay.html
   Datasheet is available from:
   http://www.national.com/pf/DP/DP83815.html

*/

FILE_LICENCE ( GPL_ANY );

/* Revision History */

/*
  02 Jul 2007  Udayan Kumar	 1.2 ported the driver from etherboot to iPXE API.
				     Fully rewritten,adapting the old driver.
		      	      	     Added a circular buffer for transmit and receive.
		                     transmit routine will not wait for transmission to finish.
			             poll routine deals with it.
  13 Dec 2003  Tim Legge         1.1 Enabled Multicast Support
  29 May 2001  Marty Connor	 1.0 Initial Release. Tested with Netgear FA311 and FA312 boards
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ipxe/io.h>
#include <errno.h>
#include <byteswap.h>
#include <unistd.h>
#include <ipxe/pci.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/spi_bit.h>
#include <ipxe/threewire.h>
#include <ipxe/nvo.h>
#include "natsemi.h"

/*  Function Prototypes: */
 
static int natsemi_spi_read_bit ( struct bit_basher *, unsigned int );
static void natsemi_spi_write_bit ( struct bit_basher *,unsigned int, unsigned long ); 
static void natsemi_init_eeprom ( struct natsemi_private * ); 
static int natsemi_probe (struct pci_device *pci);
static void natsemi_reset (struct net_device *netdev);
static int natsemi_open (struct net_device *netdev);
static int natsemi_transmit (struct net_device *netdev, struct io_buffer *iobuf);
static void natsemi_poll (struct net_device *netdev);
static void natsemi_close (struct net_device *netdev);
static void natsemi_irq (struct net_device *netdev, int enable);
static void natsemi_remove (struct pci_device *pci);

/** natsemi net device operations */
static struct net_device_operations natsemi_operations = {
        .open           = natsemi_open,
        .close          = natsemi_close,
        .transmit       = natsemi_transmit,
        .poll           = natsemi_poll,
	.irq		= natsemi_irq,
};

static int natsemi_spi_read_bit ( struct bit_basher *basher,
			      unsigned int bit_id ) {
	struct natsemi_private *np = container_of ( basher, struct natsemi_private,
						 spibit.basher );
	uint8_t mask = natsemi_ee_bits[bit_id];
	uint8_t eereg;

	eereg = inb ( np->ioaddr + EE_REG );
	return ( eereg & mask );
}

static void natsemi_spi_write_bit ( struct bit_basher *basher,
				unsigned int bit_id, unsigned long data ) {
	struct natsemi_private *np = container_of ( basher, struct natsemi_private,
						 spibit.basher );
	uint8_t mask = natsemi_ee_bits[bit_id];
	uint8_t eereg;

	eereg = inb ( np->ioaddr + EE_REG );
	eereg &= ~mask;
	eereg |= ( data & mask );
	outb ( eereg, np->ioaddr + EE_REG );
}

static struct bit_basher_operations natsemi_basher_ops = {
	.read = natsemi_spi_read_bit,
	.write = natsemi_spi_write_bit,
};

/*
 * Set up for EEPROM access
 *
 * @v NAT		NATSEMI NIC
 */
static void natsemi_init_eeprom ( struct natsemi_private *np ) {

	/* Initialise three-wire bus 
	 */
	np->spibit.basher.op = &natsemi_basher_ops;
	np->spibit.bus.mode = SPI_MODE_THREEWIRE;
	np->spibit.endianness = SPI_BIT_LITTLE_ENDIAN;
	init_spi_bit_basher ( &np->spibit );

	/*natsemi DP 83815 only supports at93c46
	 */
	init_at93c46 ( &np->eeprom, 16 );
	np->eeprom.bus = &np->spibit.bus;

	/* It looks that this portion of EEPROM can be used for
	 * non-volatile stored options. Data sheet does not talk about
	 * this region.  Currently it is not working. But with some
	 * efforts it can.
	 */
	nvo_init ( &np->nvo, &np->eeprom.nvs, 0x0c, 0x68, NULL, NULL );
}

/**
 * Probe PCI device
 *
 * @v pci	PCI device
 * @v id	PCI ID
 * @ret rc	Return status code
 */
static int natsemi_probe (struct pci_device *pci) {
	struct net_device *netdev;
	struct natsemi_private *np = NULL;
	uint8_t ll_addr_encoded[MAX_LL_ADDR_LEN];
	uint8_t last=0,last1=0;
	uint8_t prev_bytes[2];
	int i;
	int rc;

	/* Allocate net device 
	 */
	netdev = alloc_etherdev (sizeof (*np));
	if (! netdev) 
		return -ENOMEM;

	netdev_init (netdev, &natsemi_operations);
	np = netdev->priv;
	pci_set_drvdata (pci, netdev);
	netdev->dev = &pci->dev;
	memset (np, 0, sizeof (*np));
	np->ioaddr = pci->ioaddr;

	adjust_pci_device (pci);

	natsemi_reset (netdev);
	natsemi_init_eeprom ( np );
	nvs_read ( &np->eeprom.nvs, EE_MAC-1, prev_bytes, 1 );
	nvs_read ( &np->eeprom.nvs, EE_MAC, ll_addr_encoded, ETH_ALEN );

	/* decoding the MAC address read from NVS 
	 * and save it in netdev->ll_addr
         */
	last = prev_bytes[1] >> 7;
	for ( i = 0 ; i < ETH_ALEN ; i++ ) {
		last1 = ll_addr_encoded[i] >> 7;
		netdev->hw_addr[i] = ll_addr_encoded[i] << 1 | last;
		last = last1;
	}

	if ((rc = register_netdev (netdev)) != 0)
		goto err_register_netdev;

	/* Mark as link up; we don't yet handle link state */
	netdev_link_up ( netdev );

	return 0;

err_register_netdev:

	natsemi_reset (netdev);
	netdev_put (netdev);
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci	PCI device
 */
static void natsemi_remove (struct pci_device *pci) {
	struct net_device *netdev = pci_get_drvdata (pci);
 
	unregister_netdev (netdev);
	natsemi_reset (netdev);
	netdev_nullify ( netdev );
	netdev_put (netdev);
}

/**
 * Reset NIC
 *
 * @v		NATSEMI NIC
 *
 * Issues a hardware reset and waits for the reset to complete.
 */
static void natsemi_reset (struct net_device *netdev) 
{
	struct natsemi_private *np = netdev->priv;
	int i;
        u32 cfg;
        u32 wcsr;
        u32 rfcr;
        u16 pmatch[3];
        u16 sopass[3];

	natsemi_irq (netdev, 0);

        /*
         * Resetting the chip causes some registers to be lost.
         * Natsemi suggests NOT reloading the EEPROM while live, so instead
         * we save the state that would have been loaded from EEPROM
         * on a normal power-up (see the spec EEPROM map).
         */

        /* CFG */
        cfg = inl (np->ioaddr + ChipConfig) & CFG_RESET_SAVE;

        /* WCSR */
        wcsr = inl (np->ioaddr + WOLCmd) & WCSR_RESET_SAVE;

        /* RFCR */
        rfcr = inl (np->ioaddr + RxFilterAddr) & RFCR_RESET_SAVE;

        /* PMATCH */
        for (i = 0; i < 3; i++) {
		outl(i*2, np->ioaddr + RxFilterAddr);
		pmatch[i] = inw(np->ioaddr + RxFilterData);
        }

        /* SOPAS */
        for (i = 0; i < 3; i++) {
	  	outl(0xa+(i*2), np->ioaddr + RxFilterAddr);
		sopass[i] = inw(np->ioaddr + RxFilterData);
        }

        /* now whack the chip */
        outl(ChipReset, np->ioaddr + ChipCmd);
        for (i=0; i<NATSEMI_HW_TIMEOUT; i++) {
		if (! (inl (np->ioaddr + ChipCmd) & ChipReset))
		       break;
		udelay(5);
        }
        if (i == NATSEMI_HW_TIMEOUT) {
	  	DBG ("natsemi_reset: reset did not complete in %d usec.\n", i*5);
        }

        /* restore CFG */
        cfg |= inl(np->ioaddr + ChipConfig) & ~CFG_RESET_SAVE;
	cfg &= ~(CfgExtPhy | CfgPhyDis);
        outl (cfg, np->ioaddr + ChipConfig);

        /* restore WCSR */
        wcsr |= inl (np->ioaddr + WOLCmd) & ~WCSR_RESET_SAVE;
        outl (wcsr, np->ioaddr + WOLCmd);

        /* read RFCR */
        rfcr |= inl (np->ioaddr + RxFilterAddr) & ~RFCR_RESET_SAVE;

        /* restore PMATCH */
        for (i = 0; i < 3; i++) {
	  	outl (i*2, np->ioaddr + RxFilterAddr);
		outw (pmatch[i], np->ioaddr + RxFilterData);
        }
        for (i = 0; i < 3; i++) {
		outl (0xa+(i*2), np->ioaddr + RxFilterAddr);
		outw (sopass[i], np->ioaddr + RxFilterData);
        }
        /* restore RFCR */
        outl (rfcr, np->ioaddr + RxFilterAddr);
}

/**
 * Open NIC
 *
 * @v netdev		Net device
 * @ret rc		Return status code
 */
static int natsemi_open (struct net_device *netdev)
{
	struct natsemi_private *np = netdev->priv;
	uint32_t tx_config, rx_config;
	int i;
	
	/* Disable PME:
         * The PME bit is initialized from the EEPROM contents.
         * PCI cards probably have PME disabled, but motherboard
         * implementations may have PME set to enable WakeOnLan. 
         * With PME set the chip will scan incoming packets but
         * nothing will be written to memory. 
         */
        outl (inl (np->ioaddr + ClkRun) & ~0x100, np->ioaddr + ClkRun);

	/* Set MAC address in NIC
	 */
	for (i = 0 ; i < ETH_ALEN ; i+=2) {
		outl (i, np->ioaddr + RxFilterAddr);
		outw (netdev->ll_addr[i] + (netdev->ll_addr[i + 1] << 8),
		       np->ioaddr + RxFilterData);
	}

	/* Setup Tx Ring 
	 */
	np->tx_cur = 0;
	np->tx_dirty = 0;
	for (i = 0 ; i < TX_RING_SIZE ; i++) {
		np->tx[i].link   = virt_to_bus ((i + 1 < TX_RING_SIZE) ? &np->tx[i + 1] : &np->tx[0]);
		np->tx[i].cmdsts = 0;
		np->tx[i].bufptr = 0;
	}
	outl (virt_to_bus (&np->tx[0]),np->ioaddr + TxRingPtr);

	DBG ("Natsemi Tx descriptor loaded with: %#08x\n",
	     inl (np->ioaddr + TxRingPtr));

	/* Setup RX ring
	 */
	np->rx_cur = 0;
	for (i = 0 ; i < NUM_RX_DESC ; i++) {
		np->iobuf[i] = alloc_iob (RX_BUF_SIZE);
		if (! np->iobuf[i])
			goto memory_alloc_err;
		np->rx[i].link   = virt_to_bus ((i + 1 < NUM_RX_DESC) 
						? &np->rx[i + 1] : &np->rx[0]);
		np->rx[i].cmdsts = RX_BUF_SIZE;
		np->rx[i].bufptr = virt_to_bus (np->iobuf[i]->data);
		DBG (" Address of iobuf [%d] = %p and iobuf->data = %p \n", i, 
		      &np->iobuf[i],  &np->iobuf[i]->data);
	}
	outl (virt_to_bus (&np->rx[0]), np->ioaddr + RxRingPtr);

	DBG ("Natsemi Rx descriptor loaded with: %#08x\n",
	      inl (np->ioaddr + RxRingPtr));		

	/* Setup RX Filter 
	 */
	outl (RxFilterEnable | AcceptBroadcast | AcceptAllMulticast | AcceptMyPhys,
	      np->ioaddr + RxFilterAddr);

	/* Initialize other registers. 
	 * Configure the PCI bus bursts and FIFO thresholds. 
	 * Configure for standard, in-spec Ethernet. 
	 */
	if (inl (np->ioaddr + ChipConfig) & 0x20000000) {	/* Full duplex */
		DBG ("Full duplex\n");
		tx_config = 0xD0801002 |  0xC0000000;
		rx_config = 0x10000020 |  0x10000000;
	} else {
		DBG ("Half duplex\n");
		tx_config = 0x10801002 & ~0xC0000000;
		rx_config = 0x00000020 & ~0x10000000;
	}
	outl (tx_config, np->ioaddr + TxConfig);
	outl (rx_config, np->ioaddr + RxConfig);

	DBG ("Tx config register = %#08x Rx config register = %#08x\n", 
               inl (np->ioaddr + TxConfig),
	       inl (np->ioaddr + RxConfig));

	/*Set the Interrupt Mask register
	 */
	outl((RxOk|RxErr|TxOk|TxErr),np->ioaddr + IntrMask);
	/*start the receiver 
	 */
        outl (RxOn, np->ioaddr + ChipCmd);
	
	return 0;
		       
memory_alloc_err:

	/* Frees any allocated buffers when memory
	 * for all buffers requested is not available
	 */
	i = 0;
	while (np->rx[i].cmdsts == RX_BUF_SIZE) {
		free_iob (np->iobuf[i]);
		i++;
	}
	return -ENOMEM;	
}

/**
 * Close NIC
 *
 * @v netdev		Net device
 */
static void natsemi_close (struct net_device *netdev) 
{
	struct natsemi_private *np = netdev->priv;
	int i;

	natsemi_reset (netdev);

	for (i = 0; i < NUM_RX_DESC ; i++) {
		free_iob (np->iobuf[i]);
	}
}

/** 
 * Transmit packet
 *
 * @v netdev	Network device
 * @v iobuf	I/O buffer
 * @ret rc	Return status code
 */
static int natsemi_transmit (struct net_device *netdev, struct io_buffer *iobuf)
{
	struct natsemi_private *np = netdev->priv;

	if (np->tx[np->tx_cur].cmdsts != 0) {
		DBG ("TX overflow\n");
		return -ENOBUFS;
	}

	/* Used by netdev_tx_complete ()
	 */
	np->tx_iobuf[np->tx_cur] = iobuf;

	/* Pad and align packet has not been used because its not required 
	 * by the hardware.
	 * 	iob_pad (iobuf, ETH_ZLEN); 
	 * can be used to achieve it, if required
	 */

	/* Add the packet to TX ring
	 */
	np->tx[np->tx_cur].bufptr = virt_to_bus (iobuf->data);
	np->tx[np->tx_cur].cmdsts = iob_len (iobuf) | OWN;

	DBG ("TX id %d at %#08lx + %#08zx\n", np->tx_cur,
	     virt_to_bus (&iobuf->data), iob_len (iobuf));

	/* increment the circular buffer pointer to the next buffer location
	 */
	np->tx_cur = (np->tx_cur + 1) % TX_RING_SIZE;

	/*start the transmitter 
	 */
        outl (TxOn, np->ioaddr + ChipCmd);

	return 0;
}

/** 
 * Poll for received packets
 *
 * @v netdev	Network device
 */
static void natsemi_poll (struct net_device *netdev)
{
	struct natsemi_private *np = netdev->priv;
	unsigned int tx_status;
	unsigned int rx_status;
	unsigned int intr_status;
	unsigned int rx_len;
	struct io_buffer *rx_iob;
	int i;
	
	/* read the interrupt register
	 */
	intr_status = inl (np->ioaddr + IntrStatus);

	if (!intr_status)
		goto end;

        DBG ("natsemi_poll: intr_status = %#08x\n", intr_status);

	/* Check status of transmitted packets
	 */
	i = np->tx_dirty;
	while (i != np->tx_cur) {
	  	tx_status = np->tx[np->tx_dirty].cmdsts;

		DBG ("tx_dirty = %d tx_cur=%d tx_status=%#08x\n",
		     np->tx_dirty, np->tx_cur, tx_status);
		
		if (tx_status & OWN) 
			break;

		if (! (tx_status & DescPktOK)) {
			netdev_tx_complete_err (netdev,np->tx_iobuf[np->tx_dirty],-EINVAL);
			DBG ("Error transmitting packet, tx_status: %#08x\n",
			     tx_status);
		} else {
			netdev_tx_complete (netdev, np->tx_iobuf[np->tx_dirty]);
			DBG ("Success transmitting packet\n");
		}

		np->tx[np->tx_dirty].cmdsts = 0;
		np->tx_dirty = (np->tx_dirty + 1) % TX_RING_SIZE;
		i = (i + 1) % TX_RING_SIZE;
	}
	
	/* Process received packets 
	 */
	rx_status = (unsigned int) np->rx[np->rx_cur].cmdsts; 
	while ((rx_status & OWN)) {
		rx_len = (rx_status & DSIZE) - CRC_SIZE;

                DBG ("Received packet, rx_curr = %d, rx_status = %#08x, rx_len = %d\n",
                     np->rx_cur, rx_status, rx_len);
                
		if ((rx_status & (DescMore | DescPktOK | RxTooLong)) != DescPktOK) {
			netdev_rx_err (netdev, NULL, -EINVAL);

			DBG ("natsemi_poll: Corrupted packet received!"
			     " Status = %#08x\n",
			      np->rx[np->rx_cur].cmdsts);

		} else 	{


			/* If unable allocate space for this packet,
			 *  try again next poll
			 */
			rx_iob = alloc_iob (rx_len);
			if (! rx_iob) 
				goto end;
			memcpy (iob_put (rx_iob, rx_len), 
				np->iobuf[np->rx_cur]->data, rx_len);
			/* Add this packet to the receive queue. 
			 */
			netdev_rx (netdev, rx_iob);
		}
		np->rx[np->rx_cur].cmdsts = RX_BUF_SIZE;
		np->rx_cur = (np->rx_cur + 1) % NUM_RX_DESC;
		rx_status = np->rx[np->rx_cur].cmdsts; 
	}
end:
	/* re-enable the potentially idle receive state machine 
	 */
	outl (RxOn, np->ioaddr + ChipCmd);	
}				

/**
 * Enable/disable interrupts
 *
 * @v netdev    Network device
 * @v enable    Non-zero for enable, zero for disable
 */
static void natsemi_irq (struct net_device *netdev, int enable)
{
        struct natsemi_private *np = netdev->priv;

	outl ((enable ? (RxOk | RxErr | TxOk|TxErr) : 0),
	      np->ioaddr + IntrMask); 
	outl ((enable ? 1 : 0), np->ioaddr + IntrEnable);
}

static struct pci_device_id natsemi_nics[] = {
	PCI_ROM(0x100b, 0x0020, "dp83815", "DP83815", 0),
};

struct pci_driver natsemi_driver __pci_driver = {
	.ids = natsemi_nics,
	.id_count = (sizeof (natsemi_nics) / sizeof (natsemi_nics[0])),
	.probe = natsemi_probe,
	.remove = natsemi_remove,
};
