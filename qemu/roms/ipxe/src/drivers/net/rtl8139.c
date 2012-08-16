/* rtl8139.c - etherboot driver for the Realtek 8139 chipset

  ported from the linux driver written by Donald Becker
  by Rainer Bawidamann (Rainer.Bawidamann@informatik.uni-ulm.de) 1999

  This software may be used and distributed according to the terms
  of the GNU Public License, incorporated herein by reference.

  changes to the original driver:
  - removed support for interrupts, switching to polling mode (yuck!)
  - removed support for the 8129 chip (external MII)

*/

FILE_LICENCE ( GPL_ANY );

/*********************************************************************/
/* Revision History                                                  */
/*********************************************************************/

/*
  27 May 2006	mcb30@users.sourceforge.net (Michael Brown)
     Rewrote to use the new net driver API, the updated PCI API, and
     the generic three-wire serial device support for EEPROM access.

  28 Dec 2002	ken_yap@users.sourceforge.net (Ken Yap)
     Put in virt_to_bus calls to allow Etherboot relocation.

  06 Apr 2001	ken_yap@users.sourceforge.net (Ken Yap)
     Following email from Hyun-Joon Cha, added a disable routine, otherwise
     NIC remains live and can crash the kernel later.

  4 Feb 2000	espenlaub@informatik.uni-ulm.de (Klaus Espenlaub)
     Shuffled things around, removed the leftovers from the 8129 support
     that was in the Linux driver and added a bit more 8139 definitions.
     Moved the 8K receive buffer to a fixed, available address outside the
     0x98000-0x9ffff range.  This is a bit of a hack, but currently the only
     way to make room for the Etherboot features that need substantial amounts
     of code like the ANSI console support.  Currently the buffer is just below
     0x10000, so this even conforms to the tagged boot image specification,
     which reserves the ranges 0x00000-0x10000 and 0x98000-0xA0000.  My
     interpretation of this "reserved" is that Etherboot may do whatever it
     likes, as long as its environment is kept intact (like the BIOS
     variables).  Hopefully fixed rtl_poll() once and for all.  The symptoms
     were that if Etherboot was left at the boot menu for several minutes, the
     first eth_poll failed.  Seems like I am the only person who does this.
     First of all I fixed the debugging code and then set out for a long bug
     hunting session.  It took me about a week full time work - poking around
     various places in the driver, reading Don Becker's and Jeff Garzik's Linux
     driver and even the FreeBSD driver (what a piece of crap!) - and
     eventually spotted the nasty thing: the transmit routine was acknowledging
     each and every interrupt pending, including the RxOverrun and RxFIFIOver
     interrupts.  This confused the RTL8139 thoroughly.  It destroyed the
     Rx ring contents by dumping the 2K FIFO contents right where we wanted to
     get the next packet.  Oh well, what fun.

  18 Jan 2000   mdc@etherboot.org (Marty Connor)
     Drastically simplified error handling.  Basically, if any error
     in transmission or reception occurs, the card is reset.
     Also, pointed all transmit descriptors to the same buffer to
     save buffer space.  This should decrease driver size and avoid
     corruption because of exceeding 32K during runtime.

  28 Jul 1999   (Matthias Meixner - meixner@rbg.informatik.tu-darmstadt.de)
     rtl_poll was quite broken: it used the RxOK interrupt flag instead
     of the RxBufferEmpty flag which often resulted in very bad
     transmission performace - below 1kBytes/s.

*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ipxe/io.h>
#include <errno.h>
#include <unistd.h>
#include <byteswap.h>
#include <ipxe/pci.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/spi_bit.h>
#include <ipxe/threewire.h>
#include <ipxe/nvo.h>

#define TX_RING_SIZE 4
#define TX_MAX_LEN 8192

struct rtl8139_tx {
	unsigned int next;
	struct io_buffer *iobuf[TX_RING_SIZE];
};

struct rtl8139_rx {
	void *ring;
	unsigned int offset;
};

struct rtl8139_nic {
	unsigned short ioaddr;
	struct rtl8139_tx tx;
	struct rtl8139_rx rx;
	struct spi_bit_basher spibit;
	struct spi_device eeprom;
	struct nvo_block nvo;
};

/* Tuning Parameters */
#define TX_FIFO_THRESH	256	/* In bytes, rounded down to 32 byte units. */
#define RX_FIFO_THRESH	4	/* Rx buffer level before first PCI xfer.  */
#define RX_DMA_BURST	4	/* Maximum PCI burst, '4' is 256 bytes */
#define TX_DMA_BURST	4	/* Calculate as 16<<val. */
#define TX_IPG		3	/* This is the only valid value */
#define RX_BUF_LEN_IDX	0	/* 0, 1, 2 is allowed - 8,16,32K rx buffer */
#define RX_BUF_LEN ( (8192 << RX_BUF_LEN_IDX) )
#define RX_BUF_PAD 4

/* Symbolic offsets to registers. */
enum RTL8139_registers {
	MAC0=0,			/* Ethernet hardware address. */
	MAR0=8,			/* Multicast filter. */
	TxStatus0=0x10,		/* Transmit status (four 32bit registers). */
	TxAddr0=0x20,		/* Tx descriptors (also four 32bit). */
	RxBuf=0x30, RxEarlyCnt=0x34, RxEarlyStatus=0x36,
	ChipCmd=0x37, RxBufPtr=0x38, RxBufAddr=0x3A,
	IntrMask=0x3C, IntrStatus=0x3E,
	TxConfig=0x40, RxConfig=0x44,
	Timer=0x48,		/* general-purpose counter. */
	RxMissed=0x4C,		/* 24 bits valid, write clears. */
	Cfg9346=0x50, Config0=0x51, Config1=0x52,
	TimerIntrReg=0x54,	/* intr if gp counter reaches this value */
	MediaStatus=0x58,
	Config3=0x59,
	MultiIntr=0x5C,
	RevisionID=0x5E,	/* revision of the RTL8139 chip */
	TxSummary=0x60,
	MII_BMCR=0x62, MII_BMSR=0x64, NWayAdvert=0x66, NWayLPAR=0x68,
	NWayExpansion=0x6A,
	DisconnectCnt=0x6C, FalseCarrierCnt=0x6E,
	NWayTestReg=0x70,
	RxCnt=0x72,		/* packet received counter */
	CSCR=0x74,		/* chip status and configuration register */
	PhyParm1=0x78,TwisterParm=0x7c,PhyParm2=0x80,	/* undocumented */
	/* from 0x84 onwards are a number of power management/wakeup frame
	 * definitions we will probably never need to know about.  */
};

enum RxEarlyStatusBits {
	ERGood=0x08, ERBad=0x04, EROVW=0x02, EROK=0x01
};

enum ChipCmdBits {
	CmdReset=0x10, CmdRxEnb=0x08, CmdTxEnb=0x04, RxBufEmpty=0x01, };

enum IntrMaskBits {
	SERR=0x8000, TimeOut=0x4000, LenChg=0x2000,
	FOVW=0x40, PUN_LinkChg=0x20, RXOVW=0x10,
	TER=0x08, TOK=0x04, RER=0x02, ROK=0x01
};

/* Interrupt register bits, using my own meaningful names. */
enum IntrStatusBits {
	PCIErr=0x8000, PCSTimeout=0x4000, CableLenChange= 0x2000,
	RxFIFOOver=0x40, RxUnderrun=0x20, RxOverflow=0x10,
	TxErr=0x08, TxOK=0x04, RxErr=0x02, RxOK=0x01,
};
enum TxStatusBits {
	TxHostOwns=0x2000, TxUnderrun=0x4000, TxStatOK=0x8000,
	TxOutOfWindow=0x20000000, TxAborted=0x40000000,
	TxCarrierLost=0x80000000,
};
enum RxStatusBits {
	RxMulticast=0x8000, RxPhysical=0x4000, RxBroadcast=0x2000,
	RxBadSymbol=0x0020, RxRunt=0x0010, RxTooLong=0x0008, RxCRCErr=0x0004,
	RxBadAlign=0x0002, RxStatusOK=0x0001,
};

enum MediaStatusBits {
	MSRTxFlowEnable=0x80, MSRRxFlowEnable=0x40, MSRSpeed10=0x08,
	MSRLinkFail=0x04, MSRRxPauseFlag=0x02, MSRTxPauseFlag=0x01,
};

enum MIIBMCRBits {
	BMCRReset=0x8000, BMCRSpeed100=0x2000, BMCRNWayEnable=0x1000,
	BMCRRestartNWay=0x0200, BMCRDuplex=0x0100,
};

enum CSCRBits {
	CSCR_LinkOKBit=0x0400, CSCR_LinkChangeBit=0x0800,
	CSCR_LinkStatusBits=0x0f000, CSCR_LinkDownOffCmd=0x003c0,
	CSCR_LinkDownCmd=0x0f3c0,
};

enum RxConfigBits {
	RxCfgWrap=0x80,
	Eeprom9356=0x40,
	AcceptErr=0x20, AcceptRunt=0x10, AcceptBroadcast=0x08,
	AcceptMulticast=0x04, AcceptMyPhys=0x02, AcceptAllPhys=0x01,
};

enum Config1Bits {
	VPDEnable=0x02,
};

/*  EEPROM access */
#define EE_M1		0x80	/* Mode select bit 1 */
#define EE_M0		0x40	/* Mode select bit 0 */
#define EE_CS		0x08	/* EEPROM chip select */
#define EE_SK		0x04	/* EEPROM shift clock */
#define EE_DI		0x02	/* Data in */
#define EE_DO		0x01	/* Data out */

/* Offsets within EEPROM (these are word offsets) */
#define EE_MAC 7

static const uint8_t rtl_ee_bits[] = {
	[SPI_BIT_SCLK]	= EE_SK,
	[SPI_BIT_MOSI]	= EE_DI,
	[SPI_BIT_MISO]	= EE_DO,
	[SPI_BIT_SS(0)]	= ( EE_CS | EE_M1 ),
};

static int rtl_spi_read_bit ( struct bit_basher *basher,
			      unsigned int bit_id ) {
	struct rtl8139_nic *rtl = container_of ( basher, struct rtl8139_nic,
						 spibit.basher );
	uint8_t mask = rtl_ee_bits[bit_id];
	uint8_t eereg;

	eereg = inb ( rtl->ioaddr + Cfg9346 );
	return ( eereg & mask );
}

static void rtl_spi_write_bit ( struct bit_basher *basher,
				unsigned int bit_id, unsigned long data ) {
	struct rtl8139_nic *rtl = container_of ( basher, struct rtl8139_nic,
						 spibit.basher );
	uint8_t mask = rtl_ee_bits[bit_id];
	uint8_t eereg;

	eereg = inb ( rtl->ioaddr + Cfg9346 );
	eereg &= ~mask;
	eereg |= ( data & mask );
	outb ( eereg, rtl->ioaddr + Cfg9346 );
}

static struct bit_basher_operations rtl_basher_ops = {
	.read = rtl_spi_read_bit,
	.write = rtl_spi_write_bit,
};

/**
 * Set up for EEPROM access
 *
 * @v netdev		Net device
 */
static void rtl_init_eeprom ( struct net_device *netdev ) {
	struct rtl8139_nic *rtl = netdev->priv;
	int ee9356;
	int vpd;

	/* Initialise three-wire bus */
	rtl->spibit.basher.op = &rtl_basher_ops;
	rtl->spibit.bus.mode = SPI_MODE_THREEWIRE;
	init_spi_bit_basher ( &rtl->spibit );

	/* Detect EEPROM type and initialise three-wire device */
	ee9356 = ( inw ( rtl->ioaddr + RxConfig ) & Eeprom9356 );
	if ( ee9356 ) {
		DBGC ( rtl, "rtl8139 %p EEPROM is an AT93C56\n", rtl );
		init_at93c56 ( &rtl->eeprom, 16 );
	} else {
		DBGC ( rtl, "rtl8139 %p EEPROM is an AT93C46\n", rtl );
		init_at93c46 ( &rtl->eeprom, 16 );
	}
	rtl->eeprom.bus = &rtl->spibit.bus;

	/* Initialise space for non-volatile options, if available
	 *
	 * We use offset 0x40 (i.e. address 0x20), length 0x40.  This
	 * block is marked as VPD in the rtl8139 datasheets, so we use
	 * it only if we detect that the card is not supporting VPD.
	 */
	vpd = ( inw ( rtl->ioaddr + Config1 ) & VPDEnable );
	if ( vpd ) {
		DBGC ( rtl, "rtl8139 %p EEPROM in use for VPD; cannot use "
		       "for options\n", rtl );
	} else {
		nvo_init ( &rtl->nvo, &rtl->eeprom.nvs, 0x20, 0x40, NULL,
			   &netdev->refcnt );
	}
}

/**
 * Reset NIC
 *
 * @v netdev		Net device
 *
 * Issues a hardware reset and waits for the reset to complete.
 */
static void rtl_reset ( struct net_device *netdev ) {
	struct rtl8139_nic *rtl = netdev->priv;

	/* Reset chip */
	outb ( CmdReset, rtl->ioaddr + ChipCmd );
	mdelay ( 10 );
	memset ( &rtl->tx, 0, sizeof ( rtl->tx ) );
	rtl->rx.offset = 0;
}

/**
 * Open NIC
 *
 * @v netdev		Net device
 * @ret rc		Return status code
 */
static int rtl_open ( struct net_device *netdev ) {
	struct rtl8139_nic *rtl = netdev->priv;
	int i;

	/* Program the MAC address */
	for ( i = 0 ; i < ETH_ALEN ; i++ )
		outb ( netdev->ll_addr[i], rtl->ioaddr + MAC0 + i );

	/* Set up RX ring */
	rtl->rx.ring = malloc ( RX_BUF_LEN + RX_BUF_PAD );
	if ( ! rtl->rx.ring )
		return -ENOMEM;
	outl ( virt_to_bus ( rtl->rx.ring ), rtl->ioaddr + RxBuf );
	DBGC ( rtl, "rtl8139 %p RX ring at %lx\n",
	       rtl, virt_to_bus ( rtl->rx.ring ) );

	/* Enable TX and RX */
	outb ( ( CmdRxEnb | CmdTxEnb ), rtl->ioaddr + ChipCmd );
	outl ( ( ( RX_FIFO_THRESH << 13 ) | ( RX_BUF_LEN_IDX << 11 ) |
		 ( RX_DMA_BURST << 8 ) | AcceptBroadcast | AcceptMulticast |
		 AcceptMyPhys | AcceptAllPhys ), rtl->ioaddr + RxConfig );
	outl ( 0xffffffffUL, rtl->ioaddr + MAR0 + 0 );
	outl ( 0xffffffffUL, rtl->ioaddr + MAR0 + 4 );
	outl ( ( ( TX_DMA_BURST << 8 ) | ( TX_IPG << 24 ) ),
	       rtl->ioaddr + TxConfig );

	return 0;
}

/**
 * Close NIC
 *
 * @v netdev		Net device
 */
static void rtl_close ( struct net_device *netdev ) {
	struct rtl8139_nic *rtl = netdev->priv;

	/* Reset the hardware to disable everything in one go */
	rtl_reset ( netdev );

	/* Free RX ring */
	free ( rtl->rx.ring );
	rtl->rx.ring = NULL;
}

/** 
 * Transmit packet
 *
 * @v netdev	Network device
 * @v iobuf	I/O buffer
 * @ret rc	Return status code
 */
static int rtl_transmit ( struct net_device *netdev,
			  struct io_buffer *iobuf ) {
	struct rtl8139_nic *rtl = netdev->priv;

	/* Check for space in TX ring */
	if ( rtl->tx.iobuf[rtl->tx.next] != NULL ) {
		DBGC ( rtl, "rtl8139 %p TX overflow\n", rtl );
		return -ENOBUFS;
	}

	/* Check for oversized packets */
	if ( iob_len ( iobuf ) >= TX_MAX_LEN ) {
		DBGC ( rtl, "rtl8139 %p TX too large (%zd bytes)\n",
		       rtl, iob_len ( iobuf ) );
		return -ERANGE;
	}

	/* Pad and align packet */
	iob_pad ( iobuf, ETH_ZLEN );

	/* Add to TX ring */
	DBGC2 ( rtl, "rtl8139 %p TX id %d at %lx+%zx\n", rtl, rtl->tx.next,
		virt_to_bus ( iobuf->data ), iob_len ( iobuf ) );
	rtl->tx.iobuf[rtl->tx.next] = iobuf;
	outl ( virt_to_bus ( iobuf->data ),
	       rtl->ioaddr + TxAddr0 + 4 * rtl->tx.next );
	outl ( ( ( ( TX_FIFO_THRESH & 0x7e0 ) << 11 ) | iob_len ( iobuf ) ),
	       rtl->ioaddr + TxStatus0 + 4 * rtl->tx.next );
	rtl->tx.next = ( rtl->tx.next + 1 ) % TX_RING_SIZE;

	return 0;
}

/**
 * Poll for received packets
 *
 * @v netdev	Network device
 */
static void rtl_poll ( struct net_device *netdev ) {
	struct rtl8139_nic *rtl = netdev->priv;
	unsigned int status;
	unsigned int tsad;
	unsigned int rx_status;
	unsigned int rx_len;
	struct io_buffer *rx_iob;
	int wrapped_len;
	int i;

	/* Acknowledge interrupts */
	status = inw ( rtl->ioaddr + IntrStatus );
	if ( ! status )
		return;
	outw ( status, rtl->ioaddr + IntrStatus );

	/* Handle TX completions */
	tsad = inw ( rtl->ioaddr + TxSummary );
	for ( i = 0 ; i < TX_RING_SIZE ; i++ ) {
		if ( ( rtl->tx.iobuf[i] != NULL ) && ( tsad & ( 1 << i ) ) ) {
			DBGC2 ( rtl, "rtl8139 %p TX id %d complete\n",
				rtl, i );
			netdev_tx_complete ( netdev, rtl->tx.iobuf[i] );
			rtl->tx.iobuf[i] = NULL;
		}
	}

	/* Handle received packets */
	while ( ! ( inw ( rtl->ioaddr + ChipCmd ) & RxBufEmpty ) ) {
		rx_status = * ( ( uint16_t * )
				( rtl->rx.ring + rtl->rx.offset ) );
		rx_len = * ( ( uint16_t * )
			     ( rtl->rx.ring + rtl->rx.offset + 2 ) );
		if ( rx_status & RxOK ) {
			DBGC2 ( rtl, "rtl8139 %p RX packet at offset "
				"%x+%x\n", rtl, rtl->rx.offset, rx_len );

			rx_iob = alloc_iob ( rx_len );
			if ( ! rx_iob ) {
				netdev_rx_err ( netdev, NULL, -ENOMEM );
				/* Leave packet for next call to poll() */
				break;
			}

			wrapped_len = ( ( rtl->rx.offset + 4 + rx_len )
					- RX_BUF_LEN );
			if ( wrapped_len < 0 )
				wrapped_len = 0;

			memcpy ( iob_put ( rx_iob, rx_len - wrapped_len ),
				 rtl->rx.ring + rtl->rx.offset + 4,
				 rx_len - wrapped_len );
			memcpy ( iob_put ( rx_iob, wrapped_len ),
				 rtl->rx.ring, wrapped_len );
			iob_unput ( rx_iob, 4 ); /* Strip CRC */

			netdev_rx ( netdev, rx_iob );
		} else {
			DBGC ( rtl, "rtl8139 %p RX bad packet (status %#04x "
			       "len %d)\n", rtl, rx_status, rx_len );
			netdev_rx_err ( netdev, NULL, -EINVAL );
		}
		rtl->rx.offset = ( ( ( rtl->rx.offset + 4 + rx_len + 3 ) & ~3 )
				   % RX_BUF_LEN );
		outw ( rtl->rx.offset - 16, rtl->ioaddr + RxBufPtr );
	}
}

/**
 * Enable/disable interrupts
 *
 * @v netdev	Network device
 * @v enable	Interrupts should be enabled
 */
static void rtl_irq ( struct net_device *netdev, int enable ) {
	struct rtl8139_nic *rtl = netdev->priv;

	DBGC ( rtl, "rtl8139 %p interrupts %s\n",
	       rtl, ( enable ? "enabled" : "disabled" ) );
	outw ( ( enable ? ( ROK | RER | TOK | TER ) : 0 ),
	       rtl->ioaddr + IntrMask );
}

/** RTL8139 net device operations */
static struct net_device_operations rtl_operations = {
	.open		= rtl_open,
	.close		= rtl_close,
	.transmit	= rtl_transmit,
	.poll		= rtl_poll,
	.irq		= rtl_irq,
};

/**
 * Probe PCI device
 *
 * @v pci	PCI device
 * @v id	PCI ID
 * @ret rc	Return status code
 */
static int rtl_probe ( struct pci_device *pci ) {
	struct net_device *netdev;
	struct rtl8139_nic *rtl;
	int rc;

	/* Allocate net device */
	netdev = alloc_etherdev ( sizeof ( *rtl ) );
	if ( ! netdev )
		return -ENOMEM;
	netdev_init ( netdev, &rtl_operations );
	rtl = netdev->priv;
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;
	memset ( rtl, 0, sizeof ( *rtl ) );
	rtl->ioaddr = pci->ioaddr;

	/* Fix up PCI device */
	adjust_pci_device ( pci );

	/* Reset the NIC, set up EEPROM access and read MAC address */
	rtl_reset ( netdev );
	rtl_init_eeprom ( netdev );
	nvs_read ( &rtl->eeprom.nvs, EE_MAC, netdev->hw_addr, ETH_ALEN );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register_netdev;

	/* Mark as link up; we don't yet handle link state */
	netdev_link_up ( netdev );

	/* Register non-volatile storage */
	if ( rtl->nvo.nvs ) {
		if ( ( rc = register_nvo ( &rtl->nvo,
					   netdev_settings ( netdev ) ) ) != 0)
			goto err_register_nvo;
	}

	return 0;

 err_register_nvo:
	unregister_netdev ( netdev );
 err_register_netdev:
	rtl_reset ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci	PCI device
 */
static void rtl_remove ( struct pci_device *pci ) {
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct rtl8139_nic *rtl = netdev->priv;

	if ( rtl->nvo.nvs )
		unregister_nvo ( &rtl->nvo );
	unregister_netdev ( netdev );
	rtl_reset ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

static struct pci_device_id rtl8139_nics[] = {
PCI_ROM(0x10ec, 0x8129, "rtl8129",       "Realtek 8129", 0),
PCI_ROM(0x10ec, 0x8139, "rtl8139",       "Realtek 8139", 0),
PCI_ROM(0x10ec, 0x8138, "rtl8139b",      "Realtek 8139B", 0),
PCI_ROM(0x1186, 0x1300, "dfe538",        "DFE530TX+/DFE538TX", 0),
PCI_ROM(0x1113, 0x1211, "smc1211-1",     "SMC EZ10/100", 0),
PCI_ROM(0x1112, 0x1211, "smc1211",       "SMC EZ10/100", 0),
PCI_ROM(0x1500, 0x1360, "delta8139",     "Delta Electronics 8139", 0),
PCI_ROM(0x4033, 0x1360, "addtron8139",   "Addtron Technology 8139", 0),
PCI_ROM(0x1186, 0x1340, "dfe690txd",     "D-Link DFE690TXD", 0),
PCI_ROM(0x13d1, 0xab06, "fe2000vx",      "AboCom FE2000VX", 0),
PCI_ROM(0x1259, 0xa117, "allied8139",    "Allied Telesyn 8139", 0),
PCI_ROM(0x14ea, 0xab06, "fnw3603tx",     "Planex FNW-3603-TX", 0),
PCI_ROM(0x14ea, 0xab07, "fnw3800tx",     "Planex FNW-3800-TX", 0),
PCI_ROM(0xffff, 0x8139, "clone-rtl8139", "Cloned 8139", 0),
};

struct pci_driver rtl8139_driver __pci_driver = {
	.ids = rtl8139_nics,
	.id_count = ( sizeof ( rtl8139_nics ) / sizeof ( rtl8139_nics[0] ) ),
	.probe = rtl_probe,
	.remove = rtl_remove,
};
