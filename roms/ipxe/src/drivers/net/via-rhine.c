/* rhine.c:Fast Ethernet driver for Linux. */
/*
	Adapted 09-jan-2000 by Paolo Marini (paolom@prisma-eng.it)

        originally written by Donald Becker.

	This software may be used and distributed according to the terms
	of the GNU Public License (GPL), incorporated herein by reference.
	Drivers derived from this code also fall under the GPL and must retain
	this authorship and copyright notice.

	Under no circumstances are the authors responsible for
	the proper functioning of this software, nor do the authors assume any
	responsibility for damages incurred with its use.

	This driver is designed for the VIA VT86C100A Rhine-II PCI Fast Ethernet
	controller.

*/

static const char *version = "rhine.c v1.0.2 2004-10-29\n";

/* A few user-configurable values. */

// max time out delay time
#define W_MAX_TIMEOUT	0x0FFFU

/* Size of the in-memory receive ring. */
#define RX_BUF_LEN_IDX	3	/* 0==8K, 1==16K, 2==32K, 3==64K */
#define RX_BUF_LEN (8192 << RX_BUF_LEN_IDX)

/* Size of the Tx bounce buffers -- must be at least (dev->mtu+14+4). */
#define TX_BUF_SIZE	1536
#define RX_BUF_SIZE	1536

/* PCI Tuning Parameters
   Threshold is bytes transferred to chip before transmission starts. */
#define TX_FIFO_THRESH 256	/* In bytes, rounded down to 32 byte units. */

/* The following settings are log_2(bytes)-4:  0 == 16 bytes .. 6==1024. */
#define RX_FIFO_THRESH	4	/* Rx buffer level before first PCI xfer.  */
#define RX_DMA_BURST	4	/* Maximum PCI burst, '4' is 256 bytes */
#define TX_DMA_BURST	4

/* Operational parameters that usually are not changed. */
/* Time in jiffies before concluding the transmitter is hung. */
#define TX_TIMEOUT  ((2000*HZ)/1000)

#include "etherboot.h"
#include "nic.h"
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>

/* define all ioaddr */

#define byPAR0				ioaddr
#define byRCR				ioaddr + 6
#define byTCR				ioaddr + 7
#define byCR0				ioaddr + 8
#define byCR1				ioaddr + 9
#define byISR0				ioaddr + 0x0c
#define byISR1				ioaddr + 0x0d
#define byIMR0				ioaddr + 0x0e
#define byIMR1				ioaddr + 0x0f
#define byMAR0				ioaddr + 0x10
#define byMAR1				ioaddr + 0x11
#define byMAR2				ioaddr + 0x12
#define byMAR3				ioaddr + 0x13
#define byMAR4				ioaddr + 0x14
#define byMAR5				ioaddr + 0x15
#define byMAR6				ioaddr + 0x16
#define byMAR7				ioaddr + 0x17
#define dwCurrentRxDescAddr		ioaddr + 0x18
#define dwCurrentTxDescAddr		ioaddr + 0x1c
#define dwCurrentRDSE0			ioaddr + 0x20
#define dwCurrentRDSE1			ioaddr + 0x24
#define dwCurrentRDSE2			ioaddr + 0x28
#define dwCurrentRDSE3			ioaddr + 0x2c
#define dwNextRDSE0			ioaddr + 0x30
#define dwNextRDSE1			ioaddr + 0x34
#define dwNextRDSE2			ioaddr + 0x38
#define dwNextRDSE3			ioaddr + 0x3c
#define dwCurrentTDSE0			ioaddr + 0x40
#define dwCurrentTDSE1			ioaddr + 0x44
#define dwCurrentTDSE2			ioaddr + 0x48
#define dwCurrentTDSE3			ioaddr + 0x4c
#define dwNextTDSE0			ioaddr + 0x50
#define dwNextTDSE1			ioaddr + 0x54
#define dwNextTDSE2			ioaddr + 0x58
#define dwNextTDSE3			ioaddr + 0x5c
#define dwCurrRxDMAPtr			ioaddr + 0x60
#define dwCurrTxDMAPtr			ioaddr + 0x64
#define byMPHY				ioaddr + 0x6c
#define byMIISR				ioaddr + 0x6d
#define byBCR0				ioaddr + 0x6e
#define byBCR1				ioaddr + 0x6f
#define byMIICR				ioaddr + 0x70
#define byMIIAD				ioaddr + 0x71
#define wMIIDATA			ioaddr + 0x72
#define byEECSR				ioaddr + 0x74
#define byTEST				ioaddr + 0x75
#define byGPIO				ioaddr + 0x76
#define byCFGA				ioaddr + 0x78
#define byCFGB				ioaddr + 0x79
#define byCFGC				ioaddr + 0x7a
#define byCFGD				ioaddr + 0x7b
#define wTallyCntMPA			ioaddr + 0x7c
#define wTallyCntCRC			ioaddr + 0x7d
#define bySTICKHW			ioaddr + 0x83
#define byWOLcrClr			ioaddr + 0xA4
#define byWOLcgClr			ioaddr + 0xA7
#define byPwrcsrClr			ioaddr + 0xAC

/*---------------------  Exioaddr Definitions -------------------------*/

/*
 * Bits in the RCR register
 */

#define RCR_RRFT2		0x80
#define RCR_RRFT1		0x40
#define RCR_RRFT0		0x20
#define RCR_PROM		0x10
#define RCR_AB			0x08
#define RCR_AM			0x04
#define RCR_AR			0x02
#define RCR_SEP			0x01

/*
 * Bits in the TCR register
 */

#define TCR_RTSF		0x80
#define TCR_RTFT1		0x40
#define TCR_RTFT0		0x20
#define TCR_OFSET		0x08
#define TCR_LB1			0x04	/* loopback[1] */
#define TCR_LB0			0x02	/* loopback[0] */

/*
 * Bits in the CR0 register
 */

#define CR0_RDMD		0x40	/* rx descriptor polling demand */
#define CR0_TDMD		0x20	/* tx descriptor polling demand */
#define CR0_TXON		0x10
#define CR0_RXON		0x08
#define CR0_STOP		0x04	/* stop NIC, default = 1 */
#define CR0_STRT		0x02	/* start NIC */
#define CR0_INIT		0x01	/* start init process */


/*
 * Bits in the CR1 register
 */

#define CR1_SFRST		0x80	/* software reset */
#define CR1_RDMD1		0x40	/* RDMD1 */
#define CR1_TDMD1		0x20	/* TDMD1 */
#define CR1_KEYPAG		0x10	/* turn on par/key */
#define CR1_DPOLL		0x08	/* disable rx/tx auto polling */
#define CR1_FDX			0x04	/* full duplex mode */
#define CR1_ETEN		0x02	/* early tx mode */
#define CR1_EREN		0x01	/* early rx mode */

/*
 * Bits in the CR register
 */

#define CR_RDMD			0x0040	/* rx descriptor polling demand */
#define CR_TDMD			0x0020	/* tx descriptor polling demand */
#define CR_TXON			0x0010
#define CR_RXON			0x0008
#define CR_STOP			0x0004	/* stop NIC, default = 1 */
#define CR_STRT			0x0002	/* start NIC */
#define CR_INIT			0x0001	/* start init process */
#define CR_SFRST		0x8000	/* software reset */
#define CR_RDMD1		0x4000	/* RDMD1 */
#define CR_TDMD1		0x2000	/* TDMD1 */
#define CR_KEYPAG		0x1000	/* turn on par/key */
#define CR_DPOLL		0x0800	/* disable rx/tx auto polling */
#define CR_FDX			0x0400	/* full duplex mode */
#define CR_ETEN			0x0200	/* early tx mode */
#define CR_EREN			0x0100	/* early rx mode */

/*
 * Bits in the IMR0 register
 */

#define IMR0_CNTM		0x80
#define IMR0_BEM		0x40
#define IMR0_RUM		0x20
#define IMR0_TUM		0x10
#define IMR0_TXEM		0x08
#define IMR0_RXEM		0x04
#define IMR0_PTXM		0x02
#define IMR0_PRXM		0x01

/* define imrshadow */

#define IMRShadow		0x5AFF

/*
 * Bits in the IMR1 register
 */

#define IMR1_INITM		0x80
#define IMR1_SRCM		0x40
#define IMR1_NBFM		0x10
#define IMR1_PRAIM		0x08
#define IMR1_RES0M		0x04
#define IMR1_ETM		0x02
#define IMR1_ERM		0x01

/*
 * Bits in the ISR register
 */

#define ISR_INITI		0x8000
#define ISR_SRCI		0x4000
#define ISR_ABTI		0x2000
#define ISR_NORBF		0x1000
#define ISR_PKTRA		0x0800
#define ISR_RES0		0x0400
#define ISR_ETI			0x0200
#define ISR_ERI			0x0100
#define ISR_CNT			0x0080
#define ISR_BE			0x0040
#define ISR_RU			0x0020
#define ISR_TU			0x0010
#define ISR_TXE			0x0008
#define ISR_RXE			0x0004
#define ISR_PTX			0x0002
#define ISR_PRX			0x0001

/*
 * Bits in the ISR0 register
 */

#define ISR0_CNT		0x80
#define ISR0_BE			0x40
#define ISR0_RU			0x20
#define ISR0_TU			0x10
#define ISR0_TXE		0x08
#define ISR0_RXE		0x04
#define ISR0_PTX		0x02
#define ISR0_PRX		0x01

/*
 * Bits in the ISR1 register
 */

#define ISR1_INITI		0x80
#define ISR1_SRCI		0x40
#define ISR1_NORBF		0x10
#define ISR1_PKTRA		0x08
#define ISR1_ETI		0x02
#define ISR1_ERI		0x01

/* ISR ABNORMAL CONDITION */

#define ISR_ABNORMAL ISR_BE+ISR_RU+ISR_TU+ISR_CNT+ISR_NORBF+ISR_PKTRA

/*
 * Bits in the MIISR register
 */

#define MIISR_MIIERR		0x08
#define MIISR_MRERR		0x04
#define MIISR_LNKFL		0x02
#define MIISR_SPEED		0x01

/*
 * Bits in the MIICR register
 */

#define MIICR_MAUTO		0x80
#define MIICR_RCMD		0x40
#define MIICR_WCMD		0x20
#define MIICR_MDPM		0x10
#define MIICR_MOUT		0x08
#define MIICR_MDO		0x04
#define MIICR_MDI		0x02
#define MIICR_MDC		0x01

/*
 * Bits in the EECSR register
 */

#define EECSR_EEPR		0x80	/* eeprom programed status, 73h means programed */
#define EECSR_EMBP		0x40	/* eeprom embeded programming */
#define EECSR_AUTOLD		0x20	/* eeprom content reload */
#define EECSR_DPM		0x10	/* eeprom direct programming */
#define EECSR_CS		0x08	/* eeprom CS pin */
#define EECSR_SK		0x04	/* eeprom SK pin */
#define EECSR_DI		0x02	/* eeprom DI pin */
#define EECSR_DO		0x01	/* eeprom DO pin */

/*
 * Bits in the BCR0 register
 */

#define BCR0_CRFT2		0x20
#define BCR0_CRFT1		0x10
#define BCR0_CRFT0		0x08
#define BCR0_DMAL2		0x04
#define BCR0_DMAL1		0x02
#define BCR0_DMAL0		0x01

/*
 * Bits in the BCR1 register
 */

#define BCR1_CTSF		0x20
#define BCR1_CTFT1		0x10
#define BCR1_CTFT0		0x08
#define BCR1_POT2		0x04
#define BCR1_POT1		0x02
#define BCR1_POT0		0x01

/*
 * Bits in the CFGA register
 */

#define CFGA_EELOAD		0x80	/* enable eeprom embeded and direct programming */
#define CFGA_JUMPER		0x40
#define CFGA_MTGPIO		0x08
#define CFGA_T10EN		0x02
#define CFGA_AUTO		0x01

/*
 * Bits in the CFGB register
 */

#define CFGB_PD			0x80
#define CFGB_POLEN		0x02
#define CFGB_LNKEN		0x01

/*
 * Bits in the CFGC register
 */

#define CFGC_M10TIO		0x80
#define CFGC_M10POL		0x40
#define CFGC_PHY1		0x20
#define CFGC_PHY0		0x10
#define CFGC_BTSEL		0x08
#define CFGC_BPS2		0x04	/* bootrom select[2] */
#define CFGC_BPS1		0x02	/* bootrom select[1] */
#define CFGC_BPS0		0x01	/* bootrom select[0] */

/*
 * Bits in the CFGD register
 */

#define CFGD_GPIOEN		0x80
#define CFGD_DIAG		0x40
#define CFGD_MAGIC		0x10
#define CFGD_RANDOM		0x08
#define CFGD_CFDX		0x04
#define CFGD_CEREN		0x02
#define CFGD_CETEN		0x01

/* Bits in RSR */
#define RSR_RERR		0x00000001
#define RSR_CRC			0x00000002
#define RSR_FAE			0x00000004
#define RSR_FOV			0x00000008
#define RSR_LONG		0x00000010
#define RSR_RUNT		0x00000020
#define RSR_SERR		0x00000040
#define RSR_BUFF		0x00000080
#define RSR_EDP			0x00000100
#define RSR_STP			0x00000200
#define RSR_CHN			0x00000400
#define RSR_PHY			0x00000800
#define RSR_BAR			0x00001000
#define RSR_MAR			0x00002000
#define RSR_RXOK		0x00008000
#define RSR_ABNORMAL		RSR_RERR+RSR_LONG+RSR_RUNT

/* Bits in TSR */
#define TSR_NCR0		0x00000001
#define TSR_NCR1		0x00000002
#define TSR_NCR2		0x00000004
#define TSR_NCR3		0x00000008
#define TSR_COLS		0x00000010
#define TSR_CDH			0x00000080
#define TSR_ABT			0x00000100
#define TSR_OWC			0x00000200
#define TSR_CRS			0x00000400
#define TSR_UDF			0x00000800
#define TSR_TBUFF		0x00001000
#define TSR_SERR		0x00002000
#define TSR_JAB			0x00004000
#define TSR_TERR		0x00008000
#define TSR_ABNORMAL		TSR_TERR+TSR_OWC+TSR_ABT+TSR_JAB+TSR_CRS
#define TSR_OWN_BIT		0x80000000

#define CB_DELAY_LOOP_WAIT	10	/* 10ms */
/* enabled mask value of irq */

#define W_IMR_MASK_VALUE	0x1BFF	/* initial value of IMR */

/* Ethernet address filter type */
#define PKT_TYPE_DIRECTED	0x0001	/* obsolete, directed address is always accepted */
#define PKT_TYPE_MULTICAST	0x0002
#define PKT_TYPE_ALL_MULTICAST	0x0004
#define PKT_TYPE_BROADCAST	0x0008
#define PKT_TYPE_PROMISCUOUS	0x0020
#define PKT_TYPE_LONG		0x2000
#define PKT_TYPE_RUNT		0x4000
#define PKT_TYPE_ERROR		0x8000	/* accept error packets, e.g. CRC error */

/* Loopback mode */

#define NIC_LB_NONE		0x00
#define NIC_LB_INTERNAL		0x01
#define NIC_LB_PHY		0x02	/* MII or Internal-10BaseT loopback */

#define TX_RING_SIZE		2
#define RX_RING_SIZE		2
#define PKT_BUF_SZ		1536	/* Size of each temporary Rx buffer. */

#define PCI_REG_MODE3		0x53
#define MODE3_MIION		0x04    /* in PCI_REG_MOD3 OF PCI space */

enum rhine_revs {
    VT86C100A       = 0x00,
    VTunknown0      = 0x20,
    VT6102          = 0x40,
    VT8231          = 0x50, /* Integrated MAC */
    VT8233          = 0x60, /* Integrated MAC */
    VT8235          = 0x74, /* Integrated MAC */
    VT8237          = 0x78, /* Integrated MAC */
    VTunknown1      = 0x7C,
    VT6105          = 0x80,
    VT6105_B0       = 0x83,
    VT6105L 	    = 0x8A,
    VT6107          = 0x8C,
    VTunknown2      = 0x8E,
    VT6105M         = 0x90,
};

/* Transmit and receive descriptors definition */

struct rhine_tx_desc
{
    union VTC_tx_status_tag
    {
	struct
	{
	    unsigned long ncro:1;
	    unsigned long ncr1:1;
	    unsigned long ncr2:1;
	    unsigned long ncr3:1;
	    unsigned long cols:1;
	    unsigned long reserve_1:2;
	    unsigned long cdh:1;
	    unsigned long abt:1;
	    unsigned long owc:1;
	    unsigned long crs:1;
	    unsigned long udf:1;
	    unsigned long tbuff:1;
	    unsigned long serr:1;
	    unsigned long jab:1;
	    unsigned long terr:1;
	    unsigned long reserve_2:15;
	    unsigned long own_bit:1;
	}
	bits;
	unsigned long lw;
    }
    tx_status;

    union VTC_tx_ctrl_tag
    {
	struct
	{
	    unsigned long tx_buf_size:11;
	    unsigned long extend_tx_buf_size:4;
	    unsigned long chn:1;
	    unsigned long crc:1;
	    unsigned long reserve_1:4;
	    unsigned long stp:1;
	    unsigned long edp:1;
	    unsigned long ic:1;
	    unsigned long reserve_2:8;
	}
	bits;
	unsigned long lw;
    }
    tx_ctrl;

    unsigned long buf_addr_1:32;
    unsigned long buf_addr_2:32;

};

struct rhine_rx_desc
{
    union VTC_rx_status_tag
    {
	struct
	{
	    unsigned long rerr:1;
	    unsigned long crc_error:1;
	    unsigned long fae:1;
	    unsigned long fov:1;
	    unsigned long toolong:1;
	    unsigned long runt:1;
	    unsigned long serr:1;
	    unsigned long buff:1;
	    unsigned long edp:1;
	    unsigned long stp:1;
	    unsigned long chn:1;
	    unsigned long phy:1;
	    unsigned long bar:1;
	    unsigned long mar:1;
	    unsigned long reserve_1:1;
	    unsigned long rxok:1;
	    unsigned long frame_length:11;
	    unsigned long reverve_2:4;
	    unsigned long own_bit:1;
	}
	bits;
	unsigned long lw;
    }
    rx_status;

    union VTC_rx_ctrl_tag
    {
	struct
	{
	    unsigned long rx_buf_size:11;
	    unsigned long extend_rx_buf_size:4;
	    unsigned long reserved_1:17;
	}
	bits;
	unsigned long lw;
    }
    rx_ctrl;

    unsigned long buf_addr_1:32;
    unsigned long buf_addr_2:32;

};

struct {
	char txbuf[TX_RING_SIZE * PKT_BUF_SZ + 32];
	char rxbuf[RX_RING_SIZE * PKT_BUF_SZ + 32];
	char txdesc[TX_RING_SIZE * sizeof (struct rhine_tx_desc) + 32];
	char rxdesc[RX_RING_SIZE * sizeof (struct rhine_rx_desc) + 32];
} rhine_buffers __shared;

/* The I/O extent. */
#define rhine_TOTAL_SIZE 0x80

#ifdef	HAVE_DEVLIST
struct netdev_entry rhine_drv =
    { "rhine", rhine_probe, rhine_TOTAL_SIZE, NULL };
#endif

static int rhine_debug = 1;

/*
				Theory of Operation

I. Board Compatibility

This driver is designed for the VIA 86c100A Rhine-II PCI Fast Ethernet
controller.

II. Board-specific settings

Boards with this chip are functional only in a bus-master PCI slot.

Many operational settings are loaded from the EEPROM to the Config word at
offset 0x78.  This driver assumes that they are correct.
If this driver is compiled to use PCI memory space operations the EEPROM
must be configured to enable memory ops.

III. Driver operation

IIIa. Ring buffers

This driver uses two statically allocated fixed-size descriptor lists
formed into rings by a branch from the final descriptor to the beginning of
the list.  The ring sizes are set at compile time by RX/TX_RING_SIZE.

IIIb/c. Transmit/Receive Structure

This driver attempts to use a zero-copy receive and transmit scheme.

Alas, all data buffers are required to start on a 32 bit boundary, so
the driver must often copy transmit packets into bounce buffers.

The driver allocates full frame size skbuffs for the Rx ring buffers at
open() time and passes the skb->data field to the chip as receive data
buffers.  When an incoming frame is less than RX_COPYBREAK bytes long,
a fresh skbuff is allocated and the frame is copied to the new skbuff.
When the incoming frame is larger, the skbuff is passed directly up the
protocol stack.  Buffers consumed this way are replaced by newly allocated
skbuffs in the last phase of netdev_rx().

The RX_COPYBREAK value is chosen to trade-off the memory wasted by
using a full-sized skbuff for small frames vs. the copying costs of larger
frames.  New boards are typically used in generously configured machines
and the underfilled buffers have negligible impact compared to the benefit of
a single allocation size, so the default value of zero results in never
copying packets.  When copying is done, the cost is usually mitigated by using
a combined copy/checksum routine.  Copying also preloads the cache, which is
most useful with small frames.

Since the VIA chips are only able to transfer data to buffers on 32 bit
boundaries, the the IP header at offset 14 in an ethernet frame isn't
longword aligned for further processing.  Copying these unaligned buffers
has the beneficial effect of 16-byte aligning the IP header.

IIId. Synchronization

The driver runs as two independent, single-threaded flows of control.  One
is the send-packet routine, which enforces single-threaded use by the
dev->tbusy flag.  The other thread is the interrupt handler, which is single
threaded by the hardware and interrupt handling software.

The send packet thread has partial control over the Tx ring and 'dev->tbusy'
flag.  It sets the tbusy flag whenever it's queuing a Tx packet. If the next
queue slot is empty, it clears the tbusy flag when finished otherwise it sets
the 'lp->tx_full' flag.

The interrupt handler has exclusive control over the Rx ring and records stats
from the Tx ring.  After reaping the stats, it marks the Tx queue entry as
empty by incrementing the dirty_tx mark. Iff the 'lp->tx_full' flag is set, it
clears both the tx_full and tbusy flags.

IV. Notes

IVb. References

Preliminary VT86C100A manual from http://www.via.com.tw/
http://cesdis.gsfc.nasa.gov/linux/misc/100mbps.html
http://cesdis.gsfc.nasa.gov/linux/misc/NWay.html

IVc. Errata

The VT86C100A manual is not reliable information.
The chip does not handle unaligned transmit or receive buffers, resulting
in significant performance degradation for bounce buffer copies on transmit
and unaligned IP headers on receive.
The chip does not pad to minimum transmit length.

*/

/* The rest of these values should never change. */
#define NUM_TX_DESC	2	/* Number of Tx descriptor registers. */

static struct rhine_private
{
    char devname[8];		/* Used only for kernel debugging. */
    const char *product_name;
    struct rhine_rx_desc *rx_ring;
    struct rhine_tx_desc *tx_ring;
    char *rx_buffs[RX_RING_SIZE];
    char *tx_buffs[TX_RING_SIZE];

    /* temporary Rx buffers. */

    int chip_id;
    int chip_revision;
    unsigned short ioaddr;
    unsigned int cur_rx, cur_tx;	/* The next free and used entries */
    unsigned int dirty_rx, dirty_tx;
    /* The saved address of a sent-in-place packet/buffer, for skfree(). */
    struct sk_buff *tx_skbuff[TX_RING_SIZE];
    unsigned char mc_filter[8];	/* Current multicast filter. */
    char phys[4];		/* MII device addresses. */
    unsigned int tx_full:1;	/* The Tx queue is full. */
    unsigned int full_duplex:1;	/* Full-duplex operation requested. */
    unsigned int default_port:4;	/* Last dev->if_port value. */
    unsigned int media2:4;	/* Secondary monitored media port. */
    unsigned int medialock:1;	/* Don't sense media type. */
    unsigned int mediasense:1;	/* Media sensing in progress. */
}
rhine;

static void rhine_probe1 (struct nic *nic, struct pci_device *pci, int ioaddr,
				 int chip_id, int options);
static int QueryAuto (int);
static int ReadMII (int byMIIIndex, int);
static void WriteMII (char, char, char, int);
static void MIIDelay (void);
static void rhine_init_ring (struct nic *dev);
static void rhine_disable (struct nic *nic);
static void rhine_reset (struct nic *nic);
static int rhine_poll (struct nic *nic, int retreive);
static void rhine_transmit (struct nic *nic, const char *d, unsigned int t,
			    unsigned int s, const char *p);
static void reload_eeprom(int ioaddr);


static void reload_eeprom(int ioaddr)
{
	int i;
	outb(0x20, byEECSR);
	/* Typically 2 cycles to reload. */
	for (i = 0; i < 150; i++)
		if (! (inb(byEECSR) & 0x20))
			break;
}
/* Initialize the Rx and Tx rings, along with various 'dev' bits. */
static void
rhine_init_ring (struct nic *nic)
{
    struct rhine_private *tp = (struct rhine_private *) nic->priv_data;
    int i;

    tp->tx_full = 0;
    tp->cur_rx = tp->cur_tx = 0;
    tp->dirty_rx = tp->dirty_tx = 0;

    for (i = 0; i < RX_RING_SIZE; i++)
    {

	tp->rx_ring[i].rx_status.bits.own_bit = 1;
	tp->rx_ring[i].rx_ctrl.bits.rx_buf_size = 1536;

	tp->rx_ring[i].buf_addr_1 = virt_to_bus (tp->rx_buffs[i]);
	tp->rx_ring[i].buf_addr_2 = virt_to_bus (&tp->rx_ring[i + 1]);
	/* printf("[%d]buf1=%hX,buf2=%hX",i,tp->rx_ring[i].buf_addr_1,tp->rx_ring[i].buf_addr_2); */
    }
    /* Mark the last entry as wrapping the ring. */
    /* tp->rx_ring[i-1].rx_ctrl.bits.rx_buf_size =1518; */
    tp->rx_ring[i - 1].buf_addr_2 = virt_to_bus (&tp->rx_ring[0]);
    /*printf("[%d]buf1=%hX,buf2=%hX",i-1,tp->rx_ring[i-1].buf_addr_1,tp->rx_ring[i-1].buf_addr_2); */

    /* The Tx buffer descriptor is filled in as needed, but we
       do need to clear the ownership bit. */

    for (i = 0; i < TX_RING_SIZE; i++)
    {

	tp->tx_ring[i].tx_status.lw = 0;
	tp->tx_ring[i].tx_ctrl.lw = 0x00e08000;
	tp->tx_ring[i].buf_addr_1 = virt_to_bus (tp->tx_buffs[i]);
	tp->tx_ring[i].buf_addr_2 = virt_to_bus (&tp->tx_ring[i + 1]);
	/* printf("[%d]buf1=%hX,buf2=%hX",i,tp->tx_ring[i].buf_addr_1,tp->tx_ring[i].buf_addr_2); */
    }

    tp->tx_ring[i - 1].buf_addr_2 = virt_to_bus (&tp->tx_ring[0]);
    /* printf("[%d]buf1=%hX,buf2=%hX",i,tp->tx_ring[i-1].buf_addr_1,tp->tx_ring[i-1].buf_addr_2); */
}

int
QueryAuto (int ioaddr)
{
    int byMIIIndex;
    int MIIReturn;

	int advertising,mii_reg5;
	int negociated;

    byMIIIndex = 0x04;
    MIIReturn = ReadMII (byMIIIndex, ioaddr);
	advertising=MIIReturn;

    byMIIIndex = 0x05;
    MIIReturn = ReadMII (byMIIIndex, ioaddr);
	mii_reg5=MIIReturn;

	negociated=mii_reg5 & advertising;

	if ( (negociated & 0x100) || (negociated & 0x1C0) == 0x40 )
		return 1;
	else
		return 0;

}

int
ReadMII (int byMIIIndex, int ioaddr)
{
    int ReturnMII;
    char byMIIAdrbak;
    char byMIICRbak;
    char byMIItemp;
    unsigned long ct;

    byMIIAdrbak = inb (byMIIAD);
    byMIICRbak = inb (byMIICR);
    outb (byMIICRbak & 0x7f, byMIICR);
    MIIDelay ();

    outb (byMIIIndex, byMIIAD);
    MIIDelay ();

    outb (inb (byMIICR) | 0x40, byMIICR);

    byMIItemp = inb (byMIICR);
    byMIItemp = byMIItemp & 0x40;

    ct = currticks();
    while (byMIItemp != 0 && ct + 2*1000 < currticks())
    {
	byMIItemp = inb (byMIICR);
	byMIItemp = byMIItemp & 0x40;
    }
    MIIDelay ();

    ReturnMII = inw (wMIIDATA);

    outb (byMIIAdrbak, byMIIAD);
    outb (byMIICRbak, byMIICR);
    MIIDelay ();

    return (ReturnMII);

}

void
WriteMII (char byMIISetByte, char byMIISetBit, char byMIIOP, int ioaddr)
{
    int ReadMIItmp;
    int MIIMask;
    char byMIIAdrbak;
    char byMIICRbak;
    char byMIItemp;
    unsigned long ct;


    byMIIAdrbak = inb (byMIIAD);

    byMIICRbak = inb (byMIICR);
    outb (byMIICRbak & 0x7f, byMIICR);
    MIIDelay ();
    outb (byMIISetByte, byMIIAD);
    MIIDelay ();

    outb (inb (byMIICR) | 0x40, byMIICR);

    byMIItemp = inb (byMIICR);
    byMIItemp = byMIItemp & 0x40;

    ct = currticks();
    while (byMIItemp != 0 && ct + 2*1000 < currticks())
    {
	byMIItemp = inb (byMIICR);
	byMIItemp = byMIItemp & 0x40;
    }
    MIIDelay ();

    ReadMIItmp = inw (wMIIDATA);
    MIIMask = 0x0001;
    MIIMask = MIIMask << byMIISetBit;


    if (byMIIOP == 0)
    {
	MIIMask = ~MIIMask;
	ReadMIItmp = ReadMIItmp & MIIMask;
    }
    else
    {
	ReadMIItmp = ReadMIItmp | MIIMask;

    }
    outw (ReadMIItmp, wMIIDATA);
    MIIDelay ();

    outb (inb (byMIICR) | 0x20, byMIICR);
    byMIItemp = inb (byMIICR);
    byMIItemp = byMIItemp & 0x20;

    ct = currticks();
    while (byMIItemp != 0 && ct + 2*1000 < currticks())
    {
	byMIItemp = inb (byMIICR);
	byMIItemp = byMIItemp & 0x20;
    }
    MIIDelay ();

    outb (byMIIAdrbak & 0x7f, byMIIAD);
    outb (byMIICRbak, byMIICR);
    MIIDelay ();

}

void
MIIDelay (void)
{
    int i;
    for (i = 0; i < 0x7fff; i++)
    {
        ( void ) inb (0x61);
        ( void ) inb (0x61);
        ( void ) inb (0x61);
        ( void ) inb (0x61);
    }
}

/* Offsets to the device registers. */
enum register_offsets {
        StationAddr=0x00, RxConfig=0x06, TxConfig=0x07, ChipCmd=0x08,
        IntrStatus=0x0C, IntrEnable=0x0E,
        MulticastFilter0=0x10, MulticastFilter1=0x14,
        RxRingPtr=0x18, TxRingPtr=0x1C, GFIFOTest=0x54,
        MIIPhyAddr=0x6C, MIIStatus=0x6D, PCIBusConfig=0x6E,
        MIICmd=0x70, MIIRegAddr=0x71, MIIData=0x72, MACRegEEcsr=0x74,
        ConfigA=0x78, ConfigB=0x79, ConfigC=0x7A, ConfigD=0x7B,
        RxMissed=0x7C, RxCRCErrs=0x7E, MiscCmd=0x81,
        StickyHW=0x83, IntrStatus2=0x84, WOLcrClr=0xA4, WOLcgClr=0xA7,
        PwrcsrClr=0xAC,
};

/* Bits in the interrupt status/mask registers. */
enum intr_status_bits {
        IntrRxDone=0x0001, IntrRxErr=0x0004, IntrRxEmpty=0x0020,
        IntrTxDone=0x0002, IntrTxError=0x0008, IntrTxUnderrun=0x0210,
        IntrPCIErr=0x0040,
        IntrStatsMax=0x0080, IntrRxEarly=0x0100,
        IntrRxOverflow=0x0400, IntrRxDropped=0x0800, IntrRxNoBuf=0x1000,
        IntrTxAborted=0x2000, IntrLinkChange=0x4000,
        IntrRxWakeUp=0x8000,
        IntrNormalSummary=0x0003, IntrAbnormalSummary=0xC260,
        IntrTxDescRace=0x080000,        /* mapped from IntrStatus2 */
        IntrTxErrSummary=0x082218,
};
#define DEFAULT_INTR (IntrRxDone | IntrRxErr | IntrRxEmpty| IntrRxOverflow | \
                   IntrRxDropped | IntrRxNoBuf) 

/***************************************************************************
 IRQ - PXE IRQ Handler
***************************************************************************/
void rhine_irq ( struct nic *nic, irq_action_t action ) {
    struct rhine_private *tp = (struct rhine_private *) nic->priv_data;
    /* Enable interrupts by setting the interrupt mask. */
    unsigned int intr_status;

    switch ( action ) {
        case DISABLE :
        case ENABLE :
            intr_status = inw(nic->ioaddr + IntrStatus);
            /* On Rhine-II, Bit 3 indicates Tx descriptor write-back race. */

            /* added comment by guard */
            /* For supporting VT6107, please use revision id to recognize different chips in driver */
            // if (tp->chip_id == 0x3065)
            if( tp->chip_revision < 0x80 && tp->chip_revision >=0x40 )
                intr_status |= inb(nic->ioaddr + IntrStatus2) << 16;
                intr_status = (intr_status & ~DEFAULT_INTR);
                if ( action == ENABLE ) 
                    intr_status = intr_status | DEFAULT_INTR;
                    outw(intr_status, nic->ioaddr + IntrEnable);
                break;
        case FORCE :
            outw(0x0010, nic->ioaddr + 0x84);
           break;
        }
}

static struct nic_operations rhine_operations;

static int
rhine_probe ( struct nic *nic, struct pci_device *pci ) {

    struct rhine_private *tp = (struct rhine_private *) nic->priv_data;

    if (!pci->ioaddr)
	return 0;

    rhine_probe1 (nic, pci, pci->ioaddr, pci->device, -1);

    adjust_pci_device ( pci );

    rhine_reset (nic);

    nic->nic_op	= &rhine_operations;

    nic->irqno	  = pci->irq;
    nic->ioaddr   = tp->ioaddr;

    return 1;
}

static void set_rx_mode(struct nic *nic __unused) {
    	struct rhine_private *tp = (struct rhine_private *) nic->priv_data;
	unsigned char rx_mode;
    	int ioaddr = tp->ioaddr;

	/* ! IFF_PROMISC */
	outl(0xffffffff, byMAR0);
	outl(0xffffffff, byMAR4);
	rx_mode = 0x0C;

	outb(0x60 /* thresh */ | rx_mode, byRCR );
}

static void
rhine_probe1 (struct nic *nic, struct pci_device *pci, int ioaddr, int chip_id, int options)
{
    struct rhine_private *tp;
    static int did_version = 0;	/* Already printed version info. */
    unsigned int i, ww;
    unsigned int timeout;
    int FDXFlag;
    int byMIIvalue, LineSpeed, MIICRbak;
    uint8_t revision_id;    
    unsigned char mode3_reg;

    if (rhine_debug > 0 && did_version++ == 0)
	printf ("%s",version);

    // get revision id.
    pci_read_config_byte(pci, PCI_REVISION, &revision_id);

    /* D-Link provided reset code (with comment additions) */
    if (revision_id >= 0x40) {
	unsigned char byOrgValue;
	
	if(rhine_debug > 0)
		printf("Enabling Sticky Bit Workaround for Chip_id: 0x%hX\n"
				, chip_id);
	/* clear sticky bit before reset & read ethernet address */
	byOrgValue = inb(bySTICKHW);
	byOrgValue = byOrgValue & 0xFC;
	outb(byOrgValue, bySTICKHW);

	/* (bits written are cleared?) */
	/* disable force PME-enable */
	outb(0x80, byWOLcgClr);
	/* disable power-event config bit */
	outb(0xFF, byWOLcrClr);
	/* clear power status (undocumented in vt6102 docs?) */
	outb(0xFF, byPwrcsrClr);
	
    }

    /* Reset the chip to erase previous misconfiguration. */
    outw(CR_SFRST, byCR0);
    // if vt3043 delay after reset
    if (revision_id <0x40) {
       udelay(10000);
    }
    // polling till software reset complete
    // W_MAX_TIMEOUT is the timeout period
    for(ww = 0; ww < W_MAX_TIMEOUT; ww++) {
        if ((inw(byCR0) & CR_SFRST) == 0)
		break;
        }

    // issue AUTOLoad in EECSR to reload eeprom
    outb(0x20, byEECSR );

    // if vt3065 delay after reset
    if (revision_id >=0x40) {
	// delay 8ms to let MAC stable
	mdelay(8);
        /*
         * for 3065D, EEPROM reloaded will cause bit 0 in MAC_REG_CFGA
         * turned on.  it makes MAC receive magic packet
         * automatically. So, we turn it off. (D-Link)
         */
         outb(inb(byCFGA) & 0xFE, byCFGA);
    }

    /* turn on bit2 in PCI configuration register 0x53 , only for 3065*/
    if (revision_id >= 0x40) {
        pci_read_config_byte(pci, PCI_REG_MODE3, &mode3_reg);
        pci_write_config_byte(pci, PCI_REG_MODE3, mode3_reg|MODE3_MIION);
    }


    /* back off algorithm ,disable the right-most 4-bit off CFGD*/
    outb(inb(byCFGD) & (~(CFGD_RANDOM | CFGD_CFDX | CFGD_CEREN | CFGD_CETEN)), byCFGD);

    /* reload eeprom */
    reload_eeprom(ioaddr);

    /* Perhaps this should be read from the EEPROM? */
    for (i = 0; i < ETH_ALEN; i++)
	nic->node_addr[i] = inb (byPAR0 + i);

    DBG ( "IO address %#hX Ethernet Address: %s\n", ioaddr, eth_ntoa ( nic->node_addr ) );

    /* restart MII auto-negotiation */
    WriteMII (0, 9, 1, ioaddr);
    printf ("Analyzing Media type,this may take several seconds... ");
    for (i = 0; i < 5; i++)
    {
	/* need to wait 1 millisecond - we will round it up to 50-100ms */
	timeout = currticks() + 2;
	for (timeout = currticks() + 2; currticks() < timeout;)
	    /* nothing */;
	if (ReadMII (1, ioaddr) & 0x0020)
	    break;
    }
    printf ("OK.\n");

#if 0
	/* JJM : for Debug */
	printf("MII : Address %hhX ",inb(ioaddr+0x6c));
	{
	 unsigned char st1,st2,adv1,adv2,l1,l2;
	
	 st1=ReadMII(1,ioaddr)>>8;
	 st2=ReadMII(1,ioaddr)&0xFF;
	 adv1=ReadMII(4,ioaddr)>>8;
	 adv2=ReadMII(4,ioaddr)&0xFF;
	 l1=ReadMII(5,ioaddr)>>8;
	 l2=ReadMII(5,ioaddr)&0xFF;
	 printf(" status 0x%hhX%hhX, advertising 0x%hhX%hhX, link 0x%hhX%hhX\n", st1,st2,adv1,adv2,l1,l2);
	}
#endif

    
    /* query MII to know LineSpeed,duplex mode */
    byMIIvalue = inb (ioaddr + 0x6d);
    LineSpeed = byMIIvalue & MIISR_SPEED;
    if (LineSpeed != 0)						//JJM
    {
	printf ("Linespeed=10Mbs");
    }
    else
    {
	printf ("Linespeed=100Mbs");
    }
	
    FDXFlag = QueryAuto (ioaddr);
    if (FDXFlag == 1)
    {
	printf (" Fullduplex\n");
	outw (CR_FDX, byCR0);
    }
    else
    {
	printf (" Halfduplex\n");
    }


    /* set MII 10 FULL ON, only apply in vt3043 */
    if(chip_id == 0x3043)
        WriteMII (0x17, 1, 1, ioaddr);

    /* turn on MII link change */
    MIICRbak = inb (byMIICR);
    outb (MIICRbak & 0x7F, byMIICR);
    MIIDelay ();
    outb (0x41, byMIIAD);
    MIIDelay ();

    /* while((inb(byMIIAD)&0x20)==0) ; */
    outb (MIICRbak | 0x80, byMIICR);

    nic->priv_data = &rhine;
    tp = &rhine;
    tp->chip_id = chip_id;
    tp->ioaddr = ioaddr;
    tp->phys[0] = -1;
    tp->chip_revision = revision_id;

    /* The lower four bits are the media type. */
    if (options > 0)
    {
	tp->full_duplex = (options & 16) ? 1 : 0;
	tp->default_port = options & 15;
	if (tp->default_port)
	    tp->medialock = 1;
    }
    return;
}

static void 
rhine_disable ( struct nic *nic ) {

    struct rhine_private *tp = (struct rhine_private *) nic->priv_data;
    int ioaddr = tp->ioaddr;

    rhine_reset(nic);

    printf ("rhine disable\n");
    /* Switch to loopback mode to avoid hardware races. */
    outb(0x60 | 0x01, byTCR);
    /* Stop the chip's Tx and Rx processes. */
    outw(CR_STOP, byCR0);
}

/**************************************************************************
ETH_RESET - Reset adapter
***************************************************************************/
static void
rhine_reset (struct nic *nic)
{
    struct rhine_private *tp = (struct rhine_private *) nic->priv_data;
    int ioaddr = tp->ioaddr;
    int i, j;
    int FDXFlag, CRbak;
    void *rx_ring_tmp;
    void *tx_ring_tmp;
    void *rx_bufs_tmp;
    void *tx_bufs_tmp;
    unsigned long rx_ring_tmp1;
    unsigned long tx_ring_tmp1;
    unsigned long rx_bufs_tmp1;
    unsigned long tx_bufs_tmp1;

    /* printf ("rhine_reset\n"); */
    /* Soft reset the chip. */
    /*outb(CmdReset, ioaddr + ChipCmd); */

    tx_bufs_tmp = rhine_buffers.txbuf;
    tx_ring_tmp = rhine_buffers.txdesc;
    rx_bufs_tmp = rhine_buffers.rxbuf;
    rx_ring_tmp = rhine_buffers.rxdesc;

    /* tune RD TD 32 byte alignment */
    rx_ring_tmp1 = virt_to_bus ( rx_ring_tmp );
    j = (rx_ring_tmp1 + 32) & (~0x1f);
    /* printf ("txring[%d]", j); */
    tp->rx_ring = (struct rhine_rx_desc *) bus_to_virt (j);

    tx_ring_tmp1 = virt_to_bus ( tx_ring_tmp );
    j = (tx_ring_tmp1 + 32) & (~0x1f);
    tp->tx_ring = (struct rhine_tx_desc *) bus_to_virt (j);
    /* printf ("rxring[%X]", j); */


    tx_bufs_tmp1 = virt_to_bus ( tx_bufs_tmp );
    j = (int) (tx_bufs_tmp1 + 32) & (~0x1f);
    tx_bufs_tmp = bus_to_virt (j);
    /* printf ("txb[%X]", j); */

    rx_bufs_tmp1 = virt_to_bus ( rx_bufs_tmp );
    j = (int) (rx_bufs_tmp1 + 32) & (~0x1f);
    rx_bufs_tmp = bus_to_virt (j);
    /* printf ("rxb[%X][%X]", rx_bufs_tmp1, j); */

    for (i = 0; i < RX_RING_SIZE; i++)
    {
	tp->rx_buffs[i] = (char *) rx_bufs_tmp;
	/* printf("r[%X]",tp->rx_buffs[i]); */
	rx_bufs_tmp += 1536;
    }

    for (i = 0; i < TX_RING_SIZE; i++)
    {
	tp->tx_buffs[i] = (char *) tx_bufs_tmp;
	/* printf("t[%X]",tp->tx_buffs[i]);  */
	tx_bufs_tmp += 1536;
    }

    /* software reset */
    outb (CR1_SFRST, byCR1);
    MIIDelay ();

    /* printf ("init ring"); */
    rhine_init_ring (nic);
    /*write TD RD Descriptor to MAC */
    outl (virt_to_bus (tp->rx_ring), dwCurrentRxDescAddr);
    outl (virt_to_bus (tp->tx_ring), dwCurrentTxDescAddr);

    /* Setup Multicast */	
    set_rx_mode(nic);

    /* set TCR RCR threshold to store and forward*/
    outb (0x3e, byBCR0);
    outb (0x38, byBCR1);
    outb (0x2c, byRCR);
    outb (0x60, byTCR);
    /* Set Fulldupex */
    FDXFlag = QueryAuto (ioaddr);
    if (FDXFlag == 1)
    {
	outb (CFGD_CFDX, byCFGD);
	outw (CR_FDX, byCR0);
    }

    /* KICK NIC to WORK */
    CRbak = inw (byCR0);
    CRbak = CRbak & 0xFFFB;	/* not CR_STOP */
    outw ((CRbak | CR_STRT | CR_TXON | CR_RXON | CR_DPOLL), byCR0);

    /* disable all known interrupt */
    outw (0, byIMR0);
}
/* Beware of PCI posted writes */
#define IOSYNC  do { inb(nic->ioaddr + StationAddr); } while (0)

static int
rhine_poll (struct nic *nic, int retreive)
{
    struct rhine_private *tp = (struct rhine_private *) nic->priv_data;
    int rxstatus, good = 0;;

    if (tp->rx_ring[tp->cur_rx].rx_status.bits.own_bit == 0)
    {
        unsigned int intr_status;
        /* There is a packet ready */
        if(!retreive)
            return 1;

        intr_status = inw(nic->ioaddr + IntrStatus);
        /* On Rhine-II, Bit 3 indicates Tx descriptor write-back race. */
#if 0
	if (tp->chip_id == 0x3065)
	  intr_status |= inb(nic->ioaddr + IntrStatus2) << 16;
#endif
        /* Acknowledge all of the current interrupt sources ASAP. */
        if (intr_status & IntrTxDescRace)
           outb(0x08, nic->ioaddr + IntrStatus2);
        outw(intr_status & 0xffff, nic->ioaddr + IntrStatus);
	IOSYNC;

	rxstatus = tp->rx_ring[tp->cur_rx].rx_status.lw;
	if ((rxstatus & 0x0300) != 0x0300)
	{
	    printf("rhine_poll: bad status\n");
	}
	else if (rxstatus & (RSR_ABNORMAL))
	{
	    printf ("rxerr[%X]\n", rxstatus);
	}
	else
	    good = 1;

	if (good)
	{
	    nic->packetlen = tp->rx_ring[tp->cur_rx].rx_status.bits.frame_length;
	    memcpy (nic->packet, tp->rx_buffs[tp->cur_rx], nic->packetlen);
	    /* printf ("Packet RXed\n"); */
	}
	tp->rx_ring[tp->cur_rx].rx_status.bits.own_bit = 1;
	tp->cur_rx++;
	tp->cur_rx = tp->cur_rx % RX_RING_SIZE;
    }
        /* Acknowledge all of the current interrupt sources ASAP. */
        outw(DEFAULT_INTR & ~IntrRxDone, nic->ioaddr + IntrStatus);

        IOSYNC;

    return good;
}

static void
rhine_transmit (struct nic *nic,
		const char *d, unsigned int t, unsigned int s, const char *p)
{
    struct rhine_private *tp = (struct rhine_private *) nic->priv_data;
    int ioaddr = tp->ioaddr;
    int entry;
    unsigned char CR1bak;
    unsigned char CR0bak;
    unsigned int nstype;
    unsigned long ct;


    /*printf ("rhine_transmit\n"); */
    /* setup ethernet header */


    /* Calculate the next Tx descriptor entry. */
    entry = tp->cur_tx % TX_RING_SIZE;

    memcpy (tp->tx_buffs[entry], d, ETH_ALEN);	/* dst */
    memcpy (tp->tx_buffs[entry] + ETH_ALEN, nic->node_addr, ETH_ALEN);	/* src */
    
    nstype=htons(t);
    memcpy(tp->tx_buffs[entry] + 2 * ETH_ALEN, (char*)&nstype, 2);

    memcpy (tp->tx_buffs[entry] + ETH_HLEN, p, s);
    s += ETH_HLEN;
    while (s < ETH_ZLEN)
	*((char *) tp->tx_buffs[entry] + (s++)) = 0;

    tp->tx_ring[entry].tx_ctrl.bits.tx_buf_size = s;

    tp->tx_ring[entry].tx_status.bits.own_bit = 1;


    CR1bak = inb (byCR1);

    CR1bak = CR1bak | CR1_TDMD1;
    /*printf("tdsw=[%X]",tp->tx_ring[entry].tx_status.lw); */
    /*printf("tdcw=[%X]",tp->tx_ring[entry].tx_ctrl.lw); */
    /*printf("tdbuf1=[%X]",tp->tx_ring[entry].buf_addr_1); */
    /*printf("tdbuf2=[%X]",tp->tx_ring[entry].buf_addr_2); */
    /*printf("td1=[%X]",inl(dwCurrentTDSE0)); */
    /*printf("td2=[%X]",inl(dwCurrentTDSE1)); */
    /*printf("td3=[%X]",inl(dwCurrentTDSE2)); */
    /*printf("td4=[%X]",inl(dwCurrentTDSE3)); */

    outb (CR1bak, byCR1);
    do
    {
	ct = currticks();
        /* Wait until transmit is finished or timeout*/
        while((tp->tx_ring[entry].tx_status.bits.own_bit !=0) &&
		ct + 10*1000 < currticks())
        ;

        if(tp->tx_ring[entry].tx_status.bits.terr == 0)
            break;

        if(tp->tx_ring[entry].tx_status.bits.abt == 1)
        {
            // turn on TX
            CR0bak = inb(byCR0);
            CR0bak = CR0bak|CR_TXON;
            outb(CR0bak,byCR0);
        }
    }while(0);
    tp->cur_tx++;

    /*outw(IMRShadow,byIMR0); */
    /*dev_kfree_skb(tp->tx_skbuff[entry], FREE_WRITE); */
    /*tp->tx_skbuff[entry] = 0; */
}

static struct nic_operations rhine_operations = {
	.connect	= dummy_connect,
	.poll		= rhine_poll,
	.transmit	= rhine_transmit,
	.irq		= rhine_irq,

};

static struct pci_device_id rhine_nics[] = {
PCI_ROM(0x1106, 0x3065, "dlink-530tx",     "VIA 6102", 0),
PCI_ROM(0x1106, 0x3106, "via-rhine-6105",  "VIA 6105", 0),
PCI_ROM(0x1106, 0x3043, "dlink-530tx-old", "VIA 3043", 0),		/* Rhine-I 86c100a */
PCI_ROM(0x1106, 0x3053, "via6105m",        "VIA 6105M", 0),
PCI_ROM(0x1106, 0x6100, "via-rhine-old",   "VIA 86C100A", 0),	/* Rhine-II */
};

PCI_DRIVER ( rhine_driver, rhine_nics, PCI_NO_CLASS );

DRIVER ( "VIA 86C100", nic_driver, pci_driver, rhine_driver,
	 rhine_probe, rhine_disable );

/* EOF via-rhine.c */

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
