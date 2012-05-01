/**************************************************************************
*
*    mtd80x.c: Etherboot device driver for the mtd80x Ethernet chip.
*    Written 2004-2004 by Erdem Güven <zuencap@yahoo.com>
*
*    This program is free software; you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation; either version 2 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program; if not, write to the Free Software
*    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
*    Portions of this code based on:
*               fealnx.c: A Linux device driver for the mtd80x Ethernet chip
*               Written 1998-2000 by Donald Becker
*
***************************************************************************/

FILE_LICENCE ( GPL2_OR_LATER );

/* to get some global routines like printf */
#include "etherboot.h"
/* to get the interface to the body of the program */
#include "nic.h"
/* to get the PCI support functions, if this is a PCI NIC */
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>
#include <mii.h>

/* Condensed operations for readability. */
#define virt_to_le32desc(addr)  cpu_to_le32(virt_to_bus(addr))
#define le32desc_to_virt(addr)  bus_to_virt(le32_to_cpu(addr))
#define get_unaligned(ptr) (*(ptr))


/* Operational parameters that are set at compile time. */

/* Keep the ring sizes a power of two for compile efficiency.           */
/* The compiler will convert <unsigned>'%'<2^N> into a bit mask.        */
/* Making the Tx ring too large decreases the effectiveness of channel  */
/* bonding and packet priority.                                         */
/* There are no ill effects from too-large receive rings.               */
#define TX_RING_SIZE 2
#define TX_QUEUE_LEN 10 /* Limit ring entries actually used.  */
#define RX_RING_SIZE 4

/* Operational parameters that usually are not changed. */
/* Time in jiffies before concluding the transmitter is hung. */
#define HZ 100
#define TX_TIME_OUT   (6*HZ)

/* Allocation size of Rx buffers with normal sized Ethernet frames.
   Do not change this value without good reason.  This is not a limit,
   but a way to keep a consistent allocation size among drivers.
 */
#define PKT_BUF_SZ 1536

/* for different PHY */
enum phy_type_flags {
    MysonPHY = 1,
    AhdocPHY = 2,
    SeeqPHY = 3,
    MarvellPHY = 4,
    Myson981 = 5,
    LevelOnePHY = 6,
    OtherPHY = 10,
};

/* A chip capabilities table*/
enum chip_capability_flags {
    HAS_MII_XCVR,
    HAS_CHIP_XCVR,
};

#if 0 /* not used */
static
struct chip_info
{
    u16 dev_id;
    int flag;
}
mtd80x_chips[] = {
                     {0x0800, HAS_MII_XCVR},
                     {0x0803, HAS_CHIP_XCVR},
                     {0x0891, HAS_MII_XCVR}
                 };
static int chip_cnt = sizeof( mtd80x_chips ) / sizeof( struct chip_info );
#endif

/* Offsets to the Command and Status Registers. */
enum mtd_offsets {
    PAR0 = 0x0,        /* physical address 0-3 */
    PAR1 = 0x04,        /* physical address 4-5 */
    MAR0 = 0x08,        /* multicast address 0-3 */
    MAR1 = 0x0C,        /* multicast address 4-7 */
    FAR0 = 0x10,        /* flow-control address 0-3 */
    FAR1 = 0x14,        /* flow-control address 4-5 */
    TCRRCR = 0x18,        /* receive & transmit configuration */
    BCR = 0x1C,        /* bus command */
    TXPDR = 0x20,        /* transmit polling demand */
    RXPDR = 0x24,        /* receive polling demand */
    RXCWP = 0x28,        /* receive current word pointer */
    TXLBA = 0x2C,        /* transmit list base address */
    RXLBA = 0x30,        /* receive list base address */
    ISR = 0x34,        /* interrupt status */
    IMR = 0x38,        /* interrupt mask */
    FTH = 0x3C,        /* flow control high/low threshold */
    MANAGEMENT = 0x40,    /* bootrom/eeprom and mii management */
    TALLY = 0x44,        /* tally counters for crc and mpa */
    TSR = 0x48,        /* tally counter for transmit status */
    BMCRSR = 0x4c,        /* basic mode control and status */
    PHYIDENTIFIER = 0x50,    /* phy identifier */
    ANARANLPAR = 0x54,    /* auto-negotiation advertisement and link
                                                       partner ability */
    ANEROCR = 0x58,        /* auto-negotiation expansion and pci conf. */
    BPREMRPSR = 0x5c,    /* bypass & receive error mask and phy status */
};

/* Bits in the interrupt status/enable registers. */
/* The bits in the Intr Status/Enable registers, mostly interrupt sources. */
enum intr_status_bits {
    RFCON = 0x00020000, /* receive flow control xon packet */
    RFCOFF = 0x00010000, /* receive flow control xoff packet */
    LSCStatus = 0x00008000, /* link status change */
    ANCStatus = 0x00004000, /* autonegotiation completed */
    FBE = 0x00002000, /* fatal bus error */
    FBEMask = 0x00001800, /* mask bit12-11 */
    ParityErr = 0x00000000, /* parity error */
    TargetErr = 0x00001000, /* target abort */
    MasterErr = 0x00000800, /* master error */
    TUNF = 0x00000400, /* transmit underflow */
    ROVF = 0x00000200, /* receive overflow */
    ETI = 0x00000100, /* transmit early int */
    ERI = 0x00000080, /* receive early int */
    CNTOVF = 0x00000040, /* counter overflow */
    RBU = 0x00000020, /* receive buffer unavailable */
    TBU = 0x00000010, /* transmit buffer unavilable */
    TI = 0x00000008, /* transmit interrupt */
    RI = 0x00000004, /* receive interrupt */
    RxErr = 0x00000002, /* receive error */
};

/* Bits in the NetworkConfig register. */
enum rx_mode_bits {
    RxModeMask   = 0xe0,
    AcceptAllPhys = 0x80,        /* promiscuous mode */
    AcceptBroadcast = 0x40,        /* accept broadcast */
    AcceptMulticast = 0x20,        /* accept mutlicast */
    AcceptRunt   = 0x08,        /* receive runt pkt */
    ALP          = 0x04,        /* receive long pkt */
    AcceptErr    = 0x02,        /* receive error pkt */

    AcceptMyPhys = 0x00000000,
    RxEnable     = 0x00000001,
    RxFlowCtrl   = 0x00002000,
    TxEnable     = 0x00040000,
    TxModeFDX    = 0x00100000,
    TxThreshold  = 0x00e00000,

    PS1000       = 0x00010000,
    PS10         = 0x00080000,
    FD           = 0x00100000,
};

/* Bits in network_desc.status */
enum rx_desc_status_bits {
    RXOWN = 0x80000000, /* own bit */
    FLNGMASK = 0x0fff0000, /* frame length */
    FLNGShift = 16,
    MARSTATUS = 0x00004000, /* multicast address received */
    BARSTATUS = 0x00002000, /* broadcast address received */
    PHYSTATUS = 0x00001000, /* physical address received */
    RXFSD = 0x00000800, /* first descriptor */
    RXLSD = 0x00000400, /* last descriptor */
    ErrorSummary = 0x80, /* error summary */
    RUNT = 0x40,  /* runt packet received */
    LONG = 0x20,  /* long packet received */
    FAE = 0x10,  /* frame align error */
    CRC = 0x08,  /* crc error */
    RXER = 0x04,  /* receive error */
};

enum rx_desc_control_bits {
    RXIC = 0x00800000, /* interrupt control */
    RBSShift = 0,
};

enum tx_desc_status_bits {
    TXOWN = 0x80000000, /* own bit */
    JABTO = 0x00004000, /* jabber timeout */
    CSL = 0x00002000, /* carrier sense lost */
    LC = 0x00001000, /* late collision */
    EC = 0x00000800, /* excessive collision */
    UDF = 0x00000400, /* fifo underflow */
    DFR = 0x00000200, /* deferred */
    HF = 0x00000100, /* heartbeat fail */
    NCRMask = 0x000000ff, /* collision retry count */
    NCRShift = 0,
};

enum tx_desc_control_bits {
    TXIC = 0x80000000, /* interrupt control */
    ETIControl = 0x40000000, /* early transmit interrupt */
    TXLD = 0x20000000, /* last descriptor */
    TXFD = 0x10000000, /* first descriptor */
    CRCEnable = 0x08000000, /* crc control */
    PADEnable = 0x04000000, /* padding control */
    RetryTxLC = 0x02000000, /* retry late collision */
    PKTSMask = 0x3ff800, /* packet size bit21-11 */
    PKTSShift = 11,
    TBSMask = 0x000007ff, /* transmit buffer bit 10-0 */
    TBSShift = 0,
};

/* BootROM/EEPROM/MII Management Register */
#define MASK_MIIR_MII_READ       0x00000000
#define MASK_MIIR_MII_WRITE      0x00000008
#define MASK_MIIR_MII_MDO        0x00000004
#define MASK_MIIR_MII_MDI        0x00000002
#define MASK_MIIR_MII_MDC        0x00000001

/* ST+OP+PHYAD+REGAD+TA */
#define OP_READ             0x6000 /* ST:01+OP:10+PHYAD+REGAD+TA:Z0 */
#define OP_WRITE            0x5002 /* ST:01+OP:01+PHYAD+REGAD+TA:10 */

/* ------------------------------------------------------------------------- */
/*      Constants for Myson PHY                                              */
/* ------------------------------------------------------------------------- */
#define MysonPHYID      0xd0000302
/* 89-7-27 add, (begin) */
#define MysonPHYID0     0x0302
#define StatusRegister  18
#define SPEED100        0x0400 // bit10
#define FULLMODE        0x0800 // bit11
/* 89-7-27 add, (end) */

/* ------------------------------------------------------------------------- */
/*      Constants for Seeq 80225 PHY                                         */
/* ------------------------------------------------------------------------- */
#define SeeqPHYID0      0x0016

#define MIIRegister18   18
#define SPD_DET_100     0x80
#define DPLX_DET_FULL   0x40

/* ------------------------------------------------------------------------- */
/*      Constants for Ahdoc 101 PHY                                          */
/* ------------------------------------------------------------------------- */
#define AhdocPHYID0     0x0022

#define DiagnosticReg   18
#define DPLX_FULL       0x0800
#define Speed_100       0x0400

/* 89/6/13 add, */
/* -------------------------------------------------------------------------- */
/*      Constants                                                             */
/* -------------------------------------------------------------------------- */
#define MarvellPHYID0           0x0141
#define LevelOnePHYID0  0x0013

#define MII1000BaseTControlReg  9
#define MII1000BaseTStatusReg   10
#define SpecificReg  17

/* for 1000BaseT Control Register */
#define PHYAbletoPerform1000FullDuplex  0x0200
#define PHYAbletoPerform1000HalfDuplex  0x0100
#define PHY1000AbilityMask              0x300

// for phy specific status register, marvell phy.
#define SpeedMask       0x0c000
#define Speed_1000M     0x08000
#define Speed_100M      0x4000
#define Speed_10M       0
#define Full_Duplex     0x2000

// 89/12/29 add, for phy specific status register, levelone phy, (begin)
#define LXT1000_100M    0x08000
#define LXT1000_1000M   0x0c000
#define LXT1000_Full    0x200
// 89/12/29 add, for phy specific status register, levelone phy, (end)

#if 0
/* for 3-in-1 case */
#define PS10            0x00080000
#define FD              0x00100000
#define PS1000          0x00010000
#endif

/* for PHY */
#define LinkIsUp        0x0004
#define LinkIsUp2 0x00040000

/* Create a static buffer of size PKT_BUF_SZ for each
RX and TX Descriptor.  All descriptors point to a
part of this buffer */
struct {
	u8 txb[PKT_BUF_SZ * TX_RING_SIZE] __attribute__ ((aligned(8)));
	u8 rxb[PKT_BUF_SZ * RX_RING_SIZE] __attribute__ ((aligned(8)));
} mtd80x_bufs __shared;
#define txb mtd80x_bufs.txb
#define rxb mtd80x_bufs.rxb

/* The Tulip Rx and Tx buffer descriptors. */
struct mtd_desc
{
    s32 status;
    s32 control;
    u32 buffer;
    u32 next_desc;
    struct mtd_desc *next_desc_logical;
    u8* skbuff;
    u32 reserved1;
    u32 reserved2;
};

struct mtd_private
{
    struct mtd_desc rx_ring[RX_RING_SIZE];
    struct mtd_desc tx_ring[TX_RING_SIZE];

    /* Frequently used values: keep some adjacent for cache effect. */
    int flags;
    struct pci_dev *pci_dev;
    unsigned long crvalue;
    unsigned long bcrvalue;
    /*unsigned long imrvalue;*/
    struct mtd_desc *cur_rx;
    struct mtd_desc *lack_rxbuf;
    int really_rx_count;
    struct mtd_desc *cur_tx;
    struct mtd_desc *cur_tx_copy;
    int really_tx_count;
    int free_tx_count;
    unsigned int rx_buf_sz; /* Based on MTU+slack. */

    /* These values are keep track of the transceiver/media in use. */
    unsigned int linkok;
    unsigned int line_speed;
    unsigned int duplexmode;
    unsigned int default_port:
    4; /* Last dev->if_port value. */
    unsigned int PHYType;

    /* MII transceiver section. */
    int mii_cnt;  /* MII device addresses. */
    unsigned char phys[1]; /* MII device addresses. */

    /*other*/
    const char *nic_name;
    int ioaddr;
    u16 dev_id;
};

static struct mtd_private mtdx;

static int mdio_read(struct nic * , int phy_id, int location);
static void getlinktype(struct nic * );
static void getlinkstatus(struct nic * );
static void set_rx_mode(struct nic *);

/**************************************************************************
 *  init_ring - setup the tx and rx descriptors
 *************************************************************************/
static void init_ring(struct nic *nic __unused)
{
    int i;

    mtdx.cur_rx = &mtdx.rx_ring[0];

    mtdx.rx_buf_sz = PKT_BUF_SZ;
    /*mtdx.rx_head_desc = &mtdx.rx_ring[0];*/

    /* Initialize all Rx descriptors. */
    /* Fill in the Rx buffers.  Handle allocation failure gracefully. */
    for (i = 0; i < RX_RING_SIZE; i++)
    {
        mtdx.rx_ring[i].status = RXOWN;
        mtdx.rx_ring[i].control = mtdx.rx_buf_sz << RBSShift;
        mtdx.rx_ring[i].next_desc = virt_to_le32desc(&mtdx.rx_ring[i+1]);
        mtdx.rx_ring[i].next_desc_logical = &mtdx.rx_ring[i+1];
        mtdx.rx_ring[i].buffer = virt_to_le32desc(&rxb[i * PKT_BUF_SZ]);
        mtdx.rx_ring[i].skbuff = &rxb[i * PKT_BUF_SZ];
    }
    /* Mark the last entry as wrapping the ring. */
    mtdx.rx_ring[i-1].next_desc = virt_to_le32desc(&mtdx.rx_ring[0]);
    mtdx.rx_ring[i-1].next_desc_logical = &mtdx.rx_ring[0];

    /* We only use one transmit buffer, but two
     * descriptors so transmit engines have somewhere
     * to point should they feel the need */
    mtdx.tx_ring[0].status = 0x00000000;
    mtdx.tx_ring[0].buffer = virt_to_bus(&txb[0]);
    mtdx.tx_ring[0].next_desc = virt_to_le32desc(&mtdx.tx_ring[1]);

    /* This descriptor is never used */
    mtdx.tx_ring[1].status = 0x00000000;
    mtdx.tx_ring[1].buffer = 0; /*virt_to_bus(&txb[1]); */
    mtdx.tx_ring[1].next_desc = virt_to_le32desc(&mtdx.tx_ring[0]);

    return;
}

/**************************************************************************
RESET - Reset Adapter
***************************************************************************/
static void mtd_reset( struct nic *nic )
{
    /* Reset the chip to erase previous misconfiguration. */
    outl(0x00000001, mtdx.ioaddr + BCR);

    init_ring(nic);

    outl(virt_to_bus(mtdx.rx_ring), mtdx.ioaddr + RXLBA);
    outl(virt_to_bus(mtdx.tx_ring), mtdx.ioaddr + TXLBA);

    /* Initialize other registers. */
    /* Configure the PCI bus bursts and FIFO thresholds. */
    mtdx.bcrvalue = 0x10; /* little-endian, 8 burst length */
    mtdx.crvalue = 0xa00; /* rx 128 burst length */

	if ( mtdx.dev_id == 0x891 ) {
		mtdx.bcrvalue |= 0x200;	/* set PROG bit */
		mtdx.crvalue |= 0x02000000;	/* set enhanced bit */
	}

    outl( mtdx.bcrvalue, mtdx.ioaddr + BCR);

    /* Restart Rx engine if stopped. */
    outl(0, mtdx.ioaddr + RXPDR);

    getlinkstatus(nic);
    if (mtdx.linkok)
    {
        static const char* texts[]={"half","full","10","100","1000"};
        getlinktype(nic);
        DBG ( "Link is OK : %s %s\n", texts[mtdx.duplexmode-1], texts[mtdx.line_speed+1] );
    } else
    {
        DBG ( "No link!!!\n" );
    }

    mtdx.crvalue |= /*TxEnable |*/ RxEnable | TxThreshold;
    set_rx_mode(nic);

    /* Clear interrupts by setting the interrupt mask. */
    outl(FBE | TUNF | CNTOVF | RBU | TI | RI, mtdx.ioaddr + ISR);
    outl( 0, mtdx.ioaddr + IMR);
}

/**************************************************************************
POLL - Wait for a frame
***************************************************************************/
static int mtd_poll(struct nic *nic, __unused int retrieve)
{
    s32 rx_status = mtdx.cur_rx->status;
    int retval = 0;

    if( ( rx_status & RXOWN ) != 0 )
    {
        return 0;
    }

    if (rx_status & ErrorSummary)
    { /* there was a fatal error */
        printf( "%s: Receive error, Rx status %8.8x, Error(s) %s%s%s\n",
                mtdx.nic_name, (unsigned int) rx_status,
                (rx_status & (LONG | RUNT)) ? "length_error ":"",
                (rx_status & RXER) ? "frame_error ":"",
                (rx_status & CRC) ? "crc_error ":"" );
        retval = 0;
    } else if( !((rx_status & RXFSD) && (rx_status & RXLSD)) )
    {
        /* this pkt is too long, over one rx buffer */
        printf("Pkt is too long, over one rx buffer.\n");
        retval = 0;
    } else
    { /* this received pkt is ok */
        /* Omit the four octet CRC from the length. */
        short pkt_len = ((rx_status & FLNGMASK) >> FLNGShift) - 4;

        DBG ( " netdev_rx() normal Rx pkt length %d"
 	      " status %x.\n", pkt_len, (unsigned int) rx_status );

        nic->packetlen = pkt_len;
        memcpy(nic->packet, mtdx.cur_rx->skbuff, pkt_len);

        retval = 1;
    }

    while( ( mtdx.cur_rx->status & RXOWN ) == 0 )
    {
        mtdx.cur_rx->status = RXOWN;
        mtdx.cur_rx = mtdx.cur_rx->next_desc_logical;
    }

    /* Restart Rx engine if stopped. */
    outl(0, mtdx.ioaddr + RXPDR);

    return retval;
}

/**************************************************************************
TRANSMIT - Transmit a frame
***************************************************************************/
static void mtd_transmit(
    struct nic *nic,
    const char *dest,            /* Destination */
    unsigned int type,            /* Type */
    unsigned int size,            /* size */
    const char *data)            /* Packet */
{
    u32 to;
    u32 tx_status;
    unsigned int nstype = htons ( type );

    memcpy( txb, dest, ETH_ALEN );
    memcpy( txb + ETH_ALEN, nic->node_addr, ETH_ALEN );
    memcpy( txb + 2 * ETH_ALEN, &nstype, 2 );
    memcpy( txb + ETH_HLEN, data, size );

    size += ETH_HLEN;
    size &= 0x0FFF;
    while( size < ETH_ZLEN )
    {
        txb[size++] = '\0';
    }

    mtdx.tx_ring[0].control = TXLD | TXFD | CRCEnable | PADEnable;
    mtdx.tx_ring[0].control |= (size << PKTSShift); /* pkt size */
    mtdx.tx_ring[0].control |= (size << TBSShift); /* buffer size */
    mtdx.tx_ring[0].status = TXOWN;

    /* Point to transmit descriptor */
    outl(virt_to_bus(mtdx.tx_ring), mtdx.ioaddr + TXLBA);
    /* Enable Tx */
    outl( mtdx.crvalue | TxEnable, mtdx.ioaddr + TCRRCR);
    /* Wake the potentially-idle transmit channel. */
    outl(0, mtdx.ioaddr + TXPDR);

    to = currticks() + TX_TIME_OUT;
    while(( mtdx.tx_ring[0].status & TXOWN) && (currticks() < to));

    /* Disable Tx */
    outl( mtdx.crvalue & (~TxEnable), mtdx.ioaddr + TCRRCR);

    tx_status = mtdx.tx_ring[0].status;
    if (currticks() >= to){
        DBG ( "TX Time Out" );
    } else if( tx_status & (CSL | LC | EC | UDF | HF)){
        printf( "Transmit error: %8.8x %s %s %s %s %s\n",
                (unsigned int) tx_status,
                tx_status & EC ? "abort" : "",
                tx_status & CSL ? "carrier" : "",
                tx_status & LC ? "late" : "",
                tx_status & UDF ? "fifo" : "",
                tx_status & HF ? "heartbeat" : "" );
    }

    /*hex_dump( txb, size );*/
    /*pause();*/

    DBG ( "TRANSMIT\n" );
}

/**************************************************************************
DISABLE - Turn off ethernet interface
***************************************************************************/
static void mtd_disable ( struct nic *nic ) {

    /* Disable Tx Rx*/
    outl( mtdx.crvalue & (~TxEnable) & (~RxEnable), mtdx.ioaddr + TCRRCR );

    /* Reset the chip to erase previous misconfiguration. */
    mtd_reset(nic);

    DBG ( "DISABLE\n" );
}

static struct nic_operations mtd_operations = {
	.connect	= dummy_connect,
	.poll		= mtd_poll,
	.transmit	= mtd_transmit,
	.irq		= dummy_irq,

};

static struct pci_device_id mtd80x_nics[] = {
        PCI_ROM(0x1516, 0x0800, "MTD800", "Myson MTD800", 0),
        PCI_ROM(0x1516, 0x0803, "MTD803", "Surecom EP-320X", 0),
        PCI_ROM(0x1516, 0x0891, "MTD891", "Myson MTD891", 0),
};

PCI_DRIVER ( mtd80x_driver, mtd80x_nics, PCI_NO_CLASS );

/**************************************************************************
PROBE - Look for an adapter, this routine's visible to the outside
***************************************************************************/

static int mtd_probe ( struct nic *nic, struct pci_device *pci ) {

    int i;

    if (pci->ioaddr == 0)
	    return 0;

    adjust_pci_device(pci);

    nic->ioaddr = pci->ioaddr;
    nic->irqno = 0;

    mtdx.nic_name = pci->id->name;
    mtdx.dev_id = pci->device;
    mtdx.ioaddr = nic->ioaddr;

    /* read ethernet id */
    for (i = 0; i < 6; ++i)
    {
        nic->node_addr[i] = inb(mtdx.ioaddr + PAR0 + i);
    }

    if (memcmp(nic->node_addr, "\0\0\0\0\0\0", 6) == 0)
    {
        return 0;
    }

    DBG ( "%s: ioaddr %4.4x MAC %s\n", mtdx.nic_name, mtdx.ioaddr, eth_ntoa ( nic->node_addr ) );

    /* Reset the chip to erase previous misconfiguration. */
    outl(0x00000001, mtdx.ioaddr + BCR);

    /* find the connected MII xcvrs */

    if( mtdx.dev_id != 0x803 )
    {
        int phy, phy_idx = 0;

        for (phy = 1; phy < 32 && phy_idx < 1; phy++) {
            int mii_status = mdio_read(nic, phy, 1);

            if (mii_status != 0xffff && mii_status != 0x0000) {
                mtdx.phys[phy_idx] = phy;

                DBG ( "%s: MII PHY found at address %d, status "
		      "0x%4.4x.\n", mtdx.nic_name, phy, mii_status );
                /* get phy type */
                {
                    unsigned int data;

                    data = mdio_read(nic, mtdx.phys[phy_idx], 2);
                    if (data == SeeqPHYID0)
                        mtdx.PHYType = SeeqPHY;
                    else if (data == AhdocPHYID0)
                        mtdx.PHYType = AhdocPHY;
                    else if (data == MarvellPHYID0)
                        mtdx.PHYType = MarvellPHY;
                    else if (data == MysonPHYID0)
                        mtdx.PHYType = Myson981;
                    else if (data == LevelOnePHYID0)
                        mtdx.PHYType = LevelOnePHY;
                    else
                        mtdx.PHYType = OtherPHY;
                }
                phy_idx++;
            }
        }

        mtdx.mii_cnt = phy_idx;
        if (phy_idx == 0) {
            printf("%s: MII PHY not found -- this device may "
                   "not operate correctly.\n", mtdx.nic_name);
        }
    } else {
        mtdx.phys[0] = 32;
        /* get phy type */
        if (inl(mtdx.ioaddr + PHYIDENTIFIER) == MysonPHYID ) {
            mtdx.PHYType = MysonPHY;
            DBG ( "MysonPHY\n" );
        } else {
            mtdx.PHYType = OtherPHY;
            DBG ( "OtherPHY\n" );
        }
    }

    getlinkstatus(nic);
    if( !mtdx.linkok )
    {
        printf("No link!!!\n");
        return 0;
    }

    mtd_reset( nic );

    /* point to NIC specific routines */
    nic->nic_op	= &mtd_operations;
    return 1;
}


/**************************************************************************/
static void set_rx_mode(struct nic *nic __unused)
{
    u32 mc_filter[2];                       /* Multicast hash filter */
    u32 rx_mode;

    /* Too many to match, or accept all multicasts. */
    mc_filter[1] = mc_filter[0] = ~0;
    rx_mode = AcceptBroadcast | AcceptMulticast | AcceptMyPhys;

    outl(mc_filter[0], mtdx.ioaddr + MAR0);
    outl(mc_filter[1], mtdx.ioaddr + MAR1);

    mtdx.crvalue = ( mtdx.crvalue & ~RxModeMask ) | rx_mode;
    outb( mtdx.crvalue, mtdx.ioaddr + TCRRCR);
}
/**************************************************************************/
static unsigned int m80x_read_tick(void)
/* function: Reads the Timer tick count register which decrements by 2 from  */
/*           65536 to 0 every 1/36.414 of a second. Each 2 decrements of the */
/*           count represents 838 nsec's.                                    */
/* input   : none.                                                           */
/* output  : none.                                                           */
{
    unsigned char tmp;
    int value;

    outb((char) 0x06, 0x43); // Command 8254 to latch T0's count

    // now read the count.
    tmp = (unsigned char) inb(0x40);
    value = ((int) tmp) << 8;
    tmp = (unsigned char) inb(0x40);
    value |= (((int) tmp) & 0xff);
    return (value);
}

static void m80x_delay(unsigned int interval)
/* function: to wait for a specified time.                                   */
/* input   : interval ... the specified time.                                */
/* output  : none.                                                           */
{
    unsigned int interval1, interval2, i = 0;

    interval1 = m80x_read_tick(); // get initial value
    do
    {
        interval2 = m80x_read_tick();
        if (interval1 < interval2)
            interval1 += 65536;
        ++i;
    } while (((interval1 - interval2) < (u16) interval) && (i < 65535));
}


static u32 m80x_send_cmd_to_phy(long miiport, int opcode, int phyad, int regad)
{
    u32 miir;
    int i;
    unsigned int mask, data;

    /* enable MII output */
    miir = (u32) inl(miiport);
    miir &= 0xfffffff0;

    miir |= MASK_MIIR_MII_WRITE + MASK_MIIR_MII_MDO;

    /* send 32 1's preamble */
    for (i = 0; i < 32; i++) {
        /* low MDC; MDO is already high (miir) */
        miir &= ~MASK_MIIR_MII_MDC;
        outl(miir, miiport);

        /* high MDC */
        miir |= MASK_MIIR_MII_MDC;
        outl(miir, miiport);
    }

    /* calculate ST+OP+PHYAD+REGAD+TA */
    data = opcode | (phyad << 7) | (regad << 2);

    /* sent out */
    mask = 0x8000;
    while (mask) {
        /* low MDC, prepare MDO */
        miir &= ~(MASK_MIIR_MII_MDC + MASK_MIIR_MII_MDO);
        if (mask & data)
            miir |= MASK_MIIR_MII_MDO;

        outl(miir, miiport);
        /* high MDC */
        miir |= MASK_MIIR_MII_MDC;
        outl(miir, miiport);
        m80x_delay(30);

        /* next */
        mask >>= 1;
        if (mask == 0x2 && opcode == OP_READ)
            miir &= ~MASK_MIIR_MII_WRITE;
    }
    return miir;
}

static int mdio_read(struct nic *nic __unused, int phyad, int regad)
{
    long miiport = mtdx.ioaddr + MANAGEMENT;
    u32 miir;
    unsigned int mask, data;

    miir = m80x_send_cmd_to_phy(miiport, OP_READ, phyad, regad);

    /* read data */
    mask = 0x8000;
    data = 0;
    while (mask)
    {
        /* low MDC */
        miir &= ~MASK_MIIR_MII_MDC;
        outl(miir, miiport);

        /* read MDI */
        miir = inl(miiport);
        if (miir & MASK_MIIR_MII_MDI)
            data |= mask;

        /* high MDC, and wait */
        miir |= MASK_MIIR_MII_MDC;
        outl(miir, miiport);
        m80x_delay((int) 30);

        /* next */
        mask >>= 1;
    }

    /* low MDC */
    miir &= ~MASK_MIIR_MII_MDC;
    outl(miir, miiport);

    return data & 0xffff;
}

#if 0 /* not used */
static void mdio_write(struct nic *nic __unused, int phyad, int regad,
		       int data)
{
    long miiport = mtdx.ioaddr + MANAGEMENT;
    u32 miir;
    unsigned int mask;

    miir = m80x_send_cmd_to_phy(miiport, OP_WRITE, phyad, regad);

    /* write data */
    mask = 0x8000;
    while (mask)
    {
        /* low MDC, prepare MDO */
        miir &= ~(MASK_MIIR_MII_MDC + MASK_MIIR_MII_MDO);
        if (mask & data)
            miir |= MASK_MIIR_MII_MDO;
        outl(miir, miiport);

        /* high MDC */
        miir |= MASK_MIIR_MII_MDC;
        outl(miir, miiport);

        /* next */
        mask >>= 1;
    }

    /* low MDC */
    miir &= ~MASK_MIIR_MII_MDC;
    outl(miir, miiport);

    return;
}
#endif

static void getlinkstatus(struct nic *nic)
/* function: Routine will read MII Status Register to get link status.       */
/* input   : dev... pointer to the adapter block.                            */
/* output  : none.                                                           */
{
    unsigned int i, DelayTime = 0x1000;

    mtdx.linkok = 0;

    if (mtdx.PHYType == MysonPHY)
    {
        for (i = 0; i < DelayTime; ++i) {
            if (inl(mtdx.ioaddr + BMCRSR) & LinkIsUp2) {
                mtdx.linkok = 1;
                return;
            }
            // delay
            m80x_delay(100);
        }
    } else
    {
        for (i = 0; i < DelayTime; ++i) {
            if (mdio_read(nic, mtdx.phys[0], MII_BMSR) & BMSR_LSTATUS) {
                mtdx.linkok = 1;
                return;
            }
            // delay
            m80x_delay(100);
        }
    }
}


static void getlinktype(struct nic *dev)
{
    if (mtdx.PHYType == MysonPHY)
    { /* 3-in-1 case */
        if (inl(mtdx.ioaddr + TCRRCR) & FD)
            mtdx.duplexmode = 2; /* full duplex */
        else
            mtdx.duplexmode = 1; /* half duplex */
        if (inl(mtdx.ioaddr + TCRRCR) & PS10)
            mtdx.line_speed = 1; /* 10M */
        else
            mtdx.line_speed = 2; /* 100M */
    } else
    {
        if (mtdx.PHYType == SeeqPHY) { /* this PHY is SEEQ 80225 */
            unsigned int data;

            data = mdio_read(dev, mtdx.phys[0], MIIRegister18);
            if (data & SPD_DET_100)
                mtdx.line_speed = 2; /* 100M */
            else
                mtdx.line_speed = 1; /* 10M */
            if (data & DPLX_DET_FULL)
                mtdx.duplexmode = 2; /* full duplex mode */
            else
                mtdx.duplexmode = 1; /* half duplex mode */
        } else if (mtdx.PHYType == AhdocPHY) {
            unsigned int data;

            data = mdio_read(dev, mtdx.phys[0], DiagnosticReg);
            if (data & Speed_100)
                mtdx.line_speed = 2; /* 100M */
            else
                mtdx.line_speed = 1; /* 10M */
            if (data & DPLX_FULL)
                mtdx.duplexmode = 2; /* full duplex mode */
            else
                mtdx.duplexmode = 1; /* half duplex mode */
        }
        /* 89/6/13 add, (begin) */
        else if (mtdx.PHYType == MarvellPHY) {
            unsigned int data;

            data = mdio_read(dev, mtdx.phys[0], SpecificReg);
            if (data & Full_Duplex)
                mtdx.duplexmode = 2; /* full duplex mode */
            else
                mtdx.duplexmode = 1; /* half duplex mode */
            data &= SpeedMask;
            if (data == Speed_1000M)
                mtdx.line_speed = 3; /* 1000M */
            else if (data == Speed_100M)
                mtdx.line_speed = 2; /* 100M */
            else
                mtdx.line_speed = 1; /* 10M */
        }
        /* 89/6/13 add, (end) */
        /* 89/7/27 add, (begin) */
        else if (mtdx.PHYType == Myson981) {
            unsigned int data;

            data = mdio_read(dev, mtdx.phys[0], StatusRegister);

            if (data & SPEED100)
                mtdx.line_speed = 2;
            else
                mtdx.line_speed = 1;

            if (data & FULLMODE)
                mtdx.duplexmode = 2;
            else
                mtdx.duplexmode = 1;
        }
        /* 89/7/27 add, (end) */
        /* 89/12/29 add */
        else if (mtdx.PHYType == LevelOnePHY) {
            unsigned int data;

            data = mdio_read(dev, mtdx.phys[0], SpecificReg);
            if (data & LXT1000_Full)
                mtdx.duplexmode = 2; /* full duplex mode */
            else
                mtdx.duplexmode = 1; /* half duplex mode */
            data &= SpeedMask;
            if (data == LXT1000_1000M)
                mtdx.line_speed = 3; /* 1000M */
            else if (data == LXT1000_100M)
                mtdx.line_speed = 2; /* 100M */
            else
                mtdx.line_speed = 1; /* 10M */
        }
        // chage crvalue
        // mtdx.crvalue&=(~PS10)&(~FD);
        mtdx.crvalue &= (~PS10) & (~FD) & (~PS1000);
        if (mtdx.line_speed == 1)
            mtdx.crvalue |= PS10;
        else if (mtdx.line_speed == 3)
            mtdx.crvalue |= PS1000;
        if (mtdx.duplexmode == 2)
            mtdx.crvalue |= FD;
    }
}

DRIVER ( "MTD80X", nic_driver, pci_driver, mtd80x_driver,
	 mtd_probe, mtd_disable );
