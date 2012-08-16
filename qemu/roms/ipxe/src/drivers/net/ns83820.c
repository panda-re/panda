/**************************************************************************
*    ns83820.c: Etherboot device driver for the National Semiconductor 83820
*    Written 2004 by Timothy Legge <tlegge@rogers.com>
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
*	ns83820.c by Benjamin LaHaise with contributions
* 		for Linux kernel 2.4.x.
*	
*    Linux Driver Version 0.20, 20020610
* 
*    This development of this Etherboot driver was funded by:
*
*    NXTV: http://www.nxtv.com/
*    	
*    REVISION HISTORY:
*    ================
*
*    v1.0	02-16-2004	timlegge	Initial port of Linux driver
*    v1.1	02-19-2004	timlegge	More rohbust transmit and poll
*    
*    Indent Options: indent -kr -i8
***************************************************************************/

FILE_LICENCE ( GPL2_OR_LATER );

/* to get some global routines like printf */
#include "etherboot.h"
/* to get the interface to the body of the program */
#include "nic.h"
/* to get the PCI support functions, if this is a PCI NIC */
#include <ipxe/pci.h>

#if ARCH == ia64		/* Support 64-bit addressing */
#define USE_64BIT_ADDR
#endif

#define HZ 100

/* Condensed operations for readability. */
#define virt_to_le32desc(addr)  cpu_to_le32(virt_to_bus(addr))
#define le32desc_to_virt(addr)  bus_to_virt(le32_to_cpu(addr))

/* NIC specific static variables go here */

/* Global parameters.  See MODULE_PARM near the bottom. */
// static int ihr = 2;
static int reset_phy = 0;
static int lnksts = 0;		/* CFG_LNKSTS bit polarity */

#if defined(CONFIG_HIGHMEM64G) || defined(__ia64__)
#define USE_64BIT_ADDR	"+"
#endif

#if defined(USE_64BIT_ADDR)
#define TRY_DAC	1
#else
#define TRY_DAC	0
#endif

/* tunables */
#define RX_BUF_SIZE	1500	/* 8192 */

/* Must not exceed ~65000. */
#define NR_RX_DESC	64
#define NR_TX_DESC	1

		   /* not tunable *//* Extra 6 bytes for 64 bit alignment (divisable by 8) */
#define REAL_RX_BUF_SIZE (RX_BUF_SIZE + 14 + 6)	/* rx/tx mac addr + type */

#define MIN_TX_DESC_FREE	8

/* register defines */
#define CFGCS		0x04

#define CR_TXE		0x00000001
#define CR_TXD		0x00000002
/* Ramit : Here's a tip, don't do a RXD immediately followed by an RXE
 * The Receive engine skips one descriptor and moves
 * onto the next one!! */
#define CR_RXE		0x00000004
#define CR_RXD		0x00000008
#define CR_TXR		0x00000010
#define CR_RXR		0x00000020
#define CR_SWI		0x00000080
#define CR_RST		0x00000100

#define PTSCR_EEBIST_FAIL       0x00000001
#define PTSCR_EEBIST_EN         0x00000002
#define PTSCR_EELOAD_EN         0x00000004
#define PTSCR_RBIST_FAIL        0x000001b8
#define PTSCR_RBIST_DONE        0x00000200
#define PTSCR_RBIST_EN          0x00000400
#define PTSCR_RBIST_RST         0x00002000

#define MEAR_EEDI		0x00000001
#define MEAR_EEDO		0x00000002
#define MEAR_EECLK		0x00000004
#define MEAR_EESEL		0x00000008
#define MEAR_MDIO		0x00000010
#define MEAR_MDDIR		0x00000020
#define MEAR_MDC		0x00000040

#define ISR_TXDESC3	0x40000000
#define ISR_TXDESC2	0x20000000
#define ISR_TXDESC1	0x10000000
#define ISR_TXDESC0	0x08000000
#define ISR_RXDESC3	0x04000000
#define ISR_RXDESC2	0x02000000
#define ISR_RXDESC1	0x01000000
#define ISR_RXDESC0	0x00800000
#define ISR_TXRCMP	0x00400000
#define ISR_RXRCMP	0x00200000
#define ISR_DPERR	0x00100000
#define ISR_SSERR	0x00080000
#define ISR_RMABT	0x00040000
#define ISR_RTABT	0x00020000
#define ISR_RXSOVR	0x00010000
#define ISR_HIBINT	0x00008000
#define ISR_PHY		0x00004000
#define ISR_PME		0x00002000
#define ISR_SWI		0x00001000
#define ISR_MIB		0x00000800
#define ISR_TXURN	0x00000400
#define ISR_TXIDLE	0x00000200
#define ISR_TXERR	0x00000100
#define ISR_TXDESC	0x00000080
#define ISR_TXOK	0x00000040
#define ISR_RXORN	0x00000020
#define ISR_RXIDLE	0x00000010
#define ISR_RXEARLY	0x00000008
#define ISR_RXERR	0x00000004
#define ISR_RXDESC	0x00000002
#define ISR_RXOK	0x00000001

#define TXCFG_CSI	0x80000000
#define TXCFG_HBI	0x40000000
#define TXCFG_MLB	0x20000000
#define TXCFG_ATP	0x10000000
#define TXCFG_ECRETRY	0x00800000
#define TXCFG_BRST_DIS	0x00080000
#define TXCFG_MXDMA1024	0x00000000
#define TXCFG_MXDMA512	0x00700000
#define TXCFG_MXDMA256	0x00600000
#define TXCFG_MXDMA128	0x00500000
#define TXCFG_MXDMA64	0x00400000
#define TXCFG_MXDMA32	0x00300000
#define TXCFG_MXDMA16	0x00200000
#define TXCFG_MXDMA8	0x00100000

#define CFG_LNKSTS	0x80000000
#define CFG_SPDSTS	0x60000000
#define CFG_SPDSTS1	0x40000000
#define CFG_SPDSTS0	0x20000000
#define CFG_DUPSTS	0x10000000
#define CFG_TBI_EN	0x01000000
#define CFG_MODE_1000	0x00400000
/* Ramit : Dont' ever use AUTO_1000, it never works and is buggy.
 * Read the Phy response and then configure the MAC accordingly */
#define CFG_AUTO_1000	0x00200000
#define CFG_PINT_CTL	0x001c0000
#define CFG_PINT_DUPSTS	0x00100000
#define CFG_PINT_LNKSTS	0x00080000
#define CFG_PINT_SPDSTS	0x00040000
#define CFG_TMRTEST	0x00020000
#define CFG_MRM_DIS	0x00010000
#define CFG_MWI_DIS	0x00008000
#define CFG_T64ADDR	0x00004000
#define CFG_PCI64_DET	0x00002000
#define CFG_DATA64_EN	0x00001000
#define CFG_M64ADDR	0x00000800
#define CFG_PHY_RST	0x00000400
#define CFG_PHY_DIS	0x00000200
#define CFG_EXTSTS_EN	0x00000100
#define CFG_REQALG	0x00000080
#define CFG_SB		0x00000040
#define CFG_POW		0x00000020
#define CFG_EXD		0x00000010
#define CFG_PESEL	0x00000008
#define CFG_BROM_DIS	0x00000004
#define CFG_EXT_125	0x00000002
#define CFG_BEM		0x00000001

#define EXTSTS_UDPPKT	0x00200000
#define EXTSTS_TCPPKT	0x00080000
#define EXTSTS_IPPKT	0x00020000

#define SPDSTS_POLARITY	(CFG_SPDSTS1 | CFG_SPDSTS0 | CFG_DUPSTS | (lnksts ? CFG_LNKSTS : 0))

#define MIBC_MIBS	0x00000008
#define MIBC_ACLR	0x00000004
#define MIBC_FRZ	0x00000002
#define MIBC_WRN	0x00000001

#define PCR_PSEN	(1 << 31)
#define PCR_PS_MCAST	(1 << 30)
#define PCR_PS_DA	(1 << 29)
#define PCR_STHI_8	(3 << 23)
#define PCR_STLO_4	(1 << 23)
#define PCR_FFHI_8K	(3 << 21)
#define PCR_FFLO_4K	(1 << 21)
#define PCR_PAUSE_CNT	0xFFFE

#define RXCFG_AEP	0x80000000
#define RXCFG_ARP	0x40000000
#define RXCFG_STRIPCRC	0x20000000
#define RXCFG_RX_FD	0x10000000
#define RXCFG_ALP	0x08000000
#define RXCFG_AIRL	0x04000000
#define RXCFG_MXDMA512	0x00700000
#define RXCFG_DRTH	0x0000003e
#define RXCFG_DRTH0	0x00000002

#define RFCR_RFEN	0x80000000
#define RFCR_AAB	0x40000000
#define RFCR_AAM	0x20000000
#define RFCR_AAU	0x10000000
#define RFCR_APM	0x08000000
#define RFCR_APAT	0x07800000
#define RFCR_APAT3	0x04000000
#define RFCR_APAT2	0x02000000
#define RFCR_APAT1	0x01000000
#define RFCR_APAT0	0x00800000
#define RFCR_AARP	0x00400000
#define RFCR_MHEN	0x00200000
#define RFCR_UHEN	0x00100000
#define RFCR_ULM	0x00080000

#define VRCR_RUDPE	0x00000080
#define VRCR_RTCPE	0x00000040
#define VRCR_RIPE	0x00000020
#define VRCR_IPEN	0x00000010
#define VRCR_DUTF	0x00000008
#define VRCR_DVTF	0x00000004
#define VRCR_VTREN	0x00000002
#define VRCR_VTDEN	0x00000001

#define VTCR_PPCHK	0x00000008
#define VTCR_GCHK	0x00000004
#define VTCR_VPPTI	0x00000002
#define VTCR_VGTI	0x00000001

#define CR		0x00
#define CFG		0x04
#define MEAR		0x08
#define PTSCR		0x0c
#define	ISR		0x10
#define	IMR		0x14
#define	IER		0x18
#define	IHR		0x1c
#define TXDP		0x20
#define TXDP_HI		0x24
#define TXCFG		0x28
#define GPIOR		0x2c
#define RXDP		0x30
#define RXDP_HI		0x34
#define RXCFG		0x38
#define PQCR		0x3c
#define WCSR		0x40
#define PCR		0x44
#define RFCR		0x48
#define RFDR		0x4c

#define SRR		0x58

#define VRCR		0xbc
#define VTCR		0xc0
#define VDR		0xc4
#define CCSR		0xcc

#define TBICR		0xe0
#define TBISR		0xe4
#define TANAR		0xe8
#define TANLPAR		0xec
#define TANER		0xf0
#define TESR		0xf4

#define TBICR_MR_AN_ENABLE	0x00001000
#define TBICR_MR_RESTART_AN	0x00000200

#define TBISR_MR_LINK_STATUS	0x00000020
#define TBISR_MR_AN_COMPLETE	0x00000004

#define TANAR_PS2 		0x00000100
#define TANAR_PS1 		0x00000080
#define TANAR_HALF_DUP 		0x00000040
#define TANAR_FULL_DUP 		0x00000020

#define GPIOR_GP5_OE		0x00000200
#define GPIOR_GP4_OE		0x00000100
#define GPIOR_GP3_OE		0x00000080
#define GPIOR_GP2_OE		0x00000040
#define GPIOR_GP1_OE		0x00000020
#define GPIOR_GP3_OUT		0x00000004
#define GPIOR_GP1_OUT		0x00000001

#define LINK_AUTONEGOTIATE	0x01
#define LINK_DOWN		0x02
#define LINK_UP			0x04


#define __kick_rx()	writel(CR_RXE, ns->base + CR)

#define kick_rx() do { \
	DBG("kick_rx: maybe kicking\n"); \
		writel(virt_to_le32desc(&rx_ring[ns->cur_rx]), ns->base + RXDP); \
		if (ns->next_rx == ns->next_empty) \
			printf("uh-oh: next_rx == next_empty???\n"); \
		__kick_rx(); \
} while(0)


#ifdef USE_64BIT_ADDR
#define HW_ADDR_LEN	8
#else
#define HW_ADDR_LEN	4
#endif

#define CMDSTS_OWN	0x80000000
#define CMDSTS_MORE	0x40000000
#define CMDSTS_INTR	0x20000000
#define CMDSTS_ERR	0x10000000
#define CMDSTS_OK	0x08000000
#define CMDSTS_LEN_MASK	0x0000ffff

#define CMDSTS_DEST_MASK	0x01800000
#define CMDSTS_DEST_SELF	0x00800000
#define CMDSTS_DEST_MULTI	0x01000000

#define DESC_SIZE	8	/* Should be cache line sized */

#ifdef USE_64BIT_ADDR
struct ring_desc {
	uint64_t link;
	uint64_t bufptr;
	u32 cmdsts;
	u32 extsts;		/* Extended status field */
};
#else
struct ring_desc {
	u32 link;
	u32 bufptr;
	u32 cmdsts;
	u32 extsts;		/* Extended status field */
};
#endif

/* Private Storage for the NIC */
static struct ns83820_private {
	u8 *base;
	int up;
	long idle;
	u32 *next_rx_desc;
	u16 next_rx, next_empty;
	u32 cur_rx;
	u32 *descs;
	unsigned ihr;
	u32 CFG_cache;
	u32 MEAR_cache;
	u32 IMR_cache;
	int linkstate;
	u16 tx_done_idx;
	u16 tx_idx;
	u16 tx_intr_idx;
	u32 phy_descs;
	u32 *tx_descs;

} nsx;
static struct ns83820_private *ns;

/* Define the TX and RX Descriptor and Buffers */
struct {
	struct ring_desc tx_ring[NR_TX_DESC] __attribute__ ((aligned(8)));
	unsigned char txb[NR_TX_DESC * REAL_RX_BUF_SIZE];
	struct ring_desc rx_ring[NR_RX_DESC] __attribute__ ((aligned(8)));
	unsigned char rxb[NR_RX_DESC * REAL_RX_BUF_SIZE]
	__attribute__ ((aligned(8)));
} ns83820_bufs __shared;
#define tx_ring ns83820_bufs.tx_ring
#define rx_ring ns83820_bufs.rx_ring
#define txb ns83820_bufs.txb
#define rxb ns83820_bufs.rxb

static void phy_intr(struct nic *nic __unused)
{
	static char *speeds[] =
	    { "10", "100", "1000", "1000(?)", "1000F" };
	u32 cfg, new_cfg;
	u32 tbisr, tanar, tanlpar;
	int speed, fullduplex, newlinkstate;

	cfg = readl(ns->base + CFG) ^ SPDSTS_POLARITY;
	if (ns->CFG_cache & CFG_TBI_EN) {
		/* we have an optical transceiver */
		tbisr = readl(ns->base + TBISR);
		tanar = readl(ns->base + TANAR);
		tanlpar = readl(ns->base + TANLPAR);
		DBG("phy_intr: tbisr=%hX, tanar=%hX, tanlpar=%hX\n",
		    tbisr, tanar, tanlpar);

		if ((fullduplex = (tanlpar & TANAR_FULL_DUP)
		     && (tanar & TANAR_FULL_DUP))) {

			/* both of us are full duplex */
			writel(readl(ns->base + TXCFG)
			       | TXCFG_CSI | TXCFG_HBI | TXCFG_ATP,
			       ns->base + TXCFG);
			writel(readl(ns->base + RXCFG) | RXCFG_RX_FD,
			       ns->base + RXCFG);
			/* Light up full duplex LED */
			writel(readl(ns->base + GPIOR) | GPIOR_GP1_OUT,
			       ns->base + GPIOR);

		} else if (((tanlpar & TANAR_HALF_DUP)
			    && (tanar & TANAR_HALF_DUP))
			   || ((tanlpar & TANAR_FULL_DUP)
			       && (tanar & TANAR_HALF_DUP))
			   || ((tanlpar & TANAR_HALF_DUP)
			       && (tanar & TANAR_FULL_DUP))) {

			/* one or both of us are half duplex */
			writel((readl(ns->base + TXCFG)
				& ~(TXCFG_CSI | TXCFG_HBI)) | TXCFG_ATP,
			       ns->base + TXCFG);
			writel(readl(ns->base + RXCFG) & ~RXCFG_RX_FD,
			       ns->base + RXCFG);
			/* Turn off full duplex LED */
			writel(readl(ns->base + GPIOR) & ~GPIOR_GP1_OUT,
			       ns->base + GPIOR);
		}

		speed = 4;	/* 1000F */

	} else {
		/* we have a copper transceiver */
		new_cfg =
		    ns->CFG_cache & ~(CFG_SB | CFG_MODE_1000 | CFG_SPDSTS);

		if (cfg & CFG_SPDSTS1)
			new_cfg |= CFG_MODE_1000;
		else
			new_cfg &= ~CFG_MODE_1000;

		speed = ((cfg / CFG_SPDSTS0) & 3);
		fullduplex = (cfg & CFG_DUPSTS);

		if (fullduplex)
			new_cfg |= CFG_SB;

		if ((cfg & CFG_LNKSTS) &&
		    ((new_cfg ^ ns->CFG_cache) & CFG_MODE_1000)) {
			writel(new_cfg, ns->base + CFG);
			ns->CFG_cache = new_cfg;
		}

		ns->CFG_cache &= ~CFG_SPDSTS;
		ns->CFG_cache |= cfg & CFG_SPDSTS;
	}

	newlinkstate = (cfg & CFG_LNKSTS) ? LINK_UP : LINK_DOWN;

	if (newlinkstate & LINK_UP && ns->linkstate != newlinkstate) {
		printf("link now %s mbps, %s duplex and up.\n",
		       speeds[speed], fullduplex ? "full" : "half");
	} else if (newlinkstate & LINK_DOWN
		   && ns->linkstate != newlinkstate) {
		printf("link now down.\n");
	}
	ns->linkstate = newlinkstate;
}
static void ns83820_set_multicast(struct nic *nic __unused);
static void ns83820_setup_rx(struct nic *nic)
{
	unsigned i;
	ns->idle = 1;
	ns->next_rx = 0;
	ns->next_rx_desc = ns->descs;
	ns->next_empty = 0;
	ns->cur_rx = 0;


	for (i = 0; i < NR_RX_DESC; i++) {
		rx_ring[i].link = virt_to_le32desc(&rx_ring[i + 1]);
		rx_ring[i].bufptr =
		    virt_to_le32desc(&rxb[i * REAL_RX_BUF_SIZE]);
		rx_ring[i].cmdsts = cpu_to_le32(REAL_RX_BUF_SIZE);
		rx_ring[i].extsts = cpu_to_le32(0);
	}
//      No need to wrap the ring 
//      rx_ring[i].link = virt_to_le32desc(&rx_ring[0]);
	writel(0, ns->base + RXDP_HI);
	writel(virt_to_le32desc(&rx_ring[0]), ns->base + RXDP);

	DBG("starting receiver\n");

	writel(0x0001, ns->base + CCSR);
	writel(0, ns->base + RFCR);
	writel(0x7fc00000, ns->base + RFCR);
	writel(0xffc00000, ns->base + RFCR);

	ns->up = 1;

	phy_intr(nic);

	/* Okay, let it rip */
	ns->IMR_cache |= ISR_PHY;
	ns->IMR_cache |= ISR_RXRCMP;
	//dev->IMR_cache |= ISR_RXERR;
	//dev->IMR_cache |= ISR_RXOK;
	ns->IMR_cache |= ISR_RXORN;
	ns->IMR_cache |= ISR_RXSOVR;
	ns->IMR_cache |= ISR_RXDESC;
	ns->IMR_cache |= ISR_RXIDLE;
	ns->IMR_cache |= ISR_TXDESC;
	ns->IMR_cache |= ISR_TXIDLE;

	// No reason to enable interupts...
	// writel(ns->IMR_cache, ns->base + IMR);
	// writel(1, ns->base + IER);
	ns83820_set_multicast(nic);
	kick_rx();
}


static void ns83820_do_reset(struct nic *nic __unused, u32 which)
{
	DBG("resetting chip...\n");
	writel(which, ns->base + CR);
	do {

	} while (readl(ns->base + CR) & which);
	DBG("okay!\n");
}

static void ns83820_reset(struct nic *nic)
{
	unsigned i;
	DBG("ns83820_reset\n");

	writel(0, ns->base + PQCR);

	ns83820_setup_rx(nic);

	for (i = 0; i < NR_TX_DESC; i++) {
		tx_ring[i].link = 0;
		tx_ring[i].bufptr = 0;
		tx_ring[i].cmdsts = cpu_to_le32(0);
		tx_ring[i].extsts = cpu_to_le32(0);
	}

	ns->tx_idx = 0;
	ns->tx_done_idx = 0;
	writel(0, ns->base + TXDP_HI);
	return;
}
static void ns83820_getmac(struct nic *nic __unused, u8 * mac)
{
	unsigned i;
	for (i = 0; i < 3; i++) {
		u32 data;
		/* Read from the perfect match memory: this is loaded by
		 * the chip from the EEPROM via the EELOAD self test.
		 */
		writel(i * 2, ns->base + RFCR);
		data = readl(ns->base + RFDR);
		*mac++ = data;
		*mac++ = data >> 8;
	}
}

static void ns83820_set_multicast(struct nic *nic __unused)
{
	u8 *rfcr = ns->base + RFCR;
	u32 and_mask = 0xffffffff;
	u32 or_mask = 0;
	u32 val;

	/* Support Multicast */
	and_mask &= ~(RFCR_AAU | RFCR_AAM);
	or_mask |= RFCR_AAM;
	val = (readl(rfcr) & and_mask) | or_mask;
	/* Ramit : RFCR Write Fix doc says RFEN must be 0 modify other bits */
	writel(val & ~RFCR_RFEN, rfcr);
	writel(val, rfcr);

}
static void ns83820_run_bist(struct nic *nic __unused, const char *name,
			     u32 enable, u32 done, u32 fail)
{
	int timed_out = 0;
	long start;
	u32 status;
	int loops = 0;

	DBG("start %s\n", name);

	    start = currticks();

	writel(enable, ns->base + PTSCR);
	for (;;) {
		loops++;
		status = readl(ns->base + PTSCR);
		if (!(status & enable))
			break;
		if (status & done)
			break;
		if (status & fail)
			break;
		if ((currticks() - start) >= HZ) {
			timed_out = 1;
			break;
		}
	}

	if (status & fail)
	  printf("%s failed! (0x%hX & 0x%hX)\n", name, (unsigned int) status, 
		 (unsigned int) fail);
	else if (timed_out)
		printf("run_bist %s timed out! (%hX)\n", name, (unsigned int) status);
	DBG("done %s in %d loops\n", name, loops);
}

/*************************************
Check Link
*************************************/
static void ns83820_check_intr(struct nic *nic) {
	int i;
	u32 isr = readl(ns->base + ISR);
	if(ISR_PHY & isr)
		phy_intr(nic);
	if(( ISR_RXIDLE | ISR_RXDESC | ISR_RXERR) & isr)
		kick_rx();
	for (i = 0; i < NR_RX_DESC; i++) {
		if (rx_ring[i].cmdsts == CMDSTS_OWN) {
//			rx_ring[i].link = virt_to_le32desc(&rx_ring[i + 1]);
			rx_ring[i].cmdsts = cpu_to_le32(REAL_RX_BUF_SIZE);
		}
	}
}
/**************************************************************************
POLL - Wait for a frame
***************************************************************************/
static int ns83820_poll(struct nic *nic, int retrieve)
{
	/* return true if there's an ethernet packet ready to read */
	/* nic->packet should contain data on return */
	/* nic->packetlen should contain length of data */
	u32 cmdsts;
	int entry = ns->cur_rx;

	ns83820_check_intr(nic);

	cmdsts = le32_to_cpu(rx_ring[entry].cmdsts);

	if ( ! ( (CMDSTS_OWN & (cmdsts)) && (cmdsts != (CMDSTS_OWN)) ) )
	  return 0;

	if ( ! retrieve ) return 1;

	if (! (CMDSTS_OK & cmdsts) )
	  return 0;

	nic->packetlen = cmdsts & 0xffff;
	memcpy(nic->packet,
	       rxb + (entry * REAL_RX_BUF_SIZE),
	       nic->packetlen);
	//			rx_ring[entry].link = 0;
	rx_ring[entry].cmdsts = cpu_to_le32(CMDSTS_OWN);

	ns->cur_rx = (ns->cur_rx + 1) % NR_RX_DESC;

	if (ns->cur_rx == 0)	/* We have wrapped the ring */
	  kick_rx();

	return 1;
}

static inline void kick_tx(struct nic *nic __unused)
{
	DBG("kick_tx\n");
	writel(CR_TXE, ns->base + CR);
}

/**************************************************************************
TRANSMIT - Transmit a frame
***************************************************************************/
static void ns83820_transmit(struct nic *nic, const char *d,	/* Destination */
			     unsigned int t,	/* Type */
			     unsigned int s,	/* size */
			     const char *p)
{				/* Packet */
	/* send the packet to destination */

	u16 nstype;
	u32 cmdsts, extsts;
	int cur_tx = 0;
	u32 isr = readl(ns->base + ISR);
	if (ISR_TXIDLE & isr)
		kick_tx(nic);
	/* point to the current txb incase multiple tx_rings are used */
	memcpy(txb, d, ETH_ALEN);
	memcpy(txb + ETH_ALEN, nic->node_addr, ETH_ALEN);
	nstype = htons((u16) t);
	memcpy(txb + 2 * ETH_ALEN, (u8 *) & nstype, 2);
	memcpy(txb + ETH_HLEN, p, s);
	s += ETH_HLEN;
	s &= 0x0FFF;
	while (s < ETH_ZLEN)
		txb[s++] = '\0';

	/* Setup the transmit descriptor */
	extsts = 0;
	extsts |= EXTSTS_UDPPKT;

	tx_ring[cur_tx].bufptr = virt_to_le32desc(&txb);
	tx_ring[cur_tx].extsts = cpu_to_le32(extsts);

	cmdsts = cpu_to_le32(0);
	cmdsts |= cpu_to_le32(CMDSTS_OWN | s);
	tx_ring[cur_tx].cmdsts = cpu_to_le32(cmdsts);

	writel(virt_to_le32desc(&tx_ring[0]), ns->base + TXDP);
	kick_tx(nic);
}

/**************************************************************************
DISABLE - Turn off ethernet interface
***************************************************************************/
static void ns83820_disable ( struct nic *nic ) {

	/* put the card in its initial state */
	/* This function serves 3 purposes.
	 * This disables DMA and interrupts so we don't receive
	 *  unexpected packets or interrupts from the card after
	 *  etherboot has finished. 
	 * This frees resources so etherboot may use
	 *  this driver on another interface
	 * This allows etherboot to reinitialize the interface
	 *  if something is something goes wrong.
	 */
	/* disable interrupts */
	writel(0, ns->base + IMR);
	writel(0, ns->base + IER);
	readl(ns->base + IER);

	ns->up = 0;

	ns83820_do_reset(nic, CR_RST);

	ns->IMR_cache &=
	    ~(ISR_RXOK | ISR_RXDESC | ISR_RXERR | ISR_RXEARLY |
	      ISR_RXIDLE);
	writel(ns->IMR_cache, ns->base + IMR);

	/* touch the pci bus... */
	readl(ns->base + IMR);

	/* assumes the transmitter is already disabled and reset */
	writel(0, ns->base + RXDP_HI);
	writel(0, ns->base + RXDP);
}

/**************************************************************************
IRQ - Enable, Disable, or Force interrupts
***************************************************************************/
static void ns83820_irq(struct nic *nic __unused, irq_action_t action __unused)
{
  switch ( action ) {
  case DISABLE :
    break;
  case ENABLE :
    break;
  case FORCE :
    break;
  }
}

static struct nic_operations ns83820_operations = {
	.connect	= dummy_connect,
	.poll		= ns83820_poll,
	.transmit	= ns83820_transmit,
	.irq		= ns83820_irq,

};

static struct pci_device_id ns83820_nics[] = {
	PCI_ROM(0x100b, 0x0022, "ns83820", "National Semiconductor 83820", 0),
};

PCI_DRIVER ( ns83820_driver, ns83820_nics, PCI_NO_CLASS );

/**************************************************************************
PROBE - Look for an adapter, this routine's visible to the outside
***************************************************************************/

#define board_found 1
#define valid_link 0
static int ns83820_probe ( struct nic *nic, struct pci_device *pci ) {

	long addr;
	int using_dac = 0;

	if (pci->ioaddr == 0)
		return 0;

	printf("ns83820.c: Found %s, vendor=0x%hX, device=0x%hX\n",
	       pci->id->name, pci->vendor, pci->device);

	/* point to private storage */
	ns = &nsx;

	adjust_pci_device(pci);

	addr = pci_bar_start(pci, PCI_BASE_ADDRESS_1);

	ns->base = ioremap(addr, (1UL << 12));

	if (!ns->base)
		return 0;

	nic->irqno  = 0;
	nic->ioaddr = pci->ioaddr & ~3;

	/* disable interrupts */
	writel(0, ns->base + IMR);
	writel(0, ns->base + IER);
	readl(ns->base + IER);

	ns->IMR_cache = 0;

	ns83820_do_reset(nic, CR_RST);

	/* Must reset the ram bist before running it */
	writel(PTSCR_RBIST_RST, ns->base + PTSCR);
	ns83820_run_bist(nic, "sram bist", PTSCR_RBIST_EN,
			 PTSCR_RBIST_DONE, PTSCR_RBIST_FAIL);
	ns83820_run_bist(nic, "eeprom bist", PTSCR_EEBIST_EN, 0,
			 PTSCR_EEBIST_FAIL);
	ns83820_run_bist(nic, "eeprom load", PTSCR_EELOAD_EN, 0, 0);

	/* I love config registers */
	ns->CFG_cache = readl(ns->base + CFG);

	if ((ns->CFG_cache & CFG_PCI64_DET)) {
		printf("%s: detected 64 bit PCI data bus.\n", pci->id->name);
		/*dev->CFG_cache |= CFG_DATA64_EN; */
		if (!(ns->CFG_cache & CFG_DATA64_EN))
			printf
			    ("%s: EEPROM did not enable 64 bit bus.  Disabled.\n",
			     pci->id->name);
	} else
		ns->CFG_cache &= ~(CFG_DATA64_EN);

	ns->CFG_cache &= (CFG_TBI_EN | CFG_MRM_DIS | CFG_MWI_DIS |
			  CFG_T64ADDR | CFG_DATA64_EN | CFG_EXT_125 |
			  CFG_M64ADDR);
	ns->CFG_cache |=
	    CFG_PINT_DUPSTS | CFG_PINT_LNKSTS | CFG_PINT_SPDSTS |
	    CFG_EXTSTS_EN | CFG_EXD | CFG_PESEL;
	ns->CFG_cache |= CFG_REQALG;
	ns->CFG_cache |= CFG_POW;
	ns->CFG_cache |= CFG_TMRTEST;

	/* When compiled with 64 bit addressing, we must always enable
	 * the 64 bit descriptor format.
	 */
#ifdef USE_64BIT_ADDR
	ns->CFG_cache |= CFG_M64ADDR;
#endif

//FIXME: Enable section on dac or remove this
	if (using_dac)
		ns->CFG_cache |= CFG_T64ADDR;

	/* Big endian mode does not seem to do what the docs suggest */
	ns->CFG_cache &= ~CFG_BEM;

	/* setup optical transceiver if we have one */
	if (ns->CFG_cache & CFG_TBI_EN) {
		DBG("%s: enabling optical transceiver\n", pci->id->name);
		writel(readl(ns->base + GPIOR) | 0x3e8, ns->base + GPIOR);

		/* setup auto negotiation feature advertisement */
		writel(readl(ns->base + TANAR)
		       | TANAR_HALF_DUP | TANAR_FULL_DUP,
		       ns->base + TANAR);

		/* start auto negotiation */
		writel(TBICR_MR_AN_ENABLE | TBICR_MR_RESTART_AN,
		       ns->base + TBICR);
		writel(TBICR_MR_AN_ENABLE, ns->base + TBICR);
		ns->linkstate = LINK_AUTONEGOTIATE;

		ns->CFG_cache |= CFG_MODE_1000;
	}
	writel(ns->CFG_cache, ns->base + CFG);
	DBG("CFG: %hX\n", ns->CFG_cache);

	/* FIXME: reset_phy is defaulted to 0, should we reset anyway? */
	if (reset_phy) {
		DBG("%s: resetting phy\n", pci->id->name);
		writel(ns->CFG_cache | CFG_PHY_RST, ns->base + CFG);
		writel(ns->CFG_cache, ns->base + CFG);
	}
#if 0				/* Huh?  This sets the PCI latency register.  Should be done via 
				 * the PCI layer.  FIXME.
				 */
	if (readl(dev->base + SRR))
		writel(readl(dev->base + 0x20c) | 0xfe00,
		       dev->base + 0x20c);
#endif

	/* Note!  The DMA burst size interacts with packet
	 * transmission, such that the largest packet that
	 * can be transmitted is 8192 - FLTH - burst size.
	 * If only the transmit fifo was larger...
	 */
	/* Ramit : 1024 DMA is not a good idea, it ends up banging 
	 * some DELL and COMPAQ SMP systems */
	writel(TXCFG_CSI | TXCFG_HBI | TXCFG_ATP | TXCFG_MXDMA512
	       | ((1600 / 32) * 0x100), ns->base + TXCFG);

	/* Set Rx to full duplex, don't accept runt, errored, long or length
	 * range errored packets.  Use 512 byte DMA.
	 */
	/* Ramit : 1024 DMA is not a good idea, it ends up banging 
	 * some DELL and COMPAQ SMP systems 
	 * Turn on ALP, only we are accpeting Jumbo Packets */
	writel(RXCFG_AEP | RXCFG_ARP | RXCFG_AIRL | RXCFG_RX_FD
	       | RXCFG_STRIPCRC
	       //| RXCFG_ALP
	       | (RXCFG_MXDMA512) | 0, ns->base + RXCFG);

	/* Disable priority queueing */
	writel(0, ns->base + PQCR);

	/* Enable IP checksum validation and detetion of VLAN headers.
	 * Note: do not set the reject options as at least the 0x102
	 * revision of the chip does not properly accept IP fragments
	 * at least for UDP.
	 */
	/* Ramit : Be sure to turn on RXCFG_ARP if VLAN's are enabled, since
	 * the MAC it calculates the packetsize AFTER stripping the VLAN
	 * header, and if a VLAN Tagged packet of 64 bytes is received (like
	 * a ping with a VLAN header) then the card, strips the 4 byte VLAN
	 * tag and then checks the packet size, so if RXCFG_ARP is not enabled,
	 * it discrards it!.  These guys......
	 */
	writel(VRCR_IPEN | VRCR_VTDEN, ns->base + VRCR);

	/* Enable per-packet TCP/UDP/IP checksumming */
	writel(VTCR_PPCHK, ns->base + VTCR);

	/* Ramit : Enable async and sync pause frames */
//      writel(0, ns->base + PCR); 
	writel((PCR_PS_MCAST | PCR_PS_DA | PCR_PSEN | PCR_FFLO_4K |
		PCR_FFHI_8K | PCR_STLO_4 | PCR_STHI_8 | PCR_PAUSE_CNT),
	       ns->base + PCR);

	/* Disable Wake On Lan */
	writel(0, ns->base + WCSR);

	ns83820_getmac(nic, nic->node_addr);

	if (using_dac) {
		DBG("%s: using 64 bit addressing.\n", pci->id->name);
	}

	DBG("%s: DP83820 %d.%d: io=%#04lx\n",
	    pci->id->name,
	    (unsigned) readl(ns->base + SRR) >> 8,
	    (unsigned) readl(ns->base + SRR) & 0xff,
	    pci->ioaddr);

#ifdef PHY_CODE_IS_FINISHED
	ns83820_probe_phy(dev);
#endif

	ns83820_reset(nic);
	/* point to NIC specific routines */
	nic->nic_op	= &ns83820_operations;
	return 1;
}

DRIVER ( "NS83820/PCI", nic_driver, pci_driver, ns83820_driver,
	 ns83820_probe, ns83820_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
