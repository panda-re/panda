/* $Id$
 * tg3.c: Broadcom Tigon3 ethernet driver.
 *
 * Copyright (C) 2001, 2002 David S. Miller (davem@redhat.com)
 * Copyright (C) 2001, 2002 Jeff Garzik (jgarzik@mandrakesoft.com)
 * Copyright (C) 2003 Eric Biederman (ebiederman@lnxi.com)  [etherboot port]
 */

FILE_LICENCE ( GPL2_ONLY );

/* 11-13-2003	timlegge	Fix Issue with NetGear GA302T 
 * 11-18-2003   ebiederm        Generalize NetGear Fix to what the code was supposed to be.
 * 01-06-2005   Alf (Frederic Olivie) Add Dell bcm 5751 (0x1677) support
 * 04-15-2005   Martin Vogt Add Fujitsu Siemens Computer (FSC) 0x1734 bcm 5751 0x105d support
 */

#include "etherboot.h"
#include "nic.h"
#include <errno.h>
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>
#include "string.h"
#include <mii.h>
#include "tg3.h"

#define SUPPORT_COPPER_PHY  1
#define SUPPORT_FIBER_PHY   1
#define SUPPORT_LINK_REPORT 1
#define SUPPORT_PARTNO_STR  1
#define SUPPORT_PHY_STR     1

static struct tg3 tg3;

/* These numbers seem to be hard coded in the NIC firmware somehow.
 * You can't change the ring sizes, but you can change where you place
 * them in the NIC onboard memory.
 */
#define TG3_RX_RING_SIZE		512
#define TG3_DEF_RX_RING_PENDING		20	/* RX_RING_PENDING seems to be o.k. at 20 and 200 */
#define TG3_RX_RCB_RING_SIZE	1024

/*	(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705 ? \
	 512 : 1024) */
#define TG3_TX_RING_SIZE		512
#define TG3_DEF_TX_RING_PENDING		(TG3_TX_RING_SIZE - 1)

#define TG3_RX_RING_BYTES	(sizeof(struct tg3_rx_buffer_desc) * TG3_RX_RING_SIZE)
#define TG3_RX_RCB_RING_BYTES	(sizeof(struct tg3_rx_buffer_desc) * TG3_RX_RCB_RING_SIZE)

#define TG3_TX_RING_BYTES	(sizeof(struct tg3_tx_buffer_desc) * TG3_TX_RING_SIZE)
#define NEXT_TX(N)		(((N) + 1) & (TG3_TX_RING_SIZE - 1))
#define PREV_TX(N)		(((N) - 1) & (TG3_TX_RING_SIZE - 1))

#define RX_PKT_BUF_SZ		(1536 + 2 + 64)

struct eth_frame {
	uint8_t  dst_addr[ETH_ALEN];
	uint8_t  src_addr[ETH_ALEN];
	uint16_t type;
	uint8_t  data [ETH_FRAME_LEN - ETH_HLEN];
};

struct bss {
	struct tg3_rx_buffer_desc rx_std[TG3_RX_RING_SIZE];
	struct tg3_rx_buffer_desc rx_rcb[TG3_RX_RCB_RING_SIZE];
	struct tg3_tx_buffer_desc tx_ring[TG3_TX_RING_SIZE];
	struct tg3_hw_status      hw_status;
	struct tg3_hw_stats       hw_stats;
	unsigned char             rx_bufs[TG3_DEF_RX_RING_PENDING][RX_PKT_BUF_SZ];
	struct eth_frame	  tx_frame[2];
} tg3_bss __shared;

/**
 * pci_save_state - save the PCI configuration space of a device before suspending
 * @dev: - PCI device that we're dealing with
 * @buffer: - buffer to hold config space context
 *
 * @buffer must be large enough to hold the entire PCI 2.2 config space 
 * (>= 64 bytes).
 */
static int pci_save_state(struct pci_device *dev, uint32_t *buffer)
{
	int i;
	for (i = 0; i < 16; i++)
		pci_read_config_dword(dev, i * 4,&buffer[i]);
	return 0;
}

/** 
 * pci_restore_state - Restore the saved state of a PCI device
 * @dev: - PCI device that we're dealing with
 * @buffer: - saved PCI config space
 *
 */
static int pci_restore_state(struct pci_device *dev, uint32_t *buffer)
{
	int i;

	for (i = 0; i < 16; i++)
		pci_write_config_dword(dev,i * 4, buffer[i]);
	return 0;
}

static void tg3_write_indirect_reg32(uint32_t off, uint32_t val)
{
	pci_write_config_dword(tg3.pdev, TG3PCI_REG_BASE_ADDR, off);
	pci_write_config_dword(tg3.pdev, TG3PCI_REG_DATA, val);
}

#define tw32(reg,val)		tg3_write_indirect_reg32((reg),(val))
#define tw32_mailbox(reg, val)	writel(((val) & 0xffffffff), tg3.regs + (reg))
#define tw16(reg,val)		writew(((val) & 0xffff), tg3.regs + (reg))
#define tw8(reg,val)		writeb(((val) & 0xff), tg3.regs + (reg))
#define tr32(reg)		readl(tg3.regs + (reg))
#define tr16(reg)		readw(tg3.regs + (reg))
#define tr8(reg)		readb(tg3.regs + (reg))

static void tw32_carefully(uint32_t reg, uint32_t val)
{
	tw32(reg, val);
	tr32(reg);
	udelay(100);
}

static void tw32_mailbox2(uint32_t reg, uint32_t val)
{
	tw32_mailbox(reg, val);
	tr32(reg);
}

static void tg3_write_mem(uint32_t off, uint32_t val)
{
	pci_write_config_dword(tg3.pdev, TG3PCI_MEM_WIN_BASE_ADDR, off);
	pci_write_config_dword(tg3.pdev, TG3PCI_MEM_WIN_DATA, val);

	/* Always leave this as zero. */
	pci_write_config_dword(tg3.pdev, TG3PCI_MEM_WIN_BASE_ADDR, 0);
}

static void tg3_read_mem(uint32_t off, uint32_t *val)
{
	pci_write_config_dword(tg3.pdev, TG3PCI_MEM_WIN_BASE_ADDR, off);
	pci_read_config_dword(tg3.pdev, TG3PCI_MEM_WIN_DATA, val);

	/* Always leave this as zero. */
	pci_write_config_dword(tg3.pdev, TG3PCI_MEM_WIN_BASE_ADDR, 0);
}

static void tg3_disable_ints(struct tg3 *tp)
{
	tw32(TG3PCI_MISC_HOST_CTRL,
	     (tp->misc_host_ctrl | MISC_HOST_CTRL_MASK_PCI_INT));
	tw32_mailbox2(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW, 0x00000001);
}

static void tg3_switch_clocks(struct tg3 *tp)
{
	uint32_t orig_clock_ctrl, clock_ctrl;

	clock_ctrl = tr32(TG3PCI_CLOCK_CTRL);

	orig_clock_ctrl = clock_ctrl;
	clock_ctrl &= (CLOCK_CTRL_FORCE_CLKRUN | CLOCK_CTRL_CLKRUN_OENABLE | 0x1f);
	tp->pci_clock_ctrl = clock_ctrl;
	
	if ((GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705) &&
	    (!((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5750)
	       && (tp->tg3_flags & TG3_FLAG_ENABLE_ASF))) &&
		(orig_clock_ctrl & CLOCK_CTRL_44MHZ_CORE)!=0) {
		tw32_carefully(TG3PCI_CLOCK_CTRL, 
			clock_ctrl | (CLOCK_CTRL_44MHZ_CORE | CLOCK_CTRL_ALTCLK));
		tw32_carefully(TG3PCI_CLOCK_CTRL, 
			clock_ctrl | (CLOCK_CTRL_ALTCLK));
	}
	tw32_carefully(TG3PCI_CLOCK_CTRL, clock_ctrl);
}

#define PHY_BUSY_LOOPS	5000

static int tg3_readphy(struct tg3 *tp, int reg, uint32_t *val)
{
	uint32_t frame_val;
	int loops, ret;

	tw32_carefully(MAC_MI_MODE, tp->mi_mode & ~MAC_MI_MODE_AUTO_POLL);

	*val = 0xffffffff;

	frame_val  = ((PHY_ADDR << MI_COM_PHY_ADDR_SHIFT) &
		      MI_COM_PHY_ADDR_MASK);
	frame_val |= ((reg << MI_COM_REG_ADDR_SHIFT) &
		      MI_COM_REG_ADDR_MASK);
	frame_val |= (MI_COM_CMD_READ | MI_COM_START);
	
	tw32_carefully(MAC_MI_COM, frame_val);

	loops = PHY_BUSY_LOOPS;
	while (loops-- > 0) {
		udelay(10);
		frame_val = tr32(MAC_MI_COM);

		if ((frame_val & MI_COM_BUSY) == 0) {
			udelay(5);
			frame_val = tr32(MAC_MI_COM);
			break;
		}
	}

	ret = -EBUSY;
	if (loops > 0) {
		*val = frame_val & MI_COM_DATA_MASK;
		ret = 0;
	}

	tw32_carefully(MAC_MI_MODE, tp->mi_mode);

	return ret;
}

static int tg3_writephy(struct tg3 *tp, int reg, uint32_t val)
{
	uint32_t frame_val;
	int loops, ret;

	tw32_carefully(MAC_MI_MODE, tp->mi_mode & ~MAC_MI_MODE_AUTO_POLL);

	frame_val  = ((PHY_ADDR << MI_COM_PHY_ADDR_SHIFT) &
		      MI_COM_PHY_ADDR_MASK);
	frame_val |= ((reg << MI_COM_REG_ADDR_SHIFT) &
		      MI_COM_REG_ADDR_MASK);
	frame_val |= (val & MI_COM_DATA_MASK);
	frame_val |= (MI_COM_CMD_WRITE | MI_COM_START);
	
	tw32_carefully(MAC_MI_COM, frame_val);

	loops = PHY_BUSY_LOOPS;
	while (loops-- > 0) {
		udelay(10);
		frame_val = tr32(MAC_MI_COM);
		if ((frame_val & MI_COM_BUSY) == 0) {
			udelay(5);
			frame_val = tr32(MAC_MI_COM);
			break;
		}
	}

	ret = -EBUSY;
	if (loops > 0)
		ret = 0;

	tw32_carefully(MAC_MI_MODE, tp->mi_mode);

	return ret;
}

static int tg3_writedsp(struct tg3 *tp, uint16_t addr, uint16_t val)
{
	int err;
	err  = tg3_writephy(tp, MII_TG3_DSP_ADDRESS, addr);
	err |= tg3_writephy(tp, MII_TG3_DSP_RW_PORT, val);
	return err;
}


static void tg3_phy_set_wirespeed(struct tg3 *tp)
{
	uint32_t val;

	if (tp->tg3_flags2 & TG3_FLG2_NO_ETH_WIRE_SPEED)
		return;

	tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x7007);
	tg3_readphy(tp, MII_TG3_AUX_CTRL, &val);
	tg3_writephy(tp, MII_TG3_AUX_CTRL, (val | (1 << 15) | (1 << 4)));
}

static int tg3_bmcr_reset(struct tg3 *tp)
{
	uint32_t phy_control;
	int limit, err;

	/* OK, reset it, and poll the BMCR_RESET bit until it
	 * clears or we time out.
	 */
	phy_control = BMCR_RESET;
	err = tg3_writephy(tp, MII_BMCR, phy_control);
	if (err != 0)
		return -EBUSY;

	limit = 5000;
	while (limit--) {
		err = tg3_readphy(tp, MII_BMCR, &phy_control);
		if (err != 0)
			return -EBUSY;

		if ((phy_control & BMCR_RESET) == 0) {
			udelay(40);
			break;
		}
		udelay(10);
	}
	if (limit <= 0)
		return -EBUSY;

	return 0;
}

static int tg3_wait_macro_done(struct tg3 *tp)
{
	int limit = 100;

	while (limit--) {
		uint32_t tmp32;

		tg3_readphy(tp, 0x16, &tmp32);
		if ((tmp32 & 0x1000) == 0)
			break;
	}
	if (limit <= 0)
		return -EBUSY;

	return 0;
}

static int tg3_phy_write_and_check_testpat(struct tg3 *tp, int *resetp)
{
	static const uint32_t test_pat[4][6] = {
	{ 0x00005555, 0x00000005, 0x00002aaa, 0x0000000a, 0x00003456, 0x00000003 },
	{ 0x00002aaa, 0x0000000a, 0x00003333, 0x00000003, 0x0000789a, 0x00000005 },
	{ 0x00005a5a, 0x00000005, 0x00002a6a, 0x0000000a, 0x00001bcd, 0x00000003 },
	{ 0x00002a5a, 0x0000000a, 0x000033c3, 0x00000003, 0x00002ef1, 0x00000005 }
	};
	int chan;

	for (chan = 0; chan < 4; chan++) {
		int i;

		tg3_writephy(tp, MII_TG3_DSP_ADDRESS,
			(chan * 0x2000) | 0x0200);
		tg3_writephy(tp, 0x16, 0x0002);

		for (i = 0; i < 6; i++)
			tg3_writephy(tp, MII_TG3_DSP_RW_PORT,
				test_pat[chan][i]);

		tg3_writephy(tp, 0x16, 0x0202);
		if (tg3_wait_macro_done(tp)) {
			*resetp = 1;
			return -EBUSY;
		}

		tg3_writephy(tp, MII_TG3_DSP_ADDRESS,
			     (chan * 0x2000) | 0x0200);
		tg3_writephy(tp, 0x16, 0x0082);
		if (tg3_wait_macro_done(tp)) {
			*resetp = 1;
			return -EBUSY;
		}

		tg3_writephy(tp, 0x16, 0x0802);
		if (tg3_wait_macro_done(tp)) {
			*resetp = 1;
			return -EBUSY;
		}

		for (i = 0; i < 6; i += 2) {
			uint32_t low, high;

			tg3_readphy(tp, MII_TG3_DSP_RW_PORT, &low);
			tg3_readphy(tp, MII_TG3_DSP_RW_PORT, &high);
			if (tg3_wait_macro_done(tp)) {
				*resetp = 1;
				return -EBUSY;
			}
			low &= 0x7fff;
			high &= 0x000f;
			if (low != test_pat[chan][i] ||
			    high != test_pat[chan][i+1]) {
				tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x000b);
				tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x4001);
				tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x4005);

				return -EBUSY;
			}
		}
	}

	return 0;
}

static int tg3_phy_reset_chanpat(struct tg3 *tp)
{
	int chan;

	for (chan = 0; chan < 4; chan++) {
		int i;

		tg3_writephy(tp, MII_TG3_DSP_ADDRESS,
			     (chan * 0x2000) | 0x0200);
		tg3_writephy(tp, 0x16, 0x0002);
		for (i = 0; i < 6; i++)
			tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x000);
		tg3_writephy(tp, 0x16, 0x0202);
		if (tg3_wait_macro_done(tp))
			return -EBUSY;
	}

	return 0;
}

static int tg3_phy_reset_5703_4_5(struct tg3 *tp)
{
	uint32_t reg32, phy9_orig;
	int retries, do_phy_reset, err;

	retries = 10;
	do_phy_reset = 1;
	do {
		if (do_phy_reset) {
			err = tg3_bmcr_reset(tp);
			if (err)
				return err;
			do_phy_reset = 0;
		}
		
		/* Disable transmitter and interrupt.  */
		tg3_readphy(tp, MII_TG3_EXT_CTRL, &reg32);
		reg32 |= 0x3000;
		tg3_writephy(tp, MII_TG3_EXT_CTRL, reg32);

		/* Set full-duplex, 1000 mbps.  */
		tg3_writephy(tp, MII_BMCR,
			BMCR_FULLDPLX | TG3_BMCR_SPEED1000);

		/* Set to master mode.  */
		tg3_readphy(tp, MII_TG3_CTRL, &phy9_orig);
		tg3_writephy(tp, MII_TG3_CTRL,
			(MII_TG3_CTRL_AS_MASTER |
				MII_TG3_CTRL_ENABLE_AS_MASTER));

		/* Enable SM_DSP_CLOCK and 6dB.  */
		tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x0c00);

		/* Block the PHY control access.  */
		tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x8005);
		tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x0800);

		err = tg3_phy_write_and_check_testpat(tp, &do_phy_reset);
		if (!err)
			break;
	} while (--retries);

	err = tg3_phy_reset_chanpat(tp);
	if (err)
		return err;

	tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x8005);
	tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x0000);

	tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x8200);
	tg3_writephy(tp, 0x16, 0x0000);

	tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x0400);

	tg3_writephy(tp, MII_TG3_CTRL, phy9_orig);

	tg3_readphy(tp, MII_TG3_EXT_CTRL, &reg32);
	reg32 &= ~0x3000;
	tg3_writephy(tp, MII_TG3_EXT_CTRL, reg32);

	return err;
}

/* This will reset the tigon3 PHY if there is no valid
 * link.
 */
static int tg3_phy_reset(struct tg3 *tp)
{
	uint32_t phy_status;
	int err;

	err  = tg3_readphy(tp, MII_BMSR, &phy_status);
	err |= tg3_readphy(tp, MII_BMSR, &phy_status);
	if (err != 0)
		return -EBUSY;

	if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703) ||
		(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) ||
		(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705)) {
		err = tg3_phy_reset_5703_4_5(tp);
		if (err)
			return err;
		goto out;
	}
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5750) {
	  // Taken from Broadcom's source code
	  tg3_writephy(tp, 0x18, 0x0c00);
	  tg3_writephy(tp, 0x17, 0x000a);
	  tg3_writephy(tp, 0x15, 0x310b);
	  tg3_writephy(tp, 0x17, 0x201f);
	  tg3_writephy(tp, 0x15, 0x9506);
	  tg3_writephy(tp, 0x17, 0x401f);
	  tg3_writephy(tp, 0x15, 0x14e2);
	  tg3_writephy(tp, 0x18, 0x0400);
	}
	err = tg3_bmcr_reset(tp);
	if (err)
		return err;
 out:
	tg3_phy_set_wirespeed(tp);
	return 0;
}

static void tg3_set_power_state_0(struct tg3 *tp)
{
	uint16_t power_control;
	int pm = tp->pm_cap;

	/* Make sure register accesses (indirect or otherwise)
	 * will function correctly.
	 */
	pci_write_config_dword(tp->pdev,  TG3PCI_MISC_HOST_CTRL, tp->misc_host_ctrl);

	pci_read_config_word(tp->pdev, pm + PCI_PM_CTRL, &power_control);

	power_control |= PCI_PM_CTRL_PME_STATUS;
	power_control &= ~(PCI_PM_CTRL_STATE_MASK);
	power_control |= 0;
	pci_write_config_word(tp->pdev, pm + PCI_PM_CTRL, power_control);

	tw32_carefully(GRC_LOCAL_CTRL, tp->grc_local_ctrl);

	return;
}


#if SUPPORT_LINK_REPORT
static void tg3_link_report(struct tg3 *tp)
{
	if (!tp->carrier_ok) {
		printf("Link is down.\n");
	} else {
		printf("Link is up at %d Mbps, %s duplex. %s %s %s\n",
			(tp->link_config.active_speed == SPEED_1000 ?
			       1000 :
			(tp->link_config.active_speed == SPEED_100 ?
				100 : 10)),
			(tp->link_config.active_duplex == DUPLEX_FULL ?  
				"full" : "half"),
			(tp->tg3_flags & TG3_FLAG_TX_PAUSE) ? "TX" : "",
			(tp->tg3_flags & TG3_FLAG_RX_PAUSE) ? "RX" : "",
			(tp->tg3_flags & (TG3_FLAG_TX_PAUSE |TG3_FLAG_RX_PAUSE)) ? "flow control" : "");
	}
}
#else
#define tg3_link_report(tp)
#endif

static void tg3_setup_flow_control(struct tg3 *tp, uint32_t local_adv, uint32_t remote_adv)
{
	uint32_t new_tg3_flags = 0;

	if (local_adv & ADVERTISE_PAUSE_CAP) {
		if (local_adv & ADVERTISE_PAUSE_ASYM) {
			if (remote_adv & LPA_PAUSE_CAP)
				new_tg3_flags |=
					(TG3_FLAG_RX_PAUSE |
					 TG3_FLAG_TX_PAUSE);
			else if (remote_adv & LPA_PAUSE_ASYM)
				new_tg3_flags |=
					(TG3_FLAG_RX_PAUSE);
		} else {
			if (remote_adv & LPA_PAUSE_CAP)
				new_tg3_flags |=
					(TG3_FLAG_RX_PAUSE |
					 TG3_FLAG_TX_PAUSE);
		}
	} else if (local_adv & ADVERTISE_PAUSE_ASYM) {
		if ((remote_adv & LPA_PAUSE_CAP) &&
		    (remote_adv & LPA_PAUSE_ASYM))
			new_tg3_flags |= TG3_FLAG_TX_PAUSE;
	}

	tp->tg3_flags &= ~(TG3_FLAG_RX_PAUSE | TG3_FLAG_TX_PAUSE);
	tp->tg3_flags |= new_tg3_flags;

	if (new_tg3_flags & TG3_FLAG_RX_PAUSE)
		tp->rx_mode |= RX_MODE_FLOW_CTRL_ENABLE;
	else
		tp->rx_mode &= ~RX_MODE_FLOW_CTRL_ENABLE;

	if (new_tg3_flags & TG3_FLAG_TX_PAUSE)
		tp->tx_mode |= TX_MODE_FLOW_CTRL_ENABLE;
	else
		tp->tx_mode &= ~TX_MODE_FLOW_CTRL_ENABLE;
}

#if SUPPORT_COPPER_PHY
static void tg3_aux_stat_to_speed_duplex(
	struct tg3 *tp __unused, uint32_t val, uint8_t *speed, uint8_t *duplex)
{
	static const uint8_t map[] = {
		[0] = (SPEED_INVALID << 2) | DUPLEX_INVALID,
		[MII_TG3_AUX_STAT_10HALF >> 8]   = (SPEED_10 << 2) | DUPLEX_HALF,
		[MII_TG3_AUX_STAT_10FULL >> 8]   = (SPEED_10 << 2) | DUPLEX_FULL,
		[MII_TG3_AUX_STAT_100HALF >> 8]  = (SPEED_100 << 2) | DUPLEX_HALF,
		[MII_TG3_AUX_STAT_100_4 >> 8] = (SPEED_INVALID << 2) | DUPLEX_INVALID,
		[MII_TG3_AUX_STAT_100FULL >> 8]  = (SPEED_100 << 2) | DUPLEX_FULL,
		[MII_TG3_AUX_STAT_1000HALF >> 8] = (SPEED_1000 << 2) | DUPLEX_HALF,
		[MII_TG3_AUX_STAT_1000FULL >> 8] = (SPEED_1000 << 2) | DUPLEX_FULL,
	};
	uint8_t result;
	result = map[(val & MII_TG3_AUX_STAT_SPDMASK) >> 8];
	*speed = result >> 2;
	*duplex = result & 3;
}

static int tg3_phy_copper_begin(struct tg3 *tp)
{
	uint32_t new_adv;

	tp->link_config.advertising =
		(ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full |
			ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full |
			ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full |
			ADVERTISED_Autoneg | ADVERTISED_MII);
	
	if (tp->tg3_flags & TG3_FLAG_10_100_ONLY) {
		tp->link_config.advertising &=
			~(ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full);
	}
	
	new_adv = (ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP);
	if (tp->link_config.advertising & ADVERTISED_10baseT_Half) {
		new_adv |= ADVERTISE_10HALF;
	}
	if (tp->link_config.advertising & ADVERTISED_10baseT_Full) {
		new_adv |= ADVERTISE_10FULL;
	}
	if (tp->link_config.advertising & ADVERTISED_100baseT_Half) {
		new_adv |= ADVERTISE_100HALF;
	}
	if (tp->link_config.advertising & ADVERTISED_100baseT_Full) {
		new_adv |= ADVERTISE_100FULL;
	}
	tg3_writephy(tp, MII_ADVERTISE, new_adv);
	
	if (tp->link_config.advertising &
		(ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full)) {
		new_adv = 0;
		if (tp->link_config.advertising & ADVERTISED_1000baseT_Half) {
			new_adv |= MII_TG3_CTRL_ADV_1000_HALF;
		}
		if (tp->link_config.advertising & ADVERTISED_1000baseT_Full) {
			new_adv |= MII_TG3_CTRL_ADV_1000_FULL;
		}
		if (!(tp->tg3_flags & TG3_FLAG_10_100_ONLY) &&
			(tp->pci_chip_rev_id == CHIPREV_ID_5701_A0 ||
				tp->pci_chip_rev_id == CHIPREV_ID_5701_B0)) {
			new_adv |= (MII_TG3_CTRL_AS_MASTER |
				MII_TG3_CTRL_ENABLE_AS_MASTER);
		}
		tg3_writephy(tp, MII_TG3_CTRL, new_adv);
	} else {
		tg3_writephy(tp, MII_TG3_CTRL, 0);
	}

	tg3_writephy(tp, MII_BMCR, BMCR_ANENABLE | BMCR_ANRESTART);

	return 0;
}

static int tg3_init_5401phy_dsp(struct tg3 *tp)
{
	int err;

	/* Turn off tap power management. */
	err  = tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x0c20);
	
	err |= tg3_writedsp(tp, 0x0012, 0x1804);
	err |= tg3_writedsp(tp, 0x0013, 0x1204);
	err |= tg3_writedsp(tp, 0x8006, 0x0132);
	err |= tg3_writedsp(tp, 0x8006, 0x0232);
	err |= tg3_writedsp(tp, 0x201f, 0x0a20);

	udelay(40);

	return err;
}

static int tg3_setup_copper_phy(struct tg3 *tp)
{
	int current_link_up;
	uint32_t bmsr, dummy;
	int i, err;

	tw32_carefully(MAC_STATUS,
		(MAC_STATUS_SYNC_CHANGED | MAC_STATUS_CFG_CHANGED
		 | MAC_STATUS_LNKSTATE_CHANGED));

	tp->mi_mode = MAC_MI_MODE_BASE;
	tw32_carefully(MAC_MI_MODE, tp->mi_mode);

	tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x02);

	/* Some third-party PHYs need to be reset on link going
	 * down.
	 */
	if (	(	(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703) ||
			(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) ||
			(tp->pci_chip_rev_id == CHIPREV_ID_5705_A0)) &&
		(tp->carrier_ok)) {
		tg3_readphy(tp, MII_BMSR, &bmsr);
		tg3_readphy(tp, MII_BMSR, &bmsr);
		if (!(bmsr & BMSR_LSTATUS))
			tg3_phy_reset(tp);
	}

	if ((tp->phy_id & PHY_ID_MASK) == PHY_ID_BCM5401) {
		tg3_readphy(tp, MII_BMSR, &bmsr);
		tg3_readphy(tp, MII_BMSR, &bmsr);

		if (!(tp->tg3_flags & TG3_FLAG_INIT_COMPLETE))
			bmsr = 0;

		if (!(bmsr & BMSR_LSTATUS)) {
			err = tg3_init_5401phy_dsp(tp);
			if (err)
				return err;

			tg3_readphy(tp, MII_BMSR, &bmsr);
			for (i = 0; i < 1000; i++) {
				udelay(10);
				tg3_readphy(tp, MII_BMSR, &bmsr);
				if (bmsr & BMSR_LSTATUS) {
					udelay(40);
					break;
				}
			}

			if ((tp->phy_id & PHY_ID_REV_MASK) == PHY_REV_BCM5401_B0 &&
			    !(bmsr & BMSR_LSTATUS) &&
			    tp->link_config.active_speed == SPEED_1000) {
				err = tg3_phy_reset(tp);
				if (!err)
					err = tg3_init_5401phy_dsp(tp);
				if (err)
					return err;
			}
		}
	} else if (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0 ||
		   tp->pci_chip_rev_id == CHIPREV_ID_5701_B0) {
		/* 5701 {A0,B0} CRC bug workaround */
		tg3_writephy(tp, 0x15, 0x0a75);
		tg3_writephy(tp, 0x1c, 0x8c68);
		tg3_writephy(tp, 0x1c, 0x8d68);
		tg3_writephy(tp, 0x1c, 0x8c68);
	}

	/* Clear pending interrupts... */
	tg3_readphy(tp, MII_TG3_ISTAT, &dummy);
	tg3_readphy(tp, MII_TG3_ISTAT, &dummy);

	tg3_writephy(tp, MII_TG3_IMASK, ~0);

	if (tp->led_mode == led_mode_three_link)
		tg3_writephy(tp, MII_TG3_EXT_CTRL,
			     MII_TG3_EXT_CTRL_LNK3_LED_MODE);
	else
		tg3_writephy(tp, MII_TG3_EXT_CTRL, 0);

	current_link_up = 0;

	tg3_readphy(tp, MII_BMSR, &bmsr);
	tg3_readphy(tp, MII_BMSR, &bmsr);

	if (bmsr & BMSR_LSTATUS) {
		uint32_t aux_stat, bmcr;

		tg3_readphy(tp, MII_TG3_AUX_STAT, &aux_stat);
		for (i = 0; i < 2000; i++) {
			udelay(10);
			tg3_readphy(tp, MII_TG3_AUX_STAT, &aux_stat);
			if (aux_stat)
				break;
		}

		tg3_aux_stat_to_speed_duplex(tp, aux_stat,
			&tp->link_config.active_speed,
			&tp->link_config.active_duplex);
		tg3_readphy(tp, MII_BMCR, &bmcr);
		tg3_readphy(tp, MII_BMCR, &bmcr);
		if (bmcr & BMCR_ANENABLE) {
			uint32_t gig_ctrl;
			
			current_link_up = 1;
			
			/* Force autoneg restart if we are exiting
			 * low power mode.
			 */
			tg3_readphy(tp, MII_TG3_CTRL, &gig_ctrl);
			if (!(gig_ctrl & (MII_TG3_CTRL_ADV_1000_HALF |
				      MII_TG3_CTRL_ADV_1000_FULL))) {
				current_link_up = 0;
			}
		} else {
			current_link_up = 0;
		}
	}

	if (current_link_up == 1 &&
		(tp->link_config.active_duplex == DUPLEX_FULL)) {
		uint32_t local_adv, remote_adv;

		tg3_readphy(tp, MII_ADVERTISE, &local_adv);
		local_adv &= (ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM);

		tg3_readphy(tp, MII_LPA, &remote_adv);
		remote_adv &= (LPA_PAUSE_CAP | LPA_PAUSE_ASYM);

		/* If we are not advertising full pause capability,
		 * something is wrong.  Bring the link down and reconfigure.
		 */
		if (local_adv != ADVERTISE_PAUSE_CAP) {
			current_link_up = 0;
		} else {
			tg3_setup_flow_control(tp, local_adv, remote_adv);
		}
	}

	if (current_link_up == 0) {
		uint32_t tmp;

		tg3_phy_copper_begin(tp);

		tg3_readphy(tp, MII_BMSR, &tmp);
		tg3_readphy(tp, MII_BMSR, &tmp);
		if (tmp & BMSR_LSTATUS)
			current_link_up = 1;
	}

	tp->mac_mode &= ~MAC_MODE_PORT_MODE_MASK;
	if (current_link_up == 1) {
		if (tp->link_config.active_speed == SPEED_100 ||
		    tp->link_config.active_speed == SPEED_10)
			tp->mac_mode |= MAC_MODE_PORT_MODE_MII;
		else
			tp->mac_mode |= MAC_MODE_PORT_MODE_GMII;
	} else
		tp->mac_mode |= MAC_MODE_PORT_MODE_GMII;

	tp->mac_mode &= ~MAC_MODE_HALF_DUPLEX;
	if (tp->link_config.active_duplex == DUPLEX_HALF)
		tp->mac_mode |= MAC_MODE_HALF_DUPLEX;

	tp->mac_mode &= ~MAC_MODE_LINK_POLARITY;
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700) {
		if ((tp->led_mode == led_mode_link10) ||
		    (current_link_up == 1 &&
		     tp->link_config.active_speed == SPEED_10))
			tp->mac_mode |= MAC_MODE_LINK_POLARITY;
	} else {
		if (current_link_up == 1)
			tp->mac_mode |= MAC_MODE_LINK_POLARITY;
		tw32(MAC_LED_CTRL, LED_CTRL_PHY_MODE_1);
	}

	/* ??? Without this setting Netgear GA302T PHY does not
	 * ??? send/receive packets...
	 * With this other PHYs cannot bring up the link
	 */
	if ((tp->phy_id & PHY_ID_MASK) == PHY_ID_BCM5411 &&
		tp->pci_chip_rev_id == CHIPREV_ID_5700_ALTIMA) {
		tp->mi_mode |= MAC_MI_MODE_AUTO_POLL;
		tw32_carefully(MAC_MI_MODE, tp->mi_mode);
	}

	tw32_carefully(MAC_MODE, tp->mac_mode);

	/* Link change polled. */
	tw32_carefully(MAC_EVENT, 0);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 &&
	    current_link_up == 1 &&
	    tp->link_config.active_speed == SPEED_1000 &&
	    ((tp->tg3_flags & TG3_FLAG_PCIX_MODE) ||
	     (tp->tg3_flags & TG3_FLAG_PCI_HIGH_SPEED))) {
		udelay(120);
		tw32_carefully(MAC_STATUS,
			(MAC_STATUS_SYNC_CHANGED | MAC_STATUS_CFG_CHANGED));
		tg3_write_mem(
			      NIC_SRAM_FIRMWARE_MBOX,
			      NIC_SRAM_FIRMWARE_MBOX_MAGIC2);
	}

	if (current_link_up != tp->carrier_ok) {
		tp->carrier_ok = current_link_up;
		tg3_link_report(tp);
	}

	return 0;
}
#else
#define tg3_setup_copper_phy(TP) (-EINVAL)
#endif /* SUPPORT_COPPER_PHY */

#if SUPPORT_FIBER_PHY
struct tg3_fiber_aneginfo {
	int state;
#define ANEG_STATE_UNKNOWN		0
#define ANEG_STATE_AN_ENABLE		1
#define ANEG_STATE_RESTART_INIT		2
#define ANEG_STATE_RESTART		3
#define ANEG_STATE_DISABLE_LINK_OK	4
#define ANEG_STATE_ABILITY_DETECT_INIT	5
#define ANEG_STATE_ABILITY_DETECT	6
#define ANEG_STATE_ACK_DETECT_INIT	7
#define ANEG_STATE_ACK_DETECT		8
#define ANEG_STATE_COMPLETE_ACK_INIT	9
#define ANEG_STATE_COMPLETE_ACK		10
#define ANEG_STATE_IDLE_DETECT_INIT	11
#define ANEG_STATE_IDLE_DETECT		12
#define ANEG_STATE_LINK_OK		13
#define ANEG_STATE_NEXT_PAGE_WAIT_INIT	14
#define ANEG_STATE_NEXT_PAGE_WAIT	15

	uint32_t flags;
#define MR_AN_ENABLE		0x00000001
#define MR_RESTART_AN		0x00000002
#define MR_AN_COMPLETE		0x00000004
#define MR_PAGE_RX		0x00000008
#define MR_NP_LOADED		0x00000010
#define MR_TOGGLE_TX		0x00000020
#define MR_LP_ADV_FULL_DUPLEX	0x00000040
#define MR_LP_ADV_HALF_DUPLEX	0x00000080
#define MR_LP_ADV_SYM_PAUSE	0x00000100
#define MR_LP_ADV_ASYM_PAUSE	0x00000200
#define MR_LP_ADV_REMOTE_FAULT1	0x00000400
#define MR_LP_ADV_REMOTE_FAULT2	0x00000800
#define MR_LP_ADV_NEXT_PAGE	0x00001000
#define MR_TOGGLE_RX		0x00002000
#define MR_NP_RX		0x00004000

#define MR_LINK_OK		0x80000000

	unsigned long link_time, cur_time;

	uint32_t ability_match_cfg;
	int ability_match_count;

	char ability_match, idle_match, ack_match;

	uint32_t txconfig, rxconfig;
#define ANEG_CFG_NP		0x00000080
#define ANEG_CFG_ACK		0x00000040
#define ANEG_CFG_RF2		0x00000020
#define ANEG_CFG_RF1		0x00000010
#define ANEG_CFG_PS2		0x00000001
#define ANEG_CFG_PS1		0x00008000
#define ANEG_CFG_HD		0x00004000
#define ANEG_CFG_FD		0x00002000
#define ANEG_CFG_INVAL		0x00001f06

};
#define ANEG_OK		0
#define ANEG_DONE	1
#define ANEG_TIMER_ENAB	2
#define ANEG_FAILED	-1

#define ANEG_STATE_SETTLE_TIME	10000

static int tg3_fiber_aneg_smachine(struct tg3 *tp,
				   struct tg3_fiber_aneginfo *ap)
{
	unsigned long delta;
	uint32_t rx_cfg_reg;
	int ret;

	if (ap->state == ANEG_STATE_UNKNOWN) {
		ap->rxconfig = 0;
		ap->link_time = 0;
		ap->cur_time = 0;
		ap->ability_match_cfg = 0;
		ap->ability_match_count = 0;
		ap->ability_match = 0;
		ap->idle_match = 0;
		ap->ack_match = 0;
	}
	ap->cur_time++;

	if (tr32(MAC_STATUS) & MAC_STATUS_RCVD_CFG) {
		rx_cfg_reg = tr32(MAC_RX_AUTO_NEG);

		if (rx_cfg_reg != ap->ability_match_cfg) {
			ap->ability_match_cfg = rx_cfg_reg;
			ap->ability_match = 0;
			ap->ability_match_count = 0;
		} else {
			if (++ap->ability_match_count > 1) {
				ap->ability_match = 1;
				ap->ability_match_cfg = rx_cfg_reg;
			}
		}
		if (rx_cfg_reg & ANEG_CFG_ACK)
			ap->ack_match = 1;
		else
			ap->ack_match = 0;

		ap->idle_match = 0;
	} else {
		ap->idle_match = 1;
		ap->ability_match_cfg = 0;
		ap->ability_match_count = 0;
		ap->ability_match = 0;
		ap->ack_match = 0;

		rx_cfg_reg = 0;
	}

	ap->rxconfig = rx_cfg_reg;
	ret = ANEG_OK;

	switch(ap->state) {
	case ANEG_STATE_UNKNOWN:
		if (ap->flags & (MR_AN_ENABLE | MR_RESTART_AN))
			ap->state = ANEG_STATE_AN_ENABLE;

		/* fallthru */
	case ANEG_STATE_AN_ENABLE:
		ap->flags &= ~(MR_AN_COMPLETE | MR_PAGE_RX);
		if (ap->flags & MR_AN_ENABLE) {
			ap->link_time = 0;
			ap->cur_time = 0;
			ap->ability_match_cfg = 0;
			ap->ability_match_count = 0;
			ap->ability_match = 0;
			ap->idle_match = 0;
			ap->ack_match = 0;

			ap->state = ANEG_STATE_RESTART_INIT;
		} else {
			ap->state = ANEG_STATE_DISABLE_LINK_OK;
		}
		break;

	case ANEG_STATE_RESTART_INIT:
		ap->link_time = ap->cur_time;
		ap->flags &= ~(MR_NP_LOADED);
		ap->txconfig = 0;
		tw32(MAC_TX_AUTO_NEG, 0);
		tp->mac_mode |= MAC_MODE_SEND_CONFIGS;
		tw32_carefully(MAC_MODE, tp->mac_mode);

		ret = ANEG_TIMER_ENAB;
		ap->state = ANEG_STATE_RESTART;

		/* fallthru */
	case ANEG_STATE_RESTART:
		delta = ap->cur_time - ap->link_time;
		if (delta > ANEG_STATE_SETTLE_TIME) {
			ap->state = ANEG_STATE_ABILITY_DETECT_INIT;
		} else {
			ret = ANEG_TIMER_ENAB;
		}
		break;

	case ANEG_STATE_DISABLE_LINK_OK:
		ret = ANEG_DONE;
		break;

	case ANEG_STATE_ABILITY_DETECT_INIT:
		ap->flags &= ~(MR_TOGGLE_TX);
		ap->txconfig = (ANEG_CFG_FD | ANEG_CFG_PS1);
		tw32(MAC_TX_AUTO_NEG, ap->txconfig);
		tp->mac_mode |= MAC_MODE_SEND_CONFIGS;
		tw32_carefully(MAC_MODE, tp->mac_mode);

		ap->state = ANEG_STATE_ABILITY_DETECT;
		break;

	case ANEG_STATE_ABILITY_DETECT:
		if (ap->ability_match != 0 && ap->rxconfig != 0) {
			ap->state = ANEG_STATE_ACK_DETECT_INIT;
		}
		break;

	case ANEG_STATE_ACK_DETECT_INIT:
		ap->txconfig |= ANEG_CFG_ACK;
		tw32(MAC_TX_AUTO_NEG, ap->txconfig);
		tp->mac_mode |= MAC_MODE_SEND_CONFIGS;
		tw32_carefully(MAC_MODE, tp->mac_mode);

		ap->state = ANEG_STATE_ACK_DETECT;

		/* fallthru */
	case ANEG_STATE_ACK_DETECT:
		if (ap->ack_match != 0) {
			if ((ap->rxconfig & ~ANEG_CFG_ACK) ==
			    (ap->ability_match_cfg & ~ANEG_CFG_ACK)) {
				ap->state = ANEG_STATE_COMPLETE_ACK_INIT;
			} else {
				ap->state = ANEG_STATE_AN_ENABLE;
			}
		} else if (ap->ability_match != 0 &&
			   ap->rxconfig == 0) {
			ap->state = ANEG_STATE_AN_ENABLE;
		}
		break;

	case ANEG_STATE_COMPLETE_ACK_INIT:
		if (ap->rxconfig & ANEG_CFG_INVAL) {
			ret = ANEG_FAILED;
			break;
		}
		ap->flags &= ~(MR_LP_ADV_FULL_DUPLEX |
			       MR_LP_ADV_HALF_DUPLEX |
			       MR_LP_ADV_SYM_PAUSE |
			       MR_LP_ADV_ASYM_PAUSE |
			       MR_LP_ADV_REMOTE_FAULT1 |
			       MR_LP_ADV_REMOTE_FAULT2 |
			       MR_LP_ADV_NEXT_PAGE |
			       MR_TOGGLE_RX |
			       MR_NP_RX);
		if (ap->rxconfig & ANEG_CFG_FD)
			ap->flags |= MR_LP_ADV_FULL_DUPLEX;
		if (ap->rxconfig & ANEG_CFG_HD)
			ap->flags |= MR_LP_ADV_HALF_DUPLEX;
		if (ap->rxconfig & ANEG_CFG_PS1)
			ap->flags |= MR_LP_ADV_SYM_PAUSE;
		if (ap->rxconfig & ANEG_CFG_PS2)
			ap->flags |= MR_LP_ADV_ASYM_PAUSE;
		if (ap->rxconfig & ANEG_CFG_RF1)
			ap->flags |= MR_LP_ADV_REMOTE_FAULT1;
		if (ap->rxconfig & ANEG_CFG_RF2)
			ap->flags |= MR_LP_ADV_REMOTE_FAULT2;
		if (ap->rxconfig & ANEG_CFG_NP)
			ap->flags |= MR_LP_ADV_NEXT_PAGE;

		ap->link_time = ap->cur_time;

		ap->flags ^= (MR_TOGGLE_TX);
		if (ap->rxconfig & 0x0008)
			ap->flags |= MR_TOGGLE_RX;
		if (ap->rxconfig & ANEG_CFG_NP)
			ap->flags |= MR_NP_RX;
		ap->flags |= MR_PAGE_RX;

		ap->state = ANEG_STATE_COMPLETE_ACK;
		ret = ANEG_TIMER_ENAB;
		break;

	case ANEG_STATE_COMPLETE_ACK:
		if (ap->ability_match != 0 &&
		    ap->rxconfig == 0) {
			ap->state = ANEG_STATE_AN_ENABLE;
			break;
		}
		delta = ap->cur_time - ap->link_time;
		if (delta > ANEG_STATE_SETTLE_TIME) {
			if (!(ap->flags & (MR_LP_ADV_NEXT_PAGE))) {
				ap->state = ANEG_STATE_IDLE_DETECT_INIT;
			} else {
				if ((ap->txconfig & ANEG_CFG_NP) == 0 &&
				    !(ap->flags & MR_NP_RX)) {
					ap->state = ANEG_STATE_IDLE_DETECT_INIT;
				} else {
					ret = ANEG_FAILED;
				}
			}
		}
		break;

	case ANEG_STATE_IDLE_DETECT_INIT:
		ap->link_time = ap->cur_time;
		tp->mac_mode &= ~MAC_MODE_SEND_CONFIGS;
		tw32_carefully(MAC_MODE, tp->mac_mode);

		ap->state = ANEG_STATE_IDLE_DETECT;
		ret = ANEG_TIMER_ENAB;
		break;

	case ANEG_STATE_IDLE_DETECT:
		if (ap->ability_match != 0 &&
		    ap->rxconfig == 0) {
			ap->state = ANEG_STATE_AN_ENABLE;
			break;
		}
		delta = ap->cur_time - ap->link_time;
		if (delta > ANEG_STATE_SETTLE_TIME) {
			/* XXX another gem from the Broadcom driver :( */
			ap->state = ANEG_STATE_LINK_OK;
		}
		break;

	case ANEG_STATE_LINK_OK:
		ap->flags |= (MR_AN_COMPLETE | MR_LINK_OK);
		ret = ANEG_DONE;
		break;

	case ANEG_STATE_NEXT_PAGE_WAIT_INIT:
		/* ??? unimplemented */
		break;

	case ANEG_STATE_NEXT_PAGE_WAIT:
		/* ??? unimplemented */
		break;

	default:
		ret = ANEG_FAILED;
		break;
	};

	return ret;
}

static int tg3_setup_fiber_phy(struct tg3 *tp)
{
	uint32_t orig_pause_cfg;
	uint16_t orig_active_speed;
	uint8_t orig_active_duplex;
	int current_link_up;
	int i;

	orig_pause_cfg =
		(tp->tg3_flags & (TG3_FLAG_RX_PAUSE |
				  TG3_FLAG_TX_PAUSE));
	orig_active_speed = tp->link_config.active_speed;
	orig_active_duplex = tp->link_config.active_duplex;

	tp->mac_mode &= ~(MAC_MODE_PORT_MODE_MASK | MAC_MODE_HALF_DUPLEX);
	tp->mac_mode |= MAC_MODE_PORT_MODE_TBI;
	tw32_carefully(MAC_MODE, tp->mac_mode);

	/* Reset when initting first time or we have a link. */
	if (!(tp->tg3_flags & TG3_FLAG_INIT_COMPLETE) ||
	    (tr32(MAC_STATUS) & MAC_STATUS_PCS_SYNCED)) {
		/* Set PLL lock range. */
		tg3_writephy(tp, 0x16, 0x8007);

		/* SW reset */
		tg3_writephy(tp, MII_BMCR, BMCR_RESET);

		/* Wait for reset to complete. */
		mdelay(5);

		/* Config mode; select PMA/Ch 1 regs. */
		tg3_writephy(tp, 0x10, 0x8411);

		/* Enable auto-lock and comdet, select txclk for tx. */
		tg3_writephy(tp, 0x11, 0x0a10);

		tg3_writephy(tp, 0x18, 0x00a0);
		tg3_writephy(tp, 0x16, 0x41ff);

		/* Assert and deassert POR. */
		tg3_writephy(tp, 0x13, 0x0400);
		udelay(40);
		tg3_writephy(tp, 0x13, 0x0000);

		tg3_writephy(tp, 0x11, 0x0a50);
		udelay(40);
		tg3_writephy(tp, 0x11, 0x0a10);

		/* Wait for signal to stabilize */
		mdelay(150);

		/* Deselect the channel register so we can read the PHYID
		 * later.
		 */
		tg3_writephy(tp, 0x10, 0x8011);
	}

	/* Disable link change interrupt.  */
	tw32_carefully(MAC_EVENT, 0);

	current_link_up = 0;
	if (tr32(MAC_STATUS) & MAC_STATUS_PCS_SYNCED) {
		if (!(tp->tg3_flags & TG3_FLAG_GOT_SERDES_FLOWCTL)) {
			struct tg3_fiber_aneginfo aninfo;
			int status = ANEG_FAILED;
			unsigned int tick;
			uint32_t tmp;

			memset(&aninfo, 0, sizeof(aninfo));
			aninfo.flags |= (MR_AN_ENABLE);

			tw32(MAC_TX_AUTO_NEG, 0);

			tmp = tp->mac_mode & ~MAC_MODE_PORT_MODE_MASK;
			tw32_carefully(MAC_MODE, tmp | MAC_MODE_PORT_MODE_GMII);

			tw32_carefully(MAC_MODE, tp->mac_mode | MAC_MODE_SEND_CONFIGS);

			aninfo.state = ANEG_STATE_UNKNOWN;
			aninfo.cur_time = 0;
			tick = 0;
			while (++tick < 195000) {
				status = tg3_fiber_aneg_smachine(tp, &aninfo);
				if (status == ANEG_DONE ||
				    status == ANEG_FAILED)
					break;

				udelay(1);
			}

			tp->mac_mode &= ~MAC_MODE_SEND_CONFIGS;
			tw32_carefully(MAC_MODE, tp->mac_mode);

			if (status == ANEG_DONE &&
			    (aninfo.flags &
			     (MR_AN_COMPLETE | MR_LINK_OK |
			      MR_LP_ADV_FULL_DUPLEX))) {
				uint32_t local_adv, remote_adv;

				local_adv = ADVERTISE_PAUSE_CAP;
				remote_adv = 0;
				if (aninfo.flags & MR_LP_ADV_SYM_PAUSE)
					remote_adv |= LPA_PAUSE_CAP;
				if (aninfo.flags & MR_LP_ADV_ASYM_PAUSE)
					remote_adv |= LPA_PAUSE_ASYM;

				tg3_setup_flow_control(tp, local_adv, remote_adv);

				tp->tg3_flags |=
					TG3_FLAG_GOT_SERDES_FLOWCTL;
				current_link_up = 1;
			}
			for (i = 0; i < 60; i++) {
				udelay(20);
				tw32_carefully(MAC_STATUS,
					(MAC_STATUS_SYNC_CHANGED | MAC_STATUS_CFG_CHANGED));
				if ((tr32(MAC_STATUS) &
				     (MAC_STATUS_SYNC_CHANGED |
				      MAC_STATUS_CFG_CHANGED)) == 0)
					break;
			}
			if (current_link_up == 0 &&
			    (tr32(MAC_STATUS) & MAC_STATUS_PCS_SYNCED)) {
				current_link_up = 1;
			}
		} else {
			/* Forcing 1000FD link up. */
			current_link_up = 1;
		}
	}

	tp->mac_mode &= ~MAC_MODE_LINK_POLARITY;
	tw32_carefully(MAC_MODE, tp->mac_mode);

	tp->hw_status->status =
		(SD_STATUS_UPDATED |
		 (tp->hw_status->status & ~SD_STATUS_LINK_CHG));

	for (i = 0; i < 100; i++) {
		udelay(20);
		tw32_carefully(MAC_STATUS,
			(MAC_STATUS_SYNC_CHANGED | MAC_STATUS_CFG_CHANGED));
		if ((tr32(MAC_STATUS) &
		     (MAC_STATUS_SYNC_CHANGED |
		      MAC_STATUS_CFG_CHANGED)) == 0)
			break;
	}

	if ((tr32(MAC_STATUS) & MAC_STATUS_PCS_SYNCED) == 0)
		current_link_up = 0;

	if (current_link_up == 1) {
		tp->link_config.active_speed = SPEED_1000;
		tp->link_config.active_duplex = DUPLEX_FULL;
	} else {
		tp->link_config.active_speed = SPEED_INVALID;
		tp->link_config.active_duplex = DUPLEX_INVALID;
	}

	if (current_link_up != tp->carrier_ok) {
		tp->carrier_ok = current_link_up;
		tg3_link_report(tp);
	} else {
		uint32_t now_pause_cfg =
			tp->tg3_flags & (TG3_FLAG_RX_PAUSE |
					 TG3_FLAG_TX_PAUSE);
		if (orig_pause_cfg != now_pause_cfg ||
		    orig_active_speed != tp->link_config.active_speed ||
		    orig_active_duplex != tp->link_config.active_duplex)
			tg3_link_report(tp);
	}

	if ((tr32(MAC_STATUS) & MAC_STATUS_PCS_SYNCED) == 0) {
		tw32_carefully(MAC_MODE, tp->mac_mode | MAC_MODE_LINK_POLARITY);
		if (tp->tg3_flags & TG3_FLAG_INIT_COMPLETE) {
			tw32_carefully(MAC_MODE, tp->mac_mode);
		}
	}

	return 0;
}
#else
#define tg3_setup_fiber_phy(TP) (-EINVAL)
#endif /* SUPPORT_FIBER_PHY */

static int tg3_setup_phy(struct tg3 *tp)
{
	int err;

	if (tp->phy_id == PHY_ID_SERDES) {
		err = tg3_setup_fiber_phy(tp);
	} else {
		err = tg3_setup_copper_phy(tp);
	}

	if (tp->link_config.active_speed == SPEED_1000 &&
	    tp->link_config.active_duplex == DUPLEX_HALF)
		tw32(MAC_TX_LENGTHS,
		     ((2 << TX_LENGTHS_IPG_CRS_SHIFT) |
		      (6 << TX_LENGTHS_IPG_SHIFT) |
		      (0xff << TX_LENGTHS_SLOT_TIME_SHIFT)));
	else
		tw32(MAC_TX_LENGTHS,
		     ((2 << TX_LENGTHS_IPG_CRS_SHIFT) |
		      (6 << TX_LENGTHS_IPG_SHIFT) |
		      (32 << TX_LENGTHS_SLOT_TIME_SHIFT)));

	return err;
}


#define MAX_WAIT_CNT 1000

/* To stop a block, clear the enable bit and poll till it
 * clears.  
 */
static int tg3_stop_block(struct tg3 *tp, unsigned long ofs, uint32_t enable_bit)
{
	unsigned int i;
	uint32_t val;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5787) {
		switch(ofs) {
		case RCVLSC_MODE:
		case DMAC_MODE:
		case MBFREE_MODE:
		case BUFMGR_MODE:
		case MEMARB_MODE:
			/* We can't enable/disable these bits of the
			 * 5705 or 5787, just say success.
			 */
			return 0;
		default:
			break;
		}
	}
	val = tr32(ofs);
	val &= ~enable_bit;
	tw32(ofs, val);
	tr32(ofs);

	for (i = 0; i < MAX_WAIT_CNT; i++) {
		udelay(100);
		val = tr32(ofs);
		if ((val & enable_bit) == 0)
			break;
	}

	if (i == MAX_WAIT_CNT) {
		printf( "tg3_stop_block timed out, ofs=%#lx enable_bit=%3x\n",
		       ofs, enable_bit );
		return -ENODEV;
	}

	return 0;
}

static int tg3_abort_hw(struct tg3 *tp)
{
	int i, err;
	uint32_t val;

	tg3_disable_ints(tp);

	tp->rx_mode &= ~RX_MODE_ENABLE;
	tw32_carefully(MAC_RX_MODE, tp->rx_mode);

	err  = tg3_stop_block(tp, RCVBDI_MODE,   RCVBDI_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVLPC_MODE,   RCVLPC_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVLSC_MODE,   RCVLSC_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVDBDI_MODE,  RCVDBDI_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVDCC_MODE,   RCVDCC_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVCC_MODE,    RCVCC_MODE_ENABLE);

	err |= tg3_stop_block(tp, SNDBDS_MODE,   SNDBDS_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDBDI_MODE,   SNDBDI_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDDATAI_MODE, SNDDATAI_MODE_ENABLE);
	err |= tg3_stop_block(tp, RDMAC_MODE,    RDMAC_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDDATAC_MODE, SNDDATAC_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDBDC_MODE,   SNDBDC_MODE_ENABLE);
	if (err)
		goto out;

	tp->mac_mode &= ~MAC_MODE_TDE_ENABLE;
	tw32_carefully(MAC_MODE, tp->mac_mode);

	tp->tx_mode &= ~TX_MODE_ENABLE;
	tw32_carefully(MAC_TX_MODE, tp->tx_mode);

	for (i = 0; i < MAX_WAIT_CNT; i++) {
		udelay(100);
		if (!(tr32(MAC_TX_MODE) & TX_MODE_ENABLE))
			break;
	}
	if (i >= MAX_WAIT_CNT) {
		printf("tg3_abort_hw timed out TX_MODE_ENABLE will not clear MAC_TX_MODE=%x\n",
		       (unsigned int) tr32(MAC_TX_MODE));
		return -ENODEV;
	}

	err  = tg3_stop_block(tp, HOSTCC_MODE, HOSTCC_MODE_ENABLE);
	err |= tg3_stop_block(tp, WDMAC_MODE,  WDMAC_MODE_ENABLE);
	err |= tg3_stop_block(tp, MBFREE_MODE, MBFREE_MODE_ENABLE);

	val = tr32(FTQ_RESET);
	val |= FTQ_RESET_DMA_READ_QUEUE | FTQ_RESET_DMA_HIGH_PRI_READ |
	       FTQ_RESET_SEND_BD_COMPLETION | FTQ_RESET_DMA_WRITE |
	       FTQ_RESET_DMA_HIGH_PRI_WRITE | FTQ_RESET_SEND_DATA_COMPLETION |
	       FTQ_RESET_HOST_COALESCING | FTQ_RESET_MAC_TX |
	       FTQ_RESET_RX_BD_COMPLETE | FTQ_RESET_RX_LIST_PLCMT |
               FTQ_RESET_RX_DATA_COMPLETION;
	tw32(FTQ_RESET, val);

	err |= tg3_stop_block(tp, BUFMGR_MODE, BUFMGR_MODE_ENABLE);
	err |= tg3_stop_block(tp, MEMARB_MODE, MEMARB_MODE_ENABLE);
	if (err)
		goto out;

	memset(tp->hw_status, 0, TG3_HW_STATUS_SIZE);

out:
	return err;
}

static void tg3_chip_reset(struct tg3 *tp)
{
	uint32_t val;

	if (!(tp->tg3_flags2 & TG3_FLG2_SUN_5704)) {
		/* Force NVRAM to settle.
		 * This deals with a chip bug which can result in EEPROM
		 * corruption.
		 */
		if (tp->tg3_flags & TG3_FLAG_NVRAM) {
			int i;
	
			tw32(NVRAM_SWARB, SWARB_REQ_SET1);
			for (i = 0; i < 100000; i++) {
				if (tr32(NVRAM_SWARB) & SWARB_GNT1)
					break;
				udelay(10);
			}
		}
	}
	/* In Etherboot we don't need to worry about the 5701
	 * REG_WRITE_BUG because we do all register writes indirectly.
	 */

	// Alf: here patched
	/* do the reset */
	val = GRC_MISC_CFG_CORECLK_RESET;
	if (tp->tg3_flags2 & TG3_FLG2_PCI_EXPRESS) {
		if (tr32(0x7e2c) == 0x60) {
			tw32(0x7e2c, 0x20);
		}
		if (tp->pci_chip_rev_id != CHIPREV_ID_5750_A0) {
			tw32(GRC_MISC_CFG, (1 << 29));
			val |= (1 << 29);
		}
	}
	
	if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705)
	    || (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5750)
	    || (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5787)) {
		val |= GRC_MISC_CFG_KEEP_GPHY_POWER;
	}

	// Alf : Please VALIDATE THIS.
	// It is necessary in my case (5751) to prevent a reboot, but
	// I have no idea about a side effect on any other version.
	// It appears to be what's done in tigon3.c from Broadcom
	if (tp->pci_chip_rev_id != CHIPREV_ID_5750_A0) {
	  tw32(GRC_MISC_CFG, 0x20000000) ;
	  val |= 0x20000000 ;
	}

	tw32(GRC_MISC_CFG, val);

	/* Flush PCI posted writes.  The normal MMIO registers
	 * are inaccessible at this time so this is the only
	 * way to make this reliably.  I tried to use indirect
	 * register read/write but this upset some 5701 variants.
	 */
	pci_read_config_dword(tp->pdev, PCI_COMMAND, &val);

	udelay(120);

	/* Re-enable indirect register accesses. */
	pci_write_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL,
			       tp->misc_host_ctrl);

	/* Set MAX PCI retry to zero. */
	val = (PCISTATE_ROM_ENABLE | PCISTATE_ROM_RETRY_ENABLE);
	if (tp->pci_chip_rev_id == CHIPREV_ID_5704_A0 &&
	    (tp->tg3_flags & TG3_FLAG_PCIX_MODE))
		val |= PCISTATE_RETRY_SAME_DMA;
	pci_write_config_dword(tp->pdev, TG3PCI_PCISTATE, val);

	pci_restore_state(tp->pdev, tp->pci_cfg_state);

	/* Make sure PCI-X relaxed ordering bit is clear. */
	pci_read_config_dword(tp->pdev, TG3PCI_X_CAPS, &val);
	val &= ~PCIX_CAPS_RELAXED_ORDERING;
	pci_write_config_dword(tp->pdev, TG3PCI_X_CAPS, val);

	tw32(MEMARB_MODE, MEMARB_MODE_ENABLE);

	if (((tp->nic_sram_data_cfg & NIC_SRAM_DATA_CFG_MINI_PCI) != 0) &&
		(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705)) {
		tp->pci_clock_ctrl |=
			(CLOCK_CTRL_FORCE_CLKRUN | CLOCK_CTRL_CLKRUN_OENABLE);
		tw32(TG3PCI_CLOCK_CTRL, tp->pci_clock_ctrl);
	}

	tw32(TG3PCI_MISC_HOST_CTRL, tp->misc_host_ctrl);
}

static void tg3_stop_fw(struct tg3 *tp)
{
	if (tp->tg3_flags & TG3_FLAG_ENABLE_ASF) {
		uint32_t val;
		int i;

		tg3_write_mem(NIC_SRAM_FW_CMD_MBOX, FWCMD_NICDRV_PAUSE_FW);
		val = tr32(GRC_RX_CPU_EVENT);
		val |= (1 << 14);
		tw32(GRC_RX_CPU_EVENT, val);

		/* Wait for RX cpu to ACK the event.  */
		for (i = 0; i < 100; i++) {
			if (!(tr32(GRC_RX_CPU_EVENT) & (1 << 14)))
				break;
			udelay(1);
		}
	}
}

static int tg3_restart_fw(struct tg3 *tp, uint32_t state)
{
	uint32_t val;
	int i;
	
	tg3_write_mem(NIC_SRAM_FIRMWARE_MBOX, 
		NIC_SRAM_FIRMWARE_MBOX_MAGIC1);
	/* Wait for firmware initialization to complete. */
	for (i = 0; i < 100000; i++) {
		tg3_read_mem(NIC_SRAM_FIRMWARE_MBOX, &val);
		if (val == (uint32_t) ~NIC_SRAM_FIRMWARE_MBOX_MAGIC1)
			break;
		udelay(10);
	}
	if (i >= 100000 &&
		    !(tp->tg3_flags2 & TG3_FLG2_SUN_5704) &&
		    !(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5787)) {
		printf ( "Firmware will not restart magic=%#x\n",
			val );
		return -ENODEV;
	}
	if (!(tp->tg3_flags & TG3_FLAG_ENABLE_ASF)) {
	  state = DRV_STATE_SUSPEND;
	}

	if ((tp->tg3_flags2 & TG3_FLG2_PCI_EXPRESS) &&
	    (tp->pci_chip_rev_id != CHIPREV_ID_5750_A0)) {
	  // Enable PCIE bug fix
	  tg3_read_mem(0x7c00, &val);
	  tg3_write_mem(0x7c00, val | 0x02000000);
	}
	tg3_write_mem(NIC_SRAM_FW_DRV_STATE_MBOX, state);
	return 0;
}

static int tg3_halt(struct tg3 *tp)
{
	tg3_stop_fw(tp);
	tg3_abort_hw(tp);
	tg3_chip_reset(tp);
	return tg3_restart_fw(tp, DRV_STATE_UNLOAD);
}

static void __tg3_set_mac_addr(struct tg3 *tp)
{
	uint32_t addr_high, addr_low;
	int i;

	addr_high = ((tp->nic->node_addr[0] << 8) |
		     tp->nic->node_addr[1]);
	addr_low = ((tp->nic->node_addr[2] << 24) |
		    (tp->nic->node_addr[3] << 16) |
		    (tp->nic->node_addr[4] <<  8) |
		    (tp->nic->node_addr[5] <<  0));
	for (i = 0; i < 4; i++) {
		tw32(MAC_ADDR_0_HIGH + (i * 8), addr_high);
		tw32(MAC_ADDR_0_LOW + (i * 8), addr_low);
	}

	if ((GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5700) &&
		(GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5701) &&
		(GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705)) {
		for(i = 0; i < 12; i++) {
			tw32(MAC_EXTADDR_0_HIGH + (i * 8), addr_high);
			tw32(MAC_EXTADDR_0_LOW + (i * 8), addr_low);
		}
	}
	addr_high = (tp->nic->node_addr[0] +
		     tp->nic->node_addr[1] +
		     tp->nic->node_addr[2] +
		     tp->nic->node_addr[3] +
		     tp->nic->node_addr[4] +
		     tp->nic->node_addr[5]) &
		TX_BACKOFF_SEED_MASK;
	tw32(MAC_TX_BACKOFF_SEED, addr_high);
}

static void tg3_set_bdinfo(struct tg3 *tp, uint32_t bdinfo_addr,
			   dma_addr_t mapping, uint32_t maxlen_flags,
			   uint32_t nic_addr)
{
	tg3_write_mem((bdinfo_addr +
		       TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_HIGH),
		      ((uint64_t) mapping >> 32));
	tg3_write_mem((bdinfo_addr +
		       TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_LOW),
		      ((uint64_t) mapping & 0xffffffff));
	tg3_write_mem((bdinfo_addr +
		       TG3_BDINFO_MAXLEN_FLAGS),
		       maxlen_flags);
	if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705) {
		tg3_write_mem((bdinfo_addr + TG3_BDINFO_NIC_ADDR), nic_addr);
	}
}


static void tg3_init_rings(struct tg3 *tp)
{
	unsigned i;

	/* Zero out the tg3 variables */
	memset(&tg3_bss, 0, sizeof(tg3_bss));
	tp->rx_std    = &tg3_bss.rx_std[0];
	tp->rx_rcb    = &tg3_bss.rx_rcb[0];
	tp->tx_ring   = &tg3_bss.tx_ring[0];
	tp->hw_status = &tg3_bss.hw_status;
	tp->hw_stats  = &tg3_bss.hw_stats;
	tp->mac_mode  = 0;


	/* Initialize tx/rx rings for packet processing.
	 *
	 * The chip has been shut down and the driver detached from
	 * the networking, so no interrupts or new tx packets will
	 * end up in the driver.
	 */

	/* Initialize invariants of the rings, we only set this
	 * stuff once.  This works because the card does not
	 * write into the rx buffer posting rings.
	 */
	for (i = 0; i < TG3_RX_RING_SIZE; i++) {
		struct tg3_rx_buffer_desc *rxd;

		rxd = &tp->rx_std[i];
		rxd->idx_len = (RX_PKT_BUF_SZ - 2 - 64)	<< RXD_LEN_SHIFT;
		rxd->type_flags = (RXD_FLAG_END << RXD_FLAGS_SHIFT);
		rxd->opaque = (RXD_OPAQUE_RING_STD | (i << RXD_OPAQUE_INDEX_SHIFT));

		/* Note where the receive buffer for the ring is placed */
		rxd->addr_hi = 0;
		rxd->addr_lo = virt_to_bus(
			&tg3_bss.rx_bufs[i%TG3_DEF_RX_RING_PENDING][2]);
	}
}

#define TG3_WRITE_SETTINGS(TABLE) \
do { \
	const uint32_t *_table, *_end; \
	_table = TABLE; \
	_end = _table + sizeof(TABLE)/sizeof(TABLE[0]);  \
	for(; _table < _end; _table += 2) { \
		tw32(_table[0], _table[1]); \
	} \
} while(0)


/* initialize/reset the tg3 */
static int tg3_setup_hw(struct tg3 *tp)
{
	uint32_t val, rdmac_mode;
	int i, err, limit;

	/* Simply don't support setups with extremly buggy firmware in etherboot */
	if (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0) {
		printf("Error 5701_A0 firmware bug detected\n");
		return -EINVAL;
	}

	tg3_disable_ints(tp);

	/* Originally this was all in tg3_init_hw */

	/* Force the chip into D0. */
	tg3_set_power_state_0(tp);

	tg3_switch_clocks(tp);

	tw32(TG3PCI_MEM_WIN_BASE_ADDR, 0);

	// This should go somewhere else
#define T3_PCIE_CAPABILITY_ID_REG           0xD0
#define T3_PCIE_CAPABILITY_ID               0x10
#define T3_PCIE_CAPABILITY_REG              0xD2

	/* Originally this was all in tg3_reset_hw */

	tg3_stop_fw(tp);

	/* No need to call tg3_abort_hw here, it is called before tg3_setup_hw. */

	tg3_chip_reset(tp);

	tw32(GRC_MODE, tp->grc_mode);  /* Redundant? */

	err = tg3_restart_fw(tp, DRV_STATE_START);
	if (err)
		return err;

	if (tp->phy_id == PHY_ID_SERDES) {
		tp->mac_mode = MAC_MODE_PORT_MODE_TBI;
	}
	tw32_carefully(MAC_MODE, tp->mac_mode);


	/* This works around an issue with Athlon chipsets on
	 * B3 tigon3 silicon.  This bit has no effect on any
	 * other revision.
	 * Alf: Except 5750 ! (which reboots)
	 */

        if (!(tp->tg3_flags2 & TG3_FLG2_PCI_EXPRESS))
	  tp->pci_clock_ctrl |= CLOCK_CTRL_DELAY_PCI_GRANT;
	tw32_carefully(TG3PCI_CLOCK_CTRL, tp->pci_clock_ctrl);

	if (tp->pci_chip_rev_id == CHIPREV_ID_5704_A0 &&
	    (tp->tg3_flags & TG3_FLAG_PCIX_MODE)) {
		val = tr32(TG3PCI_PCISTATE);
		val |= PCISTATE_RETRY_SAME_DMA;
		tw32(TG3PCI_PCISTATE, val);
	}

	/* Descriptor ring init may make accesses to the
	 * NIC SRAM area to setup the TX descriptors, so we
	 * can only do this after the hardware has been
	 * successfully reset.
	 */
	tg3_init_rings(tp);

	/* Clear statistics/status block in chip */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705) {
		for (i = NIC_SRAM_STATS_BLK;
		     i < NIC_SRAM_STATUS_BLK + TG3_HW_STATUS_SIZE;
		     i += sizeof(uint32_t)) {
			tg3_write_mem(i, 0);
			udelay(40);
		}
	}

	/* This value is determined during the probe time DMA
	 * engine test, tg3_setup_dma.
	 */
	tw32(TG3PCI_DMA_RW_CTRL, tp->dma_rwctrl);

	tp->grc_mode &= ~(GRC_MODE_HOST_SENDBDS |
			  GRC_MODE_4X_NIC_SEND_RINGS |
			  GRC_MODE_NO_TX_PHDR_CSUM |
			  GRC_MODE_NO_RX_PHDR_CSUM);
	tp->grc_mode |= GRC_MODE_HOST_SENDBDS;
	tp->grc_mode |= GRC_MODE_NO_TX_PHDR_CSUM;
	tp->grc_mode |= GRC_MODE_NO_RX_PHDR_CSUM;

	tw32(GRC_MODE,
		tp->grc_mode | 
		(GRC_MODE_IRQ_ON_MAC_ATTN | GRC_MODE_HOST_STACKUP));

	/* Setup the timer prescalar register.  Clock is always 66Mhz. */
	tw32(GRC_MISC_CFG,
	     (65 << GRC_MISC_CFG_PRESCALAR_SHIFT));

	/* Initialize MBUF/DESC pool. */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5787) {
		/* Do nothing. */
	} else if ((GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705) &&
		(tp->pci_chip_rev_id != CHIPREV_ID_5721)) {
		tw32(BUFMGR_MB_POOL_ADDR, NIC_SRAM_MBUF_POOL_BASE);
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704)
			tw32(BUFMGR_MB_POOL_SIZE, NIC_SRAM_MBUF_POOL_SIZE64);
		else
			tw32(BUFMGR_MB_POOL_SIZE, NIC_SRAM_MBUF_POOL_SIZE96);
		tw32(BUFMGR_DMA_DESC_POOL_ADDR, NIC_SRAM_DMA_DESC_POOL_BASE);
		tw32(BUFMGR_DMA_DESC_POOL_SIZE, NIC_SRAM_DMA_DESC_POOL_SIZE);
	}
	if (!(tp->tg3_flags & TG3_FLAG_JUMBO_ENABLE)) {
		tw32(BUFMGR_MB_RDMA_LOW_WATER,
		     tp->bufmgr_config.mbuf_read_dma_low_water);
		tw32(BUFMGR_MB_MACRX_LOW_WATER,
		     tp->bufmgr_config.mbuf_mac_rx_low_water);
		tw32(BUFMGR_MB_HIGH_WATER,
		     tp->bufmgr_config.mbuf_high_water);
	} else {
		tw32(BUFMGR_MB_RDMA_LOW_WATER,
		     tp->bufmgr_config.mbuf_read_dma_low_water_jumbo);
		tw32(BUFMGR_MB_MACRX_LOW_WATER,
		     tp->bufmgr_config.mbuf_mac_rx_low_water_jumbo);
		tw32(BUFMGR_MB_HIGH_WATER,
		     tp->bufmgr_config.mbuf_high_water_jumbo);
	}
	tw32(BUFMGR_DMA_LOW_WATER,
	     tp->bufmgr_config.dma_low_water);
	tw32(BUFMGR_DMA_HIGH_WATER,
	     tp->bufmgr_config.dma_high_water);

	tw32(BUFMGR_MODE, BUFMGR_MODE_ENABLE | BUFMGR_MODE_ATTN_ENABLE);
	for (i = 0; i < 2000; i++) {
		if (tr32(BUFMGR_MODE) & BUFMGR_MODE_ENABLE)
			break;
		udelay(10);
	}
	if (i >= 2000) {
		printf("tg3_setup_hw cannot enable BUFMGR\n");
		return -ENODEV;
	}

	tw32(FTQ_RESET, 0xffffffff);
	tw32(FTQ_RESET, 0x00000000);
	for (i = 0; i < 2000; i++) {
		if (tr32(FTQ_RESET) == 0x00000000)
			break;
		udelay(10);
	}
	if (i >= 2000) {
		printf("tg3_setup_hw cannot reset FTQ\n");
		return -ENODEV;
	}

	/* Initialize TG3_BDINFO's at:
	 *  RCVDBDI_STD_BD:	standard eth size rx ring
	 *  RCVDBDI_JUMBO_BD:	jumbo frame rx ring
	 *  RCVDBDI_MINI_BD:	small frame rx ring (??? does not work)
	 *
	 * like so:
	 *  TG3_BDINFO_HOST_ADDR:	high/low parts of DMA address of ring
	 *  TG3_BDINFO_MAXLEN_FLAGS:	(rx max buffer size << 16) |
	 *                              ring attribute flags
	 *  TG3_BDINFO_NIC_ADDR:	location of descriptors in nic SRAM
	 *
	 * Standard receive ring @ NIC_SRAM_RX_BUFFER_DESC, 512 entries.
	 * Jumbo receive ring @ NIC_SRAM_RX_JUMBO_BUFFER_DESC, 256 entries.
	 *
	 * ??? No space allocated for mini receive ring? :(
	 *
	 * The size of each ring is fixed in the firmware, but the location is
	 * configurable.
	 */
	{
		static const uint32_t table_all[] = {
			/* Setup replenish thresholds. */
			RCVBDI_STD_THRESH, TG3_DEF_RX_RING_PENDING / 8,

			/* Etherboot lives below 4GB */
			RCVDBDI_STD_BD + TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_HIGH, 0,
			RCVDBDI_STD_BD + TG3_BDINFO_NIC_ADDR, NIC_SRAM_RX_BUFFER_DESC,
		};
		static const uint32_t table_not_5705[] = {
			/* Buffer maximum length */
			RCVDBDI_STD_BD + TG3_BDINFO_MAXLEN_FLAGS, RX_STD_MAX_SIZE << BDINFO_FLAGS_MAXLEN_SHIFT,
			
			/* Disable the mini frame rx ring */
			RCVDBDI_MINI_BD + TG3_BDINFO_MAXLEN_FLAGS,	BDINFO_FLAGS_DISABLED,
			
			/* Disable the jumbo frame rx ring */
			RCVBDI_JUMBO_THRESH, 0,
			RCVDBDI_JUMBO_BD + TG3_BDINFO_MAXLEN_FLAGS, BDINFO_FLAGS_DISABLED,
			
			
		};
		TG3_WRITE_SETTINGS(table_all);
		tw32(RCVDBDI_STD_BD + TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_LOW, 
			virt_to_bus(tp->rx_std));
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5787) {
			tw32(RCVDBDI_STD_BD + TG3_BDINFO_MAXLEN_FLAGS,
				RX_STD_MAX_SIZE_5705 << BDINFO_FLAGS_MAXLEN_SHIFT);
		} else {
			TG3_WRITE_SETTINGS(table_not_5705);
		}
	}

	
	/* There is only one send ring on 5705 and 5787, no need to explicitly
	 * disable the others.
	 */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705 &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5787) {
		/* Clear out send RCB ring in SRAM. */
		for (i = NIC_SRAM_SEND_RCB; i < NIC_SRAM_RCV_RET_RCB; i += TG3_BDINFO_SIZE)
			tg3_write_mem(i + TG3_BDINFO_MAXLEN_FLAGS, BDINFO_FLAGS_DISABLED);
	}

	tp->tx_prod = 0;
	tw32_mailbox(MAILBOX_SNDHOST_PROD_IDX_0 + TG3_64BIT_REG_LOW, 0);
	tw32_mailbox2(MAILBOX_SNDNIC_PROD_IDX_0 + TG3_64BIT_REG_LOW, 0);

	tg3_set_bdinfo(tp,
		NIC_SRAM_SEND_RCB,
		virt_to_bus(tp->tx_ring),
		(TG3_TX_RING_SIZE << BDINFO_FLAGS_MAXLEN_SHIFT),
		NIC_SRAM_TX_BUFFER_DESC);

	/* There is only one receive return ring on 5705 and 5787, no need to
	 * explicitly disable the others.
	 */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705 &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5787) {
		for (i = NIC_SRAM_RCV_RET_RCB; i < NIC_SRAM_STATS_BLK; i += TG3_BDINFO_SIZE) {
			tg3_write_mem(i + TG3_BDINFO_MAXLEN_FLAGS,
				BDINFO_FLAGS_DISABLED);
		}
	}

	tp->rx_rcb_ptr = 0;
	tw32_mailbox2(MAILBOX_RCVRET_CON_IDX_0 + TG3_64BIT_REG_LOW, 0);

	tg3_set_bdinfo(tp,
		NIC_SRAM_RCV_RET_RCB,
		virt_to_bus(tp->rx_rcb),
		(TG3_RX_RCB_RING_SIZE << BDINFO_FLAGS_MAXLEN_SHIFT),
		0);

	tp->rx_std_ptr = TG3_DEF_RX_RING_PENDING;
	tw32_mailbox2(MAILBOX_RCV_STD_PROD_IDX + TG3_64BIT_REG_LOW,
		     tp->rx_std_ptr);

	tw32_mailbox2(MAILBOX_RCV_JUMBO_PROD_IDX + TG3_64BIT_REG_LOW, 0);

	/* Initialize MAC address and backoff seed. */
	__tg3_set_mac_addr(tp);

	/* Calculate RDMAC_MODE setting early, we need it to determine
	 * the RCVLPC_STATE_ENABLE mask.
	 */
	rdmac_mode = (RDMAC_MODE_ENABLE | RDMAC_MODE_TGTABORT_ENAB |
		RDMAC_MODE_MSTABORT_ENAB | RDMAC_MODE_PARITYERR_ENAB |
		RDMAC_MODE_ADDROFLOW_ENAB | RDMAC_MODE_FIFOOFLOW_ENAB |
		RDMAC_MODE_FIFOURUN_ENAB | RDMAC_MODE_FIFOOREAD_ENAB |
		RDMAC_MODE_LNGREAD_ENAB);
	if (tp->tg3_flags & TG3_FLAG_SPLIT_MODE)
		rdmac_mode |= RDMAC_MODE_SPLIT_ENABLE;
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705) {
		if (tp->pci_chip_rev_id != CHIPREV_ID_5705_A0) {
			if (!(tr32(TG3PCI_PCISTATE) & PCISTATE_BUS_SPEED_HIGH) &&
				!(tp->tg3_flags2 & TG3_FLG2_IS_5788)) {
				rdmac_mode |= RDMAC_MODE_FIFO_LONG_BURST;
			}
		}
	}

	/* Setup host coalescing engine. */
	tw32(HOSTCC_MODE, 0);
	for (i = 0; i < 2000; i++) {
		if (!(tr32(HOSTCC_MODE) & HOSTCC_MODE_ENABLE))
			break;
		udelay(10);
	}

	tp->mac_mode = MAC_MODE_TXSTAT_ENABLE | MAC_MODE_RXSTAT_ENABLE |
		MAC_MODE_TDE_ENABLE | MAC_MODE_RDE_ENABLE | MAC_MODE_FHDE_ENABLE;
	tw32_carefully(MAC_MODE, tp->mac_mode | MAC_MODE_RXSTAT_CLEAR | MAC_MODE_TXSTAT_CLEAR);

	tp->grc_local_ctrl = GRC_LCLCTRL_INT_ON_ATTN | GRC_LCLCTRL_AUTO_SEEPROM;
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700)
		tp->grc_local_ctrl |= (GRC_LCLCTRL_GPIO_OE1 |
				       GRC_LCLCTRL_GPIO_OUTPUT1);
	tw32_carefully(GRC_LOCAL_CTRL, tp->grc_local_ctrl);

	tw32_mailbox(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW, 0);
	tr32(MAILBOX_INTERRUPT_0);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705) {
		tw32_carefully(DMAC_MODE, DMAC_MODE_ENABLE);
	}

	val = (	WDMAC_MODE_ENABLE | WDMAC_MODE_TGTABORT_ENAB |
		WDMAC_MODE_MSTABORT_ENAB | WDMAC_MODE_PARITYERR_ENAB |
		WDMAC_MODE_ADDROFLOW_ENAB | WDMAC_MODE_FIFOOFLOW_ENAB |
		WDMAC_MODE_FIFOURUN_ENAB | WDMAC_MODE_FIFOOREAD_ENAB |
		WDMAC_MODE_LNGREAD_ENAB);
	if ((GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705) &&
		((tr32(TG3PCI_PCISTATE) & PCISTATE_BUS_SPEED_HIGH) != 0) &&
		!(tp->tg3_flags2 & TG3_FLG2_IS_5788)) {
		val |= WDMAC_MODE_RX_ACCEL;
	}

	/* Host coalescing bug fix */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5787)
		val |= (1 << 29);

	tw32_carefully(WDMAC_MODE, val);

	if ((tp->tg3_flags & TG3_FLAG_PCIX_MODE) != 0) {
		val = tr32(TG3PCI_X_CAPS);
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703) {
			val &= PCIX_CAPS_BURST_MASK;
			val |= (PCIX_CAPS_MAX_BURST_CPIOB << PCIX_CAPS_BURST_SHIFT);
		} else if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) {
			val &= ~(PCIX_CAPS_SPLIT_MASK | PCIX_CAPS_BURST_MASK);
			val |= (PCIX_CAPS_MAX_BURST_CPIOB << PCIX_CAPS_BURST_SHIFT);
			if (tp->tg3_flags & TG3_FLAG_SPLIT_MODE)
				val |= (tp->split_mode_max_reqs <<
					PCIX_CAPS_SPLIT_SHIFT);
		}
		tw32(TG3PCI_X_CAPS, val);
	}

	tw32_carefully(RDMAC_MODE, rdmac_mode);
	{
		static const uint32_t table_all[] = {
			/* MTU + ethernet header + FCS + optional VLAN tag */
			MAC_RX_MTU_SIZE, ETH_MAX_MTU + ETH_HLEN + 8,
			
			/* The slot time is changed by tg3_setup_phy if we
			 * run at gigabit with half duplex.
			 */
			MAC_TX_LENGTHS,	
			(2 << TX_LENGTHS_IPG_CRS_SHIFT) |
			(6 << TX_LENGTHS_IPG_SHIFT) |
			(32 << TX_LENGTHS_SLOT_TIME_SHIFT),
			
			/* Receive rules. */
			MAC_RCV_RULE_CFG, RCV_RULE_CFG_DEFAULT_CLASS,
			RCVLPC_CONFIG, 0x0181,
			
			/* Receive/send statistics. */
			RCVLPC_STATS_ENABLE, 0xffffff,
			RCVLPC_STATSCTRL, RCVLPC_STATSCTRL_ENABLE,
			SNDDATAI_STATSENAB, 0xffffff,
			SNDDATAI_STATSCTRL, (SNDDATAI_SCTRL_ENABLE |SNDDATAI_SCTRL_FASTUPD),
			
			/* Host coalescing engine */
			HOSTCC_RXCOL_TICKS, 0,
			HOSTCC_TXCOL_TICKS, LOW_TXCOL_TICKS,
			HOSTCC_RXMAX_FRAMES, 1,
			HOSTCC_TXMAX_FRAMES, LOW_RXMAX_FRAMES,
			HOSTCC_RXCOAL_MAXF_INT, 1,
			HOSTCC_TXCOAL_MAXF_INT, 0,
			
			/* Status/statistics block address. */
			/* Etherboot lives below 4GB, so HIGH == 0 */
			HOSTCC_STATUS_BLK_HOST_ADDR + TG3_64BIT_REG_HIGH, 0,

			/* No need to enable 32byte coalesce mode. */
			HOSTCC_MODE, HOSTCC_MODE_ENABLE | 0,
			
			RCVCC_MODE, RCVCC_MODE_ENABLE | RCVCC_MODE_ATTN_ENABLE,
			RCVLPC_MODE, RCVLPC_MODE_ENABLE,
			
			RCVDCC_MODE, RCVDCC_MODE_ENABLE | RCVDCC_MODE_ATTN_ENABLE,

			SNDDATAC_MODE, SNDDATAC_MODE_ENABLE,
			SNDBDC_MODE, SNDBDC_MODE_ENABLE | SNDBDC_MODE_ATTN_ENABLE,
			RCVBDI_MODE, RCVBDI_MODE_ENABLE | RCVBDI_MODE_RCB_ATTN_ENAB,
			RCVDBDI_MODE, RCVDBDI_MODE_ENABLE | RCVDBDI_MODE_INV_RING_SZ,
			SNDDATAI_MODE, SNDDATAI_MODE_ENABLE,
			SNDBDI_MODE, SNDBDI_MODE_ENABLE | SNDBDI_MODE_ATTN_ENABLE,
			SNDBDS_MODE, SNDBDS_MODE_ENABLE | SNDBDS_MODE_ATTN_ENABLE,
			
			/* Accept all multicast frames. */
			MAC_HASH_REG_0, 0xffffffff,
			MAC_HASH_REG_1, 0xffffffff,
			MAC_HASH_REG_2, 0xffffffff,
			MAC_HASH_REG_3, 0xffffffff,
		};
		static const uint32_t table_not_5705[] = {
			/* Host coalescing engine */
			HOSTCC_RXCOAL_TICK_INT, 0,
			HOSTCC_TXCOAL_TICK_INT, 0,

			/* Status/statistics block address. */
			/* Etherboot lives below 4GB, so HIGH == 0 */
			HOSTCC_STAT_COAL_TICKS, DEFAULT_STAT_COAL_TICKS,
			HOSTCC_STATS_BLK_HOST_ADDR + TG3_64BIT_REG_HIGH, 0,
			HOSTCC_STATS_BLK_NIC_ADDR, NIC_SRAM_STATS_BLK,
			HOSTCC_STATUS_BLK_NIC_ADDR, NIC_SRAM_STATUS_BLK,

			RCVLSC_MODE, RCVLSC_MODE_ENABLE | RCVLSC_MODE_ATTN_ENABLE,

			MBFREE_MODE, MBFREE_MODE_ENABLE,
		};
		TG3_WRITE_SETTINGS(table_all);
		tw32(HOSTCC_STATS_BLK_HOST_ADDR + TG3_64BIT_REG_LOW,
			virt_to_bus(tp->hw_stats));
		tw32(HOSTCC_STATUS_BLK_HOST_ADDR + TG3_64BIT_REG_LOW,
			virt_to_bus(tp->hw_status));
		if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5705 &&
		    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5787) {
			TG3_WRITE_SETTINGS(table_not_5705);
		}
	}

	tp->tx_mode = TX_MODE_ENABLE;
	tw32_carefully(MAC_TX_MODE, tp->tx_mode);

	tp->rx_mode = RX_MODE_ENABLE;
	tw32_carefully(MAC_RX_MODE, tp->rx_mode);

	tp->mi_mode = MAC_MI_MODE_BASE;
	tw32_carefully(MAC_MI_MODE, tp->mi_mode);

	tw32(MAC_LED_CTRL, 0);
	tw32(MAC_MI_STAT, MAC_MI_STAT_LNKSTAT_ATTN_ENAB);
	if (tp->phy_id == PHY_ID_SERDES) {
		tw32_carefully(MAC_RX_MODE, RX_MODE_RESET);
	}
	tp->rx_mode |= RX_MODE_KEEP_VLAN_TAG; /* drop tagged vlan packets */
	tw32_carefully(MAC_RX_MODE, tp->rx_mode);

	if (tp->pci_chip_rev_id == CHIPREV_ID_5703_A1)
		tw32(MAC_SERDES_CFG, 0x616000);

	/* Prevent chip from dropping frames when flow control
	 * is enabled.
	 */
	tw32(MAC_LOW_WMARK_MAX_RX_FRAME, 2);
	tr32(MAC_LOW_WMARK_MAX_RX_FRAME);

	err = tg3_setup_phy(tp);

	/* Ignore CRC stats */

	/* Initialize receive rules. */
	tw32(MAC_RCV_RULE_0,  0xc2000000 & RCV_RULE_DISABLE_MASK);
	tw32(MAC_RCV_VALUE_0, 0xffffffff & RCV_RULE_DISABLE_MASK);
	tw32(MAC_RCV_RULE_1,  0x86000004 & RCV_RULE_DISABLE_MASK);
	tw32(MAC_RCV_VALUE_1, 0xffffffff & RCV_RULE_DISABLE_MASK);

	if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705)
	    || (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5750))
		limit = 8;
	else
		limit = 16;
	if (tp->tg3_flags & TG3_FLAG_ENABLE_ASF)
		limit -= 4;
	switch (limit) {
	case 16:	tw32(MAC_RCV_RULE_15,  0); tw32(MAC_RCV_VALUE_15,  0);
	case 15:	tw32(MAC_RCV_RULE_14,  0); tw32(MAC_RCV_VALUE_14,  0);
	case 14:	tw32(MAC_RCV_RULE_13,  0); tw32(MAC_RCV_VALUE_13,  0);
	case 13:	tw32(MAC_RCV_RULE_12,  0); tw32(MAC_RCV_VALUE_12,  0);
	case 12:	tw32(MAC_RCV_RULE_11,  0); tw32(MAC_RCV_VALUE_11,  0);
	case 11:	tw32(MAC_RCV_RULE_10,  0); tw32(MAC_RCV_VALUE_10,  0);
	case 10:	tw32(MAC_RCV_RULE_9,  0);  tw32(MAC_RCV_VALUE_9,  0);
	case 9:		tw32(MAC_RCV_RULE_8,  0);  tw32(MAC_RCV_VALUE_8,  0);
	case 8:		tw32(MAC_RCV_RULE_7,  0);  tw32(MAC_RCV_VALUE_7,  0);
	case 7:		tw32(MAC_RCV_RULE_6,  0);  tw32(MAC_RCV_VALUE_6,  0);
	case 6:		tw32(MAC_RCV_RULE_5,  0);  tw32(MAC_RCV_VALUE_5,  0);
	case 5:		tw32(MAC_RCV_RULE_4,  0);  tw32(MAC_RCV_VALUE_4,  0);
	case 4:		/* tw32(MAC_RCV_RULE_3,  0); tw32(MAC_RCV_VALUE_3,  0); */
	case 3:		/* tw32(MAC_RCV_RULE_2,  0); tw32(MAC_RCV_VALUE_2,  0); */
	case 2:
	case 1:
	default:
		break;
	};

	return err;
}



/* Chips other than 5700/5701 use the NVRAM for fetching info. */
static void tg3_nvram_init(struct tg3 *tp)
{
	tw32(GRC_EEPROM_ADDR,
	     (EEPROM_ADDR_FSM_RESET |
	      (EEPROM_DEFAULT_CLOCK_PERIOD <<
	       EEPROM_ADDR_CLKPERD_SHIFT)));

	mdelay(1);

	/* Enable seeprom accesses. */
	tw32_carefully(GRC_LOCAL_CTRL,
		tr32(GRC_LOCAL_CTRL) | GRC_LCLCTRL_AUTO_SEEPROM);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5700 &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5701) {
		uint32_t nvcfg1 = tr32(NVRAM_CFG1);

		tp->tg3_flags |= TG3_FLAG_NVRAM;
		if (nvcfg1 & NVRAM_CFG1_FLASHIF_ENAB) {
			if (nvcfg1 & NVRAM_CFG1_BUFFERED_MODE)
				tp->tg3_flags |= TG3_FLAG_NVRAM_BUFFERED;
		} else {
			nvcfg1 &= ~NVRAM_CFG1_COMPAT_BYPASS;
			tw32(NVRAM_CFG1, nvcfg1);
		}

	} else {
		tp->tg3_flags &= ~(TG3_FLAG_NVRAM | TG3_FLAG_NVRAM_BUFFERED);
	}
}


static int tg3_nvram_read_using_eeprom(
	struct tg3 *tp __unused, uint32_t offset, uint32_t *val)
{
	uint32_t tmp;
	int i;

	if (offset > EEPROM_ADDR_ADDR_MASK ||
		(offset % 4) != 0) {
		return -EINVAL;
	}

	tmp = tr32(GRC_EEPROM_ADDR) & ~(EEPROM_ADDR_ADDR_MASK |
					EEPROM_ADDR_DEVID_MASK |
					EEPROM_ADDR_READ);
	tw32(GRC_EEPROM_ADDR,
	     tmp |
	     (0 << EEPROM_ADDR_DEVID_SHIFT) |
	     ((offset << EEPROM_ADDR_ADDR_SHIFT) &
	      EEPROM_ADDR_ADDR_MASK) |
	     EEPROM_ADDR_READ | EEPROM_ADDR_START);

	for (i = 0; i < 10000; i++) {
		tmp = tr32(GRC_EEPROM_ADDR);

		if (tmp & EEPROM_ADDR_COMPLETE)
			break;
		udelay(100);
	}
	if (!(tmp & EEPROM_ADDR_COMPLETE)) {
		return -EBUSY;
	}

	*val = tr32(GRC_EEPROM_DATA);
	return 0;
}

static int tg3_nvram_read(struct tg3 *tp, uint32_t offset, uint32_t *val)
{
	int i, saw_done_clear;

	if (!(tp->tg3_flags & TG3_FLAG_NVRAM))
		return tg3_nvram_read_using_eeprom(tp, offset, val);

	if (tp->tg3_flags & TG3_FLAG_NVRAM_BUFFERED)
		offset = ((offset / NVRAM_BUFFERED_PAGE_SIZE) <<
			  NVRAM_BUFFERED_PAGE_POS) +
			(offset % NVRAM_BUFFERED_PAGE_SIZE);

	if (offset > NVRAM_ADDR_MSK)
		return -EINVAL;

	tw32(NVRAM_SWARB, SWARB_REQ_SET1);
	for (i = 0; i < 1000; i++) {
		if (tr32(NVRAM_SWARB) & SWARB_GNT1)
			break;
		udelay(20);
	}

	tw32(NVRAM_ADDR, offset);
	tw32(NVRAM_CMD,
	     NVRAM_CMD_RD | NVRAM_CMD_GO |
	     NVRAM_CMD_FIRST | NVRAM_CMD_LAST | NVRAM_CMD_DONE);

	/* Wait for done bit to clear then set again. */
	saw_done_clear = 0;
	for (i = 0; i < 1000; i++) {
		udelay(10);
		if (!saw_done_clear &&
		    !(tr32(NVRAM_CMD) & NVRAM_CMD_DONE))
			saw_done_clear = 1;
		else if (saw_done_clear &&
			 (tr32(NVRAM_CMD) & NVRAM_CMD_DONE))
			break;
	}
	if (i >= 1000) {
		tw32(NVRAM_SWARB, SWARB_REQ_CLR1);
		return -EBUSY;
	}

	*val = bswap_32(tr32(NVRAM_RDDATA));
	tw32(NVRAM_SWARB, 0x20);

	return 0;
}

struct subsys_tbl_ent {
	uint16_t subsys_vendor, subsys_devid;
	uint32_t phy_id;
};

static struct subsys_tbl_ent subsys_id_to_phy_id[] = {
	/* Broadcom boards. */
	{ 0x14e4, 0x1644, PHY_ID_BCM5401 }, /* BCM95700A6 */
	{ 0x14e4, 0x0001, PHY_ID_BCM5701 }, /* BCM95701A5 */
	{ 0x14e4, 0x0002, PHY_ID_BCM8002 }, /* BCM95700T6 */
	{ 0x14e4, 0x0003, PHY_ID_SERDES  }, /* BCM95700A9 */
	{ 0x14e4, 0x0005, PHY_ID_BCM5701 }, /* BCM95701T1 */
	{ 0x14e4, 0x0006, PHY_ID_BCM5701 }, /* BCM95701T8 */
	{ 0x14e4, 0x0007, PHY_ID_SERDES  }, /* BCM95701A7 */
	{ 0x14e4, 0x0008, PHY_ID_BCM5701 }, /* BCM95701A10 */
	{ 0x14e4, 0x8008, PHY_ID_BCM5701 }, /* BCM95701A12 */
	{ 0x14e4, 0x0009, PHY_ID_BCM5701 }, /* BCM95703Ax1 */
	{ 0x14e4, 0x8009, PHY_ID_BCM5701 }, /* BCM95703Ax2 */

	/* 3com boards. */
	{ PCI_VENDOR_ID_3COM, 0x1000, PHY_ID_BCM5401 }, /* 3C996T */
	{ PCI_VENDOR_ID_3COM, 0x1006, PHY_ID_BCM5701 }, /* 3C996BT */
	/* { PCI_VENDOR_ID_3COM, 0x1002, PHY_ID_XXX },     3C996CT */
	/* { PCI_VENDOR_ID_3COM, 0x1003, PHY_ID_XXX },     3C997T */
	{ PCI_VENDOR_ID_3COM, 0x1004, PHY_ID_SERDES  }, /* 3C996SX */
	/* { PCI_VENDOR_ID_3COM, 0x1005, PHY_ID_XXX },     3C997SZ */
	{ PCI_VENDOR_ID_3COM, 0x1007, PHY_ID_BCM5701 }, /* 3C1000T */
	{ PCI_VENDOR_ID_3COM, 0x1008, PHY_ID_BCM5701 }, /* 3C940BR01 */

	/* DELL boards. */
	{ PCI_VENDOR_ID_DELL, 0x00d1, PHY_ID_BCM5401 }, /* VIPER */
	{ PCI_VENDOR_ID_DELL, 0x0106, PHY_ID_BCM5401 }, /* JAGUAR */
	{ PCI_VENDOR_ID_DELL, 0x0109, PHY_ID_BCM5411 }, /* MERLOT */
	{ PCI_VENDOR_ID_DELL, 0x010a, PHY_ID_BCM5411 }, /* SLIM_MERLOT */
	{ PCI_VENDOR_ID_DELL, 0x0179, PHY_ID_BCM5751 }, /* EtherXpress */
	
	/* Fujitsu Siemens Computer */
	{ PCI_VENDOR_ID_FSC, 0x105d, PHY_ID_BCM5751 }, /* Futro C200 */	

	/* Compaq boards. */
	{ PCI_VENDOR_ID_COMPAQ, 0x007c, PHY_ID_BCM5701 }, /* BANSHEE */
	{ PCI_VENDOR_ID_COMPAQ, 0x009a, PHY_ID_BCM5701 }, /* BANSHEE_2 */
	{ PCI_VENDOR_ID_COMPAQ, 0x007d, PHY_ID_SERDES  }, /* CHANGELING */
	{ PCI_VENDOR_ID_COMPAQ, 0x0085, PHY_ID_BCM5701 }, /* NC7780 */
	{ PCI_VENDOR_ID_COMPAQ, 0x0099, PHY_ID_BCM5701 }  /* NC7780_2 */
};

static int tg3_phy_probe(struct tg3 *tp)
{
	uint32_t eeprom_phy_id, hw_phy_id_1, hw_phy_id_2;
	uint32_t hw_phy_id, hw_phy_id_masked;
	enum phy_led_mode eeprom_led_mode;
	uint32_t val;
	unsigned i;
	int eeprom_signature_found, err;

	tp->phy_id = PHY_ID_INVALID;

	for (i = 0; i < sizeof(subsys_id_to_phy_id)/sizeof(subsys_id_to_phy_id[0]); i++) {
		if ((subsys_id_to_phy_id[i].subsys_vendor == tp->subsystem_vendor) &&
			(subsys_id_to_phy_id[i].subsys_devid == tp->subsystem_device)) {
			tp->phy_id = subsys_id_to_phy_id[i].phy_id;
			break;
		}
	}

	eeprom_phy_id = PHY_ID_INVALID;
	eeprom_led_mode = led_mode_auto;
	eeprom_signature_found = 0;
	tg3_read_mem(NIC_SRAM_DATA_SIG, &val);
	if (val == NIC_SRAM_DATA_SIG_MAGIC) {
		uint32_t nic_cfg;

		tg3_read_mem(NIC_SRAM_DATA_CFG, &nic_cfg);
		tp->nic_sram_data_cfg = nic_cfg;

		eeprom_signature_found = 1;

		if ((nic_cfg & NIC_SRAM_DATA_CFG_PHY_TYPE_MASK) ==
		    NIC_SRAM_DATA_CFG_PHY_TYPE_FIBER) {
			eeprom_phy_id = PHY_ID_SERDES;
		} else {
			uint32_t nic_phy_id;

			tg3_read_mem(NIC_SRAM_DATA_PHY_ID, &nic_phy_id);
			if (nic_phy_id != 0) {
				uint32_t id1 = nic_phy_id & NIC_SRAM_DATA_PHY_ID1_MASK;
				uint32_t id2 = nic_phy_id & NIC_SRAM_DATA_PHY_ID2_MASK;

				eeprom_phy_id  = (id1 >> 16) << 10;
				eeprom_phy_id |= (id2 & 0xfc00) << 16;
				eeprom_phy_id |= (id2 & 0x03ff) <<  0;
			}
		}

		switch (nic_cfg & NIC_SRAM_DATA_CFG_LED_MODE_MASK) {
		case NIC_SRAM_DATA_CFG_LED_TRIPLE_SPD:
			eeprom_led_mode = led_mode_three_link;
			break;

		case NIC_SRAM_DATA_CFG_LED_LINK_SPD:
			eeprom_led_mode = led_mode_link10;
			break;

		default:
			eeprom_led_mode = led_mode_auto;
			break;
		};
		if (((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703) ||
			(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) ||
			(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705)) &&
			(nic_cfg & NIC_SRAM_DATA_CFG_EEPROM_WP)) {
			tp->tg3_flags |= TG3_FLAG_EEPROM_WRITE_PROT;
		}

		if (nic_cfg & NIC_SRAM_DATA_CFG_ASF_ENABLE)
			tp->tg3_flags |= TG3_FLAG_ENABLE_ASF;
		if (nic_cfg & NIC_SRAM_DATA_CFG_FIBER_WOL)
			tp->tg3_flags |= TG3_FLAG_SERDES_WOL_CAP;
	}

	/* Now read the physical PHY_ID from the chip and verify
	 * that it is sane.  If it doesn't look good, we fall back
	 * to either the hard-coded table based PHY_ID and failing
	 * that the value found in the eeprom area.
	 */
	err  = tg3_readphy(tp, MII_PHYSID1, &hw_phy_id_1);
	err |= tg3_readphy(tp, MII_PHYSID2, &hw_phy_id_2);

	hw_phy_id  = (hw_phy_id_1 & 0xffff) << 10;
	hw_phy_id |= (hw_phy_id_2 & 0xfc00) << 16;
	hw_phy_id |= (hw_phy_id_2 & 0x03ff) <<  0;

	hw_phy_id_masked = hw_phy_id & PHY_ID_MASK;

	if (!err && KNOWN_PHY_ID(hw_phy_id_masked)) {
		tp->phy_id = hw_phy_id;
	} else {
		/* phy_id currently holds the value found in the
		 * subsys_id_to_phy_id[] table or PHY_ID_INVALID
		 * if a match was not found there.
		 */
		if (tp->phy_id == PHY_ID_INVALID) {
			if (!eeprom_signature_found ||
			    !KNOWN_PHY_ID(eeprom_phy_id & PHY_ID_MASK))
				return -ENODEV;
			tp->phy_id = eeprom_phy_id;
		}
	}

	err = tg3_phy_reset(tp);
	if (err)
		return err;

	if (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0 ||
	    tp->pci_chip_rev_id == CHIPREV_ID_5701_B0) {
		uint32_t mii_tg3_ctrl;
		
		/* These chips, when reset, only advertise 10Mb
		 * capabilities.  Fix that.
		 */
		err  = tg3_writephy(tp, MII_ADVERTISE,
				    (ADVERTISE_CSMA |
				     ADVERTISE_PAUSE_CAP |
				     ADVERTISE_10HALF |
				     ADVERTISE_10FULL |
				     ADVERTISE_100HALF |
				     ADVERTISE_100FULL));
		mii_tg3_ctrl = (MII_TG3_CTRL_ADV_1000_HALF |
				MII_TG3_CTRL_ADV_1000_FULL |
				MII_TG3_CTRL_AS_MASTER |
				MII_TG3_CTRL_ENABLE_AS_MASTER);
		if (tp->tg3_flags & TG3_FLAG_10_100_ONLY)
			mii_tg3_ctrl = 0;

		err |= tg3_writephy(tp, MII_TG3_CTRL, mii_tg3_ctrl);
		err |= tg3_writephy(tp, MII_BMCR,
				    (BMCR_ANRESTART | BMCR_ANENABLE));
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703) {
		tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x0c00);
		tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x201f);
		tg3_writedsp(tp, MII_TG3_DSP_RW_PORT, 0x2aaa);
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) {
		tg3_writephy(tp, 0x1c, 0x8d68);
		tg3_writephy(tp, 0x1c, 0x8d68);
	}

	/* Enable Ethernet@WireSpeed */
	tg3_phy_set_wirespeed(tp);

	if (!err && ((tp->phy_id & PHY_ID_MASK) == PHY_ID_BCM5401)) {
		err = tg3_init_5401phy_dsp(tp);
	}

	/* Determine the PHY led mode. 
	 * Be careful if this gets set wrong it can result in an inability to 
	 * establish a link.
	 */
	if (tp->phy_id == PHY_ID_SERDES) {
		tp->led_mode = led_mode_three_link;
	}
	else if (tp->subsystem_vendor == PCI_VENDOR_ID_DELL) {
		tp->led_mode = led_mode_link10;
	} else {
		tp->led_mode = led_mode_three_link;
		if (eeprom_signature_found &&
		    eeprom_led_mode != led_mode_auto)
			tp->led_mode = eeprom_led_mode;
	}

	if (tp->phy_id == PHY_ID_SERDES)
		tp->link_config.advertising =
			(ADVERTISED_1000baseT_Half |
			 ADVERTISED_1000baseT_Full |
			 ADVERTISED_Autoneg |
			 ADVERTISED_FIBRE);
	if (tp->tg3_flags & TG3_FLAG_10_100_ONLY)
		tp->link_config.advertising &=
			~(ADVERTISED_1000baseT_Half |
			  ADVERTISED_1000baseT_Full);

	return err;
}

#if SUPPORT_PARTNO_STR
static void tg3_read_partno(struct tg3 *tp)
{
	unsigned char vpd_data[256];
	int i;

	for (i = 0; i < 256; i += 4) {
		uint32_t tmp;

		if (tg3_nvram_read(tp, 0x100 + i, &tmp))
			goto out_not_found;

		vpd_data[i + 0] = ((tmp >>  0) & 0xff);
		vpd_data[i + 1] = ((tmp >>  8) & 0xff);
		vpd_data[i + 2] = ((tmp >> 16) & 0xff);
		vpd_data[i + 3] = ((tmp >> 24) & 0xff);
	}

	/* Now parse and find the part number. */
	for (i = 0; i < 256; ) {
		unsigned char val = vpd_data[i];
		int block_end;

		if (val == 0x82 || val == 0x91) {
			i = (i + 3 +
			     (vpd_data[i + 1] +
			      (vpd_data[i + 2] << 8)));
			continue;
		}

		if (val != 0x90)
			goto out_not_found;

		block_end = (i + 3 +
			     (vpd_data[i + 1] +
			      (vpd_data[i + 2] << 8)));
		i += 3;
		while (i < block_end) {
			if (vpd_data[i + 0] == 'P' &&
			    vpd_data[i + 1] == 'N') {
				int partno_len = vpd_data[i + 2];

				if (partno_len > 24)
					goto out_not_found;

				memcpy(tp->board_part_number,
				       &vpd_data[i + 3],
				       partno_len);

				/* Success. */
				return;
			}
		}

		/* Part number not found. */
		goto out_not_found;
	}

out_not_found:
	memcpy(tp->board_part_number, "none", sizeof("none"));
}
#else
#define tg3_read_partno(TP) ((TP)->board_part_number[0] = '\0')
#endif

static int tg3_get_invariants(struct tg3 *tp)
{
	uint32_t misc_ctrl_reg;
	uint32_t pci_state_reg, grc_misc_cfg;
	uint16_t pci_cmd;
	uint8_t  pci_latency;
	uint32_t val ;
	int err;

	/* Read the subsystem vendor and device ids */
	pci_read_config_word(tp->pdev, PCI_SUBSYSTEM_VENDOR_ID, &tp->subsystem_vendor);
	pci_read_config_word(tp->pdev, PCI_SUBSYSTEM_ID, &tp->subsystem_device);

	/* The sun_5704 code needs infrastructure etherboot does have
	 * ignore it for now.
	 */

	/* If we have an AMD 762 or Intel ICH/ICH0 chipset, write
	 * reordering to the mailbox registers done by the host
	 * controller can cause major troubles.  We read back from
	 * every mailbox register write to force the writes to be
	 * posted to the chip in order.
	 *
	 * TG3_FLAG_MBOX_WRITE_REORDER has been forced on.
	 */

	/* Force memory write invalidate off.  If we leave it on,
	 * then on 5700_BX chips we have to enable a workaround.
	 * The workaround is to set the TG3PCI_DMA_RW_CTRL boundry
	 * to match the cacheline size.  The Broadcom driver have this
	 * workaround but turns MWI off all the times so never uses
	 * it.  This seems to suggest that the workaround is insufficient.
	 */
	pci_read_config_word(tp->pdev, PCI_COMMAND, &pci_cmd);
	pci_cmd &= ~PCI_COMMAND_INVALIDATE;
	/* Also, force SERR#/PERR# in PCI command. */
	pci_cmd |= PCI_COMMAND_PARITY | PCI_COMMAND_SERR;
	pci_write_config_word(tp->pdev, PCI_COMMAND, pci_cmd);

	/* It is absolutely critical that TG3PCI_MISC_HOST_CTRL
	 * has the register indirect write enable bit set before
	 * we try to access any of the MMIO registers.  It is also
	 * critical that the PCI-X hw workaround situation is decided
	 * before that as well.
	 */
	pci_read_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL, &misc_ctrl_reg);

	tp->pci_chip_rev_id = (misc_ctrl_reg >> MISC_HOST_CTRL_CHIPREV_SHIFT);

	/* Initialize misc host control in PCI block. */
	tp->misc_host_ctrl |= (misc_ctrl_reg &
			       MISC_HOST_CTRL_CHIPREV);
	pci_write_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL,
			       tp->misc_host_ctrl);

	pci_read_config_byte(tp->pdev, PCI_LATENCY_TIMER, &pci_latency);
	if (pci_latency < 64) {
		pci_write_config_byte(tp->pdev, PCI_LATENCY_TIMER, 64);
	}

	pci_read_config_dword(tp->pdev, TG3PCI_PCISTATE, &pci_state_reg);

	/* If this is a 5700 BX chipset, and we are in PCI-X
	 * mode, enable register write workaround.
	 *
	 * The workaround is to use indirect register accesses
	 * for all chip writes not to mailbox registers.
	 *
	 * In etherboot to simplify things we just always use this work around.
	 */
	if ((pci_state_reg & PCISTATE_CONV_PCI_MODE) == 0) {
		tp->tg3_flags |= TG3_FLAG_PCIX_MODE;
	}
	/* Back to back register writes can cause problems on the 5701,
	 * the workaround is to read back all reg writes except those to
	 * mailbox regs.
	 * In etherboot we always use indirect register accesses so
	 * we don't see this.
	 */

	if ((pci_state_reg & PCISTATE_BUS_SPEED_HIGH) != 0)
		tp->tg3_flags |= TG3_FLAG_PCI_HIGH_SPEED;
	if ((pci_state_reg & PCISTATE_BUS_32BIT) != 0)
		tp->tg3_flags |= TG3_FLAG_PCI_32BIT;

	/* Chip-specific fixup from Broadcom driver */
	if ((tp->pci_chip_rev_id == CHIPREV_ID_5704_A0) &&
	    (!(pci_state_reg & PCISTATE_RETRY_SAME_DMA))) {
		pci_state_reg |= PCISTATE_RETRY_SAME_DMA;
		pci_write_config_dword(tp->pdev, TG3PCI_PCISTATE, pci_state_reg);
	}

	/* determine if it is PCIE system */
	// Alf : I have no idea what this is about...
	// But it's definitely usefull
	val = pci_find_capability(tp->pdev, PCI_CAP_ID_EXP);
	if (val)
		tp->tg3_flags2 |= TG3_FLG2_PCI_EXPRESS;

	/* Force the chip into D0. */
	tg3_set_power_state_0(tp);

	/* Etherboot does not ask the tg3 to do checksums */
	/* Etherboot does not ask the tg3 to do jumbo frames */
	/* Ehterboot does not ask the tg3 to use WakeOnLan. */

	/* A few boards don't want Ethernet@WireSpeed phy feature */
	if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700) ||
	    (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5750) ||
		((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705) &&
			(tp->pci_chip_rev_id != CHIPREV_ID_5705_A0) &&
			(tp->pci_chip_rev_id != CHIPREV_ID_5705_A1))) {
		tp->tg3_flags2 |= TG3_FLG2_NO_ETH_WIRE_SPEED;
	}

	/* Avoid tagged irq status etherboot does not use irqs */

	/* Only 5701 and later support tagged irq status mode.
	 * Also, 5788 chips cannot use tagged irq status.
	 *
	 * However, since etherboot does not use irqs avoid tagged irqs
	 * status  because the interrupt condition is more difficult to
	 * fully clear in that mode.
	 */
	
	/* Since some 5700_AX && 5700_BX have problems with 32BYTE
	 * coalesce_mode, and the rest work fine anything set.
	 * Don't enable HOST_CC_MODE_32BYTE in etherboot.
	 */

	/* Initialize MAC MI mode, polling disabled. */
	tw32_carefully(MAC_MI_MODE, tp->mi_mode);

	/* Initialize data/descriptor byte/word swapping. */
	tw32(GRC_MODE, tp->grc_mode);

	tg3_switch_clocks(tp);

	/* Clear this out for sanity. */
	tw32(TG3PCI_MEM_WIN_BASE_ADDR, 0);

	/* Etherboot does not need to check if the PCIX_TARGET_HWBUG
	 * is needed.  It always uses it.
	 */
	
	udelay(50);
	tg3_nvram_init(tp);

	/* The TX descriptors will reside in main memory.
	 */

	/* See which board we are using.
	 */
	grc_misc_cfg = tr32(GRC_MISC_CFG);
	grc_misc_cfg &= GRC_MISC_CFG_BOARD_ID_MASK;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704 &&
	    grc_misc_cfg == GRC_MISC_CFG_BOARD_ID_5704CIOBE) {
		tp->tg3_flags |= TG3_FLAG_SPLIT_MODE;
		tp->split_mode_max_reqs = SPLIT_MODE_5704_MAX_REQ;
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705 &&
	    (grc_misc_cfg == GRC_MISC_CFG_BOARD_ID_5788 ||
	     grc_misc_cfg == GRC_MISC_CFG_BOARD_ID_5788M))
		tp->tg3_flags2 |= TG3_FLG2_IS_5788;

#define PCI_DEVICE_ID_TIGON3_5901	0x170d
#define PCI_DEVICE_ID_TIGON3_5901_2	0x170e

	/* these are limited to 10/100 only */
	if (((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703) &&
		    ((grc_misc_cfg == 0x8000) || (grc_misc_cfg == 0x4000))) ||
		((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705) &&
			(tp->pdev->vendor == PCI_VENDOR_ID_BROADCOM) &&
			((tp->pdev->device == PCI_DEVICE_ID_TIGON3_5901) ||
				(tp->pdev->device == PCI_DEVICE_ID_TIGON3_5901_2)))) {
		tp->tg3_flags |= TG3_FLAG_10_100_ONLY;
	}

	err = tg3_phy_probe(tp);
	if (err) {
		printf("phy probe failed, err %d\n", err);
	}

	tg3_read_partno(tp);


	/* 5700 BX chips need to have their TX producer index mailboxes
	 * written twice to workaround a bug.
	 * In etherboot we do this unconditionally to simplify things.
	 */

	/* 5700 chips can get confused if TX buffers straddle the
	 * 4GB address boundary in some cases.
	 * 
	 * In etherboot we can ignore the problem as etherboot lives below 4GB.
	 */

	/* In etherboot wake-on-lan is unconditionally disabled */
	return err;
}

static int  tg3_get_device_address(struct tg3 *tp)
{
	struct nic *nic = tp->nic;
	uint32_t hi, lo, mac_offset;

	if (PCI_FUNC(tp->pdev->busdevfn) == 0)
		mac_offset = 0x7c;
	else
		mac_offset = 0xcc;

	/* First try to get it from MAC address mailbox. */
	tg3_read_mem(NIC_SRAM_MAC_ADDR_HIGH_MBOX, &hi);
	if ((hi >> 16) == 0x484b) {
		nic->node_addr[0] = (hi >>  8) & 0xff;
		nic->node_addr[1] = (hi >>  0) & 0xff;

		tg3_read_mem(NIC_SRAM_MAC_ADDR_LOW_MBOX, &lo);
		nic->node_addr[2] = (lo >> 24) & 0xff;
		nic->node_addr[3] = (lo >> 16) & 0xff;
		nic->node_addr[4] = (lo >>  8) & 0xff;
		nic->node_addr[5] = (lo >>  0) & 0xff;
	}
	/* Next, try NVRAM. */
	else if (!tg3_nvram_read(tp, mac_offset + 0, &hi) &&
		 !tg3_nvram_read(tp, mac_offset + 4, &lo)) {
		nic->node_addr[0] = ((hi >> 16) & 0xff);
		nic->node_addr[1] = ((hi >> 24) & 0xff);
		nic->node_addr[2] = ((lo >>  0) & 0xff);
		nic->node_addr[3] = ((lo >>  8) & 0xff);
		nic->node_addr[4] = ((lo >> 16) & 0xff);
		nic->node_addr[5] = ((lo >> 24) & 0xff);
	}
	/* Finally just fetch it out of the MAC control regs. */
	else {
		hi = tr32(MAC_ADDR_0_HIGH);
		lo = tr32(MAC_ADDR_0_LOW);

		nic->node_addr[5] = lo & 0xff;
		nic->node_addr[4] = (lo >> 8) & 0xff;
		nic->node_addr[3] = (lo >> 16) & 0xff;
		nic->node_addr[2] = (lo >> 24) & 0xff;
		nic->node_addr[1] = hi & 0xff;
		nic->node_addr[0] = (hi >> 8) & 0xff;
	}

	return 0;
}


static int tg3_setup_dma(struct tg3 *tp)
{
	tw32(TG3PCI_CLOCK_CTRL, 0);

	if ((tp->tg3_flags & TG3_FLAG_PCIX_MODE) == 0) {
		tp->dma_rwctrl =
			(0x7 << DMA_RWCTRL_PCI_WRITE_CMD_SHIFT) |
			(0x6 << DMA_RWCTRL_PCI_READ_CMD_SHIFT) |
			(0x7 << DMA_RWCTRL_WRITE_WATER_SHIFT) |
			(0x7 << DMA_RWCTRL_READ_WATER_SHIFT) |
			(0x0f << DMA_RWCTRL_MIN_DMA_SHIFT);
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705) {
			tp->dma_rwctrl &= ~(DMA_RWCTRL_MIN_DMA << DMA_RWCTRL_MIN_DMA_SHIFT);
		}
	} else {
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704)
			tp->dma_rwctrl =
				(0x7 << DMA_RWCTRL_PCI_WRITE_CMD_SHIFT) |
				(0x6 << DMA_RWCTRL_PCI_READ_CMD_SHIFT) |
				(0x3 << DMA_RWCTRL_WRITE_WATER_SHIFT) |
				(0x7 << DMA_RWCTRL_READ_WATER_SHIFT) |
				(0x00 << DMA_RWCTRL_MIN_DMA_SHIFT);
		else
			tp->dma_rwctrl =
				(0x7 << DMA_RWCTRL_PCI_WRITE_CMD_SHIFT) |
				(0x6 << DMA_RWCTRL_PCI_READ_CMD_SHIFT) |
				(0x3 << DMA_RWCTRL_WRITE_WATER_SHIFT) |
				(0x3 << DMA_RWCTRL_READ_WATER_SHIFT) |
				(0x0f << DMA_RWCTRL_MIN_DMA_SHIFT);

		/* Wheee, some more chip bugs... */
		if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703) ||
			(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704)) {
			uint32_t ccval = tr32(TG3PCI_CLOCK_CTRL) & 0x1f;

			if ((ccval == 0x6) || (ccval == 0x7)) {
				tp->dma_rwctrl |= DMA_RWCTRL_ONE_DMA;
			}
		}
	}

	if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703) ||
		(GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704)) {
		tp->dma_rwctrl &= ~(DMA_RWCTRL_MIN_DMA << DMA_RWCTRL_MIN_DMA_SHIFT);
	}

	/*
	  Alf : Tried that, but it does not work. Should be this way though :-(
	if (tp->tg3_flags2 & TG3_FLG2_PCI_EXPRESS) {
    	  tp->dma_rwctrl |= 0x001f0000;
	}
	*/
	tp->dma_rwctrl |= DMA_RWCTRL_ASSERT_ALL_BE;

	tw32(TG3PCI_DMA_RW_CTRL, tp->dma_rwctrl);

	return 0;
}

static void tg3_init_link_config(struct tg3 *tp)
{
	tp->link_config.advertising =
		(ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full |
		 ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full |
		 ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full |
		 ADVERTISED_Autoneg | ADVERTISED_MII);
	tp->carrier_ok = 0;
	tp->link_config.active_speed = SPEED_INVALID;
	tp->link_config.active_duplex = DUPLEX_INVALID;
}


#if SUPPORT_PHY_STR
static const char * tg3_phy_string(struct tg3 *tp)
{
	switch (tp->phy_id & PHY_ID_MASK) {
	case PHY_ID_BCM5400:	return "5400";
	case PHY_ID_BCM5401:	return "5401";
	case PHY_ID_BCM5411:	return "5411";
	case PHY_ID_BCM5701:	return "5701";
	case PHY_ID_BCM5703:	return "5703";
	case PHY_ID_BCM5704:	return "5704";
        case PHY_ID_BCM5705:    return "5705";
        case PHY_ID_BCM5750:    return "5750";
	case PHY_ID_BCM5751:	return "5751"; 
	case PHY_ID_BCM5787:	return "5787";
	case PHY_ID_BCM8002:	return "8002/serdes";
	case PHY_ID_SERDES:	return "serdes";
	default:		return "unknown";
	};
}
#else
#define tg3_phy_string(TP) "?"
#endif


static void tg3_poll_link(struct tg3 *tp)
{
	uint32_t mac_stat;

	mac_stat = tr32(MAC_STATUS);
	if (tp->phy_id == PHY_ID_SERDES) {
		if (tp->carrier_ok?
			(mac_stat & MAC_STATUS_LNKSTATE_CHANGED):
			(mac_stat & MAC_STATUS_PCS_SYNCED)) {
			tw32_carefully(MAC_MODE, tp->mac_mode & ~MAC_MODE_PORT_MODE_MASK);
			tw32_carefully(MAC_MODE, tp->mac_mode);

			tg3_setup_phy(tp);
		}
	}
	else {
		if (mac_stat & MAC_STATUS_LNKSTATE_CHANGED) {
			tg3_setup_phy(tp);
		}
	}
}

/**************************************************************************
POLL - Wait for a frame
***************************************************************************/
static void tg3_ack_irqs(struct tg3 *tp)
{
	if (tp->hw_status->status & SD_STATUS_UPDATED) {
		/*
		 * writing any value to intr-mbox-0 clears PCI INTA# and
		 * chip-internal interrupt pending events.
		 * writing non-zero to intr-mbox-0 additional tells the
		 * NIC to stop sending us irqs, engaging "in-intr-handler"
		 * event coalescing.
		 */
		tw32_mailbox(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW, 
			0x00000001);
		/*
		 * Flush PCI write.  This also guarantees that our
		 * status block has been flushed to host memory.
		 */
		tr32(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW);
		tp->hw_status->status &= ~SD_STATUS_UPDATED;
	}
}

static int tg3_poll(struct nic *nic, int retrieve)
{
	/* return true if there's an ethernet packet ready to read */
	/* nic->packet should contain data on return */
	/* nic->packetlen should contain length of data */

	struct tg3 *tp = &tg3;
	int result;

	result = 0;

	if ( (tp->hw_status->idx[0].rx_producer != tp->rx_rcb_ptr) && !retrieve ) 
	  return 1;

	tg3_ack_irqs(tp);

	if (tp->hw_status->idx[0].rx_producer != tp->rx_rcb_ptr) {
		struct tg3_rx_buffer_desc *desc;
		unsigned int len;
		desc = &tp->rx_rcb[tp->rx_rcb_ptr];
		if ((desc->opaque & RXD_OPAQUE_RING_MASK) == RXD_OPAQUE_RING_STD) {
			len = ((desc->idx_len & RXD_LEN_MASK) >> RXD_LEN_SHIFT) - 4; /* omit crc */
			
			nic->packetlen = len;
			memcpy(nic->packet, bus_to_virt(desc->addr_lo), len);
			result = 1;
		}
		tp->rx_rcb_ptr = (tp->rx_rcb_ptr + 1) % TG3_RX_RCB_RING_SIZE;
		
		/* ACK the status ring */
		tw32_mailbox2(MAILBOX_RCVRET_CON_IDX_0 + TG3_64BIT_REG_LOW, tp->rx_rcb_ptr);

		/* Refill RX ring. */
		if (result) {
			tp->rx_std_ptr = (tp->rx_std_ptr + 1) % TG3_RX_RING_SIZE;
			tw32_mailbox2(MAILBOX_RCV_STD_PROD_IDX + TG3_64BIT_REG_LOW, tp->rx_std_ptr);
		}
	}
	tg3_poll_link(tp);
	return result;
}

/**************************************************************************
TRANSMIT - Transmit a frame
***************************************************************************/
#if 0
static void tg3_set_txd(struct tg3 *tp, int entry,
	dma_addr_t mapping, int len, uint32_t flags,
	uint32_t mss_and_is_end)
{
	struct tg3_tx_buffer_desc *txd =  &tp->tx_ring[entry];
	int is_end = (mss_and_is_end & 0x1);
	if (is_end) {
		flags |= TXD_FLAG_END;
	}

	txd->addr_hi   = 0;
	txd->addr_lo   = mapping & 0xffffffff;
	txd->len_flags = (len << TXD_LEN_SHIFT) | flags;
	txd->vlan_tag  = 0 << TXD_VLAN_TAG_SHIFT;
}
#endif

static void tg3_transmit(struct nic *nic, const char *dst_addr,
	unsigned int type, unsigned int size, const char *packet)
{
	static int frame_idx;
	struct eth_frame *frame;
	
	/* send the packet to destination */
	struct tg3_tx_buffer_desc *txd;
	struct tg3 *tp;
	uint32_t entry;
	int i;

	/* Wait until there is a free packet frame */
	tp = &tg3;
	i = 0;
	entry = tp->tx_prod;
	while((tp->hw_status->idx[0].tx_consumer != entry) &&
		(tp->hw_status->idx[0].tx_consumer != PREV_TX(entry))) {
		mdelay(10);	/* give the nick a chance */
		if (++i > 500) { /* timeout 5s for transmit */
			printf("transmit timed out\n");
			tg3_halt(tp);
			tg3_setup_hw(tp);
			return;
		}
	}
	if (i != 0) {
		printf("#");
	}
	
	/* Copy the packet to the our local buffer */
	frame = &tg3_bss.tx_frame[frame_idx];
	memcpy(frame->dst_addr, dst_addr, ETH_ALEN);
	memcpy(frame->src_addr, nic->node_addr, ETH_ALEN);
	frame->type = htons(type);
	memset(frame->data, 0, sizeof(frame->data));
	memcpy(frame->data, packet, size);

	/* Setup the ring buffer entry to transmit */
	txd            = &tp->tx_ring[entry];
	txd->addr_hi   = 0; /* Etherboot runs under 4GB */
	txd->addr_lo   = virt_to_bus(frame);
	txd->len_flags = ((size + ETH_HLEN) << TXD_LEN_SHIFT) | TXD_FLAG_END;
	txd->vlan_tag  = 0 << TXD_VLAN_TAG_SHIFT;

	/* Advance to the next entry */
	entry = NEXT_TX(entry);
	frame_idx ^= 1;

	/* Packets are ready, update Tx producer idx local and on card */
	tw32_mailbox((MAILBOX_SNDHOST_PROD_IDX_0 + TG3_64BIT_REG_LOW), entry);
	tw32_mailbox2((MAILBOX_SNDHOST_PROD_IDX_0 + TG3_64BIT_REG_LOW), entry);
	tp->tx_prod = entry;
}

/**************************************************************************
DISABLE - Turn off ethernet interface
***************************************************************************/
static void tg3_disable ( struct nic *nic __unused ) {
	struct tg3 *tp = &tg3;
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
	tg3_halt(tp);
	tp->tg3_flags &= ~(TG3_FLAG_INIT_COMPLETE|TG3_FLAG_GOT_SERDES_FLOWCTL);
	tp->carrier_ok = 0;
	iounmap((void *)tp->regs);
}

/**************************************************************************
IRQ - Enable, Disable, or Force interrupts
***************************************************************************/
static void tg3_irq(struct nic *nic __unused, irq_action_t action __unused)
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

static struct nic_operations tg3_operations = {
	.connect	= dummy_connect,
	.poll		= tg3_poll,
	.transmit	= tg3_transmit,
	.irq		= tg3_irq,

};

/**************************************************************************
PROBE - Look for an adapter, this routine's visible to the outside
You should omit the last argument struct pci_device * for a non-PCI NIC
***************************************************************************/
static int tg3_probe ( struct nic *nic, struct pci_device *pdev ) {

	struct tg3 *tp = &tg3;
	unsigned long tg3reg_base, tg3reg_len;
	int i, err, pm_cap;

	memset(tp, 0, sizeof(*tp));

	adjust_pci_device(pdev);

	nic->irqno  = 0;
        nic->ioaddr = pdev->ioaddr;

	/* Find power-management capability. */
	pm_cap = pci_find_capability(pdev, PCI_CAP_ID_PM);
	if (pm_cap == 0) {
		printf("Cannot find PowerManagement capability, aborting.\n");
		return 0;
	}
	tg3reg_base = pci_bar_start(pdev, PCI_BASE_ADDRESS_0);
	if (tg3reg_base == -1UL) {
		printf("Unuseable bar\n");
		return 0;
	}
	tg3reg_len  = pci_bar_size(pdev,  PCI_BASE_ADDRESS_0);

	tp->pdev       = pdev;
	tp->nic        = nic;
	tp->pm_cap     = pm_cap;
	tp->rx_mode    = 0;
	tp->tx_mode    = 0;
	tp->mi_mode    = MAC_MI_MODE_BASE;
	tp->tg3_flags  = 0 & ~TG3_FLAG_INIT_COMPLETE; 
	
	/* The word/byte swap controls here control register access byte
	 * swapping.  DMA data byte swapping is controlled in the GRC_MODE
	 * setting below.
	 */
	tp->misc_host_ctrl =
		MISC_HOST_CTRL_MASK_PCI_INT |
		MISC_HOST_CTRL_WORD_SWAP |
		MISC_HOST_CTRL_INDIR_ACCESS |
		MISC_HOST_CTRL_PCISTATE_RW;

	/* The NONFRM (non-frame) byte/word swap controls take effect
	 * on descriptor entries, anything which isn't packet data.
	 *
	 * The StrongARM chips on the board (one for tx, one for rx)
	 * are running in big-endian mode.
	 */
	tp->grc_mode = (GRC_MODE_WSWAP_DATA | GRC_MODE_BSWAP_DATA |
			GRC_MODE_WSWAP_NONFRM_DATA);
#if __BYTE_ORDER == __BIG_ENDIAN
	tp->grc_mode |= GRC_MODE_BSWAP_NONFRM_DATA;
#endif
	tp->regs = (unsigned long) ioremap(tg3reg_base, tg3reg_len);
	if (tp->regs == 0UL) {
		printf("Cannot map device registers, aborting\n");
		return 0;
	}

	tg3_init_link_config(tp);

	err = tg3_get_invariants(tp);
	if (err) {
		printf("Problem fetching invariants of chip, aborting.\n");
		goto err_out_iounmap;
	}

	err = tg3_get_device_address(tp);
	if (err) {
		printf("Could not obtain valid ethernet address, aborting.\n");
		goto err_out_iounmap;
	}

	DBG ( "Ethernet addr: %s\n", eth_ntoa ( nic->node_addr ) );

	tg3_setup_dma(tp);

	/* Now that we have fully setup the chip, save away a snapshot
	 * of the PCI config space.  We need to restore this after
	 * GRC_MISC_CFG core clock resets and some resume events.
	 */
	pci_save_state(tp->pdev, tp->pci_cfg_state);

	printf("Tigon3 [partno(%s) rev %hx PHY(%s)] (PCI%s:%s:%s)\n",
		tp->board_part_number,
		tp->pci_chip_rev_id,
		tg3_phy_string(tp),
		((tp->tg3_flags & TG3_FLAG_PCIX_MODE) ? "X" : ""),
		((tp->tg3_flags & TG3_FLAG_PCI_HIGH_SPEED) ?
			((tp->tg3_flags & TG3_FLAG_PCIX_MODE) ? "133MHz" : "66MHz") :
			((tp->tg3_flags & TG3_FLAG_PCIX_MODE) ? "100MHz" : "33MHz")),
		((tp->tg3_flags & TG3_FLAG_PCI_32BIT) ? "32-bit" : "64-bit"));


	err = tg3_setup_hw(tp); 
	if (err) {
		goto err_out_disable;
	} 
	tp->tg3_flags |= TG3_FLAG_INIT_COMPLETE;

	/* Wait for a reasonable time for the link to come up */
	tg3_poll_link(tp);
	for(i = 0; !tp->carrier_ok && (i < VALID_LINK_TIMEOUT*100); i++) {
		mdelay(1);
		tg3_poll_link(tp);
	}
	if (!tp->carrier_ok){
		printf("Valid link not established\n");
		goto err_out_disable;
	}

	nic->nic_op	= &tg3_operations;
	return 1;

 err_out_iounmap:
	iounmap((void *)tp->regs);
	return 0;
 err_out_disable:
	tg3_disable(nic);
	return 0;
}


static struct pci_device_id tg3_nics[] = {
PCI_ROM(0x14e4, 0x1644, "tg3-5700",        "Broadcom Tigon 3 5700", 0),
PCI_ROM(0x14e4, 0x1645, "tg3-5701",        "Broadcom Tigon 3 5701", 0),
PCI_ROM(0x14e4, 0x1646, "tg3-5702",        "Broadcom Tigon 3 5702", 0),
PCI_ROM(0x14e4, 0x1647, "tg3-5703",        "Broadcom Tigon 3 5703", 0),
PCI_ROM(0x14e4, 0x1648, "tg3-5704",        "Broadcom Tigon 3 5704", 0),
PCI_ROM(0x14e4, 0x164d, "tg3-5702FE",      "Broadcom Tigon 3 5702FE", 0),
PCI_ROM(0x14e4, 0x1653, "tg3-5705",        "Broadcom Tigon 3 5705", 0),
PCI_ROM(0x14e4, 0x1654, "tg3-5705_2",      "Broadcom Tigon 3 5705_2", 0),
PCI_ROM(0x14e4, 0x1659, "tg3-5721",        "Broadcom Tigon 3 5721", 0),
PCI_ROM(0x14e4, 0x165d, "tg3-5705M",       "Broadcom Tigon 3 5705M", 0),
PCI_ROM(0x14e4, 0x165e, "tg3-5705M_2",     "Broadcom Tigon 3 5705M_2", 0),
PCI_ROM(0x14e4, 0x1677, "tg3-5751",        "Broadcom Tigon 3 5751", 0),
PCI_ROM(0x14e4, 0x167a, "tg3-5754",        "Broadcom Tigon 3 5754", 0),
PCI_ROM(0x14e4, 0x1693, "tg3-5787",	   "Broadcom Tigon 3 5787", 0),
PCI_ROM(0x14e4, 0x1696, "tg3-5782",        "Broadcom Tigon 3 5782", 0),
PCI_ROM(0x14e4, 0x169a, "tg3-5786",        "Broadcom Tigon 3 5786", 0),
PCI_ROM(0x14e4, 0x169c, "tg3-5788",        "Broadcom Tigon 3 5788", 0),
PCI_ROM(0x14e4, 0x169d, "tg3-5789",        "Broadcom Tigon 3 5789", 0),
PCI_ROM(0x14e4, 0x16a6, "tg3-5702X",       "Broadcom Tigon 3 5702X", 0),
PCI_ROM(0x14e4, 0x16a7, "tg3-5703X",       "Broadcom Tigon 3 5703X", 0),
PCI_ROM(0x14e4, 0x16a8, "tg3-5704S",       "Broadcom Tigon 3 5704S", 0),
PCI_ROM(0x14e4, 0x16c6, "tg3-5702A3",      "Broadcom Tigon 3 5702A3", 0),
PCI_ROM(0x14e4, 0x16c7, "tg3-5703A3",      "Broadcom Tigon 3 5703A3", 0),
PCI_ROM(0x14e4, 0x170d, "tg3-5901",        "Broadcom Tigon 3 5901", 0),
PCI_ROM(0x14e4, 0x170e, "tg3-5901_2",      "Broadcom Tigon 3 5901_2", 0),
PCI_ROM(0x1148, 0x4400, "tg3-9DXX",        "Syskonnect 9DXX", 0),
PCI_ROM(0x1148, 0x4500, "tg3-9MXX",        "Syskonnect 9MXX", 0),
PCI_ROM(0x173b, 0x03e8, "tg3-ac1000",      "Altima AC1000", 0),
PCI_ROM(0x173b, 0x03e9, "tg3-ac1001",      "Altima AC1001", 0),
PCI_ROM(0x173b, 0x03ea, "tg3-ac9100",      "Altima AC9100", 0),
PCI_ROM(0x173b, 0x03eb, "tg3-ac1003",      "Altima AC1003", 0),
PCI_ROM(0x0e11, 0x00ca, "tg3-hp",	   "HP Tigon 3", 0),
};

PCI_DRIVER ( tg3_driver, tg3_nics, PCI_NO_CLASS );

DRIVER ( "TG3", nic_driver, pci_driver, tg3_driver,
	 tg3_probe, tg3_disable );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
